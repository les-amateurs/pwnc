from binaryninja import (
    BinaryView,
    BinaryDataNotification,
    HighLevelILInstruction,
    QualifiedName,
    SymbolType,
    Type,
    VariableSourceType,
    Function,
    CoreSymbol,
    Section,
    NotificationType,
    show_message_box,
)
from binaryninja.mainthread import worker_interactive_enqueue
from pathlib import Path
import json
import subprocess
import rpyc
import threading
from rpyc import BgServingThread
from rpyc.utils.server import ThreadedServer, spawn
from .config import *
from .extract import TypeCollection


class Client:
    def __init__(self, conn):
        self.conn = conn
        self.bg_serving_thread = BgServingThread(conn)

    def push_update(self, epoch: int):
        try:
            print("pushing update")
            self.conn.root.update_debuginfo(epoch)
            print("done pushing update")
        except Exception as e:
            print(f"error with communication: {e}")


class Service(rpyc.Service):
    def __init__(self, bv: BinaryView):
        self.bv = bv
        self.tmp = TMPDIR  # communicate path over socket later Path(mkdtemp())
        self.tmp.mkdir(parents=True, exist_ok=True)
        self.sources = self.tmp / "sources"
        self.sources.mkdir(parents=True, exist_ok=True)

        self.updates = True
        self.epoch = 0
        self.last_requested_epoch = 0
        self.stopped_functions = set()
        self.fully_visited_functions = set()

        self.first_client = True
        self.clients = dict()

        self.types = TypeCollection(bv)
        self.variables = dict()
        self.functions = dict()
        self.sections = dict()

        self.exposed_relocatable = self.bv.relocatable
        self.language = "High Level IL"
        self.stop_tag_type = self.bv.create_tag_type("BP", "🔴")

        self.visit_all_types()
        self.visit_all_variables()
        self.visit_all_functions()
        self.generate()

        print("service started!")

    def on_connect(self, conn):
        if hasattr(conn.root, "update_debuginfo"):
            client = Client(conn)
            self.clients[conn] = client
            client.push_update(self.epoch)
        else:
            Client(conn)

    def on_disconnect(self, conn):
        if conn in self.clients:
            del self.clients[conn]

    def function_updated(self, addr: int):
        fn = self.bv.get_function_at(addr)
        self.visit_function(fn)
        # self.visit_function_full(fn)
        self.push_update()

    def function_added(self, addr: int):
        fn = self.bv.get_function_at(addr)
        self.visit_function(fn)
        self.push_update()

    def function_removed(self, addr: int):
        fn = self.bv.get_function_at(addr)
        self.forget_function(fn)
        self.push_update()

    def symbol_updated(self, addr: int):
        var = self.bv.get_symbol_at(addr)
        self.visit_variable(var)
        self.push_update()

    def symbol_added(self, addr: int):
        var = self.bv.get_symbol_at(addr)
        self.visit_variable(var)
        self.push_update()

    def symbol_removed(self, addr: int):
        var = self.bv.get_symbol_at(addr)
        self.forget_variable(var)
        self.push_update()

    def type_added(self, type: Type, name: QualifiedName | str | None):
        self.visit_type(type, name)
        self.push_update()

    def type_updated(self, type: Type, name: QualifiedName | str | None):
        self.forget_type(type, name)
        self.visit_type(type, name)
        self.push_update()

    def type_removed(self, type: Type, name: QualifiedName | str | None):
        self.forget_type(type, name)
        self.push_update()

    def request_functions(self, addrs: list[int]):
        self.stopped_functions = set()

        for addr in addrs:
            if self.bv.relocatable:
                addr += self.bv.start
            for fn in self.bv.get_functions_containing(addr):
                self.visit_function_full(fn)
                self.stopped_functions.add(fn.start)

        if len(self.bv.get_functions_containing(addrs[0])) != 0:
            for addr, tag in self.bv.tags:
                if tag.type.name == self.stop_tag_type.name:
                    self.bv.remove_user_data_tag(addr, tag)

            self.bv.add_tag(addrs[0], self.stop_tag_type.name, "stop", user=True)

        self.push_update()

    def push_update(self):
        if self.updates:
            self.updates = False
            self.generate()
            for client in self.clients.values():
                client.push_update(self.epoch)

    def updated(self):
        if not self.updates:
            self.updates = True
            self.fully_visited_functions = set()

    def get_section_at(self, addr: int):
        if sections := self.bv.get_sections_at(addr):
            section: Section = sections[0]
            key = section.name
            self.sections[key] = {}
            self.sections[key]["addr"] = section.start
            self.sections[key]["size"] = section.end - section.start
            return section

    def visit_all_types(self):
        # Ignore existing dwarf types from being auto imported.
        print("visiting user types")
        for name, type in self.bv.user_type_container.types.values():
            self.visit_type(type, name)
        print("visiting library types")
        for library in self.bv.type_libraries:
            print(f"\tvisiting {library.name}")
            for name, type in library.type_container.types.values():
                self.visit_type(type, name)
        print("visiting platform types")
        for name, type in self.bv.type_container.platform.types.items():
            self.visit_type(type, name)

    def forget_type(self, type: Type, name=None):
        self.updated()
        self.types.forget(type, name)

    def visit_type(self, type: Type, name=None):
        self.updated()
        return self.types.visit(type, name)

    def visit_all_variables(self):
        for name, symbols in self.bv.symbols.items():
            for var in symbols:
                # print(f"{var = }")
                self.visit_variable(var)

    def forget_variable(self, var: CoreSymbol):
        if var.address in self.variables:
            self.updated()
            del self.variables[var.address]

    def visit_variable(self, var: CoreSymbol):
        # print(var)
        if var.type.value != SymbolType.DataSymbol.value:
            return

        var = self.bv.get_data_var_at(var.address)
        if var is None:
            return

        key = var.address
        self.updated()
        self.variables[key] = {}

        self.variables[key]["name"] = var.name
        self.variables[key]["size"] = len(var)
        self.variables[key]["typename"] = self.visit_type(var.type)
        if section := self.get_section_at(var.address):
            self.variables[key]["section"] = section.name

    def visit_all_functions(self):
        for function in self.bv.functions:
            self.visit_function(function)

    def forget_function(self, function: Function):
        if function.start in self.functions:
            self.updated()
            del self.functions[function.start]

    def visit_function(self, function: Function):
        if function.symbol.type.value != SymbolType.FunctionSymbol.value:
            return

        # print(f"visiting function normal: {function}")
        # print(self.stopped_functions, function.start in self.stopped_functions)

        key = function.start
        self.updated()

        end = max(map(lambda range: range.end, function.address_ranges))

        self.functions[key] = {}
        self.functions[key]["name"] = function.name
        self.functions[key]["start"] = function.start
        self.functions[key]["end"] = end

        arguments = []
        for parameter in function.parameter_vars:
            location = {}
            match parameter.source_type.value:
                case VariableSourceType.RegisterVariableSourceType.value:
                    location["Register"] = self.bv.arch.get_reg_name(parameter.storage)
                case VariableSourceType.StackVariableSourceType.value:
                    location["StackVariable"] = parameter.storage
                case _:
                    raise NotImplementedError(
                        f"unhandled variable source type: {parameter.source_type}"
                    )

            arguments.append(
                (location, parameter.name, self.visit_type(parameter.type))
            )

        self.functions[key]["arguments"] = arguments
        self.functions[key]["ellipsis"] = function.type.has_variable_arguments.value
        self.functions[key]["returntype"] = self.visit_type(function.type.return_value)

        if section := self.get_section_at(function.start):
            self.functions[key]["section"] = section.name

        if key in self.stopped_functions:
            self.visit_function_full(function)

    def exposed_set_language_representation(self, lang: str):
        if lang in ["High Level IL", "Pseudo C", "Pseudo Rust", "Pseudo Python"]:
            self.language = lang
            self.updated()

    def get_source_and_insns(self, function: Function):
        match self.language:
            case "High Level IL":

                def get_insn_for_line(line):
                    if list(map(str, line.tokens)) == ["do"]:
                        return None
                    return line.il_instruction

                insns = [get_insn_for_line(h) for h in function.hlil.root.lines]
                source = ["    " + str(line) for line in function.hlil.root.lines]
                offset = 1
            case "Pseudo C" | "Pseudo Rust" | "Pseudo Python":
                lines = function.language_representation(
                    self.language
                ).get_linear_lines(function.hlil.root)
                insns = [h.il_instruction for h in lines]
                source = [str(line) for line in lines]
                offset = 1
            case _:
                source = None
                insns = None
                offset = 0

        if insns:
            insns = [insn.ssa_form if insn else None for insn in insns]
        if source:
            source = [str(function)] + source
            source = "\n".join(source)

        return source, insns, offset

    def visit_function_full(self, function: Function):
        key = function.start
        if key in self.fully_visited_functions:
            return

        self.updated()
        self.fully_visited_functions.add(key)
        # print(f"visiting function full: {function}")

        """
        This is used to compute DW_OP_entry_value requests, but thats pretty complicated to
        generate and probably not worth it.
        """
        # if not shallow:
        #     calls = []
        #     for call_site in function.call_sites:
        #         insn = call_site.llil
        #         block = insn.il_basic_block
        #         match insn.operation.value:
        #             case LowLevelILOperation.LLIL_CALL:
        #                 call = {}
        #                 call["return_pc"] = block[insn.instr_index + 1 - block.start].address
        #                 call["target"] = insn.dest.value.value
        #                 calls.append(call)
        #     self.functions[key]["calls"] = calls

        def hlil_instruction_start(insn: HighLevelILInstruction):
            return min(map(lambda llil: llil.address, hlil.llils))

        def hlil_filter(self, hlil: set[HighLevelILInstruction]):
            pass

        locals = []
        localmap = dict()
        arch_specific_vars = []
        for var in function.vars:
            if var.name in ["__saved_rbp", "__return_addr"]:
                arch_specific_vars.append(var)

        for var in function.hlil.vars + function.hlil.aliased_vars + arch_specific_vars:
            if var in function.parameter_vars:
                continue

            local = {}
            local["name"] = var.name
            local["typename"] = self.visit_type(var.type)
            match var.source_type:
                case VariableSourceType.StackVariableSourceType.value:
                    local["location"] = {"StackVariable": var.storage}
                case VariableSourceType.RegisterVariableSourceType.value:
                    local["location"] = {
                        "Register": self.bv.arch.get_reg_name(var.storage)
                    }
                case _:
                    local["location"] = "None"
            local["scope"] = {}

            locals.append(local)
            localmap[var] = local

            # calculate the scope of the local
            # stack variables never go out of scope once initialized
            # register variables go out of scope once they stop being referenced

        if len(locals) > 0:
            self.functions[key]["locals"] = locals

        lines = dict()
        lineinfo = dict()

        # roots = dict()
        # for line in function.hlil.root.lines:
        #     roots[line.il_instruction] = str(line)

        def get_parent(insn):
            if insn in hlils:
                return insn
            while insn.parent not in hlils and insn.parent is not None:
                insn = insn.parent
            return insn.parent

        def get_parents(insn):
            parents = [insn]
            while parents[-1].parent:
                parents.append(parents[-1].parent)
                insn = parents[-1]
            return parents

        def get_hlil(insn):
            if insn.hlils:
                parents = [get_parent(h.ssa_form) for h in insn.hlils]
                if len(set(parents)) == 1:
                    return parents[0]
                else:
                    candidates = []
                    pparents = [get_parents(p) for p in parents]
                    for c in parents:
                        if all([c in pp for pp in pparents]):
                            candidates.append(c)
                    if len(candidates) == 1:
                        return candidates[0]
            if insn.hlil:
                return get_parent(insn.hlil.ssa_form)
            return None

        source, hlils, offset = self.get_source_and_insns(function)
        # print(hlils)
        # print(source)
        if source is not None and hlils is not None:
            for llil in function.llil.ssa_form.instructions:
                hlil = get_hlil(llil)
                # print(hlil)
                if hlil:
                    # if llil.address not in lineinfo:
                    index = hlils.index(hlil) + 1 + offset
                    # self.bv.set_comment_at(llil.address, str(hlil.non_ssa_form) + " " + str(index))
                    lineinfo[llil.address] = index

        # source = str(function.hlil)
        # hlil = list(function.hlil.instructions)
        # index = 0
        # # line 0 doesnt exist, line numbers are one indexed
        # # line 1 is reserved for function signature
        # sourceline = 2
        # for insn in hlil:
        #     if insn in roots:
        #         text = roots[insn]
        #     lines[index] = { "line": sourceline, "text": text, "scope": (len(line) - len(text)) // 4 }
        #     index += 1
        #     sourcelines += 1

        # if len(lines) != len(hlil):
        #     clean = "\n".join(map(lambda line: line["text"], lines.values()))
        #     with open(TMPDIR / "clean.txt", "w+") as fp:
        #         fp.write(clean)
        #     with open(TMPDIR / "hlil.txt", "w+") as fp:
        #         fp.write("\n".join(map(str, hlil)))
        #     raise RuntimeError(f"cleaned up lines({len(lines)}) do not match hlil({len(hlil)})")

        # labels = []
        # lineinfo = {}
        # scopes = {}
        # prev_scope = 0

        # for insn in function.hlil.instructions:
        #     curr_scope = lines[insn.instr_index]["scope"]
        #     scopes.setdefault(curr_scope, [])

        #     if curr_scope < prev_scope:
        #         for scope in scopes[prev_scope]:
        #             print(f"scope ending for {scope["var"]} @ {insn}")
        #             scope["end"] = insn.address
        #         del scopes[prev_scope]
        #     prev_scope = curr_scope

        #     match insn.operation.value:
        #         case HighLevelILOperation.HLIL_LABEL:
        #             label = {}
        #             label["address"] = insn.address
        #             label["name"] = insn.target.name
        #             labels.append(label)
        #         case HighLevelILOperation.HLIL_VAR_DECLARE:
        #             if insn.var in localmap:
        #                 scope = {}
        #                 scope["start"] = insn.address
        #                 scope["var"] = insn.var
        #                 scopes[curr_scope].append(scope)
        #         case HighLevelILOperation.HLIL_VAR_INIT:
        #             if insn.dest in localmap:
        #                 scope = {}
        #                 scope["start"] = insn.address
        #                 scope["var"] = insn.dest
        #                 scopes[curr_scope].append(scope)

        #     parts = hlil_filter(set(insn.traverse(lambda node: node)))
        #     for llil in insn.llils:
        #         parent = llil.hlil
        #         llil = function.get_low_level_il_at(llil.address)
        #         if parent is None:
        #             refs = hlil_filter(set(llil.hlils))
        #             if len(refs) == 0 or not refs.issubset(parts):
        #                 continue
        #         else:
        #             insn = parent

        #         line = lines[insn.instr_index]["line"]
        #         print(f"{llil} for {insn} @ {line}")
        #         lineinfo[llil.address] = line

        if len(lineinfo) > 0:
            self.functions[key]["lineinfo"] = sorted(
                lineinfo.items(), key=lambda info: info[0]
            )
        # if len(labels) > 0:
        #     self.functions[key]["labels"] = labels

        sourcepath = self.sources / f"{key:x}.c"
        with open(sourcepath, "w+") as fp:
            fp.write(source)
        self.functions[key]["source"] = sourcepath.name

        """
        Normally this would be used to compute a Frame Descriptor Entry for the
        debuginfo Common Information Entry, but gdb seems to ignore this and instead
        computes the fbreg base internally.
        """
        # frame = []
        # frame.append((0, 0))
        # previous_frame_offset = 0

        # rsp = self.bv.arch.get_reg_index("rsp")
        # if llil := function.llil_if_available:
        #     for insn in llil.instructions:
        #         value = insn.get_possible_reg_values_after(rsp)
        #         match value.type.value:
        #             case RegisterValueType.UndeterminedValue.value:
        #                 offset = 0
        #             case RegisterValueType.StackFrameOffset.value:
        #                 offset = value.offset
        #             case _:
        #                 print("failed to locate rsp offset")
        #                 break

        #         if offset != previous_frame_offset:
        #             frame.append((insn.address - function.start, offset))
        #             previous_frame_offset = offset

        #     self.functions[key]["frame"] = sorted(frame, key=lambda e: e[0])

    def dump(self):
        self.types.dump(self.tmp)
        with open(self.tmp / "variables.json", "w+") as fp:
            json.dump(self.variables, fp)
        with open(self.tmp / "functions.json", "w+") as fp:
            json.dump(self.functions, fp)
        with open(self.tmp / "sections.json", "w+") as fp:
            json.dump(self.sections, fp)

    def generate(self):
        self.epoch += 1
        self.dump()
        outpath = self.tmp / "info.debug"
        bin = Path(__file__).parent / "dwarf" / "target" / "release" / "teemo"
        subprocess.run([str(bin), str(self.tmp), str(outpath)], check=True)


class Notify(BinaryDataNotification):
    def __init__(self, bv: BinaryView, service: Service):
        super().__init__(
            NotificationType.FunctionAdded
            | NotificationType.FunctionRemoved
            | NotificationType.FunctionUpdated
            | NotificationType.SymbolUpdated
            | NotificationType.DataVariableAdded
            | NotificationType.DataVariableRemoved
            | NotificationType.DataVariableUpdated
            | NotificationType.TypeDefined
            | NotificationType.TypeUndefined
            | NotificationType.NotificationBarrier
        )
        self.service = service
        self.bv = bv
        self.received_event = False
        self.update_lock = threading.Lock()

    def __hash__(self):
        return self.bv.__hash__()

    def notification_barrier(self, view: "BinaryView") -> int:
        has_events = self.received_event
        self.received_event = False

        if has_events:
            return 250
        else:
            return 0

    def event(fn):
        def wrapper(cls, view, *args, **kwargs):
            cls.received_event = True
            fn(cls, view, *args, **kwargs)

        return wrapper

    def singleton(self, fn, *args, **kwargs):
        def wrapper():
            self.update_lock.acquire()
            fn(*args, **kwargs)
            self.update_lock.release()

        return wrapper

    @event
    def function_added(self, view, func):
        worker_interactive_enqueue(
            self.singleton(self.service.function_added, func.start)
        )

    @event
    def function_removed(self, view, func):
        worker_interactive_enqueue(
            self.singleton(self.service.function_removed, func.start)
        )

    @event
    def function_updated(self, view, func):
        worker_interactive_enqueue(
            self.singleton(self.service.function_updated, func.start)
        )

    @event
    def data_var_added(self, view, var):
        worker_interactive_enqueue(
            self.singleton(self.service.symbol_added, var.symbol.address)
        )

    @event
    def data_var_removed(self, view, var):
        worker_interactive_enqueue(
            self.singleton(self.service.symbol_removed, var.symbol.address)
        )

    @event
    def data_var_updated(self, view, var):
        # print("queueing data var update")
        worker_interactive_enqueue(
            self.singleton(self.service.symbol_updated, var.symbol.address)
        )

    @event
    def symbol_updated(self, view, sym):
        worker_interactive_enqueue(
            self.singleton(self.service.symbol_updated, sym.address)
        )

    @event
    def type_defined(self, view, name, type):
        # print("defining type")
        worker_interactive_enqueue(
            self.singleton(self.service.type_updated, type, name)
        )

    # not called?
    # @event
    # def type_ref_changed(self, view, name, type):
    #     print("updating type")
    #     worker_interactive_enqueue(self.singleton(self.service.type_updated, type, name))

    @event
    def type_undefined(self, view, name, type):
        worker_interactive_enqueue(
            self.singleton(self.service.type_removed, type, name)
        )


registered_servers = {}


def start_server(bv: BinaryView):
    if bv not in registered_servers:
        bv.update_analysis_and_wait()
        service = Service(bv)
        UNIX_SOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
        UNIX_SOCK_PATH.unlink(missing_ok=True)
        server = ThreadedServer(
            service=service,
            socket_path=str(UNIX_SOCK_PATH),
            protocol_config={
                "allow_all_attrs": True,
                "allow_setattr": True,
            },
        )
        spawn(server.start)

        notify = Notify(bv, service)
        bv.register_notification(notify)
        registered_servers[bv] = notify
        # show_message_box(NAME, "server started")
        print("server started")
    else:
        # show_message_box(NAME, "server already started")
        print("server already started")


def update_server(bv: BinaryView):
    if bv not in registered_servers:
        show_message_box(NAME, "server not started, starting now")
        start_server(bv)
    else:
        registered_servers[bv].service.push_update()
        show_message_box(NAME, "regenerated")


def stop_server(bv: BinaryView):
    if bv not in registered_servers:
        # show_message_box(NAME, "server is not started, cannot stop")
        print("server is not started, cannot stop")
    else:
        bv.unregister_notification(registered_servers[bv])
        del registered_servers[bv]
        # show_message_box(NAME, "server stopped")
        print("server stopped")


def stop_all_servers():
    bvs = list(registered_servers.keys())
    for bv, notif in registered_servers.items():
        bv.unregister_notification(notif)
    for bv in bvs:
        del registered_servers[bv]
    print("stopped all servers.")
