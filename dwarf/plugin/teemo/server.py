from concurrent.futures import thread
from binaryninja import (
    BinaryView,
    BinaryDataNotification,
    BinaryDataNotificationCallbacks,
    HighLevelILInstruction,
    QualifiedName,
    SymbolType,
    Type,
    VariableSourceType,
    LowLevelILOperation,
    RegisterValueType,
    Function,
    CoreSymbol,
    Section,
    NotificationType,
    HighLevelILOperation,

    show_message_box,
)
from pathlib import Path
from tempfile import mkdtemp
import json
import subprocess
import rpyc
import threading
from rpyc import async_, BgServingThread
from rpyc.utils.server import ThreadedServer, spawn
from rpyc.utils.factory import unix_connect
from threading import Lock
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
        self.tmp = TMPDIR # communicate path over socket later Path(mkdtemp())
        self.tmp.mkdir(parents=True, exist_ok=True)
        self.sources = self.tmp / "sources"
        self.sources.mkdir(parents=True, exist_ok=True)
        
        self.updates = True
        self.epoch = 0
        self.last_requested_epoch = 0
        self.stopped_functions = []

        self.first_client = True
        self.clients = dict()

        self.types = TypeCollection(bv)
        self.variables = dict()
        self.functions = dict()
        self.sections = dict()

        self.exposed_relocatable = self.bv.relocatable

        self.visit_all_types()
        self.visit_all_variables()
        self.visit_all_functions()
        self.generate()
        print("service started!")

    def on_connect(self, conn):
        if self.first_client:
            self.first_client = False
            Client(conn)
        else:
            client = Client(conn)
            self.clients[conn] = client
            client.push_update(self.epoch)

    def on_disconnect(self, conn):
        if conn in self.clients:
            del self.clients[conn]

    @rpyc.exposed
    def function_updated(self, addr: int):
        fn = self.bv.get_function_at(addr)
        self.visit_function(fn)
        # self.visit_function_full(fn)
        self.push_update()

    @rpyc.exposed
    def function_added(self, addr: int):
        fn = self.bv.get_function_at(addr)
        self.visit_function(fn)
        self.push_update()

    @rpyc.exposed
    def function_removed(self, addr: int):
        fn = self.bv.get_function_at(addr)
        self.forget_function(fn)
        self.push_update()

    @rpyc.exposed
    def symbol_updated(self, addr: int):
        var = self.bv.get_symbol_at(addr)
        self.visit_variable(var)
        self.push_update()

    @rpyc.exposed
    def symbol_added(self, addr: int):
        var = self.bv.get_symbol_at(addr)
        self.visit_variable(var)
        self.push_update()

    @rpyc.exposed
    def symbol_removed(self, addr: int):
        var = self.bv.get_symbol_at(addr)
        self.forget_variable(var)
        self.push_update()

    @rpyc.exposed
    def type_added(self, type: Type, name: QualifiedName | str | None):
        self.types.forget(type, name)
        self.types.visit(type, name)
        self.push_update()

    @rpyc.exposed
    def type_removed(self, type: Type, name: QualifiedName | str | None):
        self.types.forget(type, name)
        self.push_update()

    def request_functions(self, addrs: list[int]):
        self.stopped_functions = addrs
        print(f"received {addrs}")
        return
        
        for addr in addrs:
            for fn in self.bv.get_functions_containing(addr + self.bv.start):
                self.visit_function_full(fn)
        self.generate()
        self.push_update()

    def push_update(self):
        self.generate()
        for client in self.clients.values():
            client.push_update(self.epoch)

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
        for name, type in self.bv.user_type_container.types.values():
            self.types.visit(type, name)
        for name, type in self.bv.type_container.platform.types.items():
            self.types.visit(type, name)

    def visit_all_variables(self):
        for name, symbols in self.bv.symbols.items():
            for var in symbols:
                self.visit_variable(var)

    def forget_variable(self, var: CoreSymbol):
        if var.address in self.variables:
            self.updates = True
            del self.variables[var.address]

    def visit_variable(self, var: CoreSymbol):        
        if var.type.value != SymbolType.DataSymbol.value:
            return
        
        key = var.address        
        self.updates = True

        var = self.bv.get_data_var_at(var.address)
        self.variables[key] = {}
        self.variables[key]["name"] = var.name
        self.variables[key]["size"] = len(var)
        self.variables[key]["typename"] = self.types.visit(var.type)
        if section := self.get_section_at(var.address):
            self.variables[key]["section"] = section.name

    def visit_all_functions(self):
        for function in self.bv.functions:
            self.visit_function(function)

    def forget_function(self, function: Function):
        if function.start in self.functions:
            self.updates = True
            del self.functions[function.start]

    def visit_function(self, function: Function):
        if function.symbol.type.value != SymbolType.FunctionSymbol.value:
            return

        key = function.start
        self.updates = True
        
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
                    raise NotImplementedError(f"unhandled variable source type: {parameter.source_type}")

            arguments.append((location, parameter.name, self.types.visit(parameter.type)))

        self.functions[key]["arguments"] = arguments
        self.functions[key]["ellipsis"] = function.type.has_variable_arguments.value
        self.functions[key]["returntype"] = self.types.visit(function.type.return_value)

        if section := self.get_section_at(function.start):
            self.functions[key]["section"] = section.name

        if key in self.stopped_functions:
            self.visit_function_full(function)

    def visit_function_full(self, function: Function):
        print(f"visiting function full: {function}")

        key = function.start
        self.updates = True

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
        for var in function.hlil.vars + function.hlil.aliased_vars:
            if var in function.parameter_vars:
                continue

            local = {}
            local["name"] = var.name
            local["typename"] = self.types.visit(var.type)
            match var.source_type:
                case VariableSourceType.StackVariableSourceType.value:
                    local["location"] = { "StackVariable": var.storage }
                case VariableSourceType.RegisterVariableSourceType.value:
                    local["location"] = { "Register": self.bv.arch.get_reg_name(var.storage) }
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

        roots = dict()
        for line in function.hlil.root.lines:
            roots[line.il_instruction] = str(line)
        
        source = str(function.hlil)
        hlil = list(function.hlil.instructions)
        index = 0
        # line 0 doesnt exist, line numbers are one indexed
        # line 1 is reserved for function signature
        sourceline = 2
        for insn in hlil:
            if insn in roots:
                text = roots[insn]
            lines[index] = { "line": sourceline, "text": text, "scope": (len(line) - len(text)) // 4 }
            index += 1
            sourcelines += 1

        if len(lines) != len(hlil):
            clean = "\n".join(map(lambda line: line["text"], lines.values()))
            with open(TMPDIR / "clean.txt", "w+") as fp:
                fp.write(clean)
            with open(TMPDIR / "hlil.txt", "w+") as fp:
                fp.write("\n".join(map(str, hlil)))
            raise RuntimeError(f"cleaned up lines({len(lines)}) do not match hlil({len(hlil)})")

        labels = []
        lineinfo = {}
        scopes = {}
        prev_scope = 0

        for insn in function.hlil.instructions:
            curr_scope = lines[insn.instr_index]["scope"]
            scopes.setdefault(curr_scope, [])

            if curr_scope < prev_scope:
                for scope in scopes[prev_scope]:
                    print(f"scope ending for {scope["var"]} @ {insn}")
                    scope["end"] = insn.address
                del scopes[prev_scope]
            prev_scope = curr_scope

            match insn.operation.value:
                case HighLevelILOperation.HLIL_LABEL:
                    label = {}
                    label["address"] = insn.address
                    label["name"] = insn.target.name
                    labels.append(label)
                case HighLevelILOperation.HLIL_VAR_DECLARE:
                    if insn.var in localmap:
                        scope = {}
                        scope["start"] = insn.address
                        scope["var"] = insn.var
                        scopes[curr_scope].append(scope)
                case HighLevelILOperation.HLIL_VAR_INIT:
                    if insn.dest in localmap:
                        scope = {}
                        scope["start"] = insn.address
                        scope["var"] = insn.dest
                        scopes[curr_scope].append(scope)

            parts = hlil_filter(set(insn.traverse(lambda node: node)))
            for llil in insn.llils:
                parent = llil.hlil
                llil = function.get_low_level_il_at(llil.address)
                if parent is None:
                    refs = hlil_filter(set(llil.hlils))
                    if len(refs) == 0 or not refs.issubset(parts):
                        continue
                else:
                    insn = parent

                line = lines[insn.instr_index]["line"]
                print(f"{llil} for {insn} @ {line}")
                lineinfo[llil.address] = line

        if len(lineinfo) > 0:
            self.functions[key]["lineinfo"] = sorted(lineinfo.items(), key=lambda info: info[0])
        if len(labels) > 0:
            self.functions[key]["labels"] = labels

        sourcepath = self.sources / f"{key:x}.c"
        source = [str(function)] + ["    " + line for line in source.splitlines()]
        source = "\n".join(source)
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
        if self.updates:
            self.epoch += 1
            self.dump()
            outpath = self.tmp / "info.debug"
            bin = Path(__file__).parent / "dwarf" / "target" / "release" / "teemo"
            subprocess.run([str(bin), str(self.tmp), str(outpath)], check=True)
            self.updates = False

class Notify(BinaryDataNotification):
    def __init__(self, bv: BinaryView, service):
        super().__init__(
            NotificationType.FunctionAdded | NotificationType.FunctionRemoved | NotificationType.FunctionUpdated |
            NotificationType.SymbolUpdated |
            NotificationType.DataVariableAdded | NotificationType.DataVariableRemoved | NotificationType.DataVariableUpdated |
            NotificationType.TypeDefined | NotificationType.TypeUndefined |
            NotificationType.NotificationBarrier
        )
        self.bv = bv
        self.service = service
        self.bg_serving_thread = BgServingThread(service)
        self.received_event = False

    def __hash__(self):
        return self.bv.__hash__()
    
    def notification_barrier(self, view: 'BinaryView') -> int:
        has_events = self.received_event
        self.received_event = False

        if has_events:
            return 250
        else:
            return 0

    def event(fn):
        def wrapper(cls, view, func):
            cls.received_event = True
            fn(cls, view, func)

        return wrapper

    @event
    def function_added(self, view, func):
        async_(self.service.root.function_added)(func.start)

    @event
    def function_removed(self, view, func):
        async_(self.service.root.function_removed)(func.start)

    @event
    def function_updated(self, view, func):
        async_(self.service.root.function_updated)(func.start)

    @event
    def data_var_added(self, view, var):
        async_(self.service.root.symbol_added)(var.symbol.address)

    @event
    def data_var_removed(self, view, var):
        async_(self.service.root.symbol_removed)(var.symbol.address)

    @event
    def data_var_updated(self, view, var):
        async_(self.service.root.symbol_updated)(var.symbol.address)

    @event
    def symbol_updated(self, view, sym):
        async_(self.service.root.symbol_updated)(sym.address)

    @event
    def type_defined(self, view, name, type):
        async_(self.service.root.type_added)(type, name)

    @event
    def type_undefined(self, view, name, type):
        async_(self.service.root.type_removed)(type, name)

registered_servers = {}
    
def start_server(bv: BinaryView):
    if bv not in registered_servers:
        bv.update_analysis_and_wait()
        service = Service(bv)
        UNIX_SOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
        UNIX_SOCK_PATH.unlink(missing_ok=True)
        server = ThreadedServer(service=service, socket_path=str(UNIX_SOCK_PATH), protocol_config={
            "allow_all_attrs": True,
            "allow_setattr": True,
        })
        spawn(server.start)
        local = unix_connect(str(UNIX_SOCK_PATH), config={
            "allow_all_attrs": True,
            "allow_setattr": True,
        })
        notify = Notify(bv, local)
        bv.register_notification(notify)
        registered_servers[bv] = notify
        show_message_box(NAME, "server started")
    else:
        show_message_box(NAME, "server already started")

def update_server(bv: BinaryView):
    if bv not in registered_servers:
        show_message_box(NAME, "server not started, starting now")
        start_server(bv)
    else:
        registered_servers[bv].service.push_update()
        show_message_box(NAME, "regenerated")

def stop_server(bv: BinaryView):
    if bv not in registered_servers:
        show_message_box(NAME, "server is not started, cannot stop")
    else:
        bv.unregister_notification(registered_servers[bv])
        del registered_servers[bv]
        show_message_box(NAME, "server stopped")