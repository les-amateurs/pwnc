from binaryninja import (
    BinaryView,
    BinaryDataNotification,
    BinaryDataNotificationCallbacks,
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

    show_message_box,
)
from pathlib import Path
from tempfile import mkdtemp
import json
import subprocess
import rpyc
from rpyc.utils.server import ThreadedServer, spawn
from rpyc.utils.factory import unix_connect
from threading import Lock
from .config import *
from .extract import TypeCollection

class Service(rpyc.Service):
    def __init__(self, bv: BinaryView):
        self.bv = bv
        self.tmp = TMPDIR # communicate path over socket later Path(mkdtemp())
        self.tmp.mkdir(parents=True, exist_ok=True)
        self.updates = False

        self.types = TypeCollection(bv)
        self.variables = dict()
        self.functions = dict()
        self.sections = dict()

        self.visit_all_types()
        self.visit_all_variables()
        self.visit_all_functions()

    @rpyc.exposed
    def request_update(self):
        if self.updates:
            self.generate()
            self.updates = False

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
        for name, type in self.bv.user_type_container.types.items():
            self.types.visit(type, name)
        for name, type in self.bv.type_container.platform.types.items():
            self.types.visit(type, name)

    @rpyc.exposed
    def forget_type(self, type: Type, name: str | QualifiedName | None):
        self.types.forget(type, name)

    @rpyc.exposed
    def visit_type(self, type: Type, name: str | QualifiedName | None):
        self.types.visit(type, name)

    def visit_all_variables(self):
        for name, symbols in self.bv.symbols.items():
            for var in symbols:
                self.visit_variable(name, var)

    @rpyc.exposed
    def forget_variable(self, var: CoreSymbol):
        if var.address in self.variables:
            del self.variables[var.address]

    @rpyc.exposed
    def visit_variable(self, name: str, var: CoreSymbol):        
        if var.type != SymbolType.DataSymbol:
            return
        
        key = var.address
        if var.address in self.variables:
            return

        var = self.bv.get_data_var_at(var.address)
        self.variables[key] = {}
        self.variables[key]["name"] = name
        self.variables[key]["size"] = len(var)
        self.variables[key]["typename"] = self.types.visit(var.type)
        if section := self.get_section_at(var.address):
            self.variables[key]["section"] = section.name

    def visit_all_functions(self):
        for function in self.bv.functions:
            self.visit_function(function)

    @rpyc.exposed
    def forget_function(self, function: Function):
        if function.start in self.functions:
            del self.functions[function.start]

    @rpyc.exposed
    def visit_function(self, function: Function, shallow: bool = True):
        if function.symbol.type != SymbolType.FunctionSymbol:
            return

        key = function.start
        if key in self.functions:
            return
        
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

        """
        This is used to compute DW_OP_entry_value requests, but thats pretty complicated to
        generate and probably not worth it.
        """
        # calls = []
        # for call_site in function.call_sites:
        #     insn = call_site.llil
        #     block = insn.il_basic_block
        #     match insn.operation.value:
        #         case LowLevelILOperation.LLIL_CALL:
        #             call = {}
        #             call["return_pc"] = block[insn.instr_index + 1 - block.start].address
        #             call["target"] = insn.dest.value.value
        #             calls.append(call)

        # self.functions[key]["calls"] = calls

        self.functions[key]["ellipsis"] = function.type.has_variable_arguments.value
        self.functions[key]["returntype"] = self.types.visit(function.type.return_value)
        
        if not shallow:
            locals = []
            for var in function.vars:
                if var.source_type == VariableSourceType.StackVariableSourceType:
                    local = {}
                    local["name"] = var.name
                    local["typename"] = self.types.visit(var.type)
                    local["offset"] = var.storage
                    locals.append(local)

            self.functions[key]["locals"] = locals

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

        if section := self.get_section_at(function.start):
            self.functions[key]["section"] = section.name

    def dump(self):
        self.types.dump(self.tmp)
        with open(self.tmp / "variables.json", "w+") as fp:
            json.dump(self.variables, fp)
        with open(self.tmp / "functions.json", "w+") as fp:
            json.dump(self.functions, fp)
        with open(self.tmp / "sections.json", "w+") as fp:
            json.dump(self.sections, fp)

    @rpyc.exposed
    def generate(self):
        self.dump()
        outpath = self.tmp / "info.debug"
        bin = Path(__file__).parent / "dwarf" / "target" / "release" / "teemo"
        subprocess.run([str(bin), str(self.tmp), str(outpath)], check=True)
        print(self.tmp)

class Notify(BinaryDataNotification):
    def __init__(self, bv: BinaryView, server: ThreadedServer):
        super().__init__(
            NotificationType.FunctionAdded | NotificationType.FunctionRemoved | NotificationType.FunctionUpdated |
            NotificationType.SymbolUpdated |
            NotificationType.DataVariableAdded | NotificationType.DataVariableRemoved | NotificationType.DataVariableUpdated
        )
        self.bv = bv
        self.service = unix_connect(UNIX_SOCK_PATH)

    def __hash__(self):
        return self.bv.__hash__()

    def function_added(self, view, func):
        self.service.forget_function(func)
        self.service.visit_function(func)

    def function_removed(self, view, func):
        self.service.forget_function(func)

    def function_updated(self, view, func) -> None:
        self.service.forget_function(func)
        self.service.visit_function(func)

    def data_var_added(self, view, var):
        self.service.visit_variable(var.symbol)

    def data_var_removed(self, view, var):
        self.service.forget_variable(var.symbol)

    def data_var_updated(self, view, var):
        self.service.forget_variable(var.symbol)
        self.service.visit_variable(var.symbol)

    def symbol_updated(self, view, sym):
        self.service.forget_variable(sym)
        self.service.visit_variable(sym)

    def type_defined(self, view, name, type):
        self.service.types.forget(type, name)
        self.service.types.visit(type, name)

    def type_undefined(self, view, name, type):
        self.service.types.forget(type, name)
    
def start_server(bv: BinaryView):
    if bv not in bv._notifications:
        service = Service(bv)
        server = ThreadedServer(service=service, socket_path=UNIX_SOCK_PATH, protocol_config={
            "allow_all_attrs": True,
            "allow_setattr": True,
        })
        spawn(server.start)
        notify = Notify(bv, server)
        bv.register_notification(notify)
        server.generate()
        show_message_box(NAME, "server started")
    else:
        show_message_box(NAME, "server already started")

def update_server(bv: BinaryView):
    if bv not in bv._notifications:
        show_message_box(NAME, "server not started, starting now")
        start_server(bv)
    else:
        bv._notifications[bv].server.generate()
        show_message_box(NAME, "regenerated")

def stop_server(bv: BinaryView):
    if bv not in bv._notifications:
        show_message_box(NAME< "server is not started, cannot stop")
    else:
        bv._notifications[bv].server.stop()
        del bv._notifications[bv]
        show_message_box(NAME, "server stopped")