import binaryninja
from cle import Section
import rpyc
import os
import tqdm
import angr
from angr.utils.constants import DEFAULT_STATEMENT
from angr.engines.hook import HooksMixin
from angr.engines.vex.heavy.heavy import VEXEarlyExit
from angr.engines.vex import SimInspectMixin, HeavyResilienceMixin, TrackActionsMixin, SuperFastpathMixin
from angr.engines.vex.lifter import VEXLifter
from angr.engines.unicorn import SimEngineUnicorn
from angr.engines.syscall import SimEngineSyscall
from angr.engines.failure import SimEngineFailure
from angr.engines.soot import SootMixin
from angr.engines.vex import HeavyVEXMixin, VEXMixin
from angr.engines.engine import TLSMixin, SuccessorsMixin, SimEngineBase
from angr.engines import UberEngine
from angr import errors
import archinfo
import angr.procedures
import angr.exploration_techniques
from angr.sim_options import ABSTRACT_MEMORY
import logging
import pyvex
from pwn import asm

l = logging.getLogger(__name__)

class A:
    def __getitem__(self, i):
        print(i)

a = A()
a[0,0,0,0,0,0,0]
exit(1)
    
class Symbolic:
    def __init__(self):
        pass

    def __add__(self, other):
        return BinOp(BinOpType.ADD, self, other)

class BinOpType:
    ADD = 0
    SUB = 1

class BinOp(Symbolic):
    def __init__(self, op: BinOpType, lhs: Symbolic, rhs: Symbolic):
        self.width = lhs.width
        self.op = op
        self.lhs = lhs
        self.rhs = rhs
        
class Constant(Symbolic):
    def __init__(self, width: int, n: int):
        self.width = width
        self.n = n

    def __repr__(self):
        return str(self.n)

class Load(Symbolic):
    def __init__(self, width: int, expr: Symbolic):
        self.width = width
        self.location = expr

class Store(Symbolic):
    def __init__(self, width: int, expr: Symbolic):
        self.width = width
        self.location = expr

class Value(Symbolic):
    class Item:
        def __init__(self, expr: Symbolic, lo: int, hi: int):
            self.expr = expr
            self.lo = lo
            self.hi = hi

        def limit(self, hi: int):
            self.hi = min(self.hi, hi)

    def __init__(self, width: int):
        self.width = width
        self.bits: dict[int, None|Symbolic] = dict([(i, None) for i in range(width)])

    def __repr__(self):
        items = self.simplify(self.width, 0)
        if len(items) == 1:
            return f"Value({items[0].expr})"
        items = map(lambda item: f"{item.expr}[{item.hi}..{item.lo}]", reversed(items))
        items = ",".join(items)
        return f"Value({items})"

    def from_bits(bits: dict[int, None|Symbolic]):
        v = Value(len(bits))
        v.bits = bits
        return v

    def simplify(self, width: int, offset: int):
        hi = offset + width
        items: None|list[Value.Item] = None
        for i in range(offset, hi):
            if items is None:
                items = [Value.Item(self.bits[i], i, hi)]
            else:
                curr = self.bits[i]
                if items[-1].expr != curr:
                    items[-1].limit(i)
                    items.append(Value.Item(curr, i, hi))

        return items

    def put(self, expr: Symbolic, offset: int = 0):
        if offset + expr.width >= self.width:
            raise RuntimeError("WTF")
        for i in range(offset, offset + expr.width):
            self.bits[i] = expr

    def get(self, width: int|None = None, offset: int = 0):
        if width is None:
            width = self.width
        bits = {}
        for i in range(width):
            bits[i] = self.bits[offset + i]
        return Value.from_bits(bits)

v = Value(64)
v.put(Constant(32, 1))
print(v)
exit(1)

class Test(VEXMixin):
    def _handle_vex_stmt(self, stmt: pyvex.stmt.IRStmt):
        print("stmt handler")
        print(stmt)
        handler = self._vex_stmt_handlers[stmt.tag_int]
        print(handler)
        # handler(stmt)

    def _handle_vex_stmt_IMark(self, stmt: pyvex.stmt.IRStmt):
        return
    
        ins_addr = stmt.addr + stmt.delta
        self.state.scratch.ins_addr = 0x1337

        self.state.scratch.num_insns += 1
        self.successors.artifacts["insn_addrs"].append(0x1337)

        self.state.history.recent_instruction_count += 1
        l.info("IMark: %#x", stmt.addr)
        print(f"IMask: {stmt.addr:#x}")
        super()._handle_vex_stmt_IMark(stmt)

class Executor(VEXMixin, VEXLifter):
    def process_successors(
        self,
        successors,
        irsb=None,
        insn_text=None,
        insn_bytes=None,
        thumb=False,
        size=None,
        num_inst=None,
        extra_stop_points=None,
        opt_level=None,
        **kwargs,
    ):
        print("hi :)")
        if not pyvex.lifting.lifters[self.state.arch.name] or type(successors.addr) is not int:
            print("oops")
            return super().process_successors(
                successors,
                extra_stop_points=extra_stop_points,
                num_inst=num_inst,
                size=size,
                insn_text=insn_text,
                insn_bytes=insn_bytes,
                **kwargs,
            )

        if insn_text is not None:
            if insn_bytes is not None:
                raise errors.SimEngineError("You cannot provide both 'insn_bytes' and 'insn_text'!")

            insn_bytes = self.project.arch.asm(insn_text, addr=successors.addr, thumb=thumb)
            if insn_bytes is None:
                raise errors.AngrAssemblyError(
                    "Assembling failed. Please make sure keystone is installed, and the assembly string is correct."
                )

        successors.sort = "IRSB"
        successors.description = "IRSB"
        self.state.history.recent_block_count = 1
        addr = successors.addr
        self.state.scratch.bbl_addr = addr

        while True:
            if irsb is None:
                print("lifting vex")
                irsb = self.lift_vex(
                    addr=addr,
                    state=self.state,
                    insn_bytes=insn_bytes,
                    thumb=thumb,
                    size=size,
                    num_inst=num_inst,
                    extra_stop_points=extra_stop_points,
                    opt_level=opt_level,
                )

            if (
                irsb.jumpkind == "Ijk_NoDecode"
                and irsb.next.tag == "Iex_Const"
                and irsb.next.con.value == irsb.addr
                and not self.state.project.is_hooked(irsb.addr)
            ):
                raise errors.SimIRSBNoDecodeError(
                    f"IR decoding error at 0x{addr:02x}. You can hook this "
                    "instruction with a python replacement using project.hook"
                    f"(0x{addr:02x}, your_function, length=length_of_instruction)."
                )

            if irsb.size == 0:
                raise errors.SimIRSBError("Empty IRSB passed to HeavyVEXMixin.")

            self.state.scratch.set_tyenv(irsb.tyenv)
            self.state.scratch.irsb = irsb

            # fill in artifacts
            successors.artifacts["irsb"] = irsb
            successors.artifacts["irsb_size"] = irsb.size
            successors.artifacts["irsb_direct_next"] = irsb.direct_next
            successors.artifacts["irsb_default_jumpkind"] = irsb.jumpkind
            successors.artifacts["insn_addrs"] = []

            try:
                self.handle_vex_block(irsb)
            except errors.SimReliftException as e:
                self.state = e.state
                if insn_bytes is not None:
                    raise errors.SimEngineError("You cannot pass self-modifying code as insn_bytes!!!") from e
                new_ip = self.state.scratch.ins_addr
                if size is not None:
                    size -= new_ip - addr
                if num_inst is not None:
                    num_inst -= self.state.scratch.num_insns
                addr = new_ip

                # clear the stage before creating the new IRSB
                self.state.scratch.dirty_addrs.clear()
                irsb = None

            except errors.SimError as ex:
                ex.record_state(self.state)
                raise
            except VEXEarlyExit:
                break
            else:
                break

        successors.processed = True
        return None
    
    def _handle_vex_stmt(self, stmt):
        print("E")
        self.state.scratch.stmt_idx = self.stmt_idx
        super()._handle_vex_stmt(stmt)

    def _perform_vex_stmt_Exit(self, guard, target, jumpkind):
        exit("GG")
        cont_state = None
        exit_state = None
        guard = guard != 0

        if o.COPY_STATES not in self.state.options:
            # very special logic to try to minimize copies
            # first, check if this branch is impossible
            if guard.is_false():
                cont_state = self.state
            elif o.LAZY_SOLVES not in self.state.options and not self.state.solver.satisfiable(
                extra_constraints=(guard,)
            ):
                cont_state = self.state

            # then, check if it's impossible to continue from this branch
            elif guard.is_true():
                exit_state = self.state
            elif o.LAZY_SOLVES not in self.state.options and not self.state.solver.satisfiable(
                extra_constraints=(claripy.Not(guard),)
            ):
                exit_state = self.state
            # one more step, when LAZY_SOLVES is enabled, ignore "bad" jumpkinds
            elif o.LAZY_SOLVES in self.state.options and jumpkind.startswith("Ijk_Sig"):
                cont_state = self.state
            else:
                if o.LAZY_SOLVES not in self.state.options or not jumpkind.startswith("Ijk_Sig"):
                    # when LAZY_SOLVES is enabled, we ignore "bad" jumpkinds
                    exit_state = self.state.copy()
                cont_state = self.state
        else:
            exit_state = self.state.copy()
            cont_state = self.state

        if exit_state is not None:
            self.successors.add_successor(
                exit_state,
                target,
                guard,
                jumpkind,
                exit_stmt_idx=self.stmt_idx,
                exit_ins_addr=self.state.scratch.ins_addr,
            )

        if cont_state is None:
            raise VEXEarlyExit

        # Do our bookkeeping on the continuing self.state
        cont_condition = ~guard
        cont_state.add_constraints(cont_condition)
        cont_state.scratch.guard = claripy.And(cont_state.scratch.guard, cont_condition)

    def _perform_vex_stmt_Dirty_call(self, func_name, ty, args, func=None):
        exit("FF")
        if func is None:
            try:
                func = getattr(dirty, func_name)
            except AttributeError as e:
                raise errors.UnsupportedDirtyError(f"Unsupported dirty helper {func_name}") from e
        retval, retval_constraints = func(self.state, *args)
        self.state.add_constraints(*retval_constraints)
        return retval

    # expressions

    def _instrument_vex_expr(self, result):
        print("instrument")
        
        # if o.SIMPLIFY_EXPRS in self.state.options:
        #     result = self.state.solver.simplify(result)

        # if self.state.solver.symbolic(result) and o.CONCRETIZE in self.state.options:
        #     concrete_value = self.state.solver.BVV(self.state.solver.eval(result), len(result))
        #     self.state.add_constraints(result == concrete_value)
        #     result = concrete_value

        return super()._instrument_vex_expr(result)

    def _perform_vex_expr_Load(self, addr, ty, endness, **kwargs):
        exit("DD")
        result = super()._perform_vex_expr_Load(addr, ty, endness, **kwargs)
        if o.UNINITIALIZED_ACCESS_AWARENESS in self.state.options:
            if getattr(addr._model_vsa, "uninitialized", False):
                raise errors.SimUninitializedAccessError("addr", addr)
        return result

    def _perform_vex_expr_CCall(self, func_name, ty, args, func=None):
        exit("CC")
        if o.DO_CCALLS not in self.state.options:
            return symbol(ty, "ccall_ret")
        return super()._perform_vex_expr_CCall(func_name, ty, args, func=None)

    def _analyze_vex_defaultexit(self, expr):
        print("analyze default exit")
        # exit("BB")
        # self.state.scratch.stmt_idx = DEFAULT_STATEMENT
        return super()._analyze_vex_defaultexit(expr)

    def _perform_vex_defaultexit(self, expr, jumpkind):
        print("perform defaultexit")
        print(hex(self.state.scratch.ins_addr))

        if expr is None:
            expr = self.state.regs.ip
        print("adding successor")
        self.successors.add_successor(
            self.state,
            expr,
            self.state.scratch.guard,
            jumpkind,
            add_guard=False,  # if there is any guard, it has been added by the Exit statement
            # that we come across prior to the default exit. adding guard
            # again is unnecessary and will cause trouble in abstract solver
            # mode,
            exit_stmt_idx=DEFAULT_STATEMENT,
            exit_ins_addr=0x1337,
        )

# from claripy.frontend_mixins.model_cache_mixin import ModelCacheMixin
# from claripy.frontend_mixins.sat_cache_mixin import SatCacheMixin
# SuccessorsMixin, ClaripyDataMixin, SimStateStorageMixin, VEXMixin, VEXLifter

class CustomEngine(
    Test,
    Executor,
    SuccessorsMixin,
    # SimEngineFailure,
    # SimEngineSyscall,
    # HooksMixin,
    # SimEngineUnicorn,
    # SuperFastpathMixin,
    # TrackActionsMixin,
    # SimInspectMixin,
    # HeavyResilienceMixin,
    # SootMixin,
    VEXLifter,
    # TLSMixin,
    # ModelCacheMixin,
    # SatCacheMixin,
):
    pass

class Other(
    HeavyVEXMixin,
):
    pass

# angr please be quiet
# import logging
# log_things = ["angr", "pyvex", "claripy", "cle"]
# for log in log_things:
#     logger = logging.getLogger(log)
#     logger.disabled = True
#     logger.propagate = False
shellcode = """
    movzx eax, bp
    je .
"""
code = asm(shellcode)
p = angr.project.load_shellcode(code, load_address=0x1000, arch=archinfo.ArchAMD64(), engine=CustomEngine)
print(p.factory.default_engine)

# # cfg = p.analyses.CFGFast(normalize = True)
# delta = p.loader.main_object.image_base_delta

state: angr.SimState = p.factory.blank_state(addr=0x1000)
# simgr = p.factory.simgr(state)
# simgr.step(num_inst=1)

# print(simgr.stashes)

vex = p.factory.default_engine.lift_vex(0x1000, state=state, size=len(code))
print(vex)
for e in vex.statements:
    e: pyvex.stmt.IRStmt
    match e.tag:
        case "Ist_Put":
            e: pyvex.stmt.Put
            offset, *_ = list(e.expressions)
            consts = list(e.constants)
            print(e.tag, type(e))
            print(e.data, e.offset, pyvex.ARCH_AMD64.translate_register_name(e.offset))
            print(e.data.result_size(tyenv=None))
print(vex.next)