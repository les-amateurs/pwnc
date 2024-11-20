import binaryninja
from cle import Section
import rpyc
import os
import tqdm
import angr
from angr.engines.hook import HooksMixin
from angr.engines.vex import SimInspectMixin, HeavyResilienceMixin, TrackActionsMixin, SuperFastpathMixin
from angr.engines.unicorn import SimEngineUnicorn
from angr.engines.syscall import SimEngineSyscall
from angr.engines.failure import SimEngineFailure
from angr.engines.soot import SootMixin
from angr.engines.vex import HeavyVEXMixin, VEXMixin
from angr.engines.engine import TLSMixin
import angr.procedures
import angr.exploration_techniques
from angr.sim_options import ABSTRACT_MEMORY
import logging

# from claripy.frontend_mixins.model_cache_mixin import ModelCacheMixin
# from claripy.frontend_mixins.sat_cache_mixin import SatCacheMixin


class CustomEngine(
    # SimEngineFailure,
    # SimEngineSyscall,
    HooksMixin,
    # SimEngineUnicorn,
    # SuperFastpathMixin,
    # TrackActionsMixin,
    # SimInspectMixin,
    # HeavyResilienceMixin,
    # SootMixin,
    HeavyVEXMixin,
    # TLSMixin,
    # ModelCacheMixin,
    # SatCacheMixin,
):
    pass

# angr please be quiet
# import logging
# log_things = ["angr", "pyvex", "claripy", "cle"]
# for log in log_things:
#     logger = logging.getLogger(log)
#     logger.disabled = True
#     logger.propagate = False

c = rpyc.connect("0.0.0.0", 18812)
p = angr.Project("/usr/lib32/libc.so.6", auto_load_libs=False, engine=CustomEngine)
# cfg = p.analyses.CFGFast(normalize = True)
delta = p.loader.main_object.image_base_delta

l = logging.getLogger(name=__name__)

class BugFree(angr.SimProcedure):
    def run(self, dst_addr, src_addr, limit):
        # print(dst_addr, src_addr, limit)
        if not self.state.solver.symbolic(limit):
            # not symbolic so we just take the value
            conditional_size = self.state.solver.eval(limit)
        else:
            l.warning("ignore symbolic memcpy limits")
            return dst_addr
        
        l.debug("Memcpy running with conditional_size %#x", conditional_size)

        if conditional_size > 0:
            src_mem = self.state.memory.load(src_addr, conditional_size, endness="Iend_BE")
            if ABSTRACT_MEMORY in self.state.options:
                self.state.memory.store(dst_addr, src_mem, size=conditional_size, endness="Iend_BE")
            else:
                self.state.memory.store(dst_addr, src_mem, size=limit, endness="Iend_BE")

        return dst_addr
   
# p.hook_symbol("__memcpy_chk", BugFree()) # angr.SIM_PROCEDURES["libc"]["memcpy"]())
print(angr.SIM_PROCEDURES["libc"].keys())
p.hook(delta + 0xc1140, BugFree()) # angr.SIM_PROCEDURES["libc"]["memcpy"]())

bv: binaryninja.BinaryView = c.root.bv
bn: binaryninja = c.root.binaryninja

bin_sh_loc = list(p.loader.main_object.memory.find(b"/bin/sh"))[0]
got: Section = p.loader.main_object.sections_map[".got"]
rebased_bin_sh = delta + bin_sh_loc

targets = [
    "execve",
    "execl",
    "posix_spawn",
]
target_refs = {}
for target in targets:
    refs = []
    fns = bv.get_functions_by_name(target)
    for fn in fns:
        r = bv.get_code_refs(fn.start)
        r = map(lambda ref: bv.get_basic_blocks_at(ref.address), r)
        r = [b for blocks in r for b in blocks]
        refs.extend(r)
    target_refs[target] = refs

bin_sh_refs = list(bv.get_code_refs(bin_sh_loc))
for ref in bin_sh_refs:
    b = ref.function.get_basic_block_at(ref.address)
    if b in target_refs["execve"]:
        print(b)

        blocks = [b]
        checked: set[binaryninja.BasicBlock] = set()
        while len(blocks) != 0:
            block = blocks.pop()
            if block in checked:
                continue

            checked.add(block)
            for edge in block.incoming_edges:
                blocks.append(edge.source)

        sym = p.loader.main_object.get_symbol("execve")
        def find_target(state):
            # print(hex(state.regs.eip.concrete_value), hex(sym.rebased_addr))
            if state.regs.eip.concrete_value == sym.rebased_addr:
                return True
        
        checked = sorted(checked, key=lambda block: block.start)
        fn = b.function
        avoid = filter(lambda b: b not in checked, fn.basic_blocks)
        avoid = map(lambda b: b.start, avoid)
        avoid = list(avoid)
        avoid = []
        print(avoid)

        for block in checked:
            b = p.factory.block(delta + block.start, block.end - block.start)
            # print(block.end - block.start)
            # print(len(b.bytes))
            # print(b.disassembly)
            assert b.size == (block.end - block.start)
            state: angr.SimState = p.factory.blank_state(addr=delta + block.start, add_options={
                    angr.options.LAZY_SOLVES,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                    angr.options.SYMBOLIC,
                    angr.options.COPY_STATES,
                })
            print(state.plugin_preset.list_default_plugins())
            print(state.plugin_preset.request_plugin("mem"))
            print(state.plugin_preset.request_plugin("sym_memory"))
            
            # simgr = p.factory.simgr(state)
            # simgr.run(n=len(block))
            # print(simgr.stashes)
            continue

            gadget = block.start
            for insn, length in block:
                gadget = 0x000eaa10
                print(f"trying gadget {gadget:#x}")
                state: angr.SimState = p.factory.blank_state(addr=delta + gadget, add_options={
                    angr.options.LAZY_SOLVES,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                    angr.options.SYMBOLIC,
                    angr.options.COPY_STATES,
                })
                state.libc.max_memcpy_size = 0x40
                simgr = p.factory.simgr(state)
                simgr.use_technique(angr.exploration_techniques.DFS())
                # simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=10))

                esp = state.solver.BVS("esp", 32)
                state.regs.esp = esp
                ebp = state.solver.BVS("ebp", 32)
                state.regs.ebp = ebp
                esi = state.solver.BVS("esi", 32)
                state.solver.add(esi == got.vaddr)
                state.regs.esi = esi
                edi = state.solver.BVS("edi", 32)
                state.regs.edi = edi
                # memcpy = p.loader.main_object.get_symbol('__memcpy_chk')
                m = state.memory.load(esi + 0x16c, 4)
                # state.memory.store(esi + 0x16c, memcpy.rebased_addr, 4)
                print(m)
                # print(hex(m.concrete_value - delta))
                # print(f"{memcpy.rebased_addr = :#x}")

                simgr.explore(find=find_target, avoid=avoid, num_find=10)
                print(simgr.stashes)
                for state in simgr.found:
                    print(state.history.jumpkind)
                    print(list(state.history.jump_targets))
                    # print(list(state.history.actions))
                    c = list(state.solver.constraints)
                    # print(c)
                    # print(list(state.history.actions))
                    # state.history.lineage
                    arg0 = state.stack_read(4, 4)
                    arg1 = state.stack_read(8, 4)
                    arg2 = state.stack_read(12, 4)
                    if state.solver.eval(arg0 == rebased_bin_sh):
                        print(f"{gadget = :#x}", arg0, arg1, arg2)
                        # print(state.regs.eax)
                        # print(state.memory.load(state.regs.ebp - 0x2c, 4))
                        # exit(0)

                gadget += length
                exit(0)