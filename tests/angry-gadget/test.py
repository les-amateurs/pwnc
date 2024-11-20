import angr
import archinfo

sc = open("test.bin", "rb").read()
p = angr.project.load_shellcode(sc, arch=archinfo.ArchAMD64(), load_address=0x1000)

state = p.factory.blank_state(addr=0x1000, add_options={angr.options.REPLACEMENT_SOLVER, angr.options.SYMBOLIC_INITIAL_VALUES})

state.regs.rsp = state.solver.BVS("rsp", 64)
print(state.regs.rsi)
print(state.regs.rsp.concrete)
state.regs.rdi = state.solver.BVS("rdi", 64)

init_rsp = state.regs.rsp
init_rdi = state.regs.rdi
init_rsi = state.regs.rsi

simgr = p.factory.simgr(state)
simgr.step(num_inst=5)

# state.solver.add(init_rsp == init_rdi)

for state in simgr.active:
    print(state.solver.eval(state.regs.rsi))
    print(state.regs.rax)
    print(state.regs.rsp)
    print(state.regs.rsi)