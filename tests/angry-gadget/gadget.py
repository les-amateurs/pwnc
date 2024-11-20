#!/usr/bin/env python
import angr
from tqdm import tqdm
import argparse
import pickle
from pathlib import Path
import archinfo
from tqdm import tqdm, trange
import multiprocessing as mp
from time import sleep

# angr please be quiet
import logging
log_things = ["angr", "pyvex", "claripy", "cle"]
for log in log_things:
    logger = logging.getLogger(log)
    logger.disabled = True
    logger.propagate = False

def run_analysis(p, rebased_bin_sh, q):
    while not q.empty():
        try:
            i = q.get_nowait()
            if i is None:
                break
            state = p.factory.blank_state(addr=i)
            simgr = p.factory.simgr(state)
            simgr.step(num_inst=1)

            for state in simgr.active:
                for reg in [
                    state.regs.rax, state.regs.rbx, state.regs.rcx, state.regs.rdx,
                    state.regs.rsi, state.regs.rdi, state.regs.rsp, state.regs.rbp,
                    state.regs.r8, state.regs.r9, state.regs.r10, state.regs.r11,
                    state.regs.r12, state.regs.r13, state.regs.r14, state.regs.r15
                ]:
                    if reg.concrete:
                        if reg.cv == rebased_bin_sh:
                            print(f"/bin/sh xref = {i:#x}")
        except:
            break

def main():
    sc = open("test.bin", "rb").read()
    # p = angr.project.load_shellcode(sc, archinfo.ArchAMD64(), load_address=0x1000)
    p = angr.Project("/lib/libc.so.6", auto_load_libs=False)
    q = mp.Queue()

    binary_base = p.loader.main_object.image_base_delta
    bin_sh_loc = list(p.loader.main_object.memory.find(b"/bin/sh"))[0]
    rebased_bin_sh = binary_base + bin_sh_loc

    for segment in p.loader.main_object.segments:
        if segment.is_executable:
            for i in trange(segment.vaddr, segment.vaddr + segment.memsize):
                q.put(i)

            processes = []
            for i in range(8):
                q.put(None)
            for i in range(8):
                proc = mp.Process(target=run_analysis, args=(p, rebased_bin_sh, q))
                processes.append(proc)
                proc.start()
            # for p in processes:
            #     p.join()
            while True:
                sleep(1)
                print(f"{q.qsize()/segment.memsize*100:.2f}% done")
            print("done")


                    # rax = state.regs.rax
                    # mem = state.memory.load(state.regs.rsp + 0, 8)
                    # rsp = state.regs.rsp

                    # print(hex(state.solver.eval(rax)))
                    # print(hex(state.solver.eval(mem)))
                    # print(hex(state.solver.eval(rsp)))
                    # print(rax.shallow_repr())
                    # print(list(mem.children_asts()))
                    # print(rsp.concrete)


if __name__ == "__main__":
    main()