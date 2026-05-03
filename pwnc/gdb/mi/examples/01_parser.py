"""
Demonstrates the MI3 parser: parsing GDB machine interface output
into structured Python objects.

No GDB process needed — works on raw MI output strings.
"""

from pwnc.gdb.mi.parser import (
    parse_output,
    ResultRecord, ExecAsync, NotifyAsync,
    ConsoleStream, LogStream,
)

# ── result records ──

# simple done result
r = parse_output('^done')
print(f"Result: cls={r.cls}, results={r.results}")
# → Result: cls=done, results={}

# done with a value
r = parse_output('^done,value="0x7fffffffe320"')
print(f"Value: {r.results['value']}")
# → Value: 0x7fffffffe320

# tokenized result (token matches command to response)
r = parse_output('42^done,value="hello"')
print(f"Token: {r.token}, value: {r.results['value']}")
# → Token: 42, value: hello

# error result
r = parse_output('^error,msg="No symbol table is loaded."')
print(f"Error: {r.results['msg']}")
# → Error: No symbol table is loaded.

# ── nested values ──

# breakpoint result with nested tuple
r = parse_output(
    '10^done,bkpt={number="1",type="breakpoint",addr="0x401126",'
    'func="main",file="test.c",line="5"}'
)
bkpt = r.results["bkpt"]
print(f"Breakpoint #{bkpt['number']} at {bkpt['func']}:{bkpt['line']}")
# → Breakpoint #1 at main:5

# thread list with nested frames
r = parse_output(
    '^done,threads=['
    '{id="1",target-id="Thread 0x7ffff7c52740",frame={level="0",addr="0x401126",func="main"}},'
    '{id="2",target-id="Thread 0x7ffff7400700",frame={level="0",addr="0x7ffff7b8e360",func="futex_wait"}}'
    ']'
)
threads = r.results["threads"]
for t in threads:
    print(f"  Thread {t['id']}: {t['frame']['func']}")
# → Thread 1: main
# → Thread 2: futex_wait

# ── async records ──

# execution stopped
r = parse_output('*stopped,reason="breakpoint-hit",bkptno="1",frame={addr="0x401126",func="main"}')
print(f"Stopped: {r.results['reason']} at {r.results['frame']['func']}")
# → Stopped: breakpoint-hit at main

# notification
r = parse_output('=library-loaded,id="/lib/x86_64-linux-gnu/libc.so.6"')
print(f"Loaded: {r.results['id']}")
# → Loaded: /lib/x86_64-linux-gnu/libc.so.6

# ── stream records ──

# console output (what GDB prints to the user)
r = parse_output('~"Breakpoint 1 at 0x401126: file test.c, line 5.\\n"')
print(f"Console: {r.text}", end="")
# → Console: Breakpoint 1 at 0x401126: file test.c, line 5.

# log output (GDB internal messages)
r = parse_output('&"info registers\\n"')
print(f"Log: {r.text}", end="")
# → Log: info registers

# ── prompt and empty lines are None ──

print(f"Prompt: {parse_output('(gdb)')}")   # → None
print(f"Empty:  {parse_output('')}")         # → None

# ── register values ──

r = parse_output('^done,register-values=[{number="0",value="0x7fffffffe320"},{number="1",value="0x0"},{number="2",value="0x7fffffffe438"}]')
for reg in r.results["register-values"]:
    print(f"  reg[{reg['number']}] = {reg['value']}")

# ── disassembly ──

r = parse_output('^done,asm_insns=[{address="0x401000",func-name="main",offset="0",inst="push %rbp"},{address="0x401001",func-name="main",offset="1",inst="mov %rsp,%rbp"}]')
for insn in r.results["asm_insns"]:
    print(f"  {insn['address']}: {insn['inst']}")
