## ideas

### new stuff

#### kmod
kernel module utilities
- extract modinfo
- allow modinfo modification

#### dwarf
dwarf utilities
- extract ONLY types from dwarf file

#### sym
symbol utilities
- define new symbols for gdb debugging
    - relative symbols
    - absolute symbols

#### unstrip
more comprehensive and usable unstripping cli
- special case for libc, search popular distros for files that debuginfod misses
- normal binaries fall back to debuginfod

#### patch
nice utilities for patching files

### stuff to steal from pwntools

Base pwntools provides:
```
asm
checksec
constgrep
cyclic
debug
disasm
disablenx
elfdiff
elfpatch
errno
hex
libcdb
phd
pwnstrip
scramble
shellcraft
template
unhex
update
version
```

- `asm`/`disasm` is useful
- `checksec` will be supplemented with more information
- `errno` is useful
- `shellcraft` is useful