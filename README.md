## ideas

### new stuff

#### gdb
expose wrappers around the gdb api to use in solve scripts
- programatically place breakpoints
- oneshot breakpoints
- run python code from breakpoints
- pwntools provides this but it is fairly basic

#### minelf
minimal elf parsing and in place modification library

#### kmod
kernel module utilities
- extract modinfo
- allow modinfo modification

#### dwarf
dwarf utilities
binja plugin to generate dwarf info on the fly to import into gdb

#### unstrip
more comprehensive and usable unstripping cli
- special case for libc, search popular distros for files that debuginfod misses
- normal binaries fall back to debuginfod
- download the ubuntu/debian package to extract other libraries

#### patch
nice utilities for patching files, patchelf replacement

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