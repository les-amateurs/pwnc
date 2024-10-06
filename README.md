## commands

### kernel

#### init
- `pwnc kernel init`
- autodetects and decompresses initramfs
- saves location of initramfs and unpacked rootfs

#### compress
- `pwnc kernel compress`
- uses saved information by `init` to compress rootfs

#### decompress
- `pwnc kernel decompress`
- uses saved information by `init` to decompress rootfs

#### module
- `pwnc kernel module chal.ko`
- display modinfo
- `pwnc kernel module --set vermagic meow chal.ko`
- modinfo modification

### errno
- `pwnc errno 1`
- `pwnc errno -1`
- `pwnc errno 0xffffffff`
- displays information about error code

### patch
- `pwnc patch --rpath . --interp ./ld-linux-x86_64.so.2 chal`
- patch `DT_INTERP`, `DT_RPATH`, and `DT_NEEDED` in-place

### unstrip
- `pwnc unstrip libc.so.6`
- unstrip libc file
- `pwnc unstrip libc.so.6 --save`
- search for libc in ubuntu and debian packages, download .deb file

### unpack
- `pwnc unpack

## utilities

### gdb
expose wrappers around the gdb api to use in solve scripts
- programatically place breakpoints
- oneshot breakpoints
- run python code from breakpoints
- pwntools provides this but it is fairly basic

#### bata24 integration
- caches kernel version and kallsyms, to speed up ksymaddr-remote

### minelf
minimal elf parsing and in place modification library

### dwarf
dwarf utilities
binja plugin to generate dwarf info on the fly to import into gdb

## TODO

### asm
- default to nasm on x64/x86
- include header files for gas?
- allow labels

### checksec
- improved checksec

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