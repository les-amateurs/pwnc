## commands

### kernel

#### init

- `pwnc kernel init`
- autodetects and decompresses initramfs
- saves location of initramfs and unpacked rootfs

#### compress

- `pwnc kernel compress`
- uses saved information by `init` to compress rootfs
- `pwnc kernel compress --rootfs rootfs --initramfs initramfs.cpio.gz --gzipped --gzip-level 9`
- manually specify paths

#### decompress

- `pwnc kernel decompress`
- uses saved information by `init` to decompress rootfs
- `pwnc kernel decompress --initramfs initramfs.cpio.gz --rootfs backup-rootfs`
- manually specify paths

#### module

- `pwnc kernel module chal.ko`
- display modinfo
- `pwnc kernel module --set vermagic meow chal.ko`
- modinfo modification

#### template

- initialize various kernel exploitation templates

### errno

- `pwnc errno 1`
- `pwnc errno -1`
- `pwnc errno 0xffffffff`
- displays information about error code

### patch

- `pwnc patch --rpath . --interp ./ld-linux-x86_64.so.2 chal`
- patch `DT_INTERP`, `DT_RPATH`, and `DT_NEEDED` in-place
- does not use patchelf

### unstrip

- `pwnc unstrip libc.so.6`
- unstrip libc file
- `pwnc unstrip libc.so.6 --save`
- search for libc in ubuntu and debian packages, download .deb file

### unpack

- `pwnc unpack`
- unpacks compressed challenge archive
  - archives that contain a single toplevel directory are used directly
  - archives that contain toplevel files are moved into a new directory

### docker

#### extract

- extract files from docker image

### shellc

- utilities for compiling c code to shellcode

## utilities

### gdb

expose wrappers around the gdb api to use in solve scripts

- programatically place breakpoints
- oneshot breakpoints
- run python code from breakpoints
- pwntools also provides a version of this but it is fairly basic

### minelf

minimal elf parsing and in place modification library

### dwarf

dwarf utilities

#### Teemo

- binja plugin to generate dwarf info on the fly to import into gdb
  - types
  - function signatures
  - global variables
  - local function variables
  - address to decompilation mapping

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
