# teemo

## dwarf[WIP]

### type info

- [x] structs
- [x] unions
- [x] integers
- [x] typedefs
- [x] pointers
- [x] function prototypes
- [x] arrays
- [ ] classes

### global variables

- [x] typeinfo
- [x] correct section index

### functions

- [x] parameters
- [x] local variables
- [x] line information

## client/server

GDB client that adds a `binja` command to connect to the plugin server. Updates in binaryninja are pushed to GDB in real time.

The client is loaded by running `source plugin/gdbinit.py`.
