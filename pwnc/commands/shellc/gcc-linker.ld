OUTPUT_FORMAT(binary)

SECTIONS {
    /* here we place `.entry` as the first section */
    .entry.init : { KEEP(*(.entry.init)) }
    . = .;
    .entry      : { *(.entry) }
    . = .;
    .text       : { *(.text.*) }
    .rodata     : { *(.rodata.*) }
    .data       : { *(.data.*) }
    .entry.data : { *(.entry.data) }
    .bss        : { *(.bss.*) }

    /* remove all useless sections */
    /DISCARD/ : {
        *(.interp)
        *(.comment*)
        *(.note.*)
        *(.gnu.*)
        *(.gnu_*)
        *(.eh_frame*)
        *(.rela.*)
        *(.dynsym)
        *(.dynstr)
        *(.symtab)
        *(.strtab)
        *(.shstrtab)
        *(.dynamic)
        *(.debug_*)
        *(.ARM.*)
        *(.hash)
        *(.hash.*)
    }
}