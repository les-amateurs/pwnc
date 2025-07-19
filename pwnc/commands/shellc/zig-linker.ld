SECTIONS {
    /* here we place `.entry` as the first section */
    .entry.init : { KEEP(*(.entry.init)) }
    . = .;
    .entry      : { *(.entry) }
    . = .;
    .text       : { *(.text*) }
    .rodata     : { *(.rodata*) }
    .data       : {
        *(.data*)
        *(.entry.data)
    }
    .bss        : { *(.bss.*) }

    /* remove all useless sections */
    /DISCARD/ : { *(.comment*)   }
    /DISCARD/ : { *(.note.*)     }
    /DISCARD/ : { *(.gnu.*)      }
    /DISCARD/ : { *(.eh_frame*)  }
    /DISCARD/ : { *(.rela.*)     }
    /DISCARD/ : { *(.dynsym.*)   }
    /DISCARD/ : { *(.dynstr.*)   }
    /DISCARD/ : { *(.symtab.*)   }
    /DISCARD/ : { *(.strtab.*)   }
    /DISCARD/ : { *(.shstrtab.*) }
    /DISCARD/ : { *(.dynamic)    }
    /DISCARD/ : { *(.debug_*)    }
    /DISCARD/ : { *(.ARM.*)      }
}