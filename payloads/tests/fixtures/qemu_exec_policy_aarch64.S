/*
 * Execute an exact exit(42) sequence from a fresh anonymous mapping.
 *
 * PWNC_ADD_EXEC=0 leaves the mapping RW.  linux-user before QEMU commit
 * cdf713085131 incorrectly translates it anyway; releases containing that
 * fix report a guest instruction-fetch SIGSEGV.  PWNC_ADD_EXEC=1 changes the
 * mapping to RX first and must work under both policies.
 */

.text
.global _start
.type _start, %function
_start:
    /* mmap(NULL, 4096, PROT_READ | PROT_WRITE,
     *      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
     */
    mov x0, #0
    mov x1, #4096
    mov x2, #3
    mov x3, #0x22
    mov x4, #-1
    mov x5, #0
    mov x8, #222
    svc #0

    /* Linux syscall errors occupy [-4095, -1]. */
    cmn x0, #4095
    b.cs failure
    mov x19, x0
    mov x20, x0

    adr x1, payload_start
    adr x2, payload_end
copy_loop:
    ldrb w3, [x1], #1
    strb w3, [x19], #1
    cmp x1, x2
    b.ne copy_loop

#if PWNC_ADD_EXEC
    /* mprotect(mapping, 4096, PROT_READ | PROT_EXEC) */
    mov x0, x20
    mov x1, #4096
    mov x2, #5
    mov x8, #226
    svc #0
    cbnz x0, failure
#endif

    br x20

failure:
    mov x0, #111
    mov x8, #93
    svc #0

payload_start:
    mov x0, #42
    mov x8, #93
    svc #0
    brk #0
payload_end:

.size _start, . - _start
.section .note.GNU-stack,"",%progbits
