    global _start
    bits 64

_start:
    mov rax, rsi
    add rax, 8
    shl rax, 1
    push rax
    div rax
    times 10 nop