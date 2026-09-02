typedef unsigned long target_word;

enum Mode {
    MODE_ZERO = 0,
    MODE_ACTIVE = 7,
};

union Payload {
    int number;
    unsigned char bytes[4];
};

struct Node {
    int value;
    struct Node *next;
};

struct Base {
    int base_value;
};

struct Derived {
    struct Base base;
    union Payload payload;
};

volatile int global_counter = MODE_ACTIVE;
volatile int global_sink;
struct Node global_node = {3, (struct Node *)0};

#if defined(TEEMO_SECURITY_ANNOTATION_FIXTURE)
extern int printf(const char *format, ...);
extern int snprintf(char *destination, target_word size, const char *format, ...);

char teemo_writable_format[] = "%lu";
static const char teemo_readonly_format[] = "%lu";
char teemo_format_destination[32];

/*
 * Keep the forwarding function visible as a real call boundary.  Teemo must
 * infer that argument zero is printf-like, then classify each caller's value.
 */
__attribute__((noinline))
int teemo_printf_wrapper(const char *format, target_word value)
{
    return printf(format, value);
}

__attribute__((noinline))
int teemo_format_calls(target_word value)
{
    int result = printf(teemo_writable_format, value);
    result += printf(teemo_readonly_format, value);
    result += teemo_printf_wrapper(teemo_writable_format, value);

    /* A writable destination is not a writable snprintf format string. */
    result += snprintf(
        teemo_format_destination,
        sizeof(teemo_format_destination),
        teemo_readonly_format,
        value
    );
    return result;
}
#endif

#if defined(TEEMO_ORPHAN_IMPORT_FIXTURE)
extern void teemo_imported_win(void);

/*
 * No code or data points at this function.  Its only useful analysis seed is
 * the import tail-call, and the matching assembly fixture makes this section
 * high-entropy so Binary Ninja's ordinary linear sweep leaves it unclaimed.
 */
__attribute__((used, noinline, section(".teemo_orphan")))
void teemo_orphan_win(void)
{
#if defined(__x86_64__)
    /* Keep only this orphan import on the direct-GOT path. */
    __asm__ volatile(
        "call *teemo_imported_win@GOTPCREL(%%rip)"
        :
        :
        : "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "memory"
    );
#else
    teemo_imported_win();
#endif
}
#endif

__attribute__((noinline))
int analyzed(int argc, char **argv, struct Node *node)
{
    volatile int stack_local = argc + node->value;
    int shadow = stack_local;

    if ((argc & 1) != 0) {
        int shadow = node->value + 11;
        stack_local += shadow;
    } else {
        int branch_local = argc - 2;
        stack_local += branch_local;
    }

    for (int index = 0; index < 3; ++index) {
        int loop_local = index + shadow;
        stack_local += loop_local;
    }

    if (argv != (char **)0)
        stack_local += (int)(target_word)argv[0];
    global_sink = stack_local;
    return stack_local + global_counter;
}

__attribute__((noreturn))
void _start(void)
{
    int status = analyzed(3, (char **)0, &global_node);
#if defined(TEEMO_SECURITY_ANNOTATION_FIXTURE)
    status += teemo_format_calls((target_word)status);
#endif
#if defined(__x86_64__)
    __asm__ volatile("syscall" : : "a"(60L), "D"((long)status) : "rcx", "r11", "memory");
#elif defined(__i386__)
    __asm__ volatile("int $0x80" : : "a"(1L), "b"((long)status) : "memory");
#elif defined(__aarch64__)
    register long argument0 __asm__("x0") = status;
    register long syscall_number __asm__("x8") = 93;
    __asm__ volatile("svc #0" : : "r"(argument0), "r"(syscall_number) : "memory");
#elif defined(__arm__)
    register long argument0 __asm__("r0") = status;
    register long syscall_number __asm__("r7") = 1;
    __asm__ volatile("svc #0" : : "r"(argument0), "r"(syscall_number) : "memory");
#else
#error unsupported Teemo fixture architecture
#endif
    __builtin_unreachable();
}
