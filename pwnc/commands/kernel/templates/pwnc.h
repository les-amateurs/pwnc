#ifndef _PWNC_H_
#define _PWNC_H_

#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

typedef int64_t i64;
typedef int32_t i32;
typedef int16_t i16;
typedef int8_t i8;

typedef size_t usize;

#define try(expr)                                                              \
    ({                                                                         \
        int _i = (expr);                                                       \
        if (0 > _i) {                                                          \
            errx(1, "error at %s:%d: returned %d, %s\n", __FILE__, __LINE__,   \
                 _i, strerror(errno));                                         \
        }                                                                      \
        _i;                                                                    \
    })

#define warn(expr)                                                             \
    ({                                                                         \
        int _i = (expr);                                                       \
        if (0 > _i) {                                                          \
            printf("pwn: error at %s:%d: returned %d, %s\n", __FILE__,         \
                   __LINE__, _i, strerror(errno));                             \
        }                                                                      \
        _i;                                                                    \
    })

inline void wait() {
    char c;
    printf("[*] pause: ");
    scanf("%c", &c);
}

#endif