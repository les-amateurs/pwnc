#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PTRACE_O_EXITKILL
#define PTRACE_O_EXITKILL (1UL << 20)
#endif

#ifndef PTRACE_EVENT_EXEC
#define PTRACE_EVENT_EXEC 4
#endif

#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif

#ifndef PR_SET_PTRACER_ANY
#define PR_SET_PTRACER_ANY ((unsigned long)-1)
#endif

#define PWNC_SHIM_MAGIC 0x50574e53U /* "PWNS" */
#define PWNC_SHIM_VERSION 3U

enum frame_kind {
    FRAME_READY = 1,
    FRAME_EXIT = 2,
    FRAME_ERROR = 3,
    FRAME_ACK = 4,
    FRAME_HELLO = 5,

    COMMAND_CONTINUE = 0x101,
    COMMAND_SIGNAL = 0x102,
    COMMAND_KILL = 0x103,
    COMMAND_READY_ACK = 0x104,
    COMMAND_HELLO_ACK = 0x105,
};

enum frame_flags {
    READY_PAUSED = 1U << 0,
    READY_PIDFD = 1U << 1,

    EXIT_NORMAL = 1U << 0,
    EXIT_SIGNAL = 1U << 1,
    EXIT_CORE = 1U << 2,

    ERROR_FATAL = 1U << 0,
};

enum error_stage {
    STAGE_ARGUMENTS = 1,
    STAGE_CONTROL_CONNECT = 2,
    STAGE_SIGNAL_SETUP = 3,
    STAGE_FORK = 4,
    STAGE_CHILD_PDEATHSIG = 5,
    STAGE_CHILD_DUMPABLE = 6,
    STAGE_CHILD_PTRACER = 7,
    STAGE_CHILD_SIGNAL_RESET = 8,
    STAGE_CHILD_GATE = 9,
    STAGE_CHILD_EXEC = 10,
    STAGE_PTRACE_SEIZE = 11,
    STAGE_PTRACE_EXEC_WAIT = 12,
    STAGE_PTRACE_DETACH = 13,
    STAGE_GROUP_STOP = 14,
    STAGE_PIDFD = 15,
    STAGE_PROTOCOL = 16,
    STAGE_SIGNAL = 17,
    STAGE_WAIT = 18,
    STAGE_CHILD_CAPABILITIES = 19,
    STAGE_CHILD_NO_NEW_PRIVS = 20,
    STAGE_CHILD_ASLR = 21,
};

enum aslr_mode {
    ASLR_INHERIT = 0,
    ASLR_ENABLE = 1,
    ASLR_DISABLE = 2,
};

struct frame_wire {
    uint32_t magic;
    uint32_t version;
    uint32_t kind;
    uint32_t pid;
    uint32_t value;
    uint32_t detail;
    uint32_t flags;
    uint32_t reserved;
};

struct child_error_wire {
    uint32_t stage;
    uint32_t error_number;
};

_Static_assert(sizeof(struct frame_wire) == 32, "control frame must remain fixed-size");
_Static_assert(sizeof(struct child_error_wire) == 8, "child error frame must remain fixed-size");

static int control_fd = -1;
static int signal_fd = -1;
static int child_pidfd = -1;
static pid_t child_pid = -1;
static int control_open = 0;

static void close_if_open(int *descriptor) {
    if (*descriptor >= 0) {
        close(*descriptor);
        *descriptor = -1;
    }
}

static int set_cloexec(int descriptor) {
    int flags = fcntl(descriptor, F_GETFD);
    if (flags < 0) {
        return -1;
    }
    return fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC);
}

static int make_pipe(int descriptors[2]) {
#ifdef __linux__
    if (pipe2(descriptors, O_CLOEXEC) == 0) {
        return 0;
    }
    if (errno != ENOSYS) {
        return -1;
    }
#endif
    if (pipe(descriptors) < 0) {
        return -1;
    }
    if (set_cloexec(descriptors[0]) < 0 || set_cloexec(descriptors[1]) < 0) {
        int saved = errno;
        close(descriptors[0]);
        close(descriptors[1]);
        errno = saved;
        return -1;
    }
    return 0;
}

static ssize_t read_retry(int descriptor, void *buffer, size_t length) {
    ssize_t result;
    do {
        result = read(descriptor, buffer, length);
    } while (result < 0 && errno == EINTR);
    return result;
}

static int write_all(int descriptor, const void *buffer, size_t length) {
    const unsigned char *cursor = buffer;
    while (length > 0) {
        ssize_t written = write(descriptor, cursor, length);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (written == 0) {
            errno = EPIPE;
            return -1;
        }
        cursor += (size_t)written;
        length -= (size_t)written;
    }
    return 0;
}

static int connect_control(const char *path) {
    struct sockaddr_un address;
    size_t length = strlen(path);
    if (length == 0 || length >= sizeof(address.sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    int descriptor = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (descriptor < 0) {
        return -1;
    }

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, length + 1);
    socklen_t address_length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + length + 1);
    if (connect(descriptor, (struct sockaddr *)&address, address_length) < 0) {
        int saved = errno;
        close(descriptor);
        errno = saved;
        return -1;
    }
    return descriptor;
}

static int send_frame(uint32_t kind, pid_t pid, int32_t value, uint32_t detail, uint32_t flags, int passed_fd) {
    struct frame_wire frame = {
        .magic = htonl(PWNC_SHIM_MAGIC),
        .version = htonl(PWNC_SHIM_VERSION),
        .kind = htonl(kind),
        .pid = htonl((uint32_t)pid),
        .value = htonl((uint32_t)value),
        .detail = htonl(detail),
        .flags = htonl(flags),
        .reserved = 0,
    };
    struct iovec vector = {
        .iov_base = &frame,
        .iov_len = sizeof(frame),
    };
    struct msghdr message;
    unsigned char ancillary[CMSG_SPACE(sizeof(int))];

    memset(&message, 0, sizeof(message));
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    if (passed_fd >= 0) {
        memset(ancillary, 0, sizeof(ancillary));
        message.msg_control = ancillary;
        message.msg_controllen = sizeof(ancillary);
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), &passed_fd, sizeof(passed_fd));
    }

    ssize_t sent;
    do {
        sent = sendmsg(control_fd, &message, MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    if (sent != (ssize_t)sizeof(frame)) {
        if (sent >= 0) {
            errno = EIO;
        }
        return -1;
    }
    return 0;
}

static int send_error(enum error_stage stage, int error_number, int fatal) {
    if (!control_open) {
        return -1;
    }
    return send_frame(FRAME_ERROR, child_pid > 0 ? child_pid : 0, error_number, (uint32_t)stage,
                      fatal ? ERROR_FATAL : 0, -1);
}

static void child_fail(int error_fd, enum error_stage stage, int error_number) {
    struct child_error_wire error = {
        .stage = htonl((uint32_t)stage),
        .error_number = htonl((uint32_t)error_number),
    };
    (void)write_all(error_fd, &error, sizeof(error));
    _exit(127);
}

static int reset_child_signals(void) {
    sigset_t empty;
    if (sigemptyset(&empty) < 0 || sigprocmask(SIG_SETMASK, &empty, NULL) < 0) {
        return -1;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (sigemptyset(&action.sa_mask) < 0) {
        return -1;
    }
    for (int number = 1; number < NSIG; number++) {
        if (number == SIGKILL || number == SIGSTOP) {
            continue;
        }
        if (sigaction(number, &action, NULL) < 0 && errno != EINVAL) {
            return -1;
        }
    }
    return 0;
}

static int clear_child_capabilities(void) {
#if defined(PR_CAP_AMBIENT) && defined(PR_CAP_AMBIENT_CLEAR_ALL)
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0 && errno != EINVAL) {
        return -1;
    }
#endif

#ifdef SYS_capset
    struct __user_cap_header_struct header;
    struct __user_cap_data_struct capabilities[2];
    memset(&header, 0, sizeof(header));
    memset(capabilities, 0, sizeof(capabilities));
    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid = 0;
    if (syscall(SYS_capset, &header, capabilities) < 0) {
        return -1;
    }
    return 0;
#else
    errno = ENOSYS;
    return -1;
#endif
}

static void child_main(int armed_write, int gate_read, int error_write, pid_t expected_parent,
                       enum aslr_mode host_aslr, const char *fallback_executable, char *target_argv[]) {
    close_if_open(&control_fd);
    close_if_open(&signal_fd);
    close_if_open(&child_pidfd);

    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) < 0) {
        child_fail(error_write, STAGE_CHILD_PDEATHSIG, errno);
    }
    if (reset_child_signals() < 0) {
        child_fail(error_write, STAGE_CHILD_SIGNAL_RESET, errno);
    }
    if (clear_child_capabilities() < 0) {
        child_fail(error_write, STAGE_CHILD_CAPABILITIES, errno);
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        child_fail(error_write, STAGE_CHILD_NO_NEW_PRIVS, errno);
    }
    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0) {
        child_fail(error_write, STAGE_CHILD_DUMPABLE, errno);
    }
    if (prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0) < 0) {
        child_fail(error_write, STAGE_CHILD_PTRACER, errno);
    }
    if (getppid() != expected_parent) {
        child_fail(error_write, STAGE_CHILD_PDEATHSIG, EPIPE);
    }

    if (host_aslr != ASLR_INHERIT) {
        int current = personality(0xffffffffUL);
        if (current < 0) {
            child_fail(error_write, STAGE_CHILD_ASLR, errno);
        }
        unsigned long desired = (unsigned long)current;
        if (host_aslr == ASLR_DISABLE) {
            desired |= ADDR_NO_RANDOMIZE;
        } else {
            desired &= ~((unsigned long)ADDR_NO_RANDOMIZE);
        }
        if (personality(desired) < 0) {
            child_fail(error_write, STAGE_CHILD_ASLR, errno);
        }
    }

    unsigned char armed = 1;
    if (write_all(armed_write, &armed, sizeof(armed)) < 0) {
        child_fail(error_write, STAGE_CHILD_GATE, errno);
    }
    close(armed_write);

    unsigned char release = 0;
    ssize_t received = read_retry(gate_read, &release, sizeof(release));
    close(gate_read);
    if (received != 1 || release != 1) {
        child_fail(error_write, STAGE_CHILD_GATE, received < 0 ? errno : EPIPE);
    }

    execvp(target_argv[0], target_argv);
    if (fallback_executable != NULL &&
        (errno == ENOENT || errno == ENOEXEC || errno == EACCES)) {
        target_argv[0] = (char *)fallback_executable;
        execv(fallback_executable, target_argv);
    }
    child_fail(error_write, STAGE_CHILD_EXEC, errno);
}

static int read_child_error(int descriptor, enum error_stage *stage, int *error_number) {
    struct child_error_wire error;
    unsigned char *cursor = (unsigned char *)&error;
    size_t remaining = sizeof(error);
    while (remaining > 0) {
        ssize_t received = read_retry(descriptor, cursor, remaining);
        if (received < 0) {
            return -1;
        }
        if (received == 0) {
            if (remaining == sizeof(error)) {
                return 0;
            }
            errno = EPROTO;
            return -1;
        }
        cursor += (size_t)received;
        remaining -= (size_t)received;
    }
    *stage = (enum error_stage)ntohl(error.stage);
    *error_number = (int)ntohl(error.error_number);
    return 1;
}

static int wait_nointr(pid_t pid, int *status, int options) {
    pid_t result;
    do {
        result = waitpid(pid, status, options);
    } while (result < 0 && errno == EINTR);
    return result == pid ? 0 : -1;
}

static int wait_for_exec(pid_t pid, int *terminal_status) {
    for (;;) {
        int status = 0;
        if (wait_nointr(pid, &status, __WALL) < 0) {
            return -1;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            *terminal_status = status;
            return 0;
        }
        if (!WIFSTOPPED(status)) {
            continue;
        }
        unsigned int event = (unsigned int)status >> 16;
        if (WSTOPSIG(status) == SIGTRAP && event == PTRACE_EVENT_EXEC) {
            return 1;
        }

        int delivered = WSTOPSIG(status);
        if (delivered == SIGTRAP || delivered == SIGSTOP) {
            delivered = 0;
        }
        if (ptrace(PTRACE_CONT, pid, NULL, (void *)(uintptr_t)delivered) < 0) {
            return -1;
        }
    }
}

static int create_pidfd(pid_t pid) {
#ifdef SYS_pidfd_open
    return (int)syscall(SYS_pidfd_open, pid, 0U);
#else
    (void)pid;
    errno = ENOSYS;
    return -1;
#endif
}

static int signal_child(int number) {
#ifdef SYS_pidfd_send_signal
    if (child_pidfd >= 0) {
        if (syscall(SYS_pidfd_send_signal, child_pidfd, number, NULL, 0U) == 0) {
            return 0;
        }
        if (errno != ENOSYS) {
            return -1;
        }
    }
#endif
    return kill(child_pid, number);
}

static int decode_frame(const struct frame_wire *wire, uint32_t *kind, int32_t *value) {
    if (ntohl(wire->magic) != PWNC_SHIM_MAGIC || ntohl(wire->version) != PWNC_SHIM_VERSION ||
        ntohl(wire->pid) != 0 || ntohl(wire->detail) != 0 || ntohl(wire->flags) != 0 ||
        ntohl(wire->reserved) != 0) {
        errno = EPROTO;
        return -1;
    }
    *kind = ntohl(wire->kind);
    *value = (int32_t)ntohl(wire->value);
    return 0;
}

static int receive_command(void) {
    struct frame_wire wire;
    ssize_t received;
    do {
        received = recv(control_fd, &wire, sizeof(wire), MSG_TRUNC);
    } while (received < 0 && errno == EINTR);
    if (received == 0) {
        return 0;
    }
    if (received < 0) {
        return -1;
    }
    if (received != (ssize_t)sizeof(wire)) {
        errno = EMSGSIZE;
        return -1;
    }

    uint32_t kind = 0;
    int32_t value = 0;
    if (decode_frame(&wire, &kind, &value) < 0) {
        return -1;
    }

    int signal_number;
    switch (kind) {
    case COMMAND_CONTINUE:
        signal_number = SIGCONT;
        break;
    case COMMAND_SIGNAL:
        if (value <= 0 || value >= NSIG) {
            errno = EINVAL;
            return -1;
        }
        signal_number = value;
        break;
    case COMMAND_KILL:
        signal_number = SIGKILL;
        break;
    default:
        errno = EPROTO;
        return -1;
    }

    if (signal_child(signal_number) < 0) {
        return -1;
    }
    if (send_frame(FRAME_ACK, child_pid, (int32_t)kind, (uint32_t)signal_number, 0, -1) < 0) {
        return -1;
    }
    return 1;
}

static int receive_ready_ack_frame(void) {
    struct frame_wire wire;
    ssize_t received;
    do {
        received = recv(control_fd, &wire, sizeof(wire), MSG_TRUNC);
    } while (received < 0 && errno == EINTR);
    if (received == 0) {
        return 0;
    }
    if (received < 0) {
        return -1;
    }
    if (received != (ssize_t)sizeof(wire)) {
        errno = EMSGSIZE;
        return -1;
    }

    uint32_t kind = 0;
    int32_t value = 0;
    if (decode_frame(&wire, &kind, &value) < 0) {
        return -1;
    }
    if (kind != COMMAND_READY_ACK || value != 0) {
        errno = EPROTO;
        return -1;
    }
    if (send_frame(FRAME_ACK, child_pid, (int32_t)kind, 0, 0, -1) < 0) {
        return -1;
    }
    return 1;
}

static int receive_hello_ack_frame(void) {
    struct frame_wire wire;
    ssize_t received;
    do {
        received = recv(control_fd, &wire, sizeof(wire), MSG_TRUNC);
    } while (received < 0 && errno == EINTR);
    if (received == 0) {
        return 0;
    }
    if (received < 0) {
        return -1;
    }
    if (received != (ssize_t)sizeof(wire)) {
        errno = EMSGSIZE;
        return -1;
    }

    uint32_t kind = 0;
    int32_t value = 0;
    if (decode_frame(&wire, &kind, &value) < 0) {
        return -1;
    }
    if (kind != COMMAND_HELLO_ACK || value != 0) {
        errno = EPROTO;
        return -1;
    }
    return 1;
}

static int wait_for_ready_ack(int *terminal_status, int *has_terminal_status) {
    int saw_sigchld = 0;
    *has_terminal_status = 0;

    for (;;) {
        struct pollfd descriptors[2] = {
            {.fd = signal_fd, .events = POLLIN, .revents = 0},
            {.fd = control_fd, .events = POLLIN, .revents = 0},
        };
        int ready;
        do {
            ready = poll(descriptors, 2, -1);
        } while (ready < 0 && errno == EINTR);
        if (ready < 0) {
            return -1;
        }

        if (descriptors[0].revents & POLLIN) {
            struct signalfd_siginfo information;
            ssize_t length = read_retry(signal_fd, &information, sizeof(information));
            if (length != (ssize_t)sizeof(information)) {
                errno = length < 0 ? errno : EIO;
                return -1;
            }
            if (information.ssi_signo == SIGCHLD) {
                /* Do not reap before READY_ACK: a zombie retains the pidfd's
                   host-namespace identity for manager credential checks. */
                saw_sigchld = 1;
            } else {
                int number = (int)information.ssi_signo;
                if (signal_child(number) < 0 && errno != ESRCH) {
                    send_error(STAGE_SIGNAL, errno, 0);
                }
                if (number == SIGTERM || number == SIGINT || number == SIGHUP || number == SIGQUIT) {
                    (void)signal_child(SIGCONT);
                }
            }
        }

        if (descriptors[1].revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL)) {
            int acknowledged = receive_ready_ack_frame();
            if (acknowledged <= 0) {
                return acknowledged;
            }
            if (saw_sigchld) {
                pid_t result;
                do {
                    result = waitpid(child_pid, terminal_status, WNOHANG);
                } while (result < 0 && errno == EINTR);
                if (result == child_pid) {
                    *has_terminal_status = 1;
                } else if (result < 0 && errno != ECHILD) {
                    return -1;
                } else if (result < 0) {
                    errno = ECHILD;
                    return -1;
                }
            }
            return 1;
        }
    }
}

static int emit_exit(int status) {
    uint32_t flags = 0;
    int32_t value = 0;
    if (WIFEXITED(status)) {
        flags |= EXIT_NORMAL;
        value = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        flags |= EXIT_SIGNAL;
        value = WTERMSIG(status);
#ifdef WCOREDUMP
        if (WCOREDUMP(status)) {
            flags |= EXIT_CORE;
        }
#endif
    }
    if (control_open) {
        (void)send_frame(FRAME_EXIT, child_pid, value, (uint32_t)status, flags, -1);
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 1);
}

static int supervise(void) {
    struct pollfd descriptors[2];
    for (;;) {
        descriptors[0].fd = signal_fd;
        descriptors[0].events = POLLIN;
        descriptors[0].revents = 0;
        descriptors[1].fd = control_open ? control_fd : -1;
        descriptors[1].events = POLLIN;
        descriptors[1].revents = 0;

        int ready;
        do {
            ready = poll(descriptors, 2, -1);
        } while (ready < 0 && errno == EINTR);
        if (ready < 0) {
            send_error(STAGE_WAIT, errno, 1);
            (void)signal_child(SIGKILL);
            int status;
            if (wait_nointr(child_pid, &status, 0) == 0) {
                return emit_exit(status);
            }
            return 125;
        }

        if (descriptors[0].revents & POLLIN) {
            struct signalfd_siginfo information;
            ssize_t length = read_retry(signal_fd, &information, sizeof(information));
            if (length != (ssize_t)sizeof(information)) {
                send_error(STAGE_SIGNAL_SETUP, length < 0 ? errno : EIO, 1);
                (void)signal_child(SIGKILL);
            } else if (information.ssi_signo == SIGCHLD) {
                int status = 0;
                pid_t result;
                do {
                    result = waitpid(child_pid, &status, WNOHANG);
                } while (result < 0 && errno == EINTR);
                if (result == child_pid) {
                    return emit_exit(status);
                }
                if (result < 0 && errno != ECHILD) {
                    send_error(STAGE_WAIT, errno, 1);
                    return 125;
                }
            } else {
                int number = (int)information.ssi_signo;
                if (signal_child(number) < 0 && errno != ESRCH) {
                    send_error(STAGE_SIGNAL, errno, 0);
                }
                if (number == SIGTERM || number == SIGINT || number == SIGHUP || number == SIGQUIT) {
                    (void)signal_child(SIGCONT);
                }
            }
        }

        if (control_open && (descriptors[1].revents & POLLIN)) {
            int result = receive_command();
            if (result <= 0) {
                if (result < 0) {
                    send_error(STAGE_PROTOCOL, errno, 0);
                }
                control_open = 0;
                close_if_open(&control_fd);
                (void)signal_child(SIGKILL);
            }
        }
        if (control_open && (descriptors[1].revents & (POLLERR | POLLHUP | POLLNVAL))) {
            control_open = 0;
            close_if_open(&control_fd);
            (void)signal_child(SIGKILL);
        }
    }
}

static int setup_signal_fd(void) {
    sigset_t mask;
    if (sigfillset(&mask) < 0 || sigdelset(&mask, SIGKILL) < 0 || sigdelset(&mask, SIGSTOP) < 0) {
        return -1;
    }
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
        return -1;
    }
    return signalfd(-1, &mask, SFD_CLOEXEC);
}

static int fail_after_connect(enum error_stage stage, int error_number, int status) {
    send_error(stage, error_number, 1);
    return status;
}

static void usage(const char *program) {
    dprintf(STDERR_FILENO,
            "usage: %s --control PATH [--pause|--no-pause] "
            "[--host-aslr inherit|on|off] [--fallback-executable PATH] "
            "-- PROGRAM [ARG ...]\n",
            program);
}

int main(int argc, char **argv) {
    const char *control_path = NULL;
    int paused = 1;
    enum aslr_mode host_aslr = ASLR_INHERIT;
    const char *fallback_executable = NULL;
    int target_index = -1;

    for (int index = 1; index < argc; index++) {
        if (strcmp(argv[index], "--") == 0) {
            target_index = index + 1;
            break;
        }
        if (strcmp(argv[index], "--control") == 0 && index + 1 < argc) {
            control_path = argv[++index];
        } else if (strcmp(argv[index], "--pause") == 0) {
            paused = 1;
        } else if (strcmp(argv[index], "--no-pause") == 0) {
            paused = 0;
        } else if (strcmp(argv[index], "--host-aslr") == 0 && index + 1 < argc) {
            const char *setting = argv[++index];
            if (strcmp(setting, "inherit") == 0) {
                host_aslr = ASLR_INHERIT;
            } else if (strcmp(setting, "on") == 0) {
                host_aslr = ASLR_ENABLE;
            } else if (strcmp(setting, "off") == 0) {
                host_aslr = ASLR_DISABLE;
            } else {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[index], "--fallback-executable") == 0 && index + 1 < argc) {
            fallback_executable = argv[++index];
            if (fallback_executable[0] == '\0') {
                usage(argv[0]);
                return 2;
            }
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (control_path == NULL || target_index < 0 || target_index >= argc) {
        usage(argv[0]);
        return 2;
    }

    control_fd = connect_control(control_path);
    if (control_fd < 0) {
        dprintf(STDERR_FILENO, "pwnc sandbox shim: cannot connect control socket: %s\n", strerror(errno));
        return 125;
    }
    control_open = 1;

    /* ``exec`` preserves ignored dispositions.  Normalize them before the
       supervisor blocks signals into signalfd, most importantly SIGCHLD: an
       inherited SIG_IGN would otherwise auto-reap the target. */
    if (reset_child_signals() < 0) {
        return fail_after_connect(STAGE_SIGNAL_SETUP, errno, 125);
    }

    /* Do not fork, much less exec, until the host has checked this exact
       supervisor's host-namespace PID and all UID/GID fields.  This makes
       user-namespace remapping fail closed before any challenge code runs. */
    if (send_frame(FRAME_HELLO, 0, 0, 0, 0, -1) < 0) {
        control_open = 0;
        close_if_open(&control_fd);
        return 125;
    }
    int hello_acknowledged = receive_hello_ack_frame();
    if (hello_acknowledged <= 0) {
        if (hello_acknowledged < 0) {
            send_error(STAGE_PROTOCOL, errno, 1);
        }
        control_open = 0;
        close_if_open(&control_fd);
        return 125;
    }

    signal_fd = setup_signal_fd();
    if (signal_fd < 0) {
        return fail_after_connect(STAGE_SIGNAL_SETUP, errno, 125);
    }

    int armed[2] = {-1, -1};
    int gate[2] = {-1, -1};
    int errors[2] = {-1, -1};
    if (make_pipe(armed) < 0 || make_pipe(gate) < 0 || make_pipe(errors) < 0) {
        return fail_after_connect(STAGE_FORK, errno, 125);
    }

    pid_t supervisor_pid = getpid();
    child_pid = fork();
    if (child_pid < 0) {
        return fail_after_connect(STAGE_FORK, errno, 125);
    }
    if (child_pid == 0) {
        close(armed[0]);
        close(gate[1]);
        close(errors[0]);
        child_main(armed[1], gate[0], errors[1], supervisor_pid, host_aslr,
                   fallback_executable, &argv[target_index]);
    }

    close(armed[1]);
    close(gate[0]);
    close(errors[1]);

    child_pidfd = create_pidfd(child_pid);
    int pidfd_error = errno;

    unsigned char armed_byte = 0;
    ssize_t armed_length = read_retry(armed[0], &armed_byte, sizeof(armed_byte));
    close(armed[0]);
    if (armed_length != 1 || armed_byte != 1) {
        enum error_stage stage = STAGE_CHILD_GATE;
        int child_error = armed_length < 0 ? errno : EPIPE;
        int error_result = read_child_error(errors[0], &stage, &child_error);
        if (error_result < 0) {
            child_error = errno;
        }
        int status;
        (void)wait_nointr(child_pid, &status, 0);
        return fail_after_connect(stage, child_error, 127);
    }

    if (child_pidfd < 0 && pidfd_error != ENOSYS) {
        (void)signal_child(SIGKILL);
        int status;
        (void)wait_nointr(child_pid, &status, 0);
        return fail_after_connect(STAGE_PIDFD, pidfd_error, 125);
    }

    if (paused) {
        unsigned long options = PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL;
        if (ptrace(PTRACE_SEIZE, child_pid, NULL, (void *)options) < 0) {
            int saved = errno;
            (void)signal_child(SIGKILL);
            int status;
            (void)wait_nointr(child_pid, &status, 0);
            return fail_after_connect(STAGE_PTRACE_SEIZE, saved, 125);
        }
    }

    unsigned char release = 1;
    if (write_all(gate[1], &release, sizeof(release)) < 0) {
        int saved = errno;
        close(gate[1]);
        (void)signal_child(SIGKILL);
        int status;
        (void)wait_nointr(child_pid, &status, 0);
        return fail_after_connect(STAGE_CHILD_GATE, saved, 125);
    }
    close(gate[1]);

    if (paused) {
        int terminal_status = 0;
        int exec_result = wait_for_exec(child_pid, &terminal_status);
        if (exec_result <= 0) {
            enum error_stage stage = STAGE_PTRACE_EXEC_WAIT;
            int child_error = exec_result < 0 ? errno : ECHILD;
            int error_result = read_child_error(errors[0], &stage, &child_error);
            if (error_result < 0) {
                child_error = errno;
            }
            close(errors[0]);
            send_error(stage, child_error, 1);
            if (exec_result == 0) {
                return emit_exit(terminal_status);
            }
            (void)signal_child(SIGKILL);
            int status;
            (void)wait_nointr(child_pid, &status, __WALL);
            return 125;
        }
        close(errors[0]);

        if (kill(child_pid, SIGSTOP) < 0) {
            int saved = errno;
            (void)ptrace(PTRACE_DETACH, child_pid, NULL, NULL);
            return fail_after_connect(STAGE_GROUP_STOP, saved, 125);
        }
        if (ptrace(PTRACE_DETACH, child_pid, NULL, NULL) < 0) {
            return fail_after_connect(STAGE_PTRACE_DETACH, errno, 125);
        }
        int stop_status = 0;
        if (wait_nointr(child_pid, &stop_status, WUNTRACED) < 0 || !WIFSTOPPED(stop_status) ||
            WSTOPSIG(stop_status) != SIGSTOP) {
            int saved = errno != 0 ? errno : EPROTO;
            (void)signal_child(SIGKILL);
            return fail_after_connect(STAGE_GROUP_STOP, saved, 125);
        }
    } else {
        enum error_stage stage = STAGE_CHILD_EXEC;
        int child_error = 0;
        int error_result = read_child_error(errors[0], &stage, &child_error);
        close(errors[0]);
        if (error_result != 0) {
            if (error_result < 0) {
                child_error = errno;
            }
            int status;
            (void)wait_nointr(child_pid, &status, 0);
            send_error(stage, child_error, 1);
            return emit_exit(status);
        }
    }

    uint32_t ready_flags = paused ? READY_PAUSED : 0;
    if (child_pidfd >= 0) {
        ready_flags |= READY_PIDFD;
    }
    if (send_frame(FRAME_READY, child_pid, 0, 0, ready_flags, child_pidfd) < 0) {
        control_open = 0;
        close_if_open(&control_fd);
        (void)signal_child(SIGKILL);
        int status;
        if (wait_nointr(child_pid, &status, 0) == 0) {
            int result = emit_exit(status);
            close_if_open(&child_pidfd);
            close_if_open(&signal_fd);
            return result;
        }
        close_if_open(&child_pidfd);
        close_if_open(&signal_fd);
        return 125;
    }

    /* A running target may finish immediately after exec.  Keep it waitable
       (and therefore keep its pidfd-to-host-PID identity resolvable) until the
       manager confirms that it has consumed READY and verified credentials. */
    int terminal_status = 0;
    int has_terminal_status = 0;
    if (!paused) {
        int acknowledged = wait_for_ready_ack(&terminal_status, &has_terminal_status);
        if (acknowledged <= 0) {
            if (acknowledged < 0) {
                send_error(STAGE_PROTOCOL, errno, 1);
            }
            control_open = 0;
            close_if_open(&control_fd);
            (void)signal_child(SIGKILL);
            int status;
            int waited = wait_nointr(child_pid, &status, 0);
            int result = waited == 0 ? emit_exit(status) : 125;
            close_if_open(&child_pidfd);
            close_if_open(&signal_fd);
            return result;
        }
    }

    int result = has_terminal_status ? emit_exit(terminal_status) : supervise();
    close_if_open(&child_pidfd);
    close_if_open(&signal_fd);
    close_if_open(&control_fd);
    return result;
}
