/*
 * Red-team syscall probe (RT-NET-01, RT-NET-08, RT-NET-12, RT-FS-17, RT-FS-24, RT-AG-09). Test-only: built at test time with
 * `cc -static`, copied into the throwaway test image, never linked into or shipped with any
 * Sallyport binary or release image (CLAUDE.md, exception to the no-unsafe rule). Keep it one
 * small file.
 *
 *   probe socket <family> <type> <protocol>   socket(2)
 *   probe socketpair <family> <type> <protocol>
 *                                             socketpair(2)
 *   probe unshare <flags>                     unshare(2)
 *   probe clone <flags>                       clone(2), fork-like; the child exits at once
 *   probe clone3 <flags>                      clone3(2), fork-like; the child exits at once
 *   probe connect <family> <type> <protocol> <address> <port>
 *                                             socket(2), then connect(2) to an IPv4 (family 2)
 *                                             or IPv6 (family 10) literal; the first error wins
 *   probe send <family> <type> <protocol> <address> <port>
 *                                             socket(2), then sendto(2) of one ICMP echo request
 *   probe syscall <name> [<first>]            syscall(2) by name (`calls` below): its first
 *                                             argument `first` (default 0), every other 0
 *   probe mqueue                              mq_open(2) of a new POSIX message queue with room
 *                                             for one 1-byte message, then mq_unlink(2) (RT-AG-09)
 *
 * Numbers are decimal or 0x-hex. Prints "ok" or "errno=<n>" (send: "sent", "socket errno=<n>" or
 * "sendto errno=<n>") and exits 0 or 1; usage errors exit 2.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* The first, stable fields of `struct clone_args` (CLONE_ARGS_SIZE_VER0, 64 bytes); declared here
 * because <linux/sched.h> and glibc's <sched.h> clash. */
struct probe_clone_args {
    uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls;
};

static long num(const char *s) {
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 0);
    if (errno != 0 || end == s || *end != '\0') {
        fprintf(stderr, "bad number: %s\n", s);
        exit(2);
    }
    return v;
}

static int report(long rc) {
    if (rc < 0) {
        printf("errno=%d\n", errno);
        return 1;
    }
    printf("ok\n");
    return 0;
}

#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425 /* the same number on every architecture */
#endif

/* System calls by name for `probe syscall`: `getpid` (allowed, the control) and one call of each
 * class the profiles remove (RT-FS-24). */
static const struct {
    const char *name;
    long nr;
} calls[] = {
    {"getpid", SYS_getpid},           {"mount", SYS_mount},
    {"ptrace", SYS_ptrace},           {"bpf", SYS_bpf},
    {"io_uring_setup", SYS_io_uring_setup}, {"keyctl", SYS_keyctl},
    {"userfaultfd", SYS_userfaultfd}, {"open_by_handle_at", SYS_open_by_handle_at},
};

/* syscall(2) `name` with `first` as its first argument and every other argument 0. */
static long by_name(const char *name, long first) {
    for (size_t i = 0; i < sizeof calls / sizeof calls[0]; i++) {
        if (strcmp(calls[i].name, name) == 0) {
            return syscall(calls[i].nr, first, 0, 0, 0, 0, 0);
        }
    }
    fprintf(stderr, "unknown system call: %s\n", name);
    exit(2);
}

/* Parent side of a fork-like clone: reap the child, which exits 0 at once. */
static long reap(long pid) {
    if (pid == 0) {
        _exit(0);
    }
    if (pid > 0) {
        waitpid((pid_t)pid, NULL, 0);
    }
    return pid;
}

/* `family` `addr` `port` (a[0], a[3], a[4]) as a socket address; returns its length. */
static socklen_t target(char **a, struct sockaddr_storage *ss) {
    int family = (int)num(a[0]);
    struct sockaddr_in *in4 = (struct sockaddr_in *)ss;
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)ss;
    memset(ss, 0, sizeof *ss);
    uint16_t port = htons((uint16_t)num(a[4]));
    if (family == AF_INET && inet_pton(AF_INET, a[3], &in4->sin_addr) == 1) {
        in4->sin_family = AF_INET;
        in4->sin_port = port;
        return sizeof *in4;
    }
    if (family == AF_INET6 && inet_pton(AF_INET6, a[3], &in6->sin6_addr) == 1) {
        in6->sin6_family = AF_INET6;
        in6->sin6_port = port;
        return sizeof *in6;
    }
    fprintf(stderr, "bad family or address: %s %s\n", a[0], a[3]);
    exit(2);
}

/* socket(family, type, protocol), then connect to `addr`:`port`. */
static long connect_to(char **a) {
    struct sockaddr_storage ss;
    socklen_t len = target(a, &ss);
    long fd = socket(ss.ss_family, (int)num(a[1]), (int)num(a[2]));
    if (fd < 0) {
        return fd;
    }
    return connect((int)fd, (struct sockaddr *)&ss, len);
}

/* socket(family, type, protocol), then sendto `addr` one ICMP (v4 or v6) echo request. Prints
 * "socket errno=<n>", "sendto errno=<n>" or "sent": which step failed, or that a packet left. */
static int send_to(char **a) {
    static const unsigned char echo4[8] = {8, 0, 0xf7, 0xff}; /* type 8, checksum filled in */
    static const unsigned char echo6[8] = {128};               /* the kernel sums ICMPv6 */
    struct sockaddr_storage ss;
    socklen_t len = target(a, &ss);
    int fd = socket(ss.ss_family, (int)num(a[1]), (int)num(a[2]));
    if (fd < 0) {
        printf("socket errno=%d\n", errno);
        return 1;
    }
    const unsigned char *echo = ss.ss_family == AF_INET ? echo4 : echo6;
    if (sendto(fd, echo, 8, 0, (struct sockaddr *)&ss, len) < 0) {
        printf("sendto errno=%d\n", errno);
        return 1;
    }
    printf("sent\n");
    return 0;
}

/* A new queue charges its bytes to the caller's user, up to RLIMIT_MSGQUEUE (EMFILE past it).
 * A leftover queue of the same name is removed first, so the open always creates one. */
static long mqueue(void) {
    struct mq_attr attr;
    memset(&attr, 0, sizeof attr);
    attr.mq_maxmsg = 1;
    attr.mq_msgsize = 1;
    syscall(SYS_mq_unlink, "sp-probe");
    long fd = syscall(SYS_mq_open, "sp-probe", O_CREAT | O_EXCL | O_RDWR, 0600, &attr);
    if (fd >= 0) {
        close((int)fd);
        syscall(SYS_mq_unlink, "sp-probe");
    }
    return fd;
}

int main(int argc, char **argv) {
    if (argc == 5 && strcmp(argv[1], "socket") == 0) {
        long fd = socket((int)num(argv[2]), (int)num(argv[3]), (int)num(argv[4]));
        return report(fd);
    }
    if (argc == 5 && strcmp(argv[1], "socketpair") == 0) {
        int sv[2];
        return report(socketpair((int)num(argv[2]), (int)num(argv[3]), (int)num(argv[4]), sv));
    }
    if (argc == 3 && strcmp(argv[1], "unshare") == 0) {
        return report(unshare((int)num(argv[2])));
    }
    if (argc == 3 && strcmp(argv[1], "clone") == 0) {
        unsigned long flags = (unsigned long)num(argv[2]) | SIGCHLD;
        return report(reap(syscall(SYS_clone, flags, 0, 0, 0, 0)));
    }
    if (argc == 3 && strcmp(argv[1], "clone3") == 0) {
        struct probe_clone_args args;
        memset(&args, 0, sizeof args);
        args.flags = (uint64_t)num(argv[2]);
        args.exit_signal = SIGCHLD;
        return report(reap(syscall(SYS_clone3, &args, sizeof args)));
    }
    if (argc == 7 && strcmp(argv[1], "connect") == 0) {
        return report(connect_to(argv + 2));
    }
    if (argc == 7 && strcmp(argv[1], "send") == 0) {
        return send_to(argv + 2);
    }
    if ((argc == 3 || argc == 4) && strcmp(argv[1], "syscall") == 0) {
        return report(by_name(argv[2], argc == 4 ? num(argv[3]) : 0));
    }
    if (argc == 2 && strcmp(argv[1], "mqueue") == 0) {
        return report(mqueue());
    }
    fprintf(stderr, "usage: probe socket|socketpair <family> <type> <protocol>"
                    " | unshare|clone|clone3 <flags> | syscall <name> [<first>] | mqueue"
                    " | connect|send <family> <type> <protocol> <address> <port>\n");
    return 2;
}
