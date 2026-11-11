/*
 * Red-team syscall probe (RT-NET-01, RT-NET-08, RT-NET-12, RT-FS-17). Test-only: built at test time with
 * `cc -static`, copied into the throwaway test image, never linked into or shipped with any
 * Sallyport binary or release image (CLAUDE.md, exception to the no-unsafe rule). Keep it one
 * small file.
 *
 *   probe socket <family> <type> <protocol>   socket(2)
 *   probe unshare <flags>                     unshare(2)
 *   probe clone <flags>                       clone(2), fork-like; the child exits at once
 *   probe clone3 <flags>                      clone3(2), fork-like; the child exits at once
 *   probe connect <family> <type> <protocol> <address> <port>
 *                                             socket(2), then connect(2) to an IPv4 (family 2)
 *                                             or IPv6 (family 10) literal; the first error wins
 *
 * Numbers are decimal or 0x-hex. Prints "ok" or "errno=<n>" and exits 0 or 1; usage errors exit 2.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
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

/* socket(family, type, protocol), then connect to `addr`:`port`. */
static long connect_to(char **a) {
    int family = (int)num(a[0]);
    struct sockaddr_in in4;
    struct sockaddr_in6 in6;
    memset(&in4, 0, sizeof in4);
    memset(&in6, 0, sizeof in6);
    in4.sin_family = AF_INET;
    in6.sin6_family = AF_INET6;
    in4.sin_port = in6.sin6_port = htons((uint16_t)num(a[4]));
    int parsed = family == AF_INET ? inet_pton(AF_INET, a[3], &in4.sin_addr)
                                   : inet_pton(AF_INET6, a[3], &in6.sin6_addr);
    if ((family != AF_INET && family != AF_INET6) || parsed != 1) {
        fprintf(stderr, "bad family or address: %s %s\n", a[0], a[3]);
        exit(2);
    }
    long fd = socket(family, (int)num(a[1]), (int)num(a[2]));
    if (fd < 0) {
        return fd;
    }
    return family == AF_INET ? connect((int)fd, (struct sockaddr *)&in4, sizeof in4)
                             : connect((int)fd, (struct sockaddr *)&in6, sizeof in6);
}

int main(int argc, char **argv) {
    if (argc == 5 && strcmp(argv[1], "socket") == 0) {
        long fd = socket((int)num(argv[2]), (int)num(argv[3]), (int)num(argv[4]));
        return report(fd);
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
    fprintf(stderr, "usage: probe socket <family> <type> <protocol> | unshare|clone|clone3 <flags>"
                    " | connect <family> <type> <protocol> <address> <port>\n");
    return 2;
}
