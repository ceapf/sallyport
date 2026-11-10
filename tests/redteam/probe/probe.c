/*
 * Red-team syscall probe (RT-NET-12, RT-FS-17). Test-only: built at test time with
 * `cc -static`, copied into the throwaway test image, never linked into or shipped with any
 * Sallyport binary or release image (CLAUDE.md, exception to the no-unsafe rule). Keep it one
 * small file.
 *
 *   probe socket <family> <type> <protocol>   socket(2)
 *   probe unshare <flags>                     unshare(2)
 *   probe clone <flags>                       clone(2), fork-like; the child exits at once
 *   probe clone3 <flags>                      clone3(2), fork-like; the child exits at once
 *
 * Numbers are decimal or 0x-hex. Prints "ok" or "errno=<n>" and exits 0 or 1; usage errors exit 2.
 */
#define _GNU_SOURCE
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
    fprintf(stderr, "usage: probe socket <family> <type> <protocol> | unshare|clone|clone3 <flags>\n");
    return 2;
}
