#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

struct event {
    __u64 timestamp;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char comm[16];
    char op[16];
    unsigned long parent_ino;
    unsigned long target_ino;
    char target_name[64];
};

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog_unlink = NULL, *prog_rmdir = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    libbpf_set_print(libbpf_print_fn);

    // Bump RLIMIT_MEMLOCK
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    obj = bpf_object__open_file("obs.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    prog_unlink = bpf_object__find_program_by_name(obj, "observe_unlink");
    prog_rmdir = bpf_object__find_program_by_name(obj, "observe_rmdir");
    if (!prog_unlink || !prog_rmdir) {
        fprintf(stderr, "Failed to find programs\n");
        err = -1;
        goto cleanup;
    }

    // Attach
    err = bpf_program__attach(prog_unlink);
    if (err) {
        fprintf(stderr, "Failed to attach unlink: %d\n", err);
        goto cleanup;
    }
    err = bpf_program__attach(prog_rmdir);
    if (err) {
        fprintf(stderr, "Failed to attach rmdir: %d\n", err);
        goto cleanup;
    }

    // Ring buffer
    int map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find events map\n");
        err = -1;
        goto cleanup;
    }

    rb = ring_buffer__new(map_fd, NULL, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Listening for unlink/rmdir events... Ctrl+C to stop\n");
    printf("%-16s %-6s %-10s %-10s %s\n", "COMM", "PID", "OP", "PARENT_INO", "TARGET");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) break;
        if (err < 0) {
            fprintf(stderr, "Ring buffer poll error: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return err < 0 ? 1 : 0;
}