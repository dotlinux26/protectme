#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>

struct event {
    __u64 timestamp;
    __u64 seq;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u32 euid;
    char comm[16];
    char pcomm[16];
    char op[8];
    unsigned long parent_ino;
    unsigned long target_ino;
    unsigned short target_mode;
    unsigned int target_type;
    unsigned int parent_fsid;
    unsigned int target_fsid;
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

static void print_event(void *ctx, void *data, size_t size) {
    struct event *e = data;
    char type_char = '?';
    switch (e->target_type) {
        case 1: type_char = 'R'; break; // DT_REG
        case 2: type_char = 'D'; break; // DT_DIR
        case 4: type_char = 'L'; break; // DT_LNK
        case 6: type_char = 'B'; break; // DT_BLK
        case 10: type_char = 'S'; break; // DT_SOCK
    }
    printf("%-4llu %-6u %-6u %-6u %-6s %-4s 0x%lx 0x%lx %c %o %u %u\n",
           e->seq, e->pid, e->tgid, e->uid, e->comm, e->op,
           e->parent_ino, e->target_ino, type_char,
           e->target_mode, e->parent_fsid, e->target_fsid);
}

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog_unlink = NULL, *prog_rmdir = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    libbpf_set_print(libbpf_print_fn);

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

    int map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find events map\n");
        err = -1;
        goto cleanup;
    }

    rb = ring_buffer__new(map_fd, print_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("SEQ  PID     TGID    UID    COMM   OP     PARENT_INO  TARGET_INO  T TYPE MODE  PFSID TFSID\n");
    printf("---------------------------------------------------------------------------------------------\n");

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