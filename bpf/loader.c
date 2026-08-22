#include <linux/types.h>
#include "event.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/resource.h>
#include <errno.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig) {
    exiting = 1;
}

static void print_layout(void) {
    fprintf(stderr,
        "layout: sizeof=%zu seq=%zu pid=%zu comm=%zu op=%zu "
        "parent_ino=%zu target_ino=%zu mode=%zu type=%zu "
        "pdev=%zu tdev=%zu marker=%zu sticky=%zu inode=%zu name=%zu (expect 196/8/16/36/68/88/96/104/108/112/116/120/124/128/132)\n",
        sizeof(struct protectme_event),
        offsetof(struct protectme_event, seq),
        offsetof(struct protectme_event, pid),
        offsetof(struct protectme_event, comm),
        offsetof(struct protectme_event, op),
        offsetof(struct protectme_event, parent_ino),
        offsetof(struct protectme_event, target_ino),
        offsetof(struct protectme_event, target_mode),
        offsetof(struct protectme_event, target_type),
        offsetof(struct protectme_event, parent_dev),
        offsetof(struct protectme_event, target_dev),
        offsetof(struct protectme_event, marker),
        offsetof(struct protectme_event, ctx_sticky),
        offsetof(struct protectme_event, inode_sticky),
        offsetof(struct protectme_event, target_name));
}

static char type_char_of(unsigned int stype) {
    /* value = (st_mode & S_IFMT) >> 12 */
    switch (stype) {
        case 1:  return 'P'; /* FIFO   */
        case 2:  return 'C'; /* CHR    */
        case 4:  return 'D'; /* DIR    */
        case 6:  return 'B'; /* BLK    */
        case 8:  return 'R'; /* REG    */
        case 10: return 'L'; /* LNK    */
        case 12: return 'S'; /* SOCK   */
        default: return '?';
    }
}

static unsigned long long observed_seq = 0;

static int print_event(void *ctx, void *data, size_t size) {
    struct protectme_event *e = data;
    char type_char = type_char_of(e->target_type);
    printf("%-4llu %-6u %-6u %-6u %-15s %-11s 0x%-6llx 0x%-8llx %c %04o %u %u 0x%08x 0x%08x 0x%08x %s\n",
           ++observed_seq, e->pid, e->tgid, e->uid, e->comm, e->op,
           (unsigned long long)e->parent_ino, (unsigned long long)e->target_ino,
           type_char, e->target_mode, e->parent_dev, e->target_dev,
           e->marker, e->ctx_sticky, e->inode_sticky, e->target_name);
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_link *link;
    struct ring_buffer *rb = NULL;
    int err = 0;

    libbpf_set_print(libbpf_print_fn);

    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    print_layout();

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

    /* attach EVERY program in the object: kprobes + syscall tracepoints */
    bpf_object__for_each_program(prog, obj) {
        link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
            fprintf(stderr, "Failed to attach program %s\n",
                    bpf_program__name(prog));
            err = -1;
            goto cleanup;
        }
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

    printf("SEQ  PID     TGID    UID    COMM            OP           PARENT     TARGET     T MODE  PDEV  TDEV  MARKER     CTX        INODE      NAME\n");
    fflush(stdout);

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) break;
        if (err < 0 && err != -EAGAIN) {
            fprintf(stderr, "Ring buffer poll error: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return err < 0 ? 1 : 0;
}
