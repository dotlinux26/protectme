#define _GNU_SOURCE
#include <linux/types.h>
#include "event.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/random.h>

#include <sys/syscall.h>
#include <time.h>
#include <errno.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig) {
    exiting = 1;
}

/* ---- CAP-01E capability issuer -------------------------------------- */
#define CAP_SOCK_DIR  "/run/protectme"
#define CAP_SOCK_PATH "/run/protectme/tx.sock"
#define CAP_MAX_TTL_MS 60000u
struct cap_req  { uint32_t magic; uint32_t pid; uint32_t dev; uint32_t ino;
                  uint32_t ttl_ms; };
struct cap_resp { uint64_t nonce; }; /* nonce=0 in FD mode; fd rides cmsg */
#define CAP_REQ_MAGIC 0x34424D50u /* "PMB4" — v4: FD capability protocol */
#define PM_TX_REGFD_MAGIC 0x52454746u /* "REGF" — must match obs.bpf.c */

static int caps_fd_root(struct bpf_object *obj) {
    static int fd = -2;
    if (fd == -2) {
        struct bpf_map *m = bpf_object__find_map_by_name(obj, "root_owner");
        fd = m ? bpf_map__fd(m) : -1;
    }
    return fd;
}

static int cap_issuer_start(void) {
    mkdir(CAP_SOCK_DIR, 0755);
    unlink(CAP_SOCK_PATH); /* stale socket from a previous run */
    /* SEQPACKET: message boundaries + connected reply path (no abstract
     * peer addressing, which broke across the dgram autobind path) */
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un sa = { .sun_family = AF_UNIX };
    strncpy(sa.sun_path, CAP_SOCK_PATH, sizeof(sa.sun_path) - 1);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 ||
        listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }
    /* research build: OPEN issuer — capability is single-use + tgid-bound so
     * cross-user theft gains nothing beyond issuing your own; per-user policy
     * store arrives with the daemon phase */
    chmod(CAP_SOCK_PATH, 0666);
    fprintf(stderr, "cap issuer listening at %s\n", CAP_SOCK_PATH);
    return fd;
}

static void cap_issuer_pump(int fd, struct bpf_object *obj) {
    static int caps_fd = -2;
    if (caps_fd == -2) {
        struct bpf_map *m = bpf_object__find_map_by_name(obj, "tx_caps");
        caps_fd = m ? bpf_map__fd(m) : -1;
        fprintf(stderr, "[capiss] pump init caps_fd=%d\n", caps_fd);
    }
    if (caps_fd < 0) return;
    for (;;) {
        int c = accept4(fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (c < 0) {
            if (errno == EAGAIN || errno == EINTR) return;
            fprintf(stderr, "[capiss] accept: %s\n", strerror(errno));
            return;
        }
        struct ucred cr; socklen_t cl = sizeof(cr);
        if (!getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cr, &cl))
            fprintf(stderr, "[capiss] peer pid=%u uid=%u\n", cr.pid, cr.uid);
        struct cap_req req;
        ssize_t n = recv(c, &req, sizeof(req), 0);
        struct cap_resp resp = { .nonce = 0 };
        int fd_mode_done = 0;
        if (n == (ssize_t)sizeof(req) &&
            req.magic == CAP_REQ_MAGIC && req.pid && req.dev && req.ino &&
            getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cr, &cl) == 0 &&
            cr.pid == req.pid) {   /* anti-spoof: binder must own the claim */
            /* CAP-01E-v2 policy: requester uid must match the uid that
             * registered (owns) the protected root. Root lookup via the
             * root_owner map maintained by PM_INODE_SET. */
            __u64 rid = ((__u64)req.dev << 32) | req.ino;
            __u32 owner = 0;
            int have_owner = bpf_map_lookup_elem(caps_fd_root(obj), &rid,
                                                 &owner) == 0;
            if (have_owner && owner != cr.uid) {
                fprintf(stderr,
                    "[capiss] DENIED cross-uid: root owned by %u, peer %u\n",
                    owner, cr.uid);
                resp.nonce = 0;
            } else {
                /* CAP-02 FD path: create the capability object as a memfd,
                 * register it kernel-side from THIS root process (REGF),
                 * then hand the fd to the peer over SCM_RIGHTS.
                 * Possession of the fd becomes the authority. */
                int m = (int)syscall(SYS_memfd_create, "protectme-tx", 0ul);
                if (m >= 0) {
                    unsigned char secret[32];
                    if (getrandom(secret, sizeof(secret), 0)
                            != sizeof(secret)) {
                        close(m);
                    } else {
                        if (write(m, secret, sizeof(secret))
                                != sizeof(secret)) {
                            /* keep going: content is decorative */
                        }
                        uint32_t ttl = req.ttl_ms ? req.ttl_ms : 30000;
                        if (ttl > CAP_MAX_TTL_MS) ttl = CAP_MAX_TTL_MS;
                        syscall(SYS_prctl, PM_TX_REGFD_MAGIC,
                                (unsigned long)m,
                                (unsigned long)((__u64)cr.uid << 32 | req.dev),
                                (unsigned long)req.ino,
                                (unsigned long)ttl);
                        struct cap_resp ok = { .nonce = 0x1 };
                        union {
                            char buf[CMSG_SPACE(sizeof(int))];
                            struct cmsghdr align;
                        } u = { .align = {0} };
                        struct iovec iov = {
                            .iov_base = &ok, .iov_len = sizeof(ok) };
                        struct msghdr mh = { .msg_iov = &iov,
                                             .msg_iovlen = 1 };
                        mh.msg_control = u.buf;
                        mh.msg_controllen = sizeof(u.buf);
                        struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
                        cm->cmsg_level = SOL_SOCKET;
                        cm->cmsg_type = SCM_RIGHTS;
                        cm->cmsg_len = CMSG_LEN(sizeof(int));
                        memcpy(CMSG_DATA(cm), &m, sizeof(int));
                        ssize_t sr = sendmsg(c, &mh, 0);
                        fprintf(stderr,
                            "[capiss] FD issued dev=%u ino=%u ttl=%us "
                            "sent=%zd errno=%s\n",
                            req.dev, req.ino, ttl / 1000, sr,
                            sr < 0 ? strerror(errno) : "-");
                        close(m);
                        fd_mode_done = 1;
                    }
                }
            }
        }
        ssize_t sr = -1;
        /* nonce-mode fallback reply; FD mode already answered via SCM_RIGHTS */
        if (!fd_mode_done)
            sr = send(c, &resp, sizeof(resp), 0);
        fprintf(stderr, "[capiss] reply sent=%zd errno=%s\n",
                sr, sr < 0 ? strerror(errno) : "-");
        close(c);
    }
}

static void print_layout(void) {
    fprintf(stderr,
        "layout: sizeof=%zu seq=%zu pid=%zu comm=%zu op=%zu "
        "parent_ino=%zu target_ino=%zu mode=%zu type=%zu "
        "pdev=%zu tdev=%zu marker=%zu sticky=%zu inode=%zu psticky=%zu "
        "verdict=%zu class=%zu nearroot=%zu depth=%zu tx=%zu walkns=%zu name=%zu\n",
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
        offsetof(struct protectme_event, p_sticky),
        offsetof(struct protectme_event, verdict),
        offsetof(struct protectme_event, class),
        offsetof(struct protectme_event, near_root),
        offsetof(struct protectme_event, near_depth),
        offsetof(struct protectme_event, tx_present),
        offsetof(struct protectme_event, walk_ns),
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
    printf("%-4llu %-6u %-6u %-6u %-15s %-11s 0x%-6llx 0x%-8llx %c %04o %u %u "
           "0x%08x 0x%08x 0x%08x 0x%08x %d %u 0x%-6x %2u %u %llu %s\n",
           ++observed_seq, e->pid, e->tgid, e->uid, e->comm, e->op,
           (unsigned long long)e->parent_ino, (unsigned long long)e->target_ino,
           type_char, e->target_mode, e->parent_dev, e->target_dev,
           e->marker, e->ctx_sticky, e->inode_sticky, e->p_sticky,
           e->verdict, e->class, e->near_root, e->near_depth,
           e->tx_present, (unsigned long long)e->walk_ns, e->target_name);
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

    /* attach EVERY program: kprobes + syscall tracepoints + LSM hooks */
    bpf_object__for_each_program(prog, obj) {
        if (bpf_program__type(prog) == BPF_PROG_TYPE_LSM)
            link = bpf_program__attach_lsm(prog);
        else
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

    /* CAP-01E: capability issuer socket (root-only by fs perms).
     * Protocol: client sends {u32 'PMB1', u32 pid, u32 dev, u32 ino};
     * loader replies {u64 nonce} (0 = rejected). Nonce is single-use,
     * tgid-bound; client presents it via prctl(TXAT). */
    int cap_fd = cap_issuer_start();
    if (cap_fd < 0)
        fprintf(stderr, "cap issuer unavailable: %s\n", strerror(errno));

    printf("SEQ  PID     TGID    UID    COMM            OP           PARENT     TARGET     T MODE  PDEV  TDEV  MARKER     CTX        INODE      PSTICKY   V CLS ROOT   D TX WALK_NS   NAME\n");
    fflush(stdout);

    while (!exiting) {
        struct pollfd pfd[2] = {
            { .fd = map_fd, .events = POLLIN },
            { .fd = cap_fd, .events = POLLIN },
        };
        int pr = poll(pfd, 2, 100);
        if (pr < 0 && errno != EINTR) break;
        if (pfd[1].revents & POLLIN) cap_issuer_pump(cap_fd, obj);
        err = ring_buffer__poll(rb, 0);
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
