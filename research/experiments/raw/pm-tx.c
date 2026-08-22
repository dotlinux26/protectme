/* pm-tx.c — Protectme destruction-transaction driver, v2 (CAP-01E)
 *
 * Subcommands:
 *   run ROOT -- CMD        legacy prctl transport (run8; kept for A/B tests)
 *   run-auth ROOT -- CMD   CAP-01E: request kernel-issued nonce from the
 *                          loader's issuer socket, attach it (single-use,
 *                          tgid-bound), then exec CMD
 *   mode N                 set policy mode 0/1/2
 *   clear                  drop any bound TX on this task
 *
 * Research prototype — not a production tool.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

/* CONTROL-PLANE ABI (research quirk, unchanged since run8):
 * the opcode travels IN THE OPTION SLOT: syscall(SYS_prctl, PM_MAGIC, p1, p2).
 * The kernel-side hook is a sys_enter_prctl TRACEPOINT — side effects always
 * execute, but core prctl then rejects the unknown option with EINVAL.
 * Therefore return values are IGNORED by design; do not "fix" this by
 * switching to prctl(66, ...) without changing the BPF parser too. */
#define PM_CP(OP, A1, A2) syscall(SYS_prctl, (OP), (A1), (A2), 0, 0)

#ifndef PR_SET_PM_CTX
#define PR_SET_PM_CTX 66 /* unused; kept to document rejected alternative */
#endif

#define PM_TX_BEGIN_MAGIC  0x54584247u /* "TXBG" */
#define PM_TX_CLEAR_MAGIC  0x5458434Cu /* "TXCL" */
#define PM_MODE_SET_MAGIC  0x4D4F4445u /* "MODE" */
#define PM_TX_ATTACH_MAGIC 0x54584154u /* "TXAT" */

#define CAP_SOCK_PATH "/run/protectme/tx.sock"
struct cap_req  { uint32_t magic; uint32_t pid; uint32_t dev; uint32_t ino;
                  uint32_t ttl_ms; };
struct cap_resp { uint64_t nonce; }; /* nonce==1 => fd rides in cmsg */
#define CAP_REQ_MAGIC 0x34424D50u /* "PMB4" */
#define PM_TX_ATTFD_MAGIC 0x41544644u /* "ATFD" — must match obs.bpf.c */

static void usage(void) {
    fprintf(stderr,
        "usage: pm-tx run      ROOT -- CMD [args...]\n"
        "       pm-tx run-auth ROOT -- CMD [args...]   [ttl_ms]\n"
        "       pm-tx request ROOT [ttl_ms]   print nonce only (no attach)\n"
        "       pm-tx attach NONCE            present nonce from this task\n"
        "       pm-tx mode 0|1|2\n"
        "       pm-tx clear\n");
    exit(2);
}

static int stat_root(const char *path, uint32_t *dev, uint32_t *ino) {
    struct stat st;
    if (stat(path, &st)) { perror("stat"); exit(3); }
    *dev = (uint32_t)st.st_dev;
    *ino = (uint32_t)st.st_ino;
    return 0;
}

/* ask the privileged issuer for a capability. v4: authority is an FD
 * (memfd) received over SCM_RIGHTS — kernel-issued object, possession
 * = authority, close(fd)/exit revokes. */
static int request_cap_fd(const char *root_path, uint32_t ttl_ms,
                          uint64_t *nonce_out) {
    uint32_t dev, ino;
    stat_root(root_path, &dev, &ino);

    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) { perror("socket"); exit(3); }
    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_un srv = { .sun_family = AF_UNIX };
    strncpy(srv.sun_path, CAP_SOCK_PATH, sizeof(srv.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&srv, sizeof(srv))) {
        perror("connect(cap issuer)"); exit(3);
    }

    struct cap_req req = {
        .magic = CAP_REQ_MAGIC, .pid = (uint32_t)getpid(),
        .dev = dev, .ino = ino, .ttl_ms = ttl_ms,
    };
    if (send(fd, &req, sizeof(req), 0) != sizeof(req)) {
        perror("send"); exit(3);
    }

    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } u = { .align = {0} };
    struct cap_resp resp;
    struct iovec iov = { .iov_base = &resp, .iov_len = sizeof(resp) };
    struct msghdr mh = { .msg_iov = &iov, .msg_iovlen = 1 };
    mh.msg_control = u.buf;
    mh.msg_controllen = sizeof(u.buf);
    ssize_t n = recvmsg(fd, &mh, 0);
    if (n != (ssize_t)sizeof(resp)) {
        fprintf(stderr, "pm-tx: bad issuer reply (%zd): %s\n",
                n, strerror(errno));
        exit(3);
    }
    close(fd);
    int cfd = -1;
    for (struct cmsghdr *cm = CMSG_FIRSTHDR(&mh); cm;
         cm = CMSG_NXTHDR(&mh, cm)) {
        if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS)
            memcpy(&cfd, CMSG_DATA(cm), sizeof(int));
    }
    if (nonce_out) *nonce_out = resp.nonce;
    return cfd; /* -1 when issuer refused */
}

int main(int argc, char **argv) {
    if (argc < 2) usage();

    if (!strcmp(argv[1], "mode")) {
        if (argc != 3) usage();
        long m = strtol(argv[2], NULL, 10);
        if (m < 0 || m > 2) usage();
        PM_CP(PM_MODE_SET_MAGIC, m, 0);
        return 0;
    }
    if (!strcmp(argv[1], "clear")) {
        PM_CP(PM_TX_CLEAR_MAGIC, 0, 0);
        return 0;
    }
    if (!strcmp(argv[1], "attach")) {
        if (argc != 3) usage();
        uint64_t nonce = strtoull(argv[2], NULL, 16);
        if (!nonce) usage();
        PM_CP(PM_TX_ATTACH_MAGIC, nonce, 0); /* rc ignored — ABI note */
        fprintf(stderr, "pm-tx: attach presented nonce=0x%llx\n",
                (unsigned long long)nonce);
        return 0;
    }
    if (!strcmp(argv[1], "expiry-probe")) {
        /* ROOT TTL_MS DELAY_S — single process: request, wait, attach,
         * then unlink ROOT/probe.txt and report. Isolates expiry from
         * cross-task confounders. */
        if (argc != 5) usage();
        uint32_t ttl = (uint32_t)strtoul(argv[3], NULL, 10);
        int delay = atoi(argv[4]);
        uint64_t nr = 0;
        int cfd = request_cap_fd(argv[2], ttl, &nr);
        if (cfd < 0) { printf("RESULT=request-refused\n"); return 4; }
        fprintf(stderr, "probe: fd=%d ttl=%ums delay=%ds\n",
                cfd, ttl, delay);
        sleep(delay);
        PM_CP(PM_TX_ATTFD_MAGIC, cfd, 0);
        char pbuf[512];
        snprintf(pbuf, sizeof(pbuf), "%s/probe.txt", argv[2]);
        int r = unlink(pbuf);
        printf("RESULT=%s\n", r == 0 ? "BIND-OK" : "BIND-DENIED");
        return r == 0 ? 0 : 5;
    }
    if (!strcmp(argv[1], "attachfd")) {
        /* present fd NUMBER N of THIS process as capability */
        if (argc != 3) usage();
        long n = strtol(argv[2], NULL, 10);
        PM_CP(PM_TX_ATTFD_MAGIC, n, 0); /* rc ignored — ABI note */
        fprintf(stderr, "pm-tx: presented fd=%ld\n", n);
        return 0;
    }
    if (!strcmp(argv[1], "request")) {
        /* ROOT [ttl_ms] — obtain capability FD, print its number WITHOUT
         * attaching. Process exit closes it (= revoke). */
        if (argc < 3) usage();
        uint32_t ttl = argc > 3 ? (uint32_t)strtoul(argv[3], NULL, 10) : 0;
        uint64_t nr = 0;
        int cfd = request_cap_fd(argv[2], ttl, &nr);
        printf("fd=%d granted=%d\n", cfd, cfd >= 0);
        return cfd >= 0 ? 0 : 4;
    }

    int auth = !strcmp(argv[1], "run-auth");
    int legacy = !strcmp(argv[1], "run");
    if ((!auth && !legacy) || argc < 4 || strcmp(argv[3], "--")) usage();
    const char *root_path = argv[2];
    char **cmd = &argv[4];

    uint32_t dev, ino;
    stat_root(root_path, &dev, &ino);

    if (auth) {
        uint64_t nr = 0;
        int cfd = request_cap_fd(root_path, 0, &nr);
        if (cfd < 0) {
            fprintf(stderr, "pm-tx: issuer refused capability\n");
            exit(4);
        }
        fprintf(stderr,
            "pm-tx: capability fd=%d root=(%u,%u)\n", cfd, dev, ino);
        PM_CP(PM_TX_ATTFD_MAGIC, cfd, 0); /* rc ignored — ABI note */
        /* fd intentionally NOT CLOEXEC: exec preserves authority */
    } else {
        PM_CP(PM_TX_BEGIN_MAGIC, dev, ino); /* legacy transport, run8 A/B */
    }

    execvp(cmd[0], cmd);
    fprintf(stderr, "pm-tx: exec %s failed: %s\n", cmd[0], strerror(errno));
    return 5;
}
