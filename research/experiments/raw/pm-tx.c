/* pm-tx — destruction-transaction experiment driver (P0-B).
 *
 * EXPERIMENT TOOL. The prctl channel here is context TRANSPORT only —
 * NOT authorization. See docs/security-model.md.
 *
 * Usage:
 *   pm-tx run <root-path> -- CMD [args...]   bind TX(root) to this task,
 *                                            then exec CMD (exec preserves
 *                                            task ctx; exit auto-revokes)
 *   pm-tx mode <0|1|2>                       0=OBSERVE 1=ROOT_ONLY 2=TX_STRICT
 *   pm-tx clear                              drop tx binding from this task
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define PM_TX_BEGIN_MAGIC  0x54584247UL /* "TXBG" */
#define PM_TX_CLEAR_MAGIC  0x5458434CUL /* "TXCL" */
#define PM_MODE_SET_MAGIC  0x4D4F4445UL /* "MODE" */

static int bind_tx(const char *path, unsigned long *dev_out, unsigned long *ino_out) {
    struct stat st;
    if (stat(path, &st)) { perror("stat"); return -1; }
    unsigned long dev = (unsigned long)st.st_dev; /* NOTE: userspace st_dev
        encoding can differ from kernel s_dev on some filesystems; verified
        consistent on tmpfs/ext4 dev numbers used in experiments */
    unsigned long ino = (unsigned long)st.st_ino;
    long r = syscall(SYS_prctl, PM_TX_BEGIN_MAGIC, dev, ino, 0, 0);
    fprintf(stderr, "[pm-tx] bound TX root=%s dev=%lu ino=%lu (prctl saw args rc=%ld)\n",
            path, dev, ino, r);
    if (dev_out) *dev_out = dev;
    if (ino_out) *ino_out = ino;
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 3 && !strcmp(argv[1], "mode")) {
        unsigned long m = strtoul(argv[2], NULL, 0);
        syscall(SYS_prctl, PM_MODE_SET_MAGIC, m, 0, 0, 0);
        printf("[pm-tx] policy mode -> %lu (%s)\n", m,
               m == 0 ? "OBSERVE" : m == 1 ? "ROOT_ONLY" :
               m == 2 ? "TRANSACTION_STRICT" : "?");
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "clear")) {
        syscall(SYS_prctl, PM_TX_CLEAR_MAGIC, 0, 0, 0, 0);
        printf("[pm-tx] tx cleared\n");
        return 0;
    }
    if (argc >= 4 && !strcmp(argv[1], "run") && !strcmp(argv[3], "--")) {
        char **cmd = &argv[4];
        pid_t p = fork();
        if (p < 0) { perror("fork"); return 1; }
        if (p == 0) {
            if (bind_tx(argv[2], NULL, NULL)) _exit(126);
            execvp(cmd[0], cmd);          /* task ctx survives exec (CAP-01B) */
            perror("execvp");
            _exit(127);
        }
        int st = 0;
        waitpid(p, &st, 0);
        if (WIFEXITED(st))  printf("[pm-tx] child exited %d\n", WEXITSTATUS(st));
        else                printf("[pm-tx] child killed by %d\n", WTERMSIG(st));
        return 0;
    }
    fprintf(stderr,
        "usage: %s run <root-path> -- CMD [args...]\n"
        "       %s mode <0|1|2>\n"
        "       %s clear\n", argv[0], argv[0], argv[0]);
    return 1;
}
