/* pm-mark: set INODE_STATE on (dev, ino) via prctl magic channel.
 * Usage: pm-mark <dev> <ino> [payload]
 * This is the CAP-01D/01E primitive: bind state to an object identity.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#define PM_INODE_SET_MAGIC 0x494E4F44UL

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <dev> <ino> [payload]\n", argv[0]); return 1; }
    unsigned long dev = strtoul(argv[1], NULL, 0);
    unsigned long ino = strtoul(argv[2], NULL, 0);
    unsigned long payload = argc > 3 ? strtoul(argv[3], NULL, 0) : 0xFEEDFACEUL;
    long r = syscall(SYS_prctl, PM_INODE_SET_MAGIC, dev, ino, payload, 0);
    printf("pm-mark: prctl(0x%lx, dev=%lu, ino=%lu, payload=0x%lx) -> %ld (%s)\n",
           PM_INODE_SET_MAGIC, dev, ino, payload, r, r ? "EINVAL expected, BPF saw args" : "ok");
    return 0;
}
