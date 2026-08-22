#define _XOPEN_SOURCE 500
#include <unistd.h>
#include <ftw.h>
#include <stdio.h>

static int remove_cb(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb;
    int rc = (typeflag == FTW_D || typeflag == FTW_DP) ? rmdir(path) : unlink(path);
    if (rc != 0) perror(path);
    return rc;
}

/* post-order traversal: children first, root last — same semantics as rm -rf */
int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s <path>\n", argv[0]); return 2; }
    return nftw(argv[1], remove_cb, 64, FTW_DEPTH | FTW_PHYS);
}
