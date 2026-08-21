#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct event {
    __u64 timestamp;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char comm[16];
    char op[8];
    unsigned long parent_ino;
    unsigned long target_ino;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

SEC("lsm/inode_unlink")
int observe_unlink(void *ctx, struct inode *dir, struct dentry *dentry) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = 0;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->op, "unlink", 7);

    e->parent_ino = dir ? dir->i_ino : 0;
    e->target_ino = dentry && dentry->d_inode ? dentry->d_inode->i_ino : 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/inode_rmdir")
int observe_rmdir(void *ctx, struct inode *dir, struct dentry *dentry) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = 0;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->op, "rmdir", 6);

    e->parent_ino = dir ? dir->i_ino : 0;
    e->target_ino = dentry && dentry->d_inode ? dentry->d_inode->i_ino : 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";