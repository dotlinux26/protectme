#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

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
    unsigned int target_type;  // DT_REG=1, DT_DIR=2, etc.
    unsigned int parent_fsid;
    unsigned int target_fsid;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __u64 seq = 0;

SEC("lsm/inode_unlink")
int observe_unlink(void *ctx, struct inode *dir, struct dentry *dentry) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->seq = __atomic_add_fetch(&seq, 1, __ATOMIC_RELAXED);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid & 0xFFFFFFFF;
    e->tgid = pid_tgid >> 32;
    e->ppid = 0;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->euid = (bpf_get_current_uid_gid() >> 32) & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->op, "unlink", 7);
    e->pcomm[0] = 0;

    e->parent_ino = dir ? dir->i_ino : 0;
    e->target_ino = dentry && dentry->d_inode ? dentry->d_inode->i_ino : 0;
    e->target_mode = dentry && dentry->d_inode ? dentry->d_inode->i_mode & 0xFFFF : 0;
    e->target_type = dentry && dentry->d_inode ? (dentry->d_inode->i_mode & 0xF000) >> 12 : 0;
    e->parent_fsid = dir && dir->i_sb ? dir->i_sb->s_id : 0;
    e->target_fsid = dentry && dentry->d_inode && dentry->d_inode->i_sb ? dentry->d_inode->i_sb->s_id : 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/inode_rmdir")
int observe_rmdir(void *ctx, struct inode *dir, struct dentry *dentry) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->seq = __atomic_add_fetch(&seq, 1, __ATOMIC_RELAXED);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid & 0xFFFFFFFF;
    e->tgid = pid_tgid >> 32;
    e->ppid = 0;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->euid = (bpf_get_current_uid_gid() >> 32) & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->op, "rmdir", 6);
    e->pcomm[0] = 0;

    e->parent_ino = dir ? dir->i_ino : 0;
    e->target_ino = dentry && dentry->d_inode ? dentry->d_inode->i_ino : 0;
    e->target_mode = dentry && dentry->d_inode ? dentry->d_inode->i_mode & 0xFFFF : 0;
    e->target_type = dentry && dentry->d_inode ? (dentry->d_inode->i_mode & 0xF000) >> 12 : 0;
    e->parent_fsid = dir && dir->i_sb ? dir->i_sb->s_id : 0;
    e->target_fsid = dentry && dentry->d_inode && dentry->d_inode->i_sb ? dentry->d_inode->i_sb->s_id : 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";