#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/namei.h>

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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

// Helper to get parent inode of dentry
static __always_inline unsigned long get_parent_ino(struct dentry *dentry) {
    struct inode *inode = BPF_CORE_READ(dentry, d_parent, d_inode);
    return inode ? BPF_CORE_READ(inode, i_ino) : 0;
}

static __always_inline unsigned long get_target_ino(struct dentry *dentry) {
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    return inode ? BPF_CORE_READ(inode, i_ino) : 0;
}

static __always_inline void get_target_name(struct dentry *dentry, char *buf, int sz) {
    const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
    bpf_probe_read_kernel_str(buf, sz, name);
}

SEC("lsm/inode_unlink")
int observe_unlink(struct inode *dir, struct dentry *dentry) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = 0; // would need task_struct walk for ppid
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->op, "unlink", 7);

    e->parent_ino = BPF_CORE_READ(dir, i_ino);
    e->target_ino = get_target_ino(dentry);
    get_target_name(dentry, e->target_name, sizeof(e->target_name));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/inode_rmdir")
int observe_rmdir(struct inode *dir, struct dentry *dentry) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = 0;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->op, "rmdir", 6);

    e->parent_ino = BPF_CORE_READ(dir, i_ino);
    e->target_ino = get_target_ino(dentry);
    get_target_name(dentry, e->target_name, sizeof(e->target_name));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";