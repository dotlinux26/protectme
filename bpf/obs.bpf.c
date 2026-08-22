#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#ifndef PT_REGS_PARM1
#define PT_REGS_PARM1(ctx) ((unsigned long)(ctx)->di)
#endif
#ifndef PT_REGS_PARM2
#define PT_REGS_PARM2(ctx) ((unsigned long)(ctx)->si)
#endif
#ifndef PT_REGS_PARM3
#define PT_REGS_PARM3(ctx) ((unsigned long)(ctx)->dx)
#endif
#ifndef PT_REGS_PARM4
#define PT_REGS_PARM4(ctx) ((unsigned long)(ctx)->cx)
#endif
#ifndef PT_REGS_PARM5
#define PT_REGS_PARM5(ctx) ((unsigned long)(ctx)->r8)
#endif
#ifndef PT_REGS_PARM6
#define PT_REGS_PARM6(ctx) ((unsigned long)(ctx)->r9)
#endif

struct protectme_event {
    __u64 timestamp;
    __u64 seq;

    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u32 euid;

    char comm[16];
    char pcomm[16];
    char op[16];

    __u64 parent_ino;
    __u64 target_ino;

    __u16 target_mode;
    __u16 _pad0;

    __u32 target_type;
    __u32 parent_dev;
    __u32 target_dev;
    __u32 marker;       /* transient ctx_source: set by sys_enter_*, cleared at exit */
    __u32 ctx_sticky;   /* userspace-set persistent context (prctl magic channel) */
    __u32 inode_sticky; /* protected inode state (LRU hash) */

    char target_name[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

/* CAP-01A: syscall-context marker (ctx_source, NOT authorization).
 * Set at sys_enter_*, observed at VFS kprobes, cleared at sys_exit_*.
 * CAP-01B: sticky context settable from userspace via prctl magic channel. */
struct task_ctx {
    __u32 active;
    __u32 sticky;
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u32);
    __type(value, struct task_ctx);
} syscall_marker SEC(".maps");

struct inode_key {
    __u32 dev;
    __u32 ino;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct inode_key);
    __type(value, struct task_ctx);
} inode_state SEC(".maps");

#define PM_CTX_MAGIC 0xC0DEC0DE
#define PM_INODE_SET_MAGIC 0x494E4F44

static void marker_set(__u32 v) {
    struct task_struct *t = bpf_get_current_task_btf();
    struct task_ctx *tc = bpf_task_storage_get(&syscall_marker, t, 0,
        v ? BPF_LOCAL_STORAGE_GET_F_CREATE : 0);
    if (tc) tc->active = v;
}

static void marker_read(struct task_ctx *out) {
    out->active = 0;
    out->sticky = 0;
    struct task_struct *t = bpf_get_current_task_btf();
    struct task_ctx *tc = bpf_task_storage_get(&syscall_marker, t, 0, 0);
    if (tc) *out = *tc;
}

SEC("tp/syscalls/sys_enter_prctl")
int tp_enter_prctl(struct trace_event_raw_sys_enter *ctx) {
    __u64 op = BPF_CORE_READ(ctx, args[0]);
    if (op == PM_CTX_MAGIC) {
        __u64 payload = BPF_CORE_READ(ctx, args[1]);
        struct task_struct *t = bpf_get_current_task_btf();
        struct task_ctx *tc = bpf_task_storage_get(&syscall_marker, t, 0,
            BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (tc) tc->sticky = (__u32)payload;
        return 0;
    }
    if (op == PM_INODE_SET_MAGIC) {
        __u64 dev = BPF_CORE_READ(ctx, args[1]);
        __u64 ino = BPF_CORE_READ(ctx, args[2]);
        __u64 payload = BPF_CORE_READ(ctx, args[3]);
        struct inode_key ik = { .dev = (__u32)dev, .ino = (__u32)ino };
        struct task_ctx *ic = bpf_map_lookup_elem(&inode_state, &ik);
        if (!ic) {
            struct task_ctx new_ic = {0, (__u32)payload};
            bpf_map_update_elem(&inode_state, &ik, &new_ic, BPF_ANY);
        } else {
            ic->sticky = (__u32)payload;
        }
        return 0;
    }
    return 0;
}

SEC("tp/syscalls/sys_enter_unlink")
int tp_enter_unlink(void *ctx) { marker_set(0xC0DE0001); return 0; }
SEC("tp/syscalls/sys_exit_unlink")
int tp_exit_unlink(void *ctx)   { marker_set(0); return 0; }

SEC("tp/syscalls/sys_enter_unlinkat")
int tp_enter_unlinkat(void *ctx) { marker_set(0xC0DE0002); return 0; }
SEC("tp/syscalls/sys_exit_unlinkat")
int tp_exit_unlinkat(void *ctx)  { marker_set(0); return 0; }

SEC("tp/syscalls/sys_enter_rmdir")
int tp_enter_rmdir(void *ctx) { marker_set(0xC0DE0003); return 0; }
SEC("tp/syscalls/sys_exit_rmdir")
int tp_exit_rmdir(void *ctx)  { marker_set(0); return 0; }

#define PM_DELEGATE_MAGIC 0xDEADBEEF
#define PM_PROTECTED_MAGIC 0xFEEDFACE
#define PM_INODE_SET_MAGIC 0x494E4F44 /* "INOD" in hex */

static inline void marker_read_from(struct task_ctx *out, struct task_struct *t) {
    out->active = 0;
    out->sticky = 0;
    struct task_ctx *tc = bpf_task_storage_get(&syscall_marker, t, 0, 0);
    if (tc) *out = *tc;
}

static inline void maybe_propagate_delegation(struct task_struct *parent, struct task_struct *child) {
    struct task_ctx parent_tc = {0,0};
    marker_read_from(&parent_tc, parent);
    if (parent_tc.sticky == PM_DELEGATE_MAGIC) {
        struct task_ctx *child_tc = bpf_task_storage_get(&syscall_marker, child, 0,
            BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (child_tc) child_tc->sticky = PM_DELEGATE_MAGIC;
    }
}

SEC("tp/task/task_newtask")
int tp_task_newtask(struct trace_event_raw_task_newtask *ctx) {
    struct task_struct *parent = bpf_get_current_task_btf();
    struct task_struct *child = bpf_task_from_pid(ctx->pid);
    struct task_ctx parent_tc = {0,0};
    marker_read_from(&parent_tc, parent);

    if (parent_tc.sticky == PM_DELEGATE_MAGIC) {
        maybe_propagate_delegation(parent, child);
    }

    struct protectme_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        if (child) bpf_task_release(child);
        return 0;
    }
    e->timestamp = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid & 0xFFFFFFFF;
    e->tgid = pid_tgid >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->euid = (bpf_get_current_uid_gid() >> 32) & 0xFFFFFFFF;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memcpy(e->op, "newtask", 8);
    e->parent_ino = 0;
    e->target_ino = (__u64)ctx->pid;
    e->marker = parent_tc.active ? parent_tc.active : 0xFFFFFFFF;
    e->ctx_sticky = parent_tc.sticky;
    bpf_ringbuf_submit(e, 0);

    if (parent_tc.sticky == PM_DELEGATE_MAGIC) {
        struct protectme_event *pe = bpf_ringbuf_reserve(&events, sizeof(*pe), 0);
        if (pe) {
            pe->timestamp = bpf_ktime_get_ns();
            pe->pid = pid_tgid & 0xFFFFFFFF;
            pe->tgid = pid_tgid >> 32;
            pe->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
            pe->euid = (bpf_get_current_uid_gid() >> 32) & 0xFFFFFFFF;
            bpf_get_current_comm(pe->comm, sizeof(pe->comm));
            __builtin_memcpy(pe->op, "propagate", 10);
            pe->parent_ino = 0;
            pe->target_ino = (__u64)ctx->pid;
            pe->marker = 0xDE1E6A7E;
            pe->ctx_sticky = PM_DELEGATE_MAGIC;
            bpf_ringbuf_submit(pe, 0);
        }
    }
    if (child) bpf_task_release(child);
    return 0;
}

// kprobe/vfs_unlink
SEC("kprobe/vfs_unlink")
int trace_vfs_unlink(struct pt_regs *ctx) {
    struct protectme_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid & 0xFFFFFFFF;
    e->tgid = pid_tgid >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->euid = (bpf_get_current_uid_gid() >> 32) & 0xFFFFFFFF;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memcpy(e->op, "vfs_unlink", 11);

    // vfs_unlink(struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
    // PARM2 = dir, PARM3 = dentry
    struct inode *dir = (struct inode *)PT_REGS_PARM2(ctx);
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM3(ctx);
    struct inode *target = BPF_CORE_READ(dentry, d_inode);

    e->parent_ino = BPF_CORE_READ(dir, i_ino);
    e->parent_dev = BPF_CORE_READ(dir, i_sb, s_dev);
    e->target_ino = BPF_CORE_READ(target, i_ino);
    e->target_dev = BPF_CORE_READ(target, i_sb, s_dev);
    e->target_mode = BPF_CORE_READ(target, i_mode) & 0xFFFF;
    e->target_type = (BPF_CORE_READ(target, i_mode) & 0xF000) >> 12;

    BPF_CORE_READ_STR_INTO(e->target_name, dentry, d_name.name);

    {
        struct task_ctx tc;
        marker_read(&tc);
        e->marker = tc.active ? tc.active : 0xFFFFFFFF;
        e->ctx_sticky = tc.sticky;
    }
    /* read inode state from LRU hash */
    {
        struct inode_key ik = { .dev = BPF_CORE_READ(target, i_sb, s_dev), .ino = BPF_CORE_READ(target, i_ino) };
        struct task_ctx *ic = bpf_map_lookup_elem(&inode_state, &ik);
        e->inode_sticky = ic ? ic->sticky : 0;
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// kprobe/vfs_rmdir
SEC("kprobe/vfs_rmdir")
int trace_vfs_rmdir(struct pt_regs *ctx) {
    struct protectme_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid & 0xFFFFFFFF;
    e->tgid = pid_tgid >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->euid = (bpf_get_current_uid_gid() >> 32) & 0xFFFFFFFF;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memcpy(e->op, "vfs_rmdir", 10);

    // vfs_rmdir(struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, struct delegated_inode *delegated)
    // PARM2 = dir, PARM3 = dentry
    struct inode *dir = (struct inode *)PT_REGS_PARM2(ctx);
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM3(ctx);
    struct inode *target = BPF_CORE_READ(dentry, d_inode);

    e->parent_ino = BPF_CORE_READ(dir, i_ino);
    e->parent_dev = BPF_CORE_READ(dir, i_sb, s_dev);
    e->target_ino = BPF_CORE_READ(target, i_ino);
    e->target_dev = BPF_CORE_READ(target, i_sb, s_dev);
    e->target_mode = BPF_CORE_READ(target, i_mode) & 0xFFFF;
    e->target_type = (BPF_CORE_READ(target, i_mode) & 0xF000) >> 12;

    BPF_CORE_READ_STR_INTO(e->target_name, dentry, d_name.name);

    {
        struct task_ctx tc;
        marker_read(&tc);
        e->marker = tc.active ? tc.active : 0xFFFFFFFF;
        e->ctx_sticky = tc.sticky;
    }
    /* read inode state from LRU hash */
    {
        struct inode_key ik = { .dev = BPF_CORE_READ(target, i_sb, s_dev), .ino = BPF_CORE_READ(target, i_ino) };
        struct task_ctx *ic = bpf_map_lookup_elem(&inode_state, &ik);
        e->inode_sticky = ic ? ic->sticky : 0;
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// kprobe/vfs_rename
SEC("kprobe/vfs_rename")
int trace_vfs_rename(struct pt_regs *ctx) {
    struct protectme_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid & 0xFFFFFFFF;
    e->tgid = pid_tgid >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->euid = (bpf_get_current_uid_gid() >> 32) & 0xFFFFFFFF;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memcpy(e->op, "vfs_rename", 11);

    // vfs_rename(struct renamedata *rd)
    // PARM1 = renamedata*
    struct renamedata *rd = (struct renamedata *)PT_REGS_PARM1(ctx);
    struct dentry *old_dentry = BPF_CORE_READ(rd, old_dentry);

    struct inode *target = BPF_CORE_READ(old_dentry, d_inode);
    e->target_ino = BPF_CORE_READ(target, i_ino);
    e->target_dev = BPF_CORE_READ(target, i_sb, s_dev);
    e->target_mode = BPF_CORE_READ(target, i_mode) & 0xFFFF;
    e->target_type = (BPF_CORE_READ(target, i_mode) & 0xF000) >> 12;

    BPF_CORE_READ_STR_INTO(e->target_name, old_dentry, d_name.name);

    {
        struct task_ctx tc;
        marker_read(&tc);
        e->marker = tc.active ? tc.active : 0xFFFFFFFF;
        e->ctx_sticky = tc.sticky;
    }
    /* read inode state from LRU hash */
    {
        struct inode_key ik = { .dev = BPF_CORE_READ(target, i_sb, s_dev), .ino = BPF_CORE_READ(target, i_ino) };
        struct task_ctx *ic = bpf_map_lookup_elem(&inode_state, &ik);
        e->inode_sticky = ic ? ic->sticky : 0;
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";