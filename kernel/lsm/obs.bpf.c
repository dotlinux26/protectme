#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

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
    __u32 p_sticky;     /* state of PARENT directory inode */

    /* P0-B: LSM decision fields (meaningful on lsm_* rows only) */
    __s32 verdict;      /* 0=ALLOW, -EPERM=DENY */
    __u32 class;        /* 0=OUTSIDE, 1=SUBTREE_OP, 2=ROOT_OP */
    __u32 near_root;    /* nearest protected-root ino found by ancestry walk */
    __u32 near_depth;   /* hops from victim to near_root (0 = victim itself) */
    __u32 tx_present;   /* task holds a transaction binding */
    __u64 walk_ns;      /* ancestry-walk cost measurement (EXPERIMENTAL D1) */

    char target_name[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

/* CAP-01A: syscall-context marker (ctx_source, NOT authorization).
 * Set at sys_enter_*, observed at VFS kprobes, cleared at sys_exit_*.
 * CAP-01B: sticky context settable from userspace via prctl magic channel.
 * P0-B: tx_dev/tx_ino bind a task to a destruction-transaction root.
 *
 * SECURITY MODEL (docs/security-model.md): the prctl channel is an
 * EXPERIMENT TRANSPORT ONLY. It is NOT authorization — any process could
 * issue it. Product authority will be policy-controlled (CAP-01F). */
struct task_ctx {
    __u32 active;
    __u32 sticky;
    __u32 tx_dev;
    __u32 tx_ino;
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

/* policy mode: 0=OBSERVE 1=ROOT_ONLY 2=TRANSACTION_STRICT.
 * Runtime enforcement state only — authoritative policy lives in userspace. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} pm_mode SEC(".maps");

#define PM_CTX_MAGIC       0xC0DEC0DE
#define PM_INODE_SET_MAGIC 0x494E4F44
#define PM_TX_BEGIN_MAGIC  0x54584247 /* "TXBG" — DEPRECATED transport, run8 */
#define PM_TX_CLEAR_MAGIC  0x5458434C /* "TXCL" */
#define PM_MODE_SET_MAGIC  0x4D4F4445 /* "MODE" */
#define PM_TX_ATTACH_MAGIC 0x54584154 /* "TXAT" — CAP-01E capability attach */

/* CAP-01E: kernel-issued capability store. Only the privileged issuer
 * (loader, root) writes entries; clients present a 64-bit nonce via
 * prctl(TXAT). Nonce is SINGLE-USE and TGID-BOUND, so knowing the channel
 * without a valid unguessable nonce grants nothing. This still is not full
 * production authority (issuer policy lives in userspace), but it removes
 * "know magic = authority". */
struct tx_cap {
    __u32 dev;
    __u32 ino;
    __u32 tgid;   /* intended holder — cross-task replay rejected */
    __u32 state;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);            /* nonce */
    __type(value, struct tx_cap);
} tx_caps SEC(".maps");

#ifndef EPERM
#define EPERM 1
#endif

static void marker_set(__u32 v) {
    struct task_struct *t = bpf_get_current_task_btf();
    struct task_ctx *tc = bpf_task_storage_get(&syscall_marker, t, 0,
        v ? BPF_LOCAL_STORAGE_GET_F_CREATE : 0);
    if (tc) tc->active = v;
}

static void marker_read(struct task_ctx *out) {
    __builtin_memset(out, 0, sizeof(*out));
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
            struct task_ctx new_ic = {0};
            new_ic.sticky = (__u32)payload;
            bpf_map_update_elem(&inode_state, &ik, &new_ic, BPF_ANY);
        } else {
            ic->sticky = (__u32)payload;
        }
        return 0;
    }
    if (op == PM_TX_BEGIN_MAGIC) {
        /* EXPERIMENT TRANSPORT ONLY — see docs/security-model.md */
        __u64 dev = BPF_CORE_READ(ctx, args[1]);
        __u64 ino = BPF_CORE_READ(ctx, args[2]);
        struct task_struct *t = bpf_get_current_task_btf();
        struct task_ctx *tc = bpf_task_storage_get(&syscall_marker, t, 0,
            BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (tc) { tc->tx_dev = (__u32)dev; tc->tx_ino = (__u32)ino; }
        return 0;
    }
    if (op == PM_TX_CLEAR_MAGIC) {
        struct task_struct *t = bpf_get_current_task_btf();
        struct task_ctx *tc = bpf_task_storage_get(&syscall_marker, t, 0, 0);
        if (tc) { tc->tx_dev = 0; tc->tx_ino = 0; }
        return 0;
    }
    if (op == PM_TX_ATTACH_MAGIC) {
        /* CAP-01E: present capability nonce → bind TX to CURRENT task.
         * Single-use (entry deleted) and tgid-bound (cross-task replay
         * rejected). No nonce match = no binding = no authority.
         * Unified control-plane ABI: args[0]=opcode, args[1]=payload. */
        __u64 nonce = BPF_CORE_READ(ctx, args[1]);
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        struct tx_cap *cap = bpf_map_lookup_elem(&tx_caps, &nonce);
        if (!cap || cap->tgid != (pid_tgid >> 32))
            return 0;
        struct task_struct *t = bpf_get_current_task_btf();
        struct task_ctx *tc = bpf_task_storage_get(&syscall_marker, t, 0,
            BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (!tc) return 0;
        tc->tx_dev = cap->dev;
        tc->tx_ino = cap->ino;
        bpf_map_delete_elem(&tx_caps, &nonce);
        return 0;
    }
    if (op == PM_MODE_SET_MAGIC) {
        __u32 key = 0;
        __u32 val = (__u32)BPF_CORE_READ(ctx, args[1]);
        bpf_map_update_elem(&pm_mode, &key, &val, BPF_ANY);
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

static inline void marker_read_from(struct task_ctx *out, struct task_struct *t) {
    __builtin_memset(out, 0, sizeof(*out));
    struct task_ctx *tc = bpf_task_storage_get(&syscall_marker, t, 0, 0);
    if (tc) *out = *tc;
}

static inline void maybe_propagate_delegation(struct task_struct *parent, struct task_struct *child) {
    struct task_ctx parent_tc = {0};
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
    struct task_ctx parent_tc = {0};
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
    /* read inode state from LRU hash: target + parent dir */
    {
        struct inode_key ik = { .dev = BPF_CORE_READ(target, i_sb, s_dev), .ino = BPF_CORE_READ(target, i_ino) };
        struct task_ctx *ic = bpf_map_lookup_elem(&inode_state, &ik);
        e->inode_sticky = ic ? ic->sticky : 0;
        struct inode_key pk = { .dev = e->parent_dev, .ino = (__u32)e->parent_ino };
        struct task_ctx *pc = bpf_map_lookup_elem(&inode_state, &pk);
        e->p_sticky = pc ? pc->sticky : 0;
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
    /* read inode state from LRU hash: target + parent dir */
    {
        struct inode_key ik = { .dev = BPF_CORE_READ(target, i_sb, s_dev), .ino = BPF_CORE_READ(target, i_ino) };
        struct task_ctx *ic = bpf_map_lookup_elem(&inode_state, &ik);
        e->inode_sticky = ic ? ic->sticky : 0;
        struct inode_key pk = { .dev = e->parent_dev, .ino = (__u32)e->parent_ino };
        struct task_ctx *pc = bpf_map_lookup_elem(&inode_state, &pk);
        e->p_sticky = pc ? pc->sticky : 0;
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
    struct dentry *old_parent = BPF_CORE_READ(rd, old_parent);
    struct inode *old_dir = BPF_CORE_READ(old_parent, d_inode);

    struct inode *target = BPF_CORE_READ(old_dentry, d_inode);
    e->parent_ino = BPF_CORE_READ(old_dir, i_ino);
    e->parent_dev = BPF_CORE_READ(old_dir, i_sb, s_dev);
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
    /* read inode state from LRU hash: target + parent dir */
    {
        struct inode_key ik = { .dev = BPF_CORE_READ(target, i_sb, s_dev), .ino = BPF_CORE_READ(target, i_ino) };
        struct task_ctx *ic = bpf_map_lookup_elem(&inode_state, &ik);
        e->inode_sticky = ic ? ic->sticky : 0;
        struct inode_key pk = { .dev = e->parent_dev, .ino = (__u32)e->parent_ino };
        struct task_ctx *pc = bpf_map_lookup_elem(&inode_state, &pk);
        e->p_sticky = pc ? pc->sticky : 0;
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ================= P0-B: destruction-transaction enforcement =================
 * kprobes above = OBSERVE ONLY. These lsm hooks are the DECISION point.
 * See docs/security-model.md: prctl channel is transport, not authority;
 * modes 0/1/2 are research modes, none claims MVP completeness. */

#define PM_WALK_MAX 16   /* EXPERIMENTAL D1 bound — production design will use
                          * propagated directory→root identity instead */

struct walk_result {
    __u32 found;
    __u32 ino;   /* nearest protected root ino */
    __u32 dev;
    __u32 depth; /* hops from victim (0 = victim itself marked) */
};

static __u32 mode_get(void) {
    __u32 key = 0;
    __u32 *v = bpf_map_lookup_elem(&pm_mode, &key);
    return v ? *v : 0;
}

/* Walk victim → ancestors via d_parent, checking inode_state each hop.
 * Victim checked at depth 0, so rmdir(R)/rename-source(R) classify as ROOT_OP. */
static __noinline void nearest_root(struct dentry *victim, struct walk_result *wr) {
    wr->found = 0; wr->ino = 0; wr->dev = 0; wr->depth = 0;
    struct dentry *cur = victim;

    for (int i = 0; i <= PM_WALK_MAX; i++) {
        struct inode *ip = BPF_CORE_READ(cur, d_inode);
        if (!ip) return;
        __u32 d = (__u32)BPF_CORE_READ(ip, i_sb, s_dev);
        __u32 n = (__u32)BPF_CORE_READ(ip, i_ino);
        struct inode_key ik = { .dev = d, .ino = n };
        if (bpf_map_lookup_elem(&inode_state, &ik)) {
            wr->found = 1; wr->ino = n; wr->dev = d; wr->depth = (__u32)i;
            return;
        }
        struct dentry *up = BPF_CORE_READ(cur, d_parent);
        if (!up || up == cur) return; /* filesystem root */
        cur = up;
    }
}

static int tx_match(struct task_ctx *tc, struct walk_result *wr) {
    return tc && wr->found && tc->tx_dev == wr->dev && tc->tx_ino == wr->ino;
}

/* mode 0 OBSERVE: allow always. mode 1 ROOT_ONLY: deny ROOT_OP without bound
 * TX. mode 2 TRANSACTION_STRICT: deny any in-boundary op without bound TX
 * (deliberately breaks R1 — that IS the experiment result, not a bug). */
static int compute_verdict(__u32 mode, __u32 cls, struct walk_result *wr,
                           struct task_ctx *tc) {
    if (!mode || cls == 0) return 0;
    if (tx_match(tc, wr)) return 0;
    if (mode == 1) return cls == 2 ? -EPERM : 0;
    return -EPERM; /* mode 2, cls 1 or 2, no matching tx */
}

/* Shared decision path for the three LSM hooks. Emits a full event row with
 * classification + verdict. Fail-open on ringbuf pressure (documented). */
__always_inline int pm_decide(const char *opname, __u32 oplen,
                              struct inode *dir, struct dentry *victim) {
    struct protectme_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid & 0xFFFFFFFF;
    e->tgid = pid_tgid >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->euid = (bpf_get_current_uid_gid() >> 32) & 0xFFFFFFFF;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memcpy(e->op, opname, oplen);

    struct inode *target = BPF_CORE_READ(victim, d_inode);
    e->parent_ino = dir ? (__u64)BPF_CORE_READ(dir, i_ino) : 0;
    e->parent_dev = dir ? (__u32)BPF_CORE_READ(dir, i_sb, s_dev) : 0;
    e->target_ino = BPF_CORE_READ(target, i_ino);
    e->target_dev = BPF_CORE_READ(target, i_sb, s_dev);
    e->target_mode = BPF_CORE_READ(target, i_mode) & 0xFFFF;
    e->target_type = (BPF_CORE_READ(target, i_mode) & 0xF000) >> 12;
    BPF_CORE_READ_STR_INTO(e->target_name, victim, d_name.name);

    struct task_ctx tc;
    marker_read(&tc);
    e->marker = tc.active ? tc.active : 0xFFFFFFFF;
    e->ctx_sticky = tc.sticky;

    struct inode_key ik = { .dev = e->target_dev, .ino = (__u32)e->target_ino };
    struct task_ctx *ic = bpf_map_lookup_elem(&inode_state, &ik);
    e->inode_sticky = ic ? ic->sticky : 0;
    struct inode_key pk = { .dev = e->parent_dev, .ino = (__u32)e->parent_ino };
    struct task_ctx *pc = bpf_map_lookup_elem(&inode_state, &pk);
    e->p_sticky = pc ? pc->sticky : 0;

    __u64 t0 = bpf_ktime_get_ns();
    struct walk_result wr;
    nearest_root(victim, &wr);
    e->walk_ns = bpf_ktime_get_ns() - t0;

    __u32 cls = !wr.found ? 0 : (wr.depth == 0 ? 2 : 1);
    __u32 mode = mode_get();
    e->class = cls;
    e->near_root = wr.ino;
    e->near_depth = wr.depth;
    e->tx_present = (tc.tx_dev | tc.tx_ino) ? 1 : 0;
    int v = compute_verdict(mode, cls, &wr, &tc);
    e->verdict = v;
    bpf_ringbuf_submit(e, 0);
    return v;
}

SEC("lsm/inode_unlink")
int BPF_PROG(lsm_inode_unlink, struct inode *dir, struct dentry *victim)
{
    return pm_decide("lsm_unlink", 11, dir, victim);
}

SEC("lsm/inode_rmdir")
int BPF_PROG(lsm_inode_rmdir, struct inode *dir, struct dentry *dentry)
{
    return pm_decide("lsm_rmdir", 10, dir, dentry);
}

SEC("lsm/inode_rename")
int BPF_PROG(lsm_inode_rename, struct renamedata *rd)
{
    struct inode *dir = BPF_CORE_READ(rd, old_parent, d_inode);
    struct dentry *victim = BPF_CORE_READ(rd, old_dentry);
    return pm_decide("lsm_rename", 11, dir, victim);
}
char LICENSE[] SEC("license") = "GPL";
