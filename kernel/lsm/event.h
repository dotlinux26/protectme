#ifndef PROTECTME_EVENT_H
#define PROTECTME_EVENT_H

/* This header defines the event structure shared between BPF and userspace.
 * Use exact types matching BPF side (__u64, __u32, etc.) on both sides. */

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
    __u32 marker;
    __u32 ctx_sticky;
    __u32 inode_sticky;
    __u32 p_sticky;

    /* P0-B: LSM decision fields (lsm_* rows only) */
    __s32 verdict;
    __u32 class;      /* 0=OUTSIDE 1=SUBTREE_OP 2=ROOT_OP */
    __u32 near_root;
    __u32 near_depth;
    __u32 tx_present;
    __u64 walk_ns;

    char target_name[64];
};

#endif