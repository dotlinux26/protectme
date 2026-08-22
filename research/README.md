# Protectme Research Evidence

Empirical evidence for the P0 problem statement. Collected on the host of
the project author; reproducible with the tooling in `../bpf/`.

## Environment

| Item | Value |
|---|---|
| Kernel | `6.18.12+kali-amd64` (x86_64) |
| BPF features | kprobes, CO-RE (runtime BTF `/sys/kernel/btf/vmlinux`), ringbuf, task-local storage |
| Instrumentation | `kprobe/vfs_unlink`, `kprobe/vfs_rmdir`, `kprobe/vfs_rename`; system-wide, no filtering |
| Event ABI | 184-byte `struct protectme_event`; layout verified via userspace `offsetof` printout at loader start |
| Ordering | userspace ringbuf-consumer sequence (`SEQ` column); BPF-side counter removed as unreliable |
| Test fs | tmpfs `/tmp` (dev 43). Note: `/tmp` root dir itself has ino `0x1` |

## Run 1 — rm single-file vs rm -rf (P0-OBS-01..03)

Raw: `raw/run1-rm-ab-full.log` · events only: `raw/run1-rm-ab-full-events.txt` · filtered: `raw/run1-rm-only.txt`

Recorded identities (via `stat` before destruction):

```text
ROOT_A: dev=43 ino=37443 hex=0x9243   # /tmp/pm-A/protected
ROOT_B: dev=43 ino=37446 hex=0x9246   # /tmp/pm-B/protected
```

Relevant events:

```text
SEQ  TGID     COMM OP          PARENT   TARGET   T MODE   DEV
358  1174736  rm   vfs_unlink  0x9243   0x9244   R 100664 43    ← Test A: rm protected/a
359  1174741  rm   vfs_unlink  0x9246   0x9248   R 100664 43    ← Test B first op
360  1174741  rm   vfs_unlink  0x9246   0x9247   R 100664 43    ← Test B
361  1174741  rm   vfs_rmdir   0x9245   0x9246   D 40775  43    ← Test B root LAST
```

Findings:

- **P0-OBS-01**: first descendant unlink of `rm -rf` is structurally
  equivalent to ordinary descendant mutation at this boundary
  (op / parent / target / type / mode / dev identical in kind).
- **P0-OBS-02**: root `rmdir` fires AFTER all descendants are gone →
  a root-only veto cannot preserve tree content.
- **P0-OBS-03**: both processes were `UID=1000 COMM=rm` → process identity
  is attribution, not authorization.

## Run 2 — traversal matrix (P0-OBS-04..05)

Raw: `raw/run2-traversal-full.log` · filtered: `raw/run2-traversal-tools-only.txt`
Tool source: `raw/pm-nftw.c`.

Identities:

```text
TRV-02 ROOT=0x936a  TRV-02b ROOT=0x9370  TRV-03 ROOT=0x9375  TRV-04 ROOT=0x937b
```

```text
TRV-02  find <root> -delete            TGID 1187282
9397 unlink(ROOT→child) R  9398 unlink(ROOT→child) R  9399 unlink(sub→c) R
9400 rmdir(ROOT→sub) D      9401 rmdir(/tmp/pm-T2→ROOT) D     root LAST

TRV-02b find <root> -type f -delete    TGID 1187286
9402 unlink(ROOT→file) R    9403 unlink(sub→file) R
                            *** NO ROOT EVENT AT ALL ***

TRV-03  python3 shutil.rmtree          TGID 1187292
9404..06 unlink(children) R             9407 rmdir(ROOT→sub)
9408 rmdir(/tmp/pm-T3→ROOT) D           root LAST

TRV-04  custom C nftw()+unlink/rmdir   TGID 1187296
9409..11 unlink(children) R             9412 rmdir(ROOT→sub)
9413 rmdir(/tmp/pm-T4→ROOT) D           root LAST
```

Findings:

- **P0-OBS-04 (coverage)**: four independent implementations converge on the
  same VFS mutation sequence. Hand-written C eliminates any "rm is special"
  argument — recursive destructive traversal is a **VFS semantic class**.
- **P0-OBS-05**: bulk file deletion destroys all content while emitting ZERO
  root-boundary events. Root-only enforcement is structurally insufficient,
  not merely too late. `protected root survives` ≠ `protected tree survives`.

## Status

| Obligation | Status |
|---|---|
| Coverage (TRV-01..04) | demonstrated (this evidence) |
| Coverage (git clean, rsync --delete) | planned |
| Enforcement (distinguish & veto before first child) | OPEN → CAP-01A..E roadmap |

Full analysis: `../../P0-RESEARCH-DEEP.md` (project workspace, Parts I–V).
