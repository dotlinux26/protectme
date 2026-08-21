<p align="center">
  <img src="docs/logo.svg" alt="protectme Logo" width="180" height="180">
</p>

<h1 align="center">protectme</h1>

<p align="center"><strong>A kernel-level safety interlock for Linux</strong></p>

<p align="center">
  <em>protectme doesn't protect your files. It protects you from accidentally destroying them.</em>
</p>

<p align="center">
  <a href="https://github.com/dotlinux26/protectme/actions"><img src="https://img.shields.io/github/actions/workflow/status/dotlinux26/protectme/ci.yml?branch=master&label=build&logo=github" alt="Build"></a>
  <a href="https://github.com/dotlinux26/protectme/blob/master/LICENSE"><img src="https://img.shields.io/github/license/dotlinux26/protectme?color=blue" alt="License"></a>
  <a href="https://github.com/dotlinux26/protectme/releases"><img src="https://img.shields.io/github/v/release/dotlinux26/protectme?include_prereleases" alt="Release"></a>
  <a href="https://kernel.org"><img src="https://img.shields.io/badge/kernel-5.15%2B-green?logo=linux&logoColor=white" alt="Kernel Support"></a>
  <a href="https://github.com/dotlinux26/protectme/issues"><img src="https://img.shields.io/github/issues/dotlinux26/protectme" alt="Issues"></a>
  <img src="https://img.shields.io/badge/status-prototype-orange" alt="Prototype">
</p>

---

## Philosophy

protectme is a **kernel-level safety interlock** for Linux. It doesn't manage, modify, recover, or monitor your data. It only vetoes destructive operations on explicitly protected filesystem roots.

> **"Mày có thể làm mọi thứ với hệ thống. Nhưng nếu operation này phá hủy thứ mày đã đánh dấu bảo vệ, tao sẽ veto nó."**

### Core Invariant

```
PROTECTED TREE
       │
       │ destructive operation targets root?
       ├── NO  → ALLOW (mutate descendants freely)
       │
       └── YES → DENY (before any descendant is touched)
```

---

## What protectme Does ✅

| Feature | Status | Description |
|---------|--------|-------------|
| **Path protection** | ✅ Done | `protectme ~/project` adds path to policy |
| **Root destruction veto** | 🚧 Stub | Blocks `rm -rf /protected` before any child removed |
| **Descendant mutation allowed** | 🚧 Design | `git pull`, edits, builds work normally inside tree |
| **Explicit unprotect** | ✅ Done | `protectme --remove /path` with audit trail |
| **Audit logging** | ✅ Done | Append-only log of DENY/ALLOW decisions |
| **Works against any syscall** | 🚧 Design | Not just `rm` — `python`, `node`, `find -delete`, GUI, custom C |
| **sudo cannot bypass** | 🚧 Design | Must `protectme --remove` first (audited) |

---

## What protectme Does NOT ❌

| Feature | Reason |
|---------|--------|
| Backup / snapshot / recovery | Separate concern — use `borg`, `restic`, `timeshift` |
| Quarantine / trash / restore | Would make trusted code large; core is only ALLOW/DENY |
| GUI / cloud / account / plugin / AI | Feature creep — this tool does one thing |
| Filesystem management | Not a filesystem driver |
| Antivirus / EDR / HIPS | Different threat model |

---

## Architecture

```
┌───────────────────────────────────────────────────────────┐
│                        USERSPACE                          │
│  ┌─────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │  CLI    │───▶│ Policy File  │───▶│  protectmed      │  │
│  └─────────┘    │/etc/protectme│    │  (control plane) │  │
│                 └──────────────┘    └──────────┬───────┘  │
└────────────────────────────────────────────────┼──────────┘
                                                 │ policy update
                                                 ▼
═══════════════════════════════════════════════════════════════
                          KERNEL
═══════════════════════════════════════════════════════════════
                    ┌─────────────────────┐
                    │   protectme LSM     │  ← tiny enforcement
                    │  (BPF-LSM preferred)│
                    └──────────┬──────────┘
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
              protected root          normal object
                    │                     │
                  DENY                  ALLOW
```

**Policy lives in userspace** (`/etc/protectme/protected`). Kernel only enforces.

---

## Quick Start

```bash
# Build
make

# Install (requires root)
sudo make install

# Protect a directory
protectme ~/myproject

# List protected paths
protectme --list

# Unprotect (audited)
protectme --remove ~/oldproject

# Run daemon (requires root, stub for now)
sudo protectme --daemon
```

**Policy file** (`/etc/protectme/protected`):
```
/home/user/project DENY
/home/user/database.sqlite DENY
```

**Audit log** (`/var/log/protectme/audit.log`):
```
14:23:17 DENY unlink /home/user/project/report.pdf protected_root
14:23:18 ALLOW write /home/user/project/src/main.c
```

---

## Compatibility Reality

| Kernel | BPF-LSM | Native LSM | Status |
|--------|---------|------------|--------|
| 6.18+  | ✅      | ✅         | Supported |
| 6.6 LTS| ✅      | ✅         | Supported |
| 5.15 LTS| ❓     | ✅         | Supported |
| 5.10 LTS| ❓     | ✅         | Legacy |
| older  | ❌      | ❌         | **Unsupported** |

> **No security illusion**: If kernel can't enforce, we don't claim protection. `protectme` fails loudly.

---

## Design Decisions

- **Fail closed** for protected roots — destruction always DENY
- **Fail safe** for daemon — crash ≠ filesystem locked
- **No `rm` dependency** — works at syscall level
- **Policy in userspace** — kernel only holds minimal runtime state
- **Minimal trusted code** — policy lookup + classification + ALLOW/DENY
- **No partial state** — either entire tree preserved, or operation rejected before first child touched

---

## Development Status

| Component | Status |
|-----------|--------|
| CLI (protect/list/remove/status) | ✅ Working |
| Policy management | ✅ Working |
| Audit logging | ✅ Working |
| Daemon skeleton | ✅ Stub |
| **LSM/BPF enforcement** | 🚧 **P0 Research** |

### P0 Research Question

> *"How does kernel-level protectme know an operation is starting a destructive traversal of a protected root, while allowing all normal mutation inside that root?"*

This requires mapping filesystem operations (`unlink`, `rmdir`, `rename`, `link`) to LSM hooks and proving the invariant holds across edge cases (symlinks, hardlinks, bind mounts, rename semantics, mount boundaries, TOCTOU).

---

## Contributing

This is a **prototype** — the hard part isn't the CLI, it's proving the kernel enforcement works correctly. See `DESIGN-PHILOSOPHY.md` for full rationale.

1. Read the design philosophy
2. Build operation → LSM hook coverage matrix
3. Prototype minimal BPF-LSM
4. Test bypass attempts with direct syscalls

---

## License

MIT — use it, audit it, improve it.

---

<p align="center">
  <em>Just a cyber sec man :)).</em>
</p>
