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

## The Problem

protectme exists because destructive filesystem operations are often **less atomic than they look**.

A common mistake is not necessarily:

```bash
rm -rf /important/project
```

A much more realistic failure is trying to remove only a set of generated files using a filename pattern.

For example, the intention might be:

> "I only want to remove the ZIP files from this directory."

The operator expects the command to affect only a small, known set of files.

But when a destructive command is constructed incorrectly, a shell pattern expands unexpectedly, a path is broader than intended, or the command is executed from the wrong working directory, the resulting operation can target objects that were never intended to be destroyed.

That is the class of mistake protectme is designed to mitigate.

---

## A Real Failure Scenario

protectme was motivated by an actual filesystem accident during development.

The original intention was simple:

> Remove a few generated `.zip` files matching a filename pattern.

The command I intended to run:

```bash
rm -rf vulnghedahauilab*.zip
```

The command I accidentally executed:

```bash
rm -rf vulnghedahauilab*
```

The difference is one missing suffix.

The first targets generated ZIP files.

The second can recursively destroy every matching directory.

The operation was performed using a recursive destructive command. The pattern/path was broader than intended, and the command began traversing objects that should not have been removed.

The command was interrupted with:

```text
Ctrl+C
```

But the damage had already started.

This is an important property of recursive deletion:

```text
rm -rf
   │
   ├── remove object A
   ├── remove object B
   ├── remove object C
   ├── remove object D
   └── ...
```

`Ctrl+C` does **not** mean:

```text
ROLLBACK A
ROLLBACK B
ROLLBACK C
ROLLBACK D
```

It means:

```text
STOP EXECUTING FUTURE OPERATIONS
```

Anything that was already successfully removed remains removed.

For a sufficiently fast recursive traversal, even reacting immediately may therefore be too late.

---

## Why This Is Different From "Just Be Careful"

The problem is not that `rm` is broken.

The command is doing exactly what the kernel permits it to do.

The problem is the gap between:

```text
USER INTENT
"I only want to delete these few generated files"
```

and:

```text
ACTUAL FILESYSTEM OPERATIONS
unlink(...)
unlink(...)
unlink(...)
rmdir(...)
unlink(...)
...
```

Once those filesystem operations have been accepted, the kernel has no knowledge that the user originally intended something else.

protectme introduces an explicit safety boundary for objects the user considers important.

---

## The protectme Idea

Before the accident:

```text
User
 │
 │ "delete these files"
 ▼
rm / shell / Python / Node / GUI
 │
 ▼
filesystem
 │
 └── destructive operations
```

With protectme:

```text
User
 │
 │ destructive operation
 ▼
program / syscall
 │
 ▼
protectme enforcement boundary
 │
 ├── protected root?
 │       │
 │       ├── NO  → ALLOW
 │       │
 │       └── YES → DENY
 │
 ▼
filesystem
```

The important point is that protectme does **not** try to understand whether the user "really meant it".

It does not ask:

```text
Are you sure?
```

It does not create a backup.

It does not move the object to Trash.

It does not attempt recovery after the fact.

Instead, the user explicitly declares:

```text
"This filesystem object must not be destroyed accidentally."
```

protectme enforces that boundary at the kernel level.

---

## Why Protecting the Root Is the Key

protectme deliberately does **not** make the entire protected tree read-only.

For example:

```text
protected/
├── src/
├── build/
├── database.sqlite
└── README.md
```

Normal work remains possible:

```text
git pull
npm install
compiler writes
database updates
edit files
create files
delete temporary files
```

Descendant mutation is allowed.

What is protected is the **root object itself**:

```text
rm protected/file.txt
        │
        └── ALLOW
```

but:

```text
rm -rf protected/
        │
        └── DENY
```

The protected root therefore acts as a filesystem safety anchor.

---

## Security Invariant

The intended invariant is:

```text
A protected tree permits arbitrary mutation of its descendants,
but prevents the protected root itself from being destroyed,
moved, replaced, or recursively destroyed.
```

For recursive destruction, the critical requirement is stronger:

```text
rm -rf protected/
```

must not produce:

```text
protected/
├── some_remaining_file
└── ...
```

after descendants have already been removed.

The desired result is:

```text
DENY
 │
 └── protected tree remains intact
```

This is why protectme is fundamentally an **enforcement problem**, not a recovery problem.

---

## What protectme Is Protecting Against

protectme is specifically intended to mitigate accidental destructive operations such as:

* an overly broad shell glob
* an incorrect working directory
* an incorrect path
* an accidentally recursive command
* a destructive command executed against the wrong root
* scripts that unexpectedly invoke destructive filesystem operations
* `rm -rf` targeting a protected project
* direct `unlink()`, `rmdir()`, `rename()`, or equivalent filesystem syscalls

The common property is:

```text
The user intended one thing.
The resulting filesystem operation was more destructive than intended.
```

protectme does not attempt to infer intent.

It establishes a boundary that remains true even when the user's command is wrong.

---

## What protectme Does ✅

| Feature | Status | Description |
|---------|--------|-------------|
| **Path protection** | ✅ Done | `protectme ~/project` adds path to policy |
| **Root destruction veto** | 🚧 Design | Blocks `rm -rf /protected` before any child removed |
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
┌─────────────────────────────────────────────────────────────┐
│                        USERSPACE                            │
│  ┌─────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │  CLI    │───▶│ Policy File  │───▶│  protectmed      │  │
│  └─────────┘    │/etc/protectme│    │  (control plane) │  │
│                 └──────────────┘    └────────┬─────────┘  │
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

## Security Model

- **Fail closed** for protected roots — destruction always DENY
- **Fail safe** for daemon — crash ≠ filesystem locked
- **No `rm` dependency** — works at syscall level
- **Policy in userspace** — kernel only holds minimal runtime state
- **Minimal trusted code** — policy lookup + classification + ALLOW/DENY
- **No partial state** — either entire tree preserved, or operation rejected before first child touched

---

## P0 Research Question

> *"How does kernel-level protectme know an operation is starting a destructive traversal of a protected root, while allowing all normal mutation inside that root?"*

`rm -rf /protected` is a **post-order traversal**:

```
rm -rf /protected
       │
       ├── readdir(/protected)          ← enumeration (allowed)
       ├── unlink(/protected/a)         ← ALLOW (descendant mutation)
       ├── unlink(/protected/b)         ← ALLOW
       ├── rmdir(/protected/src)        ← ALLOW (descendant dir)
       ├── ...
       └── rmdir(/protected)            ← DENY (root destruction) — TOO LATE!
```

If we only hook `inode_rmdir` on the root, all descendants are already gone by the time DENY fires.

This is the core research problem. See `P0-RESEARCH.md` for detailed analysis, proposed solutions (token-based explicit auth + heuristic fallback), and LSM hook mapping matrix.

---

## Current Status

| Component | Status |
|-----------|--------|
| CLI (protect/list/remove/status) | ✅ Working |
| Policy management | ✅ Working |
| Audit logging | ✅ Working |
| Daemon skeleton | ✅ Stub |
| **LSM/BPF enforcement** | 🚧 **P0 Research** |

**The prototype does not yet claim kernel-level enforcement.** The security invariant above is a P0 research target.

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

## Contributing

This is a **prototype** — the hard part isn't the CLI, it's proving the kernel enforcement works correctly. See `P0-RESEARCH.md` for the detailed research plan.

1. Read the design philosophy (`DESIGN-PHILOSOPHY.md` outside git)
2. Build operation → LSM hook coverage matrix
3. Prototype minimal BPF-LSM
4. Test bypass attempts with direct syscalls

---

## License

MIT — use it, audit it, improve it.

---

<p align="center">
  <em>A small tool with the security boundary in the right place.</em>
</p>