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

# Protectme

A kernel-enforced filesystem safety layer that protects designated filesystem boundaries against unauthorized destructive traversal.

## What it does

Protectme prevents accidental destructive operations (`rm -rf`, `find -delete`, `shutil.rmtree`, custom traversal) on protected filesystem trees while allowing normal mutation operations.

## How it works

1. **Policy** — You declare protected trees in `/etc/protectme/policy`
2. **Daemon** — `protectmd` loads policy, reconciles kernel state, issues capabilities
3. **Kernel enforcement** — BPF-LSM hooks intercept unlink/rmdir/rename, classify operations, and deny unauthorized destructive traversal before the first child mutation
4. **Authorization** — Explicit destruction requires a capability obtained via `protectme destroy`

## Quick start

```bash
# Install (from .deb)
sudo apt install ./protectme_0.1.0_amd64.deb

# Protect a tree
sudo protectme /home/user/important-project

# Normal operations work
vim /home/user/important-project/file.txt    # ALLOW
mv /home/user/important-project/file.txt /home/user/important-project/file2.txt  # ALLOW

# Destructive traversal denied
rm -rf /home/user/important-project
# protectme: DENIED - destructive traversal requires authorization
# root: /home/user/important-project

# Authorized destruction
protectme destroy /home/user/important-project -- rm -rf /home/user/important-project
# Success
```

## Security model

Protectme enforces an **explicit destruction-intent boundary** at the filesystem security layer:

- **Mutation** (create, write, rename within tree, hardlink) → ALWAYS ALLOWED
- **Destruction** (unlink/rmdir of descendants, rename out of tree) → DENIED without capability
- **Capability** — FD-based, single-use, epoch-bound, first-binder-wins, TTL-limited
- **Persistence** — Policy survives daemon restart/reboot via `/etc/protectme/policy`

See [SECURITY.md](SECURITY.md) for threat model and claims table.

## Installation

```bash
# From .deb (recommended)
sudo apt install ./protectme_0.1.0_amd64.deb

# Or from source
make && sudo make install
```

## Usage

```bash
# Protect a tree
protectme /path/to/tree

# Unprotect
protectme -u /path/to/tree

# List protected trees
protectme -l

# Show daemon status
protectme -s

# Reload policy
protectme -r

# Authorized destruction
protectme destroy /path/to/tree -- rm -rf /path/to/tree
```

## Configuration

Policy file: `/etc/protectme/policy`

```text
# Protectme policy
TREE /home/user/project      # protected tree
TREE /etc/my-config U 1000   # user 1000 can request capabilities
FILE /etc/secret.key U 1000  # protected file
MODE 2                       # enforcement mode (0=off, 1=root-only, 2=strict)
```

## Limitations

- **Ancestor traversal depth** bounded at 16 hops (configurable at compile time). Deep trees should register nested roots.
- **SIGKILL daemon** leaves BPF state intact; capabilities survive until epoch bump. Use systemd `KillSignal=SIGTERM`.
- **OverlayFS**: lower (protected) layer protected via whiteout; upper layer writable.
- **Cross-filesystem rename** blocked when source is protected.
- **Kernel requirement**: Linux 5.2+ with BPF-LSM support.

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](docs/getting-started.md) | Installation, quick start, usage |
| [Security Model](SECURITY.md) | Threat model, claims table, architecture |
| [Policy Configuration](docs/policy.md) | Policy syntax, reconciliation, identity journal |
| [Capabilities](docs/capabilities.md) | FD-based capability lifecycle, revoke, fork/exec |
| [Policy](docs/policy.md) | Policy syntax, reconciliation, drift detection |
| [Capabilities](docs/capabilities.md) | FD-based capability lifecycle, revoke, fork/exec |
| [Architecture](docs/architecture.md) | System architecture, components, data flow |
| [Configuration](docs/configuration.md) | Daemon config, systemd, filesystem layout |
| [Limitations](docs/limitations.md) | Known limits, kernel requirements, filesystem support |
| [Threat Model](docs/threat-model.md) | Adversary model, attack surface, defense layers |
| [Kernel Compatibility](docs/kernel-compatibility.md) | Supported kernels, BPF-LSM requirements |

## Status

v0.1.0 — Research-backed prototype. See [CHANGELOG.md](CHANGELOG.md) for details.

## License

GPL-2.0 (kernel) / MIT (userspace)