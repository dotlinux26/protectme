# Protectme

> **Protectme doesn't protect your files. It protects you from accidentally destroying them.**

A minimal Linux kernel-level filesystem safety daemon that prevents accidental destructive operations on explicitly protected paths.

## Philosophy

Protectme is a **kernel-level safety interlock** for Linux. It doesn't manage, modify, recover, or monitor your data. It only prevents destructive operations on explicitly protected objects.

## Features (MVP)

- ✅ **Path protection** - `protectme /path/to/protect`
- ✅ **Delete enforcement** - Blocks `rm`, `unlink`, `rmdir`, `rename` on protected roots
- ✅ **Allow descendants** - Normal mutation inside protected tree (git pull, edits, builds)
- ✅ **Explicit unprotect** - `protectme --remove /path` with audit trail
- ✅ **Audit logging** - Append-only log of denied operations

## Architecture

```
protectme
├── cli          # User interface
├── daemon       # Root process, enforcement (stub - LSM pending)
├── policy       # Protected paths management
└── audit        # Event logging
```

## Build

```bash
mkdir build && cd build
cmake ..
make
sudo make install
```

## Usage

```bash
# Protect a project directory
protectme ~/myproject

# List protected paths
protectme --list

# Unprotect (audited)
protectme --remove ~/oldproject

# Check status
protectme --status

# Run daemon (requires root)
sudo protectme --daemon
```

## Policy File

`/etc/protectme/protected` - Simple text format:
```
/home/user/project DENY
/home/user/database.sqlite DENY
```

## Design Decisions

- **Fail closed** for protected paths
- **Fail safe** for daemon (daemon crash ≠ filesystem locked)
- **No rm dependency** - Works against any program/syscall
- **Policy in userspace** - Kernel only enforces
- **No quarantine/backup in core** - Separate concern
- **Minimal trusted code** - Policy lookup + classification + ALLOW/DENY

## Compatibility

| Kernel | BPF-LSM | Native LSM | Status |
|--------|---------|------------|--------|
| 6.18+  | ✓       | ✓          | supported |
| 6.6 LTS| ✓       | ✓          | supported |
| 5.15 LTS| ?      | ✓          | supported |

**No security illusion**: If kernel can't enforce, we don't claim it.

## Development Status

🚧 **Early prototype** - CLI and policy management work, daemon/LSM enforcement is a stub.

See `DESIGN-PHILOSOPHY.md` in parent directory for full design rationale.