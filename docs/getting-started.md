# Getting Started

## Installation

```bash
# From .deb package (recommended)
sudo apt install ./protectme_0.1.0_amd64.deb

# Verify installation
protectme -s
```

## Quick Start

```bash
# 1. Protect a directory (requires root)
sudo protectme /home/user/important-project

# 2. Verify it's protected
protectme -l

# 3. Try normal operations (should work)
vim /home/user/important-project/file.txt    # OK
mv /home/user/important-project/a /home/user/important-project/b  # OK

# 4. Try destructive operation (should be denied)
rm -rf /home/user/important-project
# protectme: DENIED - destructive traversal requires authorization
# root: /home/user/important-project

# 5. Unprotect to allow destruction (requires root)
sudo protectme -u /home/user/important-project

# Now rm -rf works
rm -rf /home/user/important-project
# Success - tree removed
```

## Sudo Requirements

| Command | Sudo Required? |
|---------|----------------|
| `protectme PATH` | Yes (modifies policy + kernel state) |
| `protectme -u PATH` | Yes (modifies policy + kernel state) |
| `protectme -l` | No (read-only) |
| `protectme -s` | No (reads state file) |
| `protectme -r` | **Yes** (sends SIGHUP to daemon via systemctl) |
| `rm -rf` on protected tree | No (enforced by kernel) |

> **Note**: `protectme -r` uses `systemctl reload protectmed` which requires root.
> If you get "Connection timed out" or "failed to reload", run with `sudo protectme -r`.

## Configuration

Edit `/etc/protectme/policy`:

```text
# Protectme policy
TREE /home/user/important-project
TREE /etc/my-app-config U 1000
FILE /etc/secret.key U 1000
MODE 2
```

Then reload:

```bash
sudo protectme -r
```

## Checking Status

```bash
# List protected trees
protectme -l

# Daemon status
protectme -s
# protectme: ACTIVE (age=2s, roots=3, epoch=5)
```

## Unprotecting

```bash
sudo protectme -u /path/to/tree
```

## Daemon Management

```bash
# Start/stop/restart
sudo systemctl start protectmed
sudo systemctl stop protectmed
sudo systemctl restart protectmed

# View logs
journalctl -u protectmed -f

# Policy changes apply on reload
sudo protectme -r
# or
sudo systemctl reload protectmed
```

## Troubleshooting

**Protection not working?**
```bash
protectme -s
# Check STATE=ACTIVE, roots count > 0
```

**Daemon not running?**
```bash
sudo systemctl status protectmed
sudo systemctl start protectmed
```

**Policy not reloaded?**
```bash
sudo protectme -r
# or
sudo systemctl reload protectmed
```

**Permission denied on reload?**
Run with sudo: `sudo protectme -r`