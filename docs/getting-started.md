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
# 1. Protect a directory
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

# 5. Authorized destruction
protectme destroy /home/user/important-project -- rm -rf /home/user/important-project
# Success - tree removed
```

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
protectme -r
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
protectme -u /path/to/tree
```

## Authorized Destruction Pattern

```bash
# Interactive
protectme destroy /path/to/tree -- rm -rf /path/to/tree

# In scripts
protectme destroy /data/backup -- tar -czf /tmp/backup.tar.gz /data/backup && rm -rf /data/backup
```

The `destroy` subcommand obtains a capability, attaches it, and executes the command — all in one atomic flow.

## Daemon Management

```bash
# Start/stop/restart
sudo systemctl start protectmed
sudo systemctl stop protectmed
sudo systemctl restart protectmed

# View logs
journalctl -u protectmed -f

# Policy changes apply on reload
protectme -r
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
protectme -r
# or
sudo systemctl reload protectmed
```

**Capability denied?**
- Check if tree is in policy (`protectme -l`)
- Check if daemon is ACTIVE (`protectme -s`)
- Check epoch: recent REVOKE may have invalidated old caps