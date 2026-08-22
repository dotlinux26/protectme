# Policy Configuration

## Overview

The policy file `/etc/protectme/policy` is the **source of truth** for protection state. It is a plain text file, one directive per line, reviewed by human and machine alike.

## Syntax

```text
# Comments start with #
TREE <path> [U <uid>]     # Protect directory subtree
FILE <path> [U <uid>]     # Protect single file
MODE <0|1|2>              # Global enforcement mode
```

## Directives

### TREE `<path>` `[U <uid>]`

Protects the entire subtree rooted at `<path>`.

- **Mutation operations** (create, write, rename within, hardlink, symlink) → **ALLOWED**
- **Destructive operations** (unlink/rmdir of descendants, rename out of tree) → **DENIED** without capability
- **Optional `U <uid>`** — which user may request destruction capabilities. If omitted, only root (uid 0) may request.

Example:
```text
TREE /home/user/project
TREE /etc/my-app U 1000
```

### FILE `<path>` `[U <uid>]`

Protects a single file. Same semantics as TREE but only for the exact inode.

```text
FILE /etc/secret.key U 1000
FILE /var/lib/db/production.sqlite
```

### MODE `<0|1|2>`

Global enforcement mode:

| Mode | Name | Behavior |
|------|------|----------|
| 0 | OFF | No enforcement; daemon runs but all operations ALLOW |
| 1 | ROOT_ONLY | Only operations on the registered root object itself are vetoed; child mutations ALLOWED |
| 2 | STRICT | Any operation inside a protected boundary requires capability (default) |

Default: `MODE 2`

## Reconciliation

On daemon startup and SIGHUP, `protectmd` **reconciles** kernel state from policy:

1. Parse policy file
2. For each TREE/FILE: stat path → resolve (dev, ino)
3. Compare with identity journal (`/var/lib/protectme/identities.journal`)
4. Classify: FRESH / REASSERT / DRIFTED / SKIP
5. Register in kernel maps

| Classification | Meaning |
|----------------|---------|
| FRESH | First time seeing this path; register |
| REASSERT | Same (dev, ino) as last reconcile; idempotent re-register |
| DRIFTED | Path now resolves to different inode; **loud warning**, register new inode per policy-as-written |
| SKIP | Path does not exist; **loud skip**, no registration |

DRIFTED paths are **never silently redirected** — admin is warned on stderr and in logs.

## Identity Journal

File: `/var/lib/protectme/identities.journal`

Append-only log of successful reconciliations:

```text
REG <epoch> <dev> <ino> owner=<uid> <path>
```

Used by reconcile to detect drift. Paths with spaces are truncated in journal (research limitation).

## Examples

### Minimal
```text
MODE 2
TREE /home/user/project
```

### Multi-user
```text
MODE 2
TREE /home/alice/work U 1000
TREE /home/bob/work U 1001
FILE /etc/secret.key U 0
```

### System-wide
```text
MODE 2
TREE /etc U 0
TREE /usr/local U 0
```

## Daemon Reload

Policy changes take effect on:

- Daemon restart: `systemctl restart protectmed`
- SIGHUP: `protectme -r` or `systemctl reload protectmed`

Both trigger full reconciliation. DRIFTED entries are logged but do not block reload.

## Design Principles

1. **Policy is source of truth** — kernel maps are derived, not authoritative
2. **Drift is loud** — never silently protect wrong object
3. **Human-readable** — no binary formats, no YAML/JSON
4. **Idempotent** — multiple reconciles = same result
5. **Owner-aware** — capability issuance respects `U <uid>`