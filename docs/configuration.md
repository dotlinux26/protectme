# Configuration

## Policy File

**Location:** `/etc/protectme/policy`

**Format:** One directive per line, comments with `#`

```text
TREE <path> [U <uid>]    # Protect directory subtree
FILE <path> [U <uid>]    # Protect single file
MODE <0|1|2>             # Global enforcement mode
```

See [policy.md](policy.md) for full syntax and semantics.

## Daemon Configuration

**Location:** `/etc/protectme/daemon.conf` (optional)

```text
# Capability issuer socket
issuer_socket = /run/protectme/tx.sock
issuer_socket_mode = 0660
issuer_socket_group = protectme

# Heartbeat
heartbeat_interval = 1000  # milliseconds
state_file = /run/protectme/state

# Logging
log_level = info  # debug, info, warn, error
audit_log = /var/log/protectme/audit.log

# Capability defaults
default_ttl_ms = 30000
max_ttl_ms = 60000

# Identity journal
journal_dir = /var/lib/protectme
journal_file = identities.journal
```

## Systemd Service

**Unit:** `/lib/systemd/system/protectmed.service`

```ini
[Unit]
Description=Protectme filesystem protection daemon
Documentation=man:protectmed(8)
After=network.target
ConditionPathExists=/etc/protectme/policy

[Service]
Type=simple
ExecStart=/usr/lib/protectme/protectmed
Restart=on-failure
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=5

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=false
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true

# Capabilities required
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
```

## Filesystem Layout

```
/etc/protectme/
├── policy              # Main policy file
└── daemon.conf         # Optional daemon config

/var/lib/protectme/
├── identities.journal  # Identity journal (auto-managed)
└── state/              # Runtime state

/run/protectme/
├── tx.sock             # Capability issuer socket
├── state               # Daemon heartbeat state
└── epoch               # Current capability epoch

/var/log/protectme/
├── audit.log           # Audit events
└── protectmed.log      # Daemon logs
```

## CLI Configuration

CLI reads no configuration file. All behavior controlled via:
- Command-line arguments
- Policy file (daemon-side)
- Daemon configuration (daemon-side)

## Environment Variables

None required. All configuration via files.

## Kernel Parameters

Required kernel config:
- `CONFIG_BPF_LSM=y`
- `CONFIG_BPF_SYSCALL=y`
- `CONFIG_DEBUG_INFO_BTF=y`
- `CONFIG_SECURITY=y`

Boot parameter: `lsm=...bpf...` (must include `bpf` in LSM list)

Verify:
```bash
cat /sys/kernel/security/lsm
# Must show: capability,bpf,...
```