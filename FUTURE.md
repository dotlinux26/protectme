# Protectme — FUTURE ideas (parking lot)

RULE (feature freeze, 2026-08-22): nothing below touches the core until
Protectme 0.1.0 meets the Definition of Done (docs/architecture.md).
New ideas land here first. Core work = hardening only.

## Explicitly NOT now
- New intent types beyond destruction (REPLACEMENT / MIGRATION / NORMAL_MUTATION taxonomy)
- GUI / tray / notifications
- Backup, snapshot, restore features
- Cloud sync / telemetry
- AI-assisted anything

## Parked research & engineering ideas
- Upstream coreutils `rm` understanding Protectme (integration phase)
- Intent taxonomy expansion after destruction semantics are boring-solid
- Network filesystems (NFS/CIFS) identity model
- Containers / mount namespaces compatibility matrix
- Multi-principal policy language (principal → allowed roots → allowed intents)
- Audit log viewer / journal integration UX
- Seccomp profile generator for protectmed hardening
- IMA/EVM interplay study
- Fanotify pre-content access comparison study (why LSM was chosen)
