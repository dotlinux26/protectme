# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial v0.1.0 research-backed prototype
- BPF-LSM enforcement for unlink/rmdir/rename
- FD-based capability system (possession = authority)
- Epoch-based global revoke (O(1))
- Persistent policy with SIGHUP reload
- Object identity journal (FRESH/REASSERT/DRIFT/SKIP)
- Ancestor boundary walk (PM_WALK_MAX=16)
- Rename-out protection via path_rename hook
- Heartbeat DEAD-state visibility
- Comprehensive adversarial test suite

### Security
- Unauthorized traversal denied before first child mutation
- Tool-independent enforcement (rm, find, python, custom)
- Capability lifecycle: expiry, revoke, fork/exec semantics, SIGKILL handling
- Persistent policy with drift detection
- Rename-out and cross-filesystem rename protection

### Known Limitations
- Ancestor walk bounded at 16 hops
- SIGKILL daemon leaves capabilities alive until epoch bump
- OverlayFS upper layer writable (lower protected via whiteout)

---

## [v0.1.0] - 2026-08-22

### Added
- Initial release

### Research Foundation
Based on 17 experimental runs (OBS-01..06, CAP-01A..E, STATE-01..03, P0.1..P0.7)
demonstrating:
- VFS semantic gap: destructive traversal cannot be inferred from single operations
- Explicit destruction context closes the gap
- FD capability model provides possession-based authority
- Epoch-based revoke provides O(1) global invalidation
- Persistent policy survives daemon restart/reboot
- Adversarial testing: 17/18 scenarios pass, 1 documented limitation

See SECURITY.md for full threat model and claims table.