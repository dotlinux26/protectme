# Protectme — rm Integration Architecture

Status: v0.1 (2026-08-22). Design decisions for shell-level integration.
NOT implemented yet — queued behind CAP-01E (capability authenticity + lifetime).

## Principle: kernel is the authority, rm is just a client

```
                 user
                   │
                  rm                      python / custom C /
                   │                      shutil.rmtree / backup tool
          ┌────────┴────────┐                   │
     normal rm         destructive              │
          │                 │                    │
     exec rm.real    obtain TX(root)                │
          │                 │                    │
          └────────┬────────┴────────────────────┘
                   ▼
             VFS / LSM  ← final authority, ALWAYS
                   │
              ALLOW / DENY
```

The wrapper is a **reference client / compatibility shim**, never the security
boundary. Bypassing it (`/usr/bin/rm.real`, `shutil.rmtree`, raw `unlinkat`)
must simply land on kernel enforcement — proven by RUN8 case F
(tool independence: denial does not depend on which destructor runs).

## UX contract

Users keep using `rm` unchanged:

```console
$ rm -rf ~/project
rm: cannot remove '/home/user/project': Operation not permitted
protectme: protected tree

$ protectme -u ~/project           # lift protection (state change)
$ rm -rf ~/project                 # works — object is unprotected now
```

`protectme destroy PATH [-- CMD…]`, if ever shipped, is pure UX sugar over
(confirm intent → unprotect → exec rm) — NOT a destruction authority and NOT
in the MVP. Protection is a state; destroying protected data requires
changing that state first. No command carries a "magic destruction authority"
that punches through policy (see architecture.md, THE PIVOT).

## Wrapper mechanics (drop-in replacement)

```text
/usr/libexec/protectme/rm.real      # original coreutils binary, system-managed
/usr/bin/rm                         # protectme launcher
```

Launcher responsibilities:
1. parse full coreutils rm CLI (flags, exit codes, output parity)
2. resolve targets → detect protected roots among them
3. no protected root involved → `execve(rm.real, argv)` (zero overhead path)
4. protected root involved → request TX(root) from authority → exec rm.real
5. TX acquisition failure → fall through to plain exec (kernel still denies;
   error surface identical to today's behavior)

Installer must NOT clobber coreutils blindly: package-update integration and
immutable `rm.real` management required (distro packaging concern).

## Known limits (documented, accepted)

- Absolute-path callers bypass the launcher — irrelevant to security (kernel
  decides), relevant only to convenience.
- Non-rm destructors never touch the wrapper at all.
- Long-term Linux-native path: upstream coreutils understanding Protectme
  ("rm asks: is this intended destruction?") — integration phase, NOT P0.

## Positioning

```
PROTECTME
    ├── Kernel semantic layer   = authority (ALLOW/DENY, capability model)
    └── rm integration          = convenience (reference client of the
                                  filesystem intent protocol)
```

Future clients of the same protocol: deployment tools, backup tools, package
managers, custom applications — each obtains TX(root) explicitly; everything
else stays default-deny inside protected boundaries (mode 2 semantics).
