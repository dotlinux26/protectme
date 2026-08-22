# Research: Kernel Experiments (CAP protocol & object state)

Hands-on kernel experiments backing the CAP roadmap. Raw logs in `raw/`
(`*.log` files are local-only per .gitignore; filtered extracts are committed).

| Run | Experiment | Result |
|---|---|---|
| run3 | CAP-01A syscall→task→VFS bridge | see ../lifecycle |
| run6 | CAP-01D inode-state map (⚠️ harness bug: state never set — kept for honesty record) | invalidated |
| run7 | primitive matrix + rm -rf visibility trace; **P0-OBS-06 ancestor gap** | PARTIAL |

Tool sources: `raw/pm-mark.c` (inode-state setter via prctl magic channel),
`raw/pm-nftw.c` (custom nftw traversal).
