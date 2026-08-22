# Research: Task Lifecycle & Context Propagation (CAP-01A..01C)

How task-bound context behaves across the process lifecycle — the "WHO" channel
of the decision point.

| Run | Experiment | Result |
|---|---|---|
| run3 | CAP-01A: sys_enter marker → task storage → VFS kprobe | ✅ PASS |
| run4 | CAP-01B: fork / exec / thread inheritance matrix | ✅ characterized |
| run5 | CAP-01C: explicit delegation at `task_newtask` | ✅ PASS |

Key facts: task-local storage survives execve but does NOT auto-inherit across
fork or thread creation; explicit propagation at `task_newtask` works.

Raw data: `../experiments/raw/run3..5-*`.
