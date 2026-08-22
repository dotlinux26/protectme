# Research: Destruction Semantics Engine (OPEN)

The semantic layer: classifying operation **streams** as ordinary mutation vs
destructive traversal — without process names, thresholds, or timing heuristics.

Status: problem formulation only. See PART XI/XII of `P0-RESEARCH-DEEP.md`
(project workspace) for the thesis and constraints imposed by:

- P0-OBS-01 — single-op indistinguishability (mutation ≡ first op of destruction)
- P0-OBS-06 — ancestor context gap (depth ≥ 2 invisible to parent-state lookup)

Candidate approaches under investigation:
1. explicit destruction transaction protocol (`BEGIN(root)…COMMIT(root)`)
2. dir-handle-bound authorization
3. stream-level state machine over VFS events (the "final boss")
