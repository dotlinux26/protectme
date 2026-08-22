# Research: Destruction Traversal Convergence

Empirical basis for treating recursive tree destruction as a **VFS semantic
class**, independent of the tool performing it.

| Run | Tools | Finding |
|---|---|---|
| run1 | `rm file` vs `rm -rf dir` | P0-OBS-01..03 |
| run2 | `find -delete`, `find -type f -delete`, `shutil.rmtree`, custom C nftw | P0-OBS-04..05 |

Raw data: `../experiments/raw/run1-*`, `../experiments/raw/run2-*`;
custom tool source: `../experiments/raw/pm-nftw.c`.

Planned additions: `git clean -fdx`, `rsync --delete`.
