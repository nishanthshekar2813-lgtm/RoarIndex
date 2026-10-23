# RoarIndex: Threat Correlation Engine (Roaring Bitmap) - Team 14

DSA Lab Evaluation 3 | Python 3.8+. No installs needed.

## Team 14
| Name | Roll No. | Role |
|---|---|---|
| Nishanth Shekar T (Team Leader) | CB.SC.U4CSE25138 | Core Roaring Bitmap + live demo |
| Neeraj | CB.SC.U4CSE25118 | Set operations (AND / OR / AND NOT) |
| Sandeep | CB.SC.U4CSE25139 | Baselines + synthetic data generator |
| Rithika Goru | CB.SC.U4CSE25146 | Tests + benchmark |

Run every command from THIS folder (the one that contains nishanth/, neeraj/, sandeep/, rithika/).
Imports need all four folders present, so merge everyone's work before running the full demo.

## Folders and ownership (commit only your own folder, from your own GitHub account)
| Folder | Owner | Files | Difficulty | Job |
|---|---|---|---|---|
| `nishanth/` | Nishanth | `roaring.py`, `threatboard.py` | HARD (core, ~400 lines) | The Roaring Bitmap: chunk split, array/bitmap/run containers, add/remove/contains, container switching at 4096, optimize(). Plus the live demo. |
| `rithika/` | Rithika | `benchmark.py`, `test_edge_cases.py` | MEDIUM (~190 lines) | 22 edge-case tests and the Roaring vs bitset vs hash-set benchmark |
| `neeraj/` | Neeraj | `setops.py` | MEDIUM (~125 lines) | AND / OR / AND NOT at chunk level and container level |
| `sandeep/` | Sandeep | `baselines.py`, `datagen.py` | EASY (~100 lines) | Plain bitset, hash set, synthetic security-log generator |

Everyone must understand the whole project. Sir interviews each member separately.

## Run (from this folder)
    python -m unittest discover -s rithika -t . -p "test_*.py" -v     # 22 tests
    python -m rithika.benchmark                                       # 1M events, mixed data
    python -m rithika.benchmark --n 50000000 --mode sparse
    python -m nishanth.threatboard                                    # interactive demo
    python -m nishanth.threatboard --auto                             # scripted walkthrough

Demo commands: `stats`, `query failed_login AND suspicious_ip AND NOT whitelisted`, `burst`, `regen 1000000 sparse`, `quit`.

## Git (each member, once)
    git clone <repo-url> && cd RoarIndex
    git config user.name "Your Name"
    git config user.email "your-verified-github-email"
    git checkout -b <your-name>-part
    git add <your-folder> && git commit -m "meaningful message"
    git push -u origin <your-name>-part        # open a Pull Request and merge into main

## Honest results to present
* Memory: Roaring is far smaller than a hash set, and smaller than a bitset when flags are sparse or clustered into runs.
* Speed: in this PURE PYTHON build the bitset is faster (Python's big-int AND runs in C). Real Roaring libraries (CRoaring) are C with SIMD. Say this yourself; it is a limitation, not a bug.
* Weak spot: random sparse IDs spread over many chunks give many tiny array containers (`--mode sparse`).