# code-audit

Checks scripts and code downloaded from the internet for obviously dangerous
behaviour, scores them, and reports an A/B/C/D grade with a risk level, pointing at
the exact line that triggered each finding.

The target is never executed, imported, or connected to. Static reading only.
Pure Python standard library, one file, no dependencies.

## Usage

- `python audit.py` scans the default directory
- `python audit.py <dir>` scans one directory
- `python audit.py <dir1> <dir2>` scans several
- `python audit.py some.user.js` scans a single file
- `python audit.py --selftest` runs the self-test

On Windows, double-click `启动审查.bat` for the same thing.

Exit codes: `0` = A/B, `1` = C, `2` = D, `3` = bad path.

Reports go to `reports/`: a `.md` for humans and a `.json` for scripts.

## Pipeline

1. **Inventory**: walk the tree, compute size and SHA256, identify the real file
   type from the header bytes rather than the extension
2. **File level**: double extensions, extension/type mismatch, symlinks, executables
3. **Archives**: most downloads are zips, so entries are read in memory without
   extracting anything to disk
4. **Content**: 42 rules across 14 categories
5. **Scoring**: weighted deductions, per-category cap, any critical finding forces D
6. **Report**: markdown detail plus JSON

## Grades

| Grade | Risk | Deduction | Advice |
|-------|------|-----------|--------|
| A | Low | <= 4 | Safe to open, still worth a glance at the entry file |
| B | Medium | 5-19 | Run it in a sandbox first |
| C | High | 20-39 | Only in a sandbox |
| D | Critical | >= 40 or any critical finding | Do not run on your machine |

Weights: critical 40, high 18, medium 8, low 3, info 0. Each rule counts once
across the whole tree, and each category is capped at 45 points.

## Categories

Download-and-execute, network egress, credentials (SSH, browser, wallets,
keyloggers), persistence (registry, scheduled tasks, startup folder), destructive
operations, privilege escalation, dynamic execution, obfuscation, process spawning,
install hooks (npm postinstall, setup.py), system modification (hosts, PATH,
firewall), anti-analysis (AMSI, VM detection, self-delete), suspicious files,
metadata.

Dangerous commands that appear in documentation files (.md, .txt) are reported as
info only, since describing something is not the same as doing it.

## Autorun

To scan on login, either put a shortcut to `启动审查.bat` in `shell:startup`
(Win+R, type `shell:startup`), or create a scheduled task that triggers at logon.

## Limitations

- Static analysis only. Anything packed in a binary, assembled at runtime, or
  encrypted will be missed.
- It can show that suspicious behaviour exists. It cannot show that code is safe.
  Grade A is not a clean bill of health.
- No coverage for supply-chain attacks inside dependencies, runtime behaviour, or
  network traffic.
- Archives are opened one level deep; nested archives are flagged but not followed.

## License

No LICENSE file is bundled with this subdirectory; see the repository root.
Depends only on the Python standard library (PSF license).

## Layout

- `audit.py` main program
- `启动审查.bat` double-click launcher
- `README.md`
- `reports/` generated reports, not committed
