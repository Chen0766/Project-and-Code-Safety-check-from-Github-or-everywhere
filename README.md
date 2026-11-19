# dep-audit

Checks dependency manifests and lock files for typosquats, untrusted sources,
unpinned versions, and install hooks.

The moment you run `npm install` or `pip install`, you are executing someone else's
install script with your own privileges. Clean source code does not help if a
dependency is compromised.

Reads manifests only. Nothing is installed or downloaded. Pure Python standard
library.

The companion tool [code-audit](../code-audit/) looks at what the code itself does;
this one looks at what the code drags in.

## Usage

- `python depaudit.py <project-dir>` offline, local rules only
- `python depaudit.py <project-dir> --online` also verifies against PyPI / npm
- `python depaudit.py --selftest` runs the self-test
- `python depaudit.py <dir> --blocklist my.json` adds your own blocklist

Exit codes: `0` = A/B, `1` = C, `2` = D, `3` = bad path.

## What it checks

| # | Check | Signal |
|---|-------|--------|
| 1 | Typosquatting | Edit distance against 220 popular package names: one character off, missing separator, or `l/I/1` lookalikes |
| 2 | Source trust | Non-official index, `git+http://`, `file:` / `link:` dependencies, `--trusted-host` |
| 3 | Version pinning | Missing version, lower bound only, `*`, `latest` |
| 4 | Install hooks | `preinstall` / `install` / `postinstall` / `prepare` in package.json, `cmdclass` in pyproject.toml |
| 5 | Transitive dependencies | Parses lock files and checks the packages you never declared but will install anyway |

### Supported lock files

`package-lock.json` (v1/v2/v3), `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`,
`poetry.lock`, `uv.lock`, `Pipfile.lock`

Three things are checked on transitive dependencies:

- Install hooks: npm lock entries carrying `hasInstallScript: true`
- Download host: a `resolved` URL pointing outside the official registry means the
  package was swapped or came from a private mirror
- Names: the whole tree goes through the blocklist, and the first 400 entries also
  get the lookalike comparison

`--online` adds three more: whether the package exists at all (404 means a typo or
a takedown), how old the package is (under 30 days is high risk), whether the pinned
version was yanked, and whether the npm latest release carries a postinstall hook.

## Grades

| Grade | Risk | Meaning |
|-------|------|---------|
| A | Low | Names normal, sources official, versions pinned |
| B | Medium | Hygiene issues, nothing fatal |
| C | High | Something needs manual confirmation |
| D | Critical | Fatal: typosquat, install hook, untrusted source |

Weights: critical 40, high 18, medium 8, low 3, per-category cap 45. Version,
lookalike and source findings are counted per occurrence (up to five); every other
rule counts once. Any critical finding forces D.

## Self-test

`python depaudit.py --selftest` runs offline and asserts nine things: a clean
manifest grades A, a dirty one grades D, `reqeusts` is caught as a lookalike of
`requests`, a postinstall hook is found, a known malicious name is found, transitive
dependencies are read, a lock-file install hook is found, a non-official host in a
lock file is found, and a clean lock file produces no false positives.

## Adding to the blocklist

Format: `{"pypi": ["name"], "npm": ["name"]}`

The built-in list holds about twenty historical cases. It is a starting point, not a
complete dataset; maintain your own for real use.

## Limitations

- Edit distance catches names that look similar, not packages that are malicious in
  entirely different ways.
- Cannot defend against a legitimate package being hijacked after the fact
  (`event-stream` style). Only lock files plus diff review help there.
- npm publish dates are not checked: there is no lightweight registry endpoint for
  that, and full packuments run to several megabytes for popular packages.
- `--online` sends your dependency names to pypi.org and npmjs.org.
- Lookalike comparison on transitive dependencies covers the first 400 entries only;
  the blocklist covers the full tree.
- `pnpm-lock.yaml` is YAML and the standard library has no parser, so it is read
  with line-based regex and complex structures may be missed.
- Nothing installed at runtime (`npx`, dynamic imports) is visible.

## License

No LICENSE file is bundled with this subdirectory; see the repository root.
Depends only on the Python standard library (PSF license).

## Layout

- `depaudit.py` main program
- `启动依赖审查.bat` double-click launcher
- `README.md`
- `reports/` generated reports, not committed
