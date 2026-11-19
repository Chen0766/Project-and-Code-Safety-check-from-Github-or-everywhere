# audit-tools

Two small tools that check whether code downloaded from the internet is safe to run.
Pure Python standard library, no third-party dependencies.

Before cloning a repo or running a script, I want to know what it reads, what it
installs, and where it connects. Most tools in this space either pull in a pile of
dependencies or upload your code to someone else's server, so I wrote these instead.

| Tool | What it checks | Entry point |
|------|----------------|-------------|
| [code-audit](code-audit/) | What the code does: dangerous commands, credential access, persistence, obfuscation | `python audit.py <dir>` |
| [dep-audit](dep-audit/) | What the code pulls in: typosquats, untrusted sources, install hooks, transitive dependencies | `python depaudit.py <dir>` |

## Shared properties

- Read-only: the target code is never executed, imported, or sent anywhere
- Zero dependencies: one file per tool, standard library only
- The same scoring scale across both tools

| Grade | Risk | Meaning |
|-------|------|---------|
| A | Low | No suspicious behaviour found |
| B | Medium | A few things worth a look |
| C | High | Clear dangerous behaviour |
| D | Critical | Fatal findings, do not run on your machine |

Any critical finding forces grade D. The usual ones are download-and-execute,
SSH key access, autorun persistence, and npm install hooks.

## Usage
cd code-audit && python audit.py ../some-project cd dep-audit && python depaudit.py ../some-project --online

Both tools support `--selftest`, which runs offline.

## Limitations

Static analysis only catches behaviour with a visible signature. Anything hiding in
a binary, assembled at runtime, or shipped through a hijacked upstream package will
not show up. The output is a risk estimate, not proof of safety.

## License

PolyForm Noncommercial License 1.0.0. You may read, study, modify and use this for
personal and research purposes. Commercial use requires a separate license.
