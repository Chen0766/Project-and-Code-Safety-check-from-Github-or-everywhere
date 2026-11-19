# dep-audit

检查依赖清单和锁文件，看有没有山寨包、可疑来源、没锁的版本、安装钩子。

`npm install` 或 `pip install` 一敲，你就在以自己的身份执行别人写的安装脚本。源码干净、依赖被投毒，一样中招。

只读清单，不安装、不下载任何包。只用 Python 标准库。

配套工具 `code-audit` 查代码本身写了什么，这个查它要拉进来什么。

## 用法

```
python depaudit.py <项目目录>             离线，只用本地规则，不联网
python depaudit.py <项目目录> --online    联网核验 PyPI / npm
python depaudit.py --selftest             自检
python depaudit.py <目录> --blocklist my.json   追加黑名单
```

退出码：`0` = A/B，`1` = C，`2` = D，`3` = 路径错误。

## 检查什么

| # | 检查项 | 判据 |
|---|---|---|
| 1 | 名字是不是山寨 | 和 220 个高频包名做编辑距离，差 1 个字符、少了分隔符、`l/I/1` 形近，报候选 |
| 2 | 来源可不可信 | 非官方 index、`git+http://`、`file:` / `link:` 本地依赖、`--trusted-host` |
| 3 | 版本锁没锁 | 没写版本、只写下限、`*`、`latest` |
| 4 | 有没有安装钩子 | `package.json` 的 preinstall / install / postinstall / prepare，`pyproject.toml` 的 cmdclass |
| 5 | 传递依赖 | 读锁文件，把没在清单里声明、但会一起装的包也查一遍 |

### 支持的锁文件

`package-lock.json`（v1/v2/v3）、`npm-shrinkwrap.json`、`yarn.lock`、`pnpm-lock.yaml`、`poetry.lock`、`uv.lock`、`Pipfile.lock`

对传递依赖查三件事：

- 安装钩子：npm 锁文件里 `hasInstallScript: true` 的条目
- 下载地址：`resolved` 指向非官方仓库，说明包被换过或走了私服
- 恶意或山寨名：整棵树过黑名单，前 400 个额外做形近比对

`--online` 再加三项：包在不在（404 说明拼错或已下架）、整个包是不是新上线（30 天内算高风险）、指定版本是否被 yanked 撤回，以及 npm 的 latest 版是否带 postinstall。

## 评级

| 等级 | 风险 | 含义 |
|---|---|---|
| A | 低 | 名字正常、来源正式、版本基本锁定 |
| B | 中 | 有卫生问题，不致命 |
| C | 高 | 有需要人工确认的项 |
| D | 极高 | 有致命项：山寨名、安装钩子、可疑来源 |

扣分：致命 40 / 高 18 / 中 8 / 低 3。同类封顶 45。版本、山寨、来源这几类按条数计（最多 5 条），其余每类只算一次。命中致命项直接判 D。

## 自检

```
python depaudit.py --selftest
```

九项断言，离线可跑：干净清单判 A、脏清单判 D、认出 `reqeusts` 与 `requests` 的差别、认出 postinstall 钩子、认出已知恶意包、读到传递依赖、认出锁文件里的安装钩子、认出锁文件里的非官方来源、干净锁文件不误报。

## 扩展黑名单

`my.json` 格式：`{"pypi": ["包名"], "npm": ["包名"]}`

内置名单只有二十来个公开案例，是示例不是全量，正式使用建议自己维护。

## 局限

- 编辑距离只能抓长得像的，抓不到完全不同但恶意的包。
- 防不住官方包被接管后投毒（`event-stream` 那种），这种只能靠锁文件加审查 diff。
- npm 不查发布时间，官方没有轻量接口，拉全量 packument 对热门包是几 MB。
- `--online` 会把依赖名单发给 pypi.org 和 npmjs.org，介意就只用离线模式。
- 传递依赖的形近比对只做前 400 个，黑名单是全量过的。
- `pnpm-lock.yaml` 是 YAML，标准库没有解析器，按行正则兜底，复杂结构可能漏条目。
- 看不到运行时才装的依赖（`npx`、动态 import）。

## 许可

未附带 LICENSE 文件，默认保留所有权利。只依赖 Python 标准库（PSF 许可）。

## 目录

```
depaudit.py          主程序
启动依赖审查.bat      双击即跑
README.md
reports/             报告（md + json），不入库
```
