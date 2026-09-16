# selfguard_audit

给 [Operit](https://github.com/AAswordman/Operit) 用的工程安全自检技能。

用它扫自己写的项目，找几类最容易出事、也最容易被忽略的问题：写死在代码或产物里的密钥、长得像真凭据的字符串、URL 里带的 token、DES/ECB 这类弱加密和固定 IV、`eval` 与 `child_process` 拼接执行、打包时忘了剥掉的 sourcemap。另外可以不解压就看 `.toolpkg` / `.apk` / `.zip` 里有什么，并按内容估个还原难度。

写的初衷是发版前自己过一遍，别把密钥打进包里，也别让人反编译后一眼就能看清源码结构。所以它只做静态扫描，不联网、不改文件。

## 先看清楚

只扫你自己的工程，或者你已经明确拿到授权的工程。别人家的软件、闭源 App、平台，不做认证绕过、令牌伪造、校验跳过、签名破解。这不是免责话术，是使用前提；越界的请求会被直接拒绝，包括各种"变通"的写法。

## 能查出什么

| 类别 | 具体表现 |
|---|---|
| 硬编码凭据 | `apiKey = "..."`、`password: "..."` 这类赋值 |
| 真凭据格式 | `sk-…`、`ghp_…`、`AKIA…`、JWT、`-----BEGIN PRIVATE KEY-----` |
| URL 带密钥 | `?access_token=`、`?api_key=`、`?signature=` |
| 弱加密 | DES、RC4、ECB 模式、固定 IV、用 MD5/SHA1 存口令 |
| 动态执行 | `eval`、`new Function`、`child_process` 拼接命令 |
| sourcemap 泄漏 | 产物里残留 `sourceMappingURL=`、`sourceURL=` |
| 产物内容 | `.toolpkg` / `.apk` / `.zip` 免解压列条目 + 可逆性评分 |

误报是有的，尤其"硬编码凭据"这一条：正则命中不等于真问题，得你自己看一眼。宁可多报一条，也不想漏。

## 安装

方式一：下载 `dist/selfguard_audit-skill-v1.0.0.zip`，解压到 `/sdcard/Download/Operit/skills/`。

方式二：直接拷目录。把仓库里的 `selfguard_audit/` 整个放进 `/sdcard/Download/Operit/skills/`，最终结构是：

```text
/sdcard/Download/Operit/skills/selfguard_audit/
├── SKILL.md
├── scripts/
│   ├── selfguard_scan.js
│   └── params.example.json
└── references/
    └── POLICY.md
```

然后在 Operit 里打开 **包管理 → 技能 → 刷新**，列表里会出现 `selfguard_audit`。条目右边的开关决定 AI 会不会自动用它。

Operit 是直接读这个目录的，本地那份要留着，不能只放云端。

## 使用

检测引擎是独立的沙盒包 `selfguard`（源码在 `package/selfguard.js`，需要单独装进 Operit）。这个 Skill 负责的是"什么时候该用、怎么调、结果怎么读"。

首选走沙盒包，能力最全，支持二进制产物探测：

```text
use_package("selfguard")
selfguard:selfguard  action=scan_source     path=/sdcard/Download/myproject
selfguard:selfguard  action=probe_artifact  path=/sdcard/Download/app.toolpkg
selfguard:selfguard  action=report          path=/sdcard/Download/myproject
```

- `action` 不填默认 `scan_source`
- `environment` 默认 `android`；扫 Linux 侧的工程填 `linux`
- `max_depth` / `max_files` / `max_findings` 默认 8 / 300 / 150

包没启用的话：

```text
operit_editor:set_sandbox_package_enabled(package_name="selfguard", enabled=true)
operit_editor:debug_install_js_package(source_path="/sdcard/Download/Operit/dev_package/selfguard/selfguard.js")
```

同一个引擎还有个等价的包 `pojia_guard`，`use_package("pojia_guard")` 之后调 `pojia_guard:pojia_guard`，参数一样。

只想跑一次、不想装包，可以走脚本：把参数写进 `scripts/params.json`（照着 `params.example.json` 抄），然后调

```text
operit_editor:debug_run_sandbox_script(source_path="/sdcard/Download/Operit/skills/selfguard_audit/scripts/selfguard_scan.js")
```

脚本把参数转发给沙盒包。包不在时它会报错并给出安装命令，不会给你一份编出来的结果。

## 输出

每条命中包含：风险级别、文件与行号、类别、命中的原始片段、修改建议。
二进制产物另外给条目清单（路径、压缩方式、压缩前后大小）和可逆性评分及理由。
最后是一份按优先级排的修复清单：密钥挪到环境变量、口令换 KDF + AEAD、去掉动态执行、构建时剥掉 sourcemap、补混淆与完整性校验。

## 仓库结构

```text
.
├── README.md
├── LICENSE
├── CHANGELOG.md
├── selfguard_audit/              # Skill 本体（拷进 skills/ 即可用）
│   ├── SKILL.md
│   ├── scripts/
│   │   ├── selfguard_scan.js
│   │   └── params.example.json
│   └── references/
│       └── POLICY.md
├── package/
│   └── selfguard.js              # 检测引擎（沙盒包源码）
└── dist/
    ├── selfguard_audit-skill-v1.0.0.zip
    └── selfguard-audit-src-v1.0.0.zip
```

## 想改点什么

| 目标 | 改哪里 |
|---|---|
| AI 什么时候自动用它、看到的简介 | `SKILL.md` 顶部 frontmatter 的 `description` |
| 执行流程、参数说明、输出要求 | `SKILL.md` 正文 |
| 备用脚本行为、默认参数 | `scripts/selfguard_scan.js` |
| 检测规则本身 | `package/selfguard.js`（沙盒包，改完要重新烧录） |
| 边界与免责声明 | `references/POLICY.md` |

改完去 **包管理 → 技能 → 刷新** 重新读一次。

## 已知限制

- 纯静态正则加启发式，不做数据流分析，跨行拼接的密钥可能扫不到。
- 不联网，也不验证命中的密钥是否还在生效。
- 可逆性评分是启发式估算，不能替代完整的逆向评估。
- 二进制探测只读容器目录，不反编译代码。

## 许可

MIT，见 [LICENSE](LICENSE)。

## 声明

本插件仅用于学习和参考。只允许检测你自己拥有、或已获得明确书面授权的工程与产物；严禁用于绕过他人版权、授权、DRM、支付或访问控制。使用者需自行确保对被测对象拥有合法处置权，作者不对越界使用承担责任。
