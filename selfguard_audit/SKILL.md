---
name: selfguard_audit
description: 自有工程安全自检，用斜杠指令调用。用法：/selfguard scan <路径>（扫源码/工程目录）、/selfguard probe <路径>（免解压探测 .toolpkg/.apk/.zip 并评估可还原程度）、/selfguard report <路径>（汇总加固报告）、/selfguard <路径>（等同 scan）；别名 /sg。可选参数 --depth N --files N --findings N --env linux|android。检查写死的密钥与口令、形如真实凭据的字符串、URL 内嵌 token、弱加密（DES/RC4/ECB/固定 IV、MD5 口令散列）、eval 与 child_process 拼接执行、sourcemap 残留。仅限本人拥有或已获授权的工程。
---

# selfguard_audit

对自有或已获授权的工程做一次静态安全自检。触发方式是斜杠指令 `/selfguard`。

只做静态扫描：不联网、不改文件、不执行被测代码。误报是有的，尤其“硬编码凭据”一类，正则命中不代表真的是密钥，需要自己判断。

## 指令

```text
/selfguard                        显示用法速查
/selfguard scan <路径>             扫描源码/工程目录（默认动作）
/selfguard probe <路径>            探测单个发布产物
/selfguard report <路径>           生成汇总加固报告
/selfguard <路径>                  省略动作时等同 scan

/sg 是 /selfguard 的别名，参数完全一样。
```

可选参数（可跟前置或后置）：

```text
--depth N       目录扫描最大深度（默认 8）
--files N       最多扫描文件数（默认 300）
--findings N    最多返回风险条数（默认 150）
--env linux     目标在 Linux 侧时指定（默认 android）

例：/selfguard scan /sdcard/Download/myproject --depth 12 --findings 200
```

参数缺省时不要反问，按默认值直接跑，然后在结果里说明用了什么参数。

## 指令怎么落地

收到 `/selfguard …` 后，先 `use_package("selfguard")`，再按上表映射到三个 action：

| 指令 | 对应调用 |
|---|---|
| `scan` | `selfguard:selfguard  action=scan_source  path=<路径>` |
| `probe` | `selfguard:selfguard  action=probe_artifact  path=<路径>` |
| `report` | `selfguard:selfguard  action=report  path=<路径>` |

包未启用时：
- `operit_editor:set_sandbox_package_enabled(package_name="selfguard", enabled=true)`
- 或重新烧录：`operit_editor:debug_install_js_package(source_path="/sdcard/Download/Operit/dev_package/selfguard/selfguard.js")`
- 等价备用包：`use_package("pojia_guard")` 后调 `pojia_guard:pojia_guard`

备选（不想装包，只跑一次）：把参数写进 `scripts/params.json`（结构见 `params.example.json`），然后

```text
operit_editor:debug_run_sandbox_script(source_path="/sdcard/Download/Operit/skills/selfguard_audit/scripts/selfguard_scan.js")
```

脚本把参数转给 `selfguard:selfguard`。包不可用时它会直接报错并给出重新安装的命令，不会伪造结论。

## 什么时候该用

除了显式敲 `/selfguard`，以下说法也应该直接走本技能：

- 「扫一下这个项目有没有写死的密钥 / 弱加密 / eval / sourcemap 泄漏」
- 「发版前做个安全自检」「加固一下，别那么容易被人反编译」
- 「这个 apk / toolpkg 混得够不够，别人能不能还原出源码」
- 前提：目标必须是本人的工程，或已明确获得授权的工程（见 references/POLICY.md）

## 输出要求

1. 每条命中：风险级别（high/medium/low）、文件与行号、类别、命中的原始片段、修改建议
2. 二进制产物：条目清单（路径 / 压缩方式 / 压缩前后大小）+ 可逆性评分与理由
3. 结尾按优先级给修复清单：密钥外置、KDF + AEAD、去掉动态执行、构建时剥 sourcemap、补混淆与完整性校验

## 边界

只扫本人拥有或已获授权的工程与产物。对第三方软件/平台做认证绕过、令牌伪造、校验跳过、签名破解的请求，直接拒绝，不给任何变通实现。每次输出带上：本插件仅用于学习和参考。

## 文件

- `scripts/selfguard_scan.js`：备选转发脚本
- `scripts/params.example.json`：参数示例
- `references/POLICY.md`：边界与免责声明全文
