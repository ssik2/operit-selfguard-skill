---
name: selfguard_audit
description: 自有工程安全自检。扫源码/工程目录里写死的密钥与口令、长得像真凭据的字符串、URL 内嵌 token、弱加密（DES/RC4/ECB/固定 IV、MD5 口令散列）、eval 与 child_process 拼接执行、sourcemap 残留；也能免解压探测 .toolpkg / .apk / .zip 并评估可还原程度、汇总加固报告。在 Operit 里输入 / 后从面板选中本技能即可调用，也可以直接说“安全自检 / 加固体检 + 路径”。接受动作词 scan / probe / report 与参数 --depth / --files / --findings / --env。仅限本人拥有或已获授权的工程。
---

# selfguard_audit

对自有或已获授权的工程做一次静态安全自检。

只做静态扫描：不联网、不改文件、不执行被测代码。误报是有的，尤其“硬编码凭据”一类，正则命中不代表真的是密钥，需要自己判断。

## 在 Operit 里怎么调用

先说清楚平台机制：**Operit 输入框的 `/` 是引用（mention）选择器，不是命令行解析器**。相关源码在 `app/src/main/java/com/ai/assistance/operit/ui/features/chat/webview/WorkspaceFileSelector.kt` 与 `ui/features/chat/viewmodel/ChatViewModel.kt` 的 `findActiveMentionTrigger`。它的实际行为：

- 光标所在的“不含空格的片段”里，最近的那个 `/`（在行首，或前面是空格）算触发符；
- `/` 之后到光标的那串字，被当作**搜索词**，去匹配 工具包 / Skill 包 / MCP 包 的包名、标题、描述；
- 搜索词为空 → 列出全部包；匹配不到 → 面板显示“没有匹配的包”；
- 选中某一项 → 输入框写入 `/包名 `，并把该包的内容（对本技能就是这份 SKILL.md）作为**附件**挂到这条消息上。

所以三种调用方式都能用：

**方式 A：斜杠唤起（推荐，和电脑版一致）**

```text
1. 输入 /
2. 在面板里选中 selfguard_audit（也可以先打 sel 过滤）
3. 空格之后写需求，例如 scan /sdcard/Download/myproject --depth 12
4. 发送
```

**方式 B：一行写完**

```text
/selfguard scan /sdcard/Download/myproject --findings 200
```

注意：这行里有以 `/` 开头的路径，输入框上方的面板会跟着弹出来，并按“光标前最后一段路径”当搜索词，于是显示“没有匹配的包”。这是引用选择器的正常表现，不是报错，**不影响消息发送，忽略它直接发即可**。不要为了躲开提示去改路径写法，路径照写。

**方式 C：不说斜杠**

直接说人话同样走本技能：「扫一下这个项目有没有写死的密钥」「发版前做个安全自检」「这个 toolpkg 别人能不能还原出源码」。

## 动作与参数

方式 A / C 用自然语言说清动作和路径就行。方式 B 的字符串约定如下——它是写给 AI 读的语义约定，不是平台语法：

```text
/selfguard                        显示用法速查
/selfguard scan <路径>             扫描源码/工程目录（默认动作）
/selfguard probe <路径>            探测单个发布产物
/selfguard report <路径>           生成汇总加固报告
/selfguard <路径>                  省略动作时等同 scan

/sg 是 /selfguard 的别名，参数完全一样。
```

可选参数（可前置或后置）：

```text
--depth N       目录扫描最大深度（默认 8）
--files N       最多扫描文件数（默认 300）
--findings N    最多返回风险条数（默认 150）
--env linux     目标在 Linux 侧时指定（默认 android）
例：/selfguard scan /sdcard/Download/myproject --depth 12 --findings 200
```

参数缺省时不要反问，按默认值直接跑，然后在结果里说明用了什么参数。

## 指令怎么落地

收到斜杠写法、方式 A 的附件、或上述自然语言说法后，先 `use_package("selfguard")`，再按上表映射到三个 action：

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