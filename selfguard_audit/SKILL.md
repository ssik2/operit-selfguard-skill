---
name: selfguard_audit
description: 自有工程安全自检。检查项目里写死的密钥/口令、形如真实凭据的字符串、URL 内嵌 token、弱加密（DES/RC4/ECB/固定 IV、MD5 口令散列）、eval 与 child_process 拼接执行、sourcemap 残留；也能免解压探测 .toolpkg/.apk/.zip 的条目并评估可还原程度。触发场景：安全自检、代码审计、加固、防破解、防逆向、密钥泄漏排查、发版前检查、混淆效果与可逆性评估。仅限本人拥有或已获授权的工程。
---

# selfguard_audit

对自有或已获授权的工程做一次静态安全自检。

只做静态扫描：不联网、不改文件、不执行被测代码。误报是有的，尤其“硬编码凭据”一类，正则命中不代表真的是密钥，需要自己判断。

## 什么时候用

- 用户说：「扫一下这个项目有没有写死的密钥 / 弱加密 / eval / sourcemap 泄漏」
- 用户说：「发版前做个安全自检」「加固一下，别那么容易被人反编译」
- 用户说：「这个 apk / toolpkg 混得够不够，别人能不能还原出源码」
- 前提：目标必须是本人的工程，或已明确获得授权的工程（见 references/POLICY.md）

## 怎么跑

### 首选：调用沙盒包

```text
use_package("selfguard")
selfguard:selfguard  action=scan_source     path=/sdcard/Download/myproject
selfguard:selfguard  action=probe_artifact  path=/sdcard/Download/app.toolpkg
selfguard:selfguard  action=report          path=/sdcard/Download/myproject
```

参数：
- `action`：`scan_source`（默认，扫源码/文本）、`probe_artifact`（单个产物）、`report`（汇总报告）
- `path`：目标文件或目录（必填）
- `environment`：`android`（默认）或 `linux`
- `max_depth` / `max_files` / `max_findings`：默认 8 / 300 / 150

包未启用时：
- `operit_editor:set_sandbox_package_enabled(package_name="selfguard", enabled=true)`
- 或重新烧录：`operit_editor:debug_install_js_package(source_path="/sdcard/Download/Operit/dev_package/selfguard/selfguard.js")`
- 等价备用包：`use_package("pojia_guard")` 后调 `pojia_guard:pojia_guard`

### 备选：脚本转发

把参数写进 `scripts/params.json`（结构见 `params.example.json`），然后：

```text
operit_editor:debug_run_sandbox_script(source_path="/sdcard/Download/Operit/skills/selfguard_audit/scripts/selfguard_scan.js")
```

脚本把参数转给 `selfguard:selfguard`。包不可用时它会直接报错并给出重新安装的命令，不会伪造结论。

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
