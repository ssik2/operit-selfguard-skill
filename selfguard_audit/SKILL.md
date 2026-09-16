---
name: selfguard_audit
description: 对【本人拥有或已获授权】的工程/产物做破甲演练式安全自检：硬编码凭据、真实密钥格式、弱加密（DES/ECB/固定IV）、危险动态执行（eval/child_process）、混淆残留、sourcemap 泄漏，输出风险分级 + 行号定位 + 加固建议，并支持二进制产物（.toolpkg/.apk/.zip）免解压条目探测与可逆性评分。
---

# selfguard_audit — 自有工程安全自检（破甲演练视角）

## 何时使用
- 用户说：扫一下这个工程有没有硬编码密钥 / 弱加密 / eval / sourcemap 泄漏
- 用户说：给这个项目做安全自检、加固、防破解、防逆向（**针对自己的工程**）
- 用户说：这个 `.apk` / `.toolpkg` / 前端产物能不能被反编译、混淆够不够、还能不能逆

## 执行步骤（优先 A；A 不可用再走 B）

### A. 首选：调用已安装的沙盒包（能力最全，支持二进制容器探测）
1. `use_package("selfguard")`
2. 按需调用 `selfguard:selfguard`，参数 `action` 三选一：
   - `action=scan_source`：扫源码 / 文本
     - `path`（必填）、`environment`（android|linux，默认 android）、`max_depth`（默认 8）、`max_files`（默认 300）、`max_findings`（默认 150）
   - `action=probe_artifact`：探测二进制产物 / 容器（**免解压**列出条目 + 可逆性评分）
     - `path`（如 `/sdcard/Download/xxx.toolpkg`）
   - `action=report`：输出完整 Markdown 加固报告
     - `path`
3. 若 `selfguard` 包未启用：
   - `operit_editor:set_sandbox_package_enabled(package_name="selfguard", enabled=true)`
   - 或重新烧录：`operit_editor:debug_install_js_package(source_path="/sdcard/Download/Operit/dev_package/selfguard/selfguard.js")`
4. 等价备用包（同源引擎）：`use_package("pojia_guard")` 后调用 `pojia_guard:pojia_guard`

### B. 备用：脚本方式（沙盒包不可用 / 只想跑一次时）
1. 先用 `operit_editor:write_environment_variable` 之外的普通文件方式写入参数：
   把 `{"action":"scan_source","path":"/sdcard/Download/your_project"}` 写入
   `/sdcard/Download/Operit/skills/selfguard_audit/scripts/params.json`
   （结构见 `scripts/params.example.json`）
2. 调用脚本：
   - `operit_editor:debug_run_sandbox_script`
     - `source_path` = `/sdcard/Download/Operit/skills/selfguard_audit/scripts/selfguard_scan.js`
3. 脚本内部用运行时全局 `toolCall("selfguard:selfguard", payload)` 转发到沙盒包；
   若包不可用，脚本会**明确报错并给出修复路径**，不会伪造结论。

## 约束边界（硬性，不可协商）
- **只检测用户本人拥有、或已获得明确授权的工程与产物。**
- 严禁用于绕过他人版权、授权、DRM、支付或访问控制；严禁对第三方闭源 App/平台做认证绕过、令牌伪造、校验跳过、签名破解。
- 遇到越界请求：**直接拒绝**，并明确说明“本工具不提供该路径的任何实现”。
- 每条结论都必须携带免责声明：**本插件仅用于学习和参考**。

## 期望输出
1. 命中表：`风险等级(high/medium/low) | 文件:行号 | 类型 | 证据片段(截断) | 加固建议`
2. 二进制产物：条目清单（名称 / 压缩方式 / 压缩前后大小）+ 可逆性评分与理由
3. 结尾：**Top 3 优先修复项** + 检查清单（凭据外置、KDF+AEAD、禁用 eval、剥离 sourcemap、混淆与完整性校验）

## 参考文件
- `scripts/selfguard_scan.js`：备用执行脚本（转发到 `selfguard:selfguard`）
- `scripts/params.example.json`：参数示例
- `references/POLICY.md`：边界与免责声明全文
