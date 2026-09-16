# selfguard_audit — Operit Skill：自有工程安全自检（破甲演练视角）

一个给 [Operit](https://github.com/AAswordman/Operit) 用的 **Skill**：对**本人拥有或已获明确授权**的工程 / 发布产物做安全自检，输出「风险分级 + 行号定位 + 加固建议」，并支持二进制产物的**免解压条目探测 + 可逆性评分**。

> ⚠️ **用途声明**：本项目仅用于**学习和参考**。只允许检测**你自己拥有、或已获得明确书面授权**的工程与产物。**严禁**用于绕过他人版权、授权、DRM、支付或访问控制；**严禁**对第三方闭源 App / 平台做认证绕过、令牌伪造、校验跳过、签名破解。

---

## 它能查出什么

| 类别 | 说明 |
|---|---|
| 硬编码凭据 | 源码里写死的密钥 / 口令 / 账号赋值 |
| 凭据 / 私钥泄漏 | 符合真实密钥格式的片段（`sk-live-…`、私钥头等） |
| URL 内嵌密钥 | 查询串里携带 `access_token` / `api_key` 等 |
| 弱加密算法 | DES / RC4 / ECB / 固定 IV、MD5 / SHA1 口令散列 |
| 危险动态执行 | `eval` / `new Function` / `child_process` 拼接执行 |
| Sourcemap 泄漏 | 产物携带 `sourceMappingURL` / `sourceURL` |
| 二进制产物探测 | `.toolpkg` / `.apk` / `.zip` 免解压列出条目 + 可逆性评分 |

---

## 安装（在 Operit 里）

Skill 的部署方式就是「放文件夹」：

```bash
# 目标位置
/sdcard/Download/Operit/skills/selfguard_audit/
```

1. 把本仓库里的 `selfguard_audit/` 整个目录复制到 `/sdcard/Download/Operit/skills/` 下，
   最终结构必须是：
   ```text
   /sdcard/Download/Operit/skills/selfguard_audit/
     SKILL.md
     scripts/selfguard_scan.js
     scripts/params.example.json
     references/POLICY.md
   ```
2. 打开 Operit → **包管理 → 技能** → 右上角「**刷新**」，即可看到 `selfguard_audit`
3. 确认该条目右侧开关处于**打开**状态（控制 AI 是否自动使用本 Skill）

> 注意：Skill 由 Operit **直接读取本地文件夹**，所以本地副本必须保留，不能只放到云端。

---

## 使用

### A. 首选：调用沙盒包（能力最全，含二进制容器探测）

```text
use_package("selfguard")
selfguard:selfguard  action=scan_source      path=<工程目录>
selfguard:selfguard  action=probe_artifact   path=<.toolpkg/.apk/.zip>
selfguard:selfguard  action=report           path=<工程目录>
```

若 `selfguard` 沙盒包未启用：
- `operit_editor:set_sandbox_package_enabled(package_name="selfguard", enabled=true)`
- 或重新烧录：`operit_editor:debug_install_js_package(source_path="<dev_package/selfguard/selfguard.js>")`

### B. 备用：脚本方式

1. 写参数：`scripts/params.json`
   ```json
   {"action":"scan_source","path":"/sdcard/Download/your_project","max_findings":50}
   ```
   （结构见 `scripts/params.example.json`）
2. `operit_editor:debug_run_sandbox_script(source_path=".../selfguard_audit/scripts/selfguard_scan.js")`
3. 脚本内部用运行时全局 `toolCall("selfguard:selfguard", payload)` 转发；包不可用时会**明确报错并给出修复路径**，不会伪造结论。

---

## 目录结构

```text
selfguard_audit/
├── SKILL.md                      # 主文件：frontmatter + 使用场景 / 执行步骤 / 约束边界 / 期望输出
├── scripts/
│   ├── selfguard_scan.js         # 备用执行脚本（读取 params.json → 转发到 selfguard 沙盒包）
│   └── params.example.json       # 参数示例
└── references/
    └── POLICY.md                 # 边界与免责声明全文
```

---

## 自定义

| 想改什么 | 改哪个文件 |
|---|---|
| 「什么时候自动用我」、AI 看到的简介 | `SKILL.md` 顶部 frontmatter 的 `description` |
| 执行流程 / 参数说明 / 输出格式 / 边界文案 | `SKILL.md` 正文 |
| 备用脚本行为、默认参数 | `scripts/selfguard_scan.js` |
| 检测规则本身（加规则、压误报、忽略清单） | 沙盒包 `selfguard.js`（不在本仓库），改完重新烧录 |

改完后到 **包管理 → 技能 → 刷新** 重新读取。

---

## 免责声明

> 本插件仅用于学习和参考，只允许检测本人拥有或已获授权分析的工程；严禁用于绕过他人版权、授权、DRM 或访问控制。

使用者需自行确保其对所检测的工程 / 产物拥有合法处置权。作者不对任何越界使用承担责任。
