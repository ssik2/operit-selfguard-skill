# Changelog

## 1.1.1 - 2026-09-16

- 按平台真实机制重写调用说明。实测确认：Operit 输入框的 `/` 是**引用选择器**（`WorkspaceFileSelector.kt` 的 Packages 面板），不是命令行解析器；`/` 后到光标之间的无空格文本会被当作搜索词去匹配包名/标题/描述
- 因此把推荐用法改为：敲 `/` → 面板里选中 `selfguard_audit`（`SKILL.md` 内容会自动作为附件挂上）→ 空格后写需求
- 明确记录一行写完 `/selfguard scan <路径>` 时的现象：路径里的斜杠会让面板把最后一段路径当搜索词，显示“没有匹配的包”。这是正常表现，不影响发送（面板只是悬浮提示，不拦截输入、不改写文本）
- 同步更新 `SKILL.md` 的 `description` 与 README 的调用段、安装段、已知限制

## 1.1.0 - 2026-09-16

- 新增斜杠指令：`/selfguard`（别名 `/sg`），支持 `scan` / `probe` / `report` 三个子命令
- 指令里可直接带 `--depth` / `--files` / `--findings` / `--env` 参数
- 指令格式写进 `SKILL.md` 的 `description`，靠描述常驻上下文实现（Operit 无原生斜杠解析）
- README 重写：指令放最前，安装拆成“装技能 / 装引擎”两步，补机制说明
- 修复 `environment=linux` 时目录能列、文件读不到的问题：`readSegments` 未透传 environment，且 `Files.read` 需用 `{path, environment}` 重载调用

## 1.0.0 - 2026-09-16

- 首次发布
