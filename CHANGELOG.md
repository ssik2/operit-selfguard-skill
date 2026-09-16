# Changelog

## 1.1.0 - 2026-09-16

- 新增斜杠指令：`/selfguard`（别名 `/sg`），支持 `scan` / `probe` / `report` 三个子命令
- 指令里可直接带 `--depth` / `--files` / `--findings` / `--env` 参数
- 指令格式写进 `SKILL.md` 的 `description`，靠描述常驻上下文实现（Operit 无原生斜杠解析）
- README 重写：指令放最前，安装拆成“装技能 / 装引擎”两步，补机制说明

## 1.0.0 - 2026-09-16

- 首次发布
