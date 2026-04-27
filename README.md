# 网络扫描双模块工具

基于 Tkinter 的本地网络资产探测工具，包含两大模块：

- 模块1：主机发现（Ping / TCP / ARP 兜底）
- 模块2：端口扫描（支持常见端口或自定义端口段）

## 功能特性

- 主机探测策略可选：`ping-only` / `ping+tcp` / `tcp-only`
- 对 Ping/TCP 都不通的目标支持 ARP 兜底探测
- 支持“仅同网段启用 ARP 兜底”开关
- 模块1三态结果：`online` / `suspected` / `offline`
- 生成 HTML 报告（含 IP 分布图、状态统计、端口明细）

## 运行方式（源码）

```bash
python network_scan_gui.py
```

## 打包 EXE

```bash
python -m PyInstaller --noconfirm --clean --onefile --windowed --name "network_scan_gui" "network_scan_gui.py"
```

生成物路径：

- `dist/network_scan_gui.exe`

## 发布到 GitHub（推荐）

建议使用“两层发布”：

1. 仓库只存源码（不提交 `dist/`、`build/`）
2. 可执行文件放到 GitHub Releases 附件

### 版本发布建议

- Tag：`v1.0.0`、`v1.0.1`...
- Release 标题：与 Tag 一致
- 附件：`network_scan_gui.exe`

### Release 说明模板

```text
## 更新内容
- 优化界面布局，默认窗口显示完整按钮
- 增加 TCP 补探测端口可配置
- 增加 ARP 兜底与同网段限制开关
- 模块1结果升级为 online/suspected/offline 三态

## 使用说明
- 下载并双击 network_scan_gui.exe
- 仅在授权网络环境中使用
```

## 免责声明

本工具仅用于授权环境下的资产探测与运维排查，请勿用于未授权场景。
