# 📡 WiFi 热点流量监控工具

> 一款运行在 Windows 上的 WiFi 热点实时流量监控工具，帮助你掌握每台连接设备的网速与用量，同时内置校园网多设备检测绕过功能。

![Python](https://img.shields.io/badge/Python-3.8+-blue) ![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey) ![License](https://img.shields.io/badge/License-MIT-green)

## 🧐 软件用途

当你在宿舍或寝室用电脑开 Windows 移动热点给手机/平板等设备共享网络时，这款工具能帮你做到：

| 需求 | 解决方案 |
|------|----------|
| 想知道哪台设备在疯狂占带宽 | 实时显示每台设备的上下行速率 |
| 想统计室友/自己每天/每月用了多少流量 | 按日 / 月 / 年 / 全部 查看流量记录 |
| 校园网检测到多设备后断网 | 内置 TTL 伪装，一键绕过 TTL 差异检测 |
| 想踢掉某台设备 | 右键选中设备一键断开 |
| 想记住每台设备叫什么 | 双击设备自定义备注名，持久保存 |
| 想查看历史上有哪些设备连过 | 完整设备连接历史，含首次/最后连接时间 |

## ✨ 功能特性

- **📊 实时监控**：每 2 秒刷新，显示连接设备的 IP、MAC、实时上下行速率、累计流量
- **📋 设备历史**：自动记录所有曾经连接过的设备，含首次/最后连接时间、累计上线次数
- **📈 流量统计**：按日 / 月 / 年 / 全部 筛选各设备流量用量，支持点击列头排序
- **✏️ 自定义设备名**：双击或右键重命名设备，名称持久保存，下次打开自动恢复
- **🏫 校园网模式**：将 Windows TTL 改为 64，绕过校园网通过 TTL 差异检测多设备共享的机制
- **⚡ 断开设备**：通过重启热点快速断开指定设备
- **💾 数据持久化**：设备历史、流量日志、自定义名称均保存至本地 `data/` 目录，重启不丢失

## 🖥️ 界面预览

三个标签页：**实时监控** / **设备历史** / **流量统计**

## 📦 下载安装

### 方式一：直接下载 exe（推荐，无需安装 Python）

前往 [Releases](../../releases) 页面下载最新版 `WiFi监控.exe`，双击右键以管理员身份运行即可。

### 方式二：从源码运行

**环境要求**

| 依赖 | 说明 |
|------|------|
| Python 3.8+ | [python.org](https://www.python.org/) |
| psutil | `pip install psutil` |
| scapy | `pip install scapy`（流量统计需要） |
| Npcap | [npcap.com](https://npcap.com/#download)（安装时勾选 WinPcap API-compatible Mode） |

> 不安装 scapy / Npcap 时程序仍可运行，但流量数据显示为 0，仅支持设备列表扫描。

```bash
pip install scapy psutil
```

**必须以管理员身份运行**（修改 TTL 和网络抓包需要管理员权限）：

- 双击 `以管理员启动.bat` 即可
- 或右键 `启动监控.bat` → 以管理员身份运行

## 🏫 校园网模式说明

校园网通过比对数据包 TTL 判断是否有多台设备共享流量。

| 场景 | TTL |
|------|-----|
| 手机直接上网 | 64 |
| 电脑通过热点（默认）| 128 → 学校看到 127（每跳 -1） |
| 开启校园网模式后 | 64 → 学校看到 63，与手机一致 |

**⚠️ 注意**：此方法只能绕过 TTL 检测，若学校还使用以下方式检测，TTL 伪装无效：

- **HTTP 头检测**（`Via`、`Proxy-Connection` 字段）→ 手机端**关闭代理/VPN**
- DPI 深度包检测
- UA 特征识别

## 🔨 自行打包 exe

安装 PyInstaller 后运行：

```bash
pip install pyinstaller
build_exe.bat
```

打包完成后 exe 在 `dist/WiFi监控.exe`。

## 📁 数据文件

```
data/
├── custom_names.json   # 自定义设备名称
├── device_history.json # 设备连接历史
└── traffic_log.json    # 按日流量日志
```

`data/` 目录已加入 `.gitignore`，不会上传到 GitHub。

## License

MIT
