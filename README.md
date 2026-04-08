# 📡 WiFi 热点流量监控工具

实时监控 Windows 移动热点连接设备的流量使用情况，支持设备历史记录、按日/月/年流量统计，以及校园网 TTL 伪装。

![Python](https://img.shields.io/badge/Python-3.8+-blue) ![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey) ![License](https://img.shields.io/badge/License-MIT-green)

## 功能特性

- **实时监控**：每 2 秒刷新，显示连接设备的 IP、MAC、实时上下行速率、累计流量
- **设备历史**：自动记录所有曾连接过的设备，含首次/最后连接时间、累计上线次数
- **流量统计**：按日 / 月 / 年 / 全部统计各设备用量，支持排序
- **自定义设备名**：双击或右键重命名设备，名称持久保存
- **校园网模式**：将 Windows TTL 改为 64，绕过校园网通过 TTL 差异检测多设备的机制
- **断开设备**：通过重启热点快速断开指定设备
- **数据持久化**：设备历史、流量日志、自定义名称均保存至本地 `data/` 目录

## 截图

> 实时监控 / 设备历史 / 流量统计 三个标签页

## 环境要求

| 依赖 | 说明 |
|------|------|
| Python 3.8+ | [python.org](https://www.python.org/) |
| psutil | `pip install psutil` |
| scapy | `pip install scapy`（流量统计需要） |
| Npcap | [npcap.com](https://npcap.com/#download)（安装时勾选 WinPcap API-compatible Mode） |

> 不安装 scapy / Npcap 时程序仍可运行，但流量数据显示为 0，仅支持设备列表扫描。

## 安装与运行

```bash
pip install scapy psutil
```

**必须以管理员身份运行**（修改 TTL 和网络抓包需要管理员权限）：

- 双击 `以管理员启动.bat` 即可
- 或右键 `启动监控.bat` → 以管理员身份运行

## 校园网模式说明

校园网通过比对数据包 TTL 判断是否有多台设备共享流量。

| 场景 | TTL |
|------|-----|
| 手机直接上网 | 64 |
| 电脑通过热点（默认）| 128 → 学校看到 127（每跳 -1） |
| 开启校园网模式后 | 64 → 学校看到 63，与手机一致 |

**⚠ 注意**：此方法只能绕过 TTL 检测，若学校还使用以下方式检测，TTL 伪装无效：

- HTTP 请求头检测（`Via`、`Proxy-Connection` 字段）→ **手机端关闭代理/VPN**
- DPI 深度包检测
- UA 特征识别

## 数据文件

```
data/
├── custom_names.json   # 自定义设备名称
├── device_history.json # 设备连接历史
└── traffic_log.json    # 按日流量日志
```

`data/` 目录已加入 `.gitignore`，不会上传到 GitHub。

## License

MIT
