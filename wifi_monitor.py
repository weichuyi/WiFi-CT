#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFi热点设备流量监控工具
需要管理员权限运行，依赖：scapy, psutil, npcap
安装：pip install scapy psutil
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import subprocess
import re
import time
import socket
import json
import os
from collections import defaultdict
from datetime import datetime, date

# 尝试导入scapy
try:
    from scapy.all import sniff, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import psutil
import winreg


# ─────────────────────── 颜色主题（Win11 Mica · 浅色） ───────────────────────

C = {
    # 背景层（白色/浅灰，Mica 质感）
    "base":     "#f3f3f3",   # 主背景（Mica 浅灰）
    "mantle":   "#ffffff",   # 标题栏/卡片（纯白）
    "crust":    "#e8e8e8",   # 最外层/分隔背景
    # 面板
    "surface0": "#f8f8f8",   # 轻卡片/表格背景
    "surface1": "#e3edff",   # 蓝色选中高亮
    "surface2": "#c7d9f8",   # 深选中/焦点边框
    # 文字
    "overlay0": "#c0c0c0",   # 极淡占位文字
    "overlay1": "#8a8a8a",   # 次级说明文字
    "text":     "#1a1a1a",   # 主文字（近黑）
    "subtext1": "#3c3c3c",   # 二级文字
    "subtext0": "#606060",   # 三级文字
    # 彩色 Accent（加深版，在白色背景上清晰）
    "blue":     "#0078d4",   # Win11 主蓝
    "green":    "#0e7a0e",   # 深翠绿
    "red":      "#c42b2b",   # 深红
    "yellow":   "#a85c00",   # 深琥珀
    "peach":    "#c45000",   # 深橙
    "teal":     "#007070",   # 青绿
    "pink":     "#b5006e",   # 品红
    "mauve":    "#6929c4",   # 深紫
    "lavender": "#3f51b5",   # 靛蓝
    "sky":      "#0097a7",   # 天蓝
    "sapphire": "#1565c0",   # 宝石蓝
}


def _darken(hex_color: str, factor: float = 0.82) -> str:
    """将颜色加深，用于 hover 效果"""
    c = hex_color.lstrip("#")
    r, g, b = int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)
    return f"#{int(r*factor):02x}{int(g*factor):02x}{int(b*factor):02x}"


class Tooltip:
    """鼠标悬停提示气泡"""
    def __init__(self, widget, text: str):
        self._widget = widget
        self._text   = text
        self._tip    = None
        widget.bind("<Enter>",   self._show, add="+")
        widget.bind("<Leave>",   self._hide, add="+")
        widget.bind("<Button>",  self._hide, add="+")

    def _show(self, event=None):
        if self._tip:
            return
        x = self._widget.winfo_rootx() + 10
        y = self._widget.winfo_rooty() + self._widget.winfo_height() + 4
        self._tip = tw = tk.Toplevel(self._widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tw.wm_attributes("-topmost", True)
        outer = tk.Frame(tw, bg=C["blue"], padx=1, pady=1)
        outer.pack()
        tk.Label(outer, text=self._text,
                 font=("微软雅黑", 8),
                 fg=C["text"], bg=C["surface0"],
                 padx=10, pady=5).pack()

    def _hide(self, event=None):
        if self._tip:
            self._tip.destroy()
            self._tip = None


def _make_rounded_card(parent, color: str, title: str,
                       default_val: str, val_font_size: int = 16):
    """发光边框卡片：1px 彩色外框 + 左侧色条，返回 (card_frame, value_label)"""
    # 外层用 accent 色作 1px 边框 → 产生发光感
    glow = tk.Frame(parent, bg=color, padx=1, pady=1)

    inner = tk.Frame(glow, bg=C["surface0"])
    inner.pack(fill=tk.BOTH, expand=True)

    # 左侧 4px 色条
    tk.Frame(inner, bg=color, width=4).pack(side=tk.LEFT, fill=tk.Y)

    content = tk.Frame(inner, bg=C["surface0"], padx=14, pady=10)
    content.pack(fill=tk.BOTH, expand=True)

    tk.Label(content, text=title,
             font=("微软雅黑", 8), fg=C["overlay1"],
             bg=C["surface0"]).pack(anchor="w")

    val_lbl = tk.Label(content, text=default_val,
                       font=("微软雅黑", val_font_size, "bold"),
                       fg=color, bg=C["surface0"])
    val_lbl.pack(anchor="w", pady=(3, 0))

    return glow, val_lbl


# ─────────────────────── 数据持久化 ───────────────────────

DATA_DIR  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
NAMES_FILE   = os.path.join(DATA_DIR, "custom_names.json")
HISTORY_FILE = os.path.join(DATA_DIR, "device_history.json")
TRAFFIC_FILE = os.path.join(DATA_DIR, "traffic_log.json")

os.makedirs(DATA_DIR, exist_ok=True)


def _load_json(path, default):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return default


def _save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


# ─────────────────────── Npcap 检测 ───────────────────────

def is_npcap_installed():
    """检测 Npcap 是否已安装"""
    import os
    if os.path.isdir(r"C:\Windows\System32\Npcap"):
        return True
    for reg_path in [
        r"SYSTEM\CurrentControlSet\Services\npcap",
        r"SOFTWARE\Npcap",
    ]:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
            winreg.CloseKey(key)
            return True
        except FileNotFoundError:
            pass
    return False


# ─────────────────────── TTL 管理 ───────────────────────

TTL_REG_PATH   = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
TTL_VALUE_NAME = "DefaultTTL"
TTL_CAMPUS  = 64
TTL_DEFAULT = 128


def get_current_ttl():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, TTL_REG_PATH)
        val, _ = winreg.QueryValueEx(key, TTL_VALUE_NAME)
        winreg.CloseKey(key)
        return int(val)
    except Exception:
        return TTL_DEFAULT


def set_ttl(value: int):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, TTL_REG_PATH, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, TTL_VALUE_NAME, 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        return True, f"TTL已设置为 {value}"
    except PermissionError:
        return False, "权限不足，请以管理员身份运行程序"
    except Exception as e:
        return False, f"设置失败：{e}"


def reset_ttl():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, TTL_REG_PATH, 0, winreg.KEY_SET_VALUE)
        try:
            winreg.DeleteValue(key, TTL_VALUE_NAME)
        except FileNotFoundError:
            pass
        winreg.CloseKey(key)
        return True, "TTL已恢复默认（128）"
    except PermissionError:
        return False, "权限不足，请以管理员身份运行程序"
    except Exception as e:
        return False, f"恢复失败：{e}"


# ─────────────────────── 网络工具 ───────────────────────

def get_hotspot_subnet():
    """检测热点网关，返回 (gateway_ip, iface_name, subnet_prefix) 或 (None, None, None)"""
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ip = addr.address
                if ip.startswith("192.168.137."):
                    prefix = ".".join(ip.split(".")[:3]) + "."
                    return ip, iface, prefix
    # 兜底：检测热点相关接口名
    for iface, addrs in psutil.net_if_addrs().items():
        if any(k in iface.lower() for k in ("wi-fi direct", "hosted", "virtual")):
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    if not ip.startswith("127.") and not ip.startswith("169.254."):
                        prefix = ".".join(ip.split(".")[:3]) + "."
                        return ip, iface, prefix
    return None, None, None


def get_arp_table():
    """获取ARP表，返回 {ip: mac}"""
    arp_map = {}
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, encoding="gbk", errors="ignore"
        )
        for line in result.stdout.splitlines():
            match = re.search(
                r"(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F]{2}[-:][\da-fA-F]{2}[-:]"
                r"[\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2})",
                line
            )
            if match:
                ip  = match.group(1)
                mac = match.group(2).upper().replace("-", ":")
                arp_map[ip] = mac
    except Exception:
        pass
    return arp_map


def is_broadcast_or_multicast_mac(mac: str) -> bool:
    """判断是否为广播或组播 MAC"""
    if mac == "FF:FF:FF:FF:FF:FF":
        return True
    try:
        first_byte = int(mac.split(":")[0], 16)
        if first_byte & 1:
            return True
    except Exception:
        pass
    return False


# ─────────────────────── 流量统计（scapy 抓包）───────────────────────

traffic_lock    = threading.Lock()
traffic_stats   = defaultdict(lambda: {"upload": 0, "download": 0, "total": 0})
speed_stats     = defaultdict(lambda: {"up_speed": 0.0, "down_speed": 0.0})

hotspot_prefix  = "192.168.137."
hotspot_gw_ip   = None

_prev_snapshot      = {}
_prev_snapshot_time = time.time()

sniff_error = None


def packet_callback(pkt):
    if not pkt.haslayer(IP):
        return
    src    = pkt[IP].src
    dst    = pkt[IP].dst
    length = len(pkt)
    with traffic_lock:
        src_client = src.startswith(hotspot_prefix) and src != hotspot_gw_ip
        dst_client = dst.startswith(hotspot_prefix) and dst != hotspot_gw_ip
        if src_client:
            traffic_stats[src]["upload"] += length
            traffic_stats[src]["total"]  += length
        if dst_client:
            traffic_stats[dst]["download"] += length
            traffic_stats[dst]["total"]    += length


def calc_speeds():
    """根据上次快照计算实时速率（B/s）"""
    global _prev_snapshot, _prev_snapshot_time
    now     = time.time()
    elapsed = now - _prev_snapshot_time
    if elapsed < 0.1:
        return
    with traffic_lock:
        current = {ip: dict(s) for ip, s in traffic_stats.items()}
    for ip, stat in current.items():
        prev = _prev_snapshot.get(ip, {"upload": 0, "download": 0})
        if elapsed > 0:
            speed_stats[ip]["up_speed"]   = max(0, (stat["upload"]   - prev["upload"])   / elapsed)
            speed_stats[ip]["down_speed"] = max(0, (stat["download"] - prev["download"]) / elapsed)
    _prev_snapshot      = current
    _prev_snapshot_time = now


def get_scapy_iface():
    """从 scapy 接口列表中找到热点接口对象（兼容 scapy 旧/新版 ip/ips 属性）"""
    if not SCAPY_AVAILABLE:
        return None
    try:
        from scapy.all import conf
        for iface_obj in conf.ifaces.values():
            # 兼容不同 scapy 版本：旧版用 ip(str/list)，新版用 ips(list)
            for attr in ('ip', 'ips'):
                raw = getattr(iface_obj, attr, None)
                if raw is None:
                    continue
                if isinstance(raw, str):
                    candidates = [raw]
                elif isinstance(raw, (list, tuple)):
                    candidates = raw
                else:
                    try:
                        candidates = list(raw)
                    except Exception:
                        candidates = [str(raw)]
                for ip in candidates:
                    if ip and str(ip).startswith(hotspot_prefix):
                        return iface_obj
    except Exception:
        pass
    return None


def start_sniff(scapy_iface):
    """在热点接口上启动 scapy 抓包（后台线程）"""
    global sniff_error
    if not SCAPY_AVAILABLE:
        return
    try:
        if scapy_iface is not None:
            # 找到了明确的热点接口，直接在该接口抓包
            sniff(iface=scapy_iface, prn=packet_callback, store=False, filter="ip")
        else:
            # 未能定位热点接口，在所有接口上抓包并用 BPF 过滤热点子网
            # 注意：sniff() 不指定 iface 只监听默认接口，必须传 all_ifaces
            subnet = hotspot_prefix + "0/24"
            from scapy.all import conf
            all_ifaces = list(conf.ifaces.values())
            if all_ifaces:
                sniff(iface=all_ifaces, prn=packet_callback, store=False,
                      filter=f"ip and net {subnet}")
            else:
                sniff(prn=packet_callback, store=False,
                      filter=f"ip and net {subnet}")
    except Exception as e:
        sniff_error = str(e)


# ─────────────────────── 常量 ───────────────────────

OFFLINE_DISPLAY_SECONDS = 60


# ──────────────────────────── GUI ────────────────────────────

class WifiMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi热点流量监控")
        self.root.geometry("1160x740")
        self.root.minsize(900, 600)
        self.root.resizable(True, True)
        self.root.configure(bg=C["crust"])

        self.running          = False
        self.sniff_thread     = None
        self.refresh_interval = 2000
        self.campus_mode_on   = False

        self.device_cache       = {}
        self.device_cache_lock  = threading.Lock()
        self.custom_names       = _load_json(NAMES_FILE, {})
        self._resolving_ips     = set()

        self._device_history    = _load_json(HISTORY_FILE, {})
        self._traffic_log       = _load_json(TRAFFIC_FILE, {})
        self._session_base      = {}
        self._session_date      = date.today().isoformat()

        self._blink_state       = True
        self._blink_job         = None
        self._uptime_job        = None
        self._start_time        = 0.0

        self._build_ui()
        self._build_context_menu()
        self._check_requirements()
        self._sync_ttl_state()

    # ──────── UI 构建 ────────

    def _build_ui(self):
        # ── 顶部标题栏 ──
        header = tk.Frame(self.root, bg=C["mantle"], pady=0)
        header.pack(fill=tk.X)

        # 左侧：图标 + 标题 + 版本
        left_hdr = tk.Frame(header, bg=C["mantle"])
        left_hdr.pack(side=tk.LEFT, padx=18, pady=10)

        tk.Label(left_hdr, text="📡", font=("Segoe UI Emoji", 18),
                 bg=C["mantle"], fg=C["blue"]).pack(side=tk.LEFT)
        tk.Label(left_hdr, text="  WiFi 热点流量监控",
                 font=("微软雅黑", 15, "bold"),
                 fg=C["text"], bg=C["mantle"]).pack(side=tk.LEFT)
        tk.Label(left_hdr, text="  v1.0",
                 font=("微软雅黑", 9),
                 fg=C["overlay0"], bg=C["mantle"]).pack(side=tk.LEFT, pady=(4, 0))

        # 右侧：运行状态指示
        right_hdr = tk.Frame(header, bg=C["mantle"])
        right_hdr.pack(side=tk.RIGHT, padx=18, pady=10)

        self._header_dot = tk.Label(right_hdr, text="●",
                                    font=("微软雅黑", 13),
                                    fg=C["red"], bg=C["mantle"])
        self._header_dot.pack(side=tk.LEFT, padx=(0, 4))

        self.status_label = tk.Label(right_hdr, text="未启动",
                                     font=("微软雅黑", 9),
                                     fg=C["overlay1"], bg=C["mantle"])
        self.status_label.pack(side=tk.LEFT)

        # ── 彩色渐变光带（标题栏底边，Win11 风格） ──
        accent_bar = tk.Canvas(self.root, height=3, highlightthickness=0,
                               bg=C["blue"])
        accent_bar.pack(fill=tk.X)

        def _draw_accent(event=None):
            w = accent_bar.winfo_width()
            if w < 2:
                return
            accent_bar.delete("all")
            # blue → mauve → pink，60段
            stops = [(0x4d, 0xa6, 0xff), (0xb8, 0x80, 0xff), (0xff, 0x7e, 0xc8)]
            segs = 60
            for i in range(segs):
                t = i / segs
                if t < 0.5:
                    t2  = t * 2
                    r1, g1, b1 = stops[0]
                    r2, g2, b2 = stops[1]
                else:
                    t2  = (t - 0.5) * 2
                    r1, g1, b1 = stops[1]
                    r2, g2, b2 = stops[2]
                r = int(r1 + (r2 - r1) * t2)
                g = int(g1 + (g2 - g1) * t2)
                b = int(b1 + (b2 - b1) * t2)
                x0 = int(w * i / segs)
                x1 = int(w * (i + 1) / segs) + 1
                accent_bar.create_rectangle(x0, 0, x1, 3,
                                            fill=f"#{r:02x}{g:02x}{b:02x}",
                                            outline="")
        accent_bar.bind("<Configure>", lambda e: _draw_accent())
        accent_bar.after_idle(_draw_accent)

        # ── 校园网模式栏 ──
        campus_bar = tk.Frame(self.root, bg=C["surface0"], pady=0)
        campus_bar.pack(fill=tk.X)

        campus_left = tk.Frame(campus_bar, bg=C["surface0"])
        campus_left.pack(side=tk.LEFT, padx=12, pady=7)

        tk.Label(campus_left, text="🏫",
                 font=("Segoe UI Emoji", 11), bg=C["surface0"],
                 fg=C["yellow"]).pack(side=tk.LEFT)
        tk.Label(campus_left, text="  校园网模式",
                 font=("微软雅黑", 9, "bold"),
                 fg=C["yellow"], bg=C["surface0"]).pack(side=tk.LEFT)

        tk.Label(campus_bar,
                 text="修改 TTL=64 使校园网无法通过 TTL 差异检测多设备   ⚠ 手机代理/VPN 会修改 HTTP 头，需在手机端关闭",
                 font=("微软雅黑", 8), fg=C["overlay1"], bg=C["surface0"],
                 anchor="w", padx=6).pack(side=tk.LEFT, fill=tk.X, expand=True)

        campus_right = tk.Frame(campus_bar, bg=C["surface0"])
        campus_right.pack(side=tk.RIGHT, padx=10, pady=5)

        self.ttl_status_label = tk.Label(
            campus_right, text=f"TTL: {get_current_ttl()}",
            font=("微软雅黑", 8, "bold"), fg=C["sky"], bg=C["surface0"],
            padx=8, pady=3)
        self.ttl_status_label.pack(side=tk.LEFT)

        self.campus_btn = self._make_btn(
            campus_right, "开启校园网模式", C["yellow"],
            self.toggle_campus_mode, font_size=8, padx=10, pady=3,
            tooltip="开启后将系统 TTL 改为 64，绕过校园网多设备检测")
        self.campus_btn.pack(side=tk.LEFT, padx=6)

        # 分割线
        tk.Frame(self.root, bg=C["crust"], height=1).pack(fill=tk.X)

        # ── 工具栏 ──
        toolbar = tk.Frame(self.root, bg=C["base"], pady=0)
        toolbar.pack(fill=tk.X, padx=0)

        btn_area = tk.Frame(toolbar, bg=C["base"])
        btn_area.pack(side=tk.LEFT, padx=14, pady=8)

        self.start_btn = self._make_btn(
            btn_area, "▶  开始监控", C["green"],
            self.toggle_monitor, font_size=9, padx=14, pady=5,
            tooltip="开始/停止监控热点设备")
        self.start_btn.pack(side=tk.LEFT, padx=(0, 6))

        for text, color, cmd, tip in [
            ("🔄  刷新", C["sapphire"], self.refresh_devices,  "立即刷新设备列表"),
            ("🗑  清空", C["red"],      self.clear_stats,      "清空本次会话流量统计（历史记录不受影响）"),
            ("⚡  断开", C["mauve"],    self.kick_selected_device, "断开选中设备（重启热点）"),
        ]:
            self._make_btn(btn_area, text, color, cmd,
                           font_size=9, padx=10, pady=5,
                           tooltip=tip).pack(side=tk.LEFT, padx=3)

        self.hotspot_info = tk.Label(
            toolbar, text="热点状态：检测中...",
            font=("微软雅黑", 8), fg=C["overlay1"], bg=C["base"],
            anchor="e", padx=14)
        self.hotspot_info.pack(side=tk.RIGHT, fill=tk.X, expand=True)

        # ── 统计卡片栏 ──
        cards_frame = tk.Frame(self.root, bg=C["crust"])
        cards_frame.pack(fill=tk.X, padx=14, pady=(6, 0))

        self._build_stat_cards(cards_frame)

        # ── Notebook 标签页 ──
        self._apply_notebook_style()
        self.notebook = ttk.Notebook(self.root, style="Custom.TNotebook")
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=14, pady=(6, 0))

        tab1 = tk.Frame(self.notebook, bg=C["mantle"])
        tab2 = tk.Frame(self.notebook, bg=C["mantle"])
        tab3 = tk.Frame(self.notebook, bg=C["mantle"])

        self.notebook.add(tab1, text="  📊  实时监控  ")
        self.notebook.add(tab2, text="  📋  设备历史  ")
        self.notebook.add(tab3, text="  📈  流量统计  ")

        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        self._build_monitor_tab(tab1)
        self._build_history_tab(tab2)
        self._build_traffic_tab(tab3)

        # ── 底部状态栏 ──
        bottom = tk.Frame(self.root, bg=C["surface0"], pady=0)
        bottom.pack(fill=tk.X, side=tk.BOTTOM)

        tk.Frame(self.root, bg=C["crust"], height=1).pack(fill=tk.X, side=tk.BOTTOM)

        self._status_dot = tk.Label(bottom, text="●",
                                    font=("微软雅黑", 8),
                                    fg=C["overlay0"], bg=C["surface0"])
        self._status_dot.pack(side=tk.LEFT, padx=(10, 2), pady=4)

        self.bottom_label = tk.Label(
            bottom, text="就绪 | 需要管理员权限运行以获取完整功能",
            font=("微软雅黑", 8), fg=C["overlay1"], bg=C["surface0"],
            anchor="w")
        self.bottom_label.pack(side=tk.LEFT, fill=tk.X, expand=True, pady=4)

        self.device_count_label = tk.Label(
            bottom, text="在线：0 | 可见：0",
            font=("微软雅黑", 8), fg=C["subtext0"], bg=C["surface0"], padx=12)
        self.device_count_label.pack(side=tk.RIGHT, pady=4)

    def _make_btn(self, parent, text, color, command,
                  font_size=9, padx=10, pady=4, fg=None, tooltip=None):
        """按钮工厂：自动添加 hover 变暗效果 + 可选 Tooltip"""
        if fg is None:
            fg = "#ffffff"
        hover = _darken(color)
        btn = tk.Button(
            parent, text=text,
            font=("微软雅黑", font_size, "bold"),
            bg=color, fg=fg,
            relief=tk.FLAT, padx=padx, pady=pady,
            cursor="hand2", command=command,
            activebackground=hover, activeforeground=fg, bd=0)
        btn.bind("<Enter>", lambda e: btn.config(bg=hover))
        btn.bind("<Leave>", lambda e: btn.config(bg=color))
        if tooltip:
            Tooltip(btn, tooltip)
        return btn

    def _apply_notebook_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Custom.TNotebook",
                         background=C["crust"], borderwidth=0, tabmargins=[0, 0, 0, 0])
        style.configure("Custom.TNotebook.Tab",
                         background=C["surface0"], foreground=C["subtext0"],
                         padding=[4, 6], font=("微软雅黑", 9),
                         borderwidth=0)
        style.map("Custom.TNotebook.Tab",
                  background=[("selected", C["mantle"]), ("active", C["surface1"])],
                  foreground=[("selected", C["blue"]),   ("active", C["text"])])
        style.configure("Dark.Treeview",
                         background=C["mantle"], foreground=C["text"],
                         fieldbackground=C["mantle"], rowheight=30,
                         font=("微软雅黑", 9))
        style.configure("Dark.Treeview.Heading",
                         background=C["surface0"], foreground=C["blue"],
                         font=("微软雅黑", 9, "bold"), relief=tk.FLAT)
        style.map("Dark.Treeview",
                  background=[("selected", C["surface1"])],
                  foreground=[("selected", C["text"])])
        style.configure("Dark.Vertical.TScrollbar",
                         background=C["surface0"], troughcolor=C["mantle"],
                         arrowcolor=C["overlay0"], borderwidth=0, relief=tk.FLAT)

    def _build_stat_cards(self, parent):
        """构建4个统计卡片（Canvas 圆角版）：在线设备 / 总上传 / 总下载 / 运行时长"""
        ICONS = ["💻", "⬆", "⬇", "⏱"]
        card_defs = [
            ("在线设备", "0",        C["blue"],    "_card_devices_val"),
            ("总上传",   "0 B",      C["green"],   "_card_upload_val"),
            ("总下载",   "0 B",      C["peach"],   "_card_download_val"),
            ("运行时长", "00:00:00", C["mauve"],   "_card_uptime_val"),
        ]
        for i, ((label, default, color, attr), icon) in enumerate(
                zip(card_defs, ICONS)):
            outer, val_lbl = _make_rounded_card(parent, color, f"{icon}  {label}", default)
            outer.grid(row=0, column=i, padx=5, pady=0, sticky="nsew")
            parent.columnconfigure(i, weight=1)
            setattr(self, attr, val_lbl)

    def _update_stat_cards(self, online_count, stats_copy):
        """更新统计卡片数据（在 _update_table 里调用）"""
        self._card_devices_val.config(text=str(online_count))
        total_up   = sum(s.get("upload",   0) for s in stats_copy.values())
        total_down = sum(s.get("download", 0) for s in stats_copy.values())
        self._card_upload_val.config(text=_fmt_bytes(total_up))
        self._card_download_val.config(text=_fmt_bytes(total_down))

    def _start_blink(self):
        self._blink_state = True
        self._do_blink()

    def _do_blink(self):
        if not self.running:
            return
        color = C["green"] if self._blink_state else C["overlay0"]
        self._header_dot.config(fg=color)
        self._blink_state = not self._blink_state
        self._blink_job = self.root.after(900, self._do_blink)

    def _stop_blink(self):
        if self._blink_job:
            self.root.after_cancel(self._blink_job)
            self._blink_job = None
        self._header_dot.config(fg=C["red"])

    def _start_uptime(self):
        self._start_time = time.time()
        self._update_uptime()

    def _update_uptime(self):
        if not self.running:
            return
        elapsed = int(time.time() - self._start_time)
        h = elapsed // 3600
        m = (elapsed % 3600) // 60
        s = elapsed % 60
        self._card_uptime_val.config(text=f"{h:02d}:{m:02d}:{s:02d}")
        self._uptime_job = self.root.after(1000, self._update_uptime)

    def _stop_uptime(self):
        if self._uptime_job:
            self.root.after_cancel(self._uptime_job)
            self._uptime_job = None
        self._card_uptime_val.config(text="00:00:00")

    def _build_monitor_tab(self, parent):
        """实时监控标签页"""
        self.tree = ttk.Treeview(
            parent,
            columns=("设备名", "IP地址", "MAC地址",
                     "↑速率", "↓速率",
                     "上传总量", "下载总量", "总流量",
                     "状态", "首次发现"),
            show="headings",
            style="Dark.Treeview",
            selectmode="browse")

        col_cfg = [
            ("设备名",   160, tk.W),
            ("IP地址",   118, tk.CENTER),
            ("MAC地址",  150, tk.CENTER),
            ("↑速率",    90,  tk.CENTER),
            ("↓速率",    90,  tk.CENTER),
            ("上传总量",  88,  tk.CENTER),
            ("下载总量",  88,  tk.CENTER),
            ("总流量",    88,  tk.CENTER),
            ("状态",      52,  tk.CENTER),
            ("首次发现", 110,  tk.CENTER),
        ]
        for col, w, anchor in col_cfg:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor=anchor, minwidth=40)

        # 斑马纹 + 状态颜色
        self.tree.tag_configure("offline",      foreground=C["overlay1"],
                                background=C["mantle"])
        self.tree.tag_configure("offline_alt",  foreground=C["overlay1"],
                                background="#f0f4ff")
        self.tree.tag_configure("online",       foreground=C["text"],
                                background=C["mantle"])
        self.tree.tag_configure("online_alt",   foreground=C["text"],
                                background="#f0f4ff")
        self.tree.tag_configure("active",       foreground=C["green"],
                                background=C["mantle"])
        self.tree.tag_configure("active_alt",   foreground=C["green"],
                                background="#f0f4ff")

        vsb = ttk.Scrollbar(parent, orient="vertical",
                            command=self.tree.yview,
                            style="Dark.Vertical.TScrollbar")
        self.tree.configure(yscrollcommand=vsb.set)

        # 空状态提示（叠加在 tree 上方，无设备时显示）
        self._empty_state = tk.Label(
            parent,
            text="暂无设备连接\n\n请开启 Windows 移动热点\n然后点击【▶  开始监控】",
            font=("微软雅黑", 12), fg=C["overlay0"],
            bg=C["mantle"], justify="center")

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(8, 0), pady=8)
        vsb.pack(side=tk.RIGHT, fill=tk.Y, pady=8, padx=(0, 6))

        # 初始显示空状态
        self._empty_state.place(relx=0.5, rely=0.5, anchor="center")

        self.tree.bind("<Double-1>", lambda e: self._rename_device())
        self.tree.bind("<Button-3>", self._on_right_click)

    def _build_history_tab(self, parent):
        """设备历史标签页"""
        toolbar = tk.Frame(parent, bg=C["mantle"])
        toolbar.pack(fill=tk.X, pady=(8, 4), padx=8)

        tk.Label(toolbar, text="所有曾连接过的设备（按最后上线时间排序）",
                 font=("微软雅黑", 9), fg=C["subtext0"],
                 bg=C["mantle"]).pack(side=tk.LEFT)

        self._make_btn(toolbar, "🗑  清空历史", C["red"],
                       self._clear_history, font_size=8, padx=8, pady=3,
                       tooltip="永久清空所有历史设备记录"
                       ).pack(side=tk.RIGHT, padx=4)
        self._make_btn(toolbar, "🔄  刷新", C["sapphire"],
                       self._refresh_history_tab, font_size=8, padx=8, pady=3,
                       tooltip="重新加载历史记录"
                       ).pack(side=tk.RIGHT, padx=4)

        h_cols = ("设备名", "MAC地址", "最后IP", "首次连接", "最后连接", "累计上线次数")
        h_widths = [190, 155, 128, 155, 155, 100]

        frame = tk.Frame(parent, bg=C["mantle"])
        frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        self.history_tree = ttk.Treeview(frame, columns=h_cols, show="headings",
                                          style="Dark.Treeview", selectmode="browse")
        for col, w in zip(h_cols, h_widths):
            self.history_tree.heading(col, text=col)
            self.history_tree.column(col, width=w, anchor=tk.CENTER)

        self.history_tree.tag_configure("even", background=C["mantle"])
        self.history_tree.tag_configure("odd",  background="#f0f4ff")

        vsb2 = ttk.Scrollbar(frame, orient="vertical",
                             command=self.history_tree.yview,
                             style="Dark.Vertical.TScrollbar")
        self.history_tree.configure(yscrollcommand=vsb2.set)
        self.history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb2.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 2))

    def _build_traffic_tab(self, parent):
        """流量统计标签页"""
        # 筛选工具栏
        filter_bar = tk.Frame(parent, bg=C["surface0"], pady=6)
        filter_bar.pack(fill=tk.X, padx=8, pady=(8, 0))

        tk.Label(filter_bar, text="  统计范围",
                 font=("微软雅黑", 8, "bold"), fg=C["subtext0"],
                 bg=C["surface0"]).pack(side=tk.LEFT, padx=(4, 8))

        self._traffic_range = tk.StringVar(value="日")
        for txt, color in [("日", C["blue"]), ("月", C["teal"]),
                           ("年", C["mauve"]), ("全部", C["overlay1"])]:
            rb = tk.Radiobutton(
                filter_bar, text=f"  {txt}  ",
                variable=self._traffic_range, value=txt,
                font=("微软雅黑", 9, "bold"),
                fg=C["text"], bg=C["surface0"],
                selectcolor=C["surface1"],
                activebackground=C["surface0"],
                activeforeground=C["text"],
                indicatoron=False,
                relief=tk.FLAT, padx=6, pady=3,
                cursor="hand2",
                command=self._refresh_traffic_tab)
            rb.pack(side=tk.LEFT, padx=2)

        tk.Label(filter_bar, text="  日期:",
                 font=("微软雅黑", 8), fg=C["subtext0"],
                 bg=C["surface0"]).pack(side=tk.LEFT, padx=(12, 2))

        self._traffic_date_var = tk.StringVar(value=date.today().isoformat())
        date_entry = tk.Entry(
            filter_bar, textvariable=self._traffic_date_var,
            width=12, font=("微软雅黑", 9),
            bg=C["surface1"], fg=C["text"],
            insertbackground=C["text"], relief=tk.FLAT,
            highlightthickness=1, highlightcolor=C["blue"],
            highlightbackground=C["surface2"])
        date_entry.pack(side=tk.LEFT, padx=4)

        self._make_btn(filter_bar, "查询", C["blue"],
                       self._refresh_traffic_tab,
                       font_size=8, padx=10, pady=3,
                       tooltip="按所选时间范围查询流量").pack(side=tk.LEFT, padx=4)
        self._make_btn(filter_bar, "🔄", C["surface1"],
                       self._refresh_traffic_tab,
                       font_size=8, padx=6, pady=3,
                       fg=C["text"],
                       tooltip="刷新流量数据").pack(side=tk.LEFT)

        # 合计摘要
        summary_frame = tk.Frame(parent, bg=C["mantle"], pady=5)
        summary_frame.pack(fill=tk.X, padx=8, pady=(4, 0))

        self._traffic_summary_label = tk.Label(
            summary_frame, text="  请点击查询",
            font=("微软雅黑", 9, "bold"),
            fg=C["yellow"], bg=C["mantle"], anchor="w", padx=8)
        self._traffic_summary_label.pack(fill=tk.X)

        # 表格
        t_cols = ("设备名", "MAC地址", "上传", "下载", "总流量")
        t_widths = [200, 160, 120, 120, 120]

        frame = tk.Frame(parent, bg=C["mantle"])
        frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(4, 8))

        self.traffic_tree = ttk.Treeview(frame, columns=t_cols, show="headings",
                                          style="Dark.Treeview", selectmode="browse")
        for col, w in zip(t_cols, t_widths):
            self.traffic_tree.heading(
                col, text=col,
                command=lambda c=col: self._sort_traffic_tree(c))
            self.traffic_tree.column(col, width=w, anchor=tk.CENTER)

        self.traffic_tree.tag_configure("even", background=C["mantle"])
        self.traffic_tree.tag_configure("odd",  background="#f0f4ff")

        vsb3 = ttk.Scrollbar(frame, orient="vertical",
                             command=self.traffic_tree.yview,
                             style="Dark.Vertical.TScrollbar")
        self.traffic_tree.configure(yscrollcommand=vsb3.set)
        self.traffic_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb3.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 2))

        self._traffic_sort_col = "总流量"
        self._traffic_sort_asc = False

    def _build_context_menu(self):
        self.context_menu = tk.Menu(
            self.root, tearoff=0,
            bg=C["surface0"], fg=C["text"],
            activebackground=C["surface2"], activeforeground=C["text"],
            font=("微软雅黑", 9))
        self.context_menu.add_command(label="✏  重命名设备",
                                      foreground=C["blue"],
                                      activeforeground=C["blue"],
                                      command=self._rename_device)
        self.context_menu.add_command(label="📋 复制 IP 地址",
                                      foreground=C["subtext0"],
                                      activeforeground=C["text"],
                                      command=lambda: self._copy_field(1))
        self.context_menu.add_command(label="📋 复制 MAC 地址",
                                      foreground=C["subtext0"],
                                      activeforeground=C["text"],
                                      command=lambda: self._copy_field(2))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="⚡ 断开该设备",
                                      foreground=C["red"],
                                      activeforeground=C["red"],
                                      command=self.kick_selected_device)

    # ──────── 交互事件 ────────

    def _on_right_click(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def _copy_field(self, idx):
        sel = self.tree.selection()
        if not sel:
            return
        text = self.tree.item(sel[0], "values")[idx]
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._set_status(f"已复制：{text}")

    def _rename_device(self):
        sel = self.tree.selection()
        if not sel:
            return
        values       = self.tree.item(sel[0], "values")
        ip           = values[1]
        current_name = self.custom_names.get(ip, values[0])
        new_name = simpledialog.askstring(
            "重命名设备",
            f"为 {ip} 设置备注名称：",
            initialvalue=current_name,
            parent=self.root)
        if new_name and new_name.strip():
            self.custom_names[ip] = new_name.strip()
            _save_json(NAMES_FILE, self.custom_names)
            self.refresh_devices()

    # ──────── TTL / 校园网 ────────

    def _sync_ttl_state(self):
        current = get_current_ttl()
        self.ttl_status_label.config(text=f"TTL: {current}")
        if current == TTL_CAMPUS:
            self.campus_mode_on = True
            self.campus_btn.config(text="✅ 关闭校园网模式", bg=C["green"])
        else:
            self.campus_mode_on = False
            self.campus_btn.config(text="开启校园网模式", bg=C["yellow"])

    def toggle_campus_mode(self):
        if not self.campus_mode_on:
            ok, msg = set_ttl(TTL_CAMPUS)
            if ok:
                self.campus_mode_on = True
                self.campus_btn.config(text="✅ 关闭校园网模式", bg=C["green"])
                self.ttl_status_label.config(text=f"TTL: {TTL_CAMPUS}")
                self._set_status("校园网模式已开启（TTL=64），热点设备不再被检测为多设备")
            else:
                messagebox.showerror("失败", msg + "\n\n请右键程序选择【以管理员身份运行】")
        else:
            ok, msg = reset_ttl()
            if ok:
                self.campus_mode_on = False
                self.campus_btn.config(text="开启校园网模式", bg=C["yellow"])
                self.ttl_status_label.config(text=f"TTL: {get_current_ttl()}")
                self._set_status("校园网模式已关闭，TTL已恢复默认（128）")
            else:
                messagebox.showerror("失败", msg)

    # ──────── 断开设备 ────────

    def kick_selected_device(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("提示", "请先在列表中选中一台设备")
            return
        values   = self.tree.item(sel[0], "values")
        ip, name = values[1], values[0]
        if messagebox.askyesno(
            "确认",
            f"确定要断开设备 {name}（{ip}）的连接吗？\n\n"
            "注：将通过重启热点方式断开所有设备，其他设备需重新连接。"
        ):
            try:
                subprocess.run(["netsh", "wlan", "stop", "hostednetwork"], capture_output=True)
                time.sleep(1)
                subprocess.run(["netsh", "wlan", "start", "hostednetwork"], capture_output=True)
                self._set_status(f"已重启热点，{name} 已断开")
            except Exception as e:
                messagebox.showerror("失败", str(e))

    # ──────── 环境检测 ────────

    def _check_requirements(self):
        global hotspot_gw_ip, hotspot_prefix
        npcap_ok      = is_npcap_installed()
        gw_ip, iface, prefix = get_hotspot_subnet()
        if gw_ip:
            hotspot_gw_ip  = gw_ip
            hotspot_prefix = prefix
            if SCAPY_AVAILABLE and npcap_ok:
                status_text = "scapy+Npcap ✓"
            elif SCAPY_AVAILABLE:
                status_text = "⚠ 缺少Npcap（流量统计不可用）"
            else:
                status_text = "基础模式（仅ARP扫描）"
            self.hotspot_info.config(
                text=f"热点网关：{gw_ip}  |  接口：{iface}  |  {status_text}")
            self.iface = iface
        else:
            self.hotspot_info.config(
                text="⚠ 未检测到热点网关，请先开启Windows移动热点（设置→网络→移动热点）")
            self.iface = None

        if SCAPY_AVAILABLE and not npcap_ok:
            self._set_status(
                "⚠ 流量统计需要 Npcap！下载：https://npcap.com/#download  安装后重启软件",
                color=C["yellow"])
        self._npcap_ok = npcap_ok

    # ──────── 监控控制 ────────

    def toggle_monitor(self):
        if not self.running:
            self.start_monitor()
        else:
            self.stop_monitor()

    def start_monitor(self):
        self._check_requirements()
        if not self.iface:
            messagebox.showwarning("提示", "未检测到热点，请先开启Windows移动热点。")
            return

        if SCAPY_AVAILABLE and not getattr(self, '_npcap_ok', True):
            if not messagebox.askyesno(
                "缺少 Npcap",
                "流量统计需要安装 Npcap。\n"
                "下载：https://npcap.com/#download\n"
                "（安装时勾选 WinPcap API-compatible Mode）\n\n"
                "是否继续（只显示设备列表，流量为 0）？"
            ):
                return

        self.running = True
        self.start_btn.config(text="⏹  停止监控", bg=C["red"])
        self.status_label.config(text="监控中", fg=C["green"])
        self._start_blink()
        self._start_uptime()

        if SCAPY_AVAILABLE:
            scapy_iface = get_scapy_iface()
            iface_desc  = (getattr(scapy_iface, 'description', None)
                           or getattr(scapy_iface, 'name', '全局过滤模式')) if scapy_iface else '全局过滤模式'
            self._scapy_iface_name = iface_desc
            self.sniff_thread = threading.Thread(
                target=start_sniff, args=(scapy_iface,), daemon=True)
            self.sniff_thread.start()
            self.root.after(1500, self._check_sniff_error)

        self._schedule_refresh()
        self._set_status("监控已启动，每2秒刷新一次...")

    def _check_sniff_error(self):
        global sniff_error
        if sniff_error:
            self._set_status(f"⚠ 抓包错误：{sniff_error[:90]}", color=C["red"])
            sniff_error = None
        else:
            self._set_status(
                f"✅ 抓包已启动（接口：{getattr(self, '_scapy_iface_name', '未知')}），流量统计正常")

    def stop_monitor(self):
        self.running = False
        self.start_btn.config(text="▶  开始监控", bg=C["green"])
        self.status_label.config(text="已停止", fg=C["peach"])
        self._stop_blink()
        self._stop_uptime()
        self._set_status("监控已停止")

    def _schedule_refresh(self):
        if self.running:
            self.refresh_devices()
            self.root.after(self.refresh_interval, self._schedule_refresh)

    # ──────── 数据获取 ────────

    def refresh_devices(self):
        threading.Thread(target=self._fetch_and_update, daemon=True).start()

    def _fetch_and_update(self):
        arp_map = get_arp_table()
        now     = time.time()
        now_str = datetime.now().strftime("%H:%M:%S")
        today   = date.today().isoformat()

        # 过滤：热点网段 + 排除网关 + 排除广播IP + 排除广播/组播MAC
        hotspot_devices = {
            ip: mac for ip, mac in arp_map.items()
            if (ip.startswith(hotspot_prefix)
                and ip != hotspot_gw_ip
                and not ip.endswith(".255")
                and not is_broadcast_or_multicast_mac(mac))
        }

        with self.device_cache_lock:
            for ip, mac in hotspot_devices.items():
                if ip not in self.device_cache:
                    self.device_cache[ip] = {
                        "mac":        mac,
                        "hostname":   "查询中...",
                        "first_seen": now_str,
                        "last_seen":  now,
                        "offline":    False,
                    }
                    if ip not in self._resolving_ips:
                        self._resolving_ips.add(ip)
                        threading.Thread(
                            target=self._resolve_hostname_bg,
                            args=(ip,), daemon=True).start()
                    # 更新设备历史
                    self._update_device_history(ip, mac, now_str, is_new=True)
                else:
                    self.device_cache[ip]["last_seen"] = now
                    self.device_cache[ip]["offline"]   = False
                    self._update_device_history(ip, mac, now_str, is_new=False)

            # 标记不在 ARP 表中的设备为离线
            for ip, info in self.device_cache.items():
                if ip not in hotspot_devices:
                    info["offline"] = True

            cache_snap = {ip: dict(info) for ip, info in self.device_cache.items()}

        calc_speeds()
        with traffic_lock:
            stats_copy  = {ip: dict(s) for ip, s in traffic_stats.items()}
        speeds_copy = {ip: dict(s) for ip, s in speed_stats.items()}

        # 更新流量日志（每次刷新累积增量）
        self._accumulate_traffic_log(cache_snap, stats_copy, today)

        self.root.after(0, lambda: self._update_table(cache_snap, stats_copy, speeds_copy, now))

    def _resolve_hostname_bg(self, ip: str):
        """后台 DNS 解析（2秒超时）"""
        try:
            old_to = socket.getdefaulttimeout()
            socket.setdefaulttimeout(2)
            hostname = socket.gethostbyaddr(ip)[0]
            socket.setdefaulttimeout(old_to)
        except Exception:
            hostname = ip
        with self.device_cache_lock:
            if ip in self.device_cache:
                self.device_cache[ip]["hostname"] = hostname
        self._resolving_ips.discard(ip)

    # ──────── 表格更新 ────────

    def _update_table(self, cache_snap, stats_copy, speeds_copy, scan_time):
        # 保留选中行
        selected_ip = None
        sel = self.tree.selection()
        if sel:
            vals = self.tree.item(sel[0], "values")
            if vals:
                selected_ip = vals[1]

        for item in self.tree.get_children():
            self.tree.delete(item)

        online_count = 0
        new_sel_item = None

        sorted_devices = sorted(
            cache_snap.items(),
            key=lambda x: (x[1].get("offline", False), x[1].get("first_seen", ""))
        )

        for ip, info in sorted_devices:
            offline = info.get("offline", False)
            # 超时离线不显示
            if offline and (scan_time - info.get("last_seen", 0)) > OFFLINE_DISPLAY_SECONDS:
                continue

            display_name = self.custom_names.get(ip, info.get("hostname", ip))
            mac          = info.get("mac", "")
            first_seen   = info.get("first_seen", "-")
            status       = "● 离线" if offline else "● 在线"

            stat = stats_copy.get(ip,  {"upload": 0, "download": 0, "total": 0})
            spd  = speeds_copy.get(ip, {"up_speed": 0.0, "down_speed": 0.0})

            if offline:
                tag = "offline_alt" if online_count % 2 else "offline"
            elif spd["up_speed"] > 1024 or spd["down_speed"] > 1024:
                tag = "active_alt"  if online_count % 2 else "active"
            else:
                tag = "online_alt"  if online_count % 2 else "online"

            row_id = self.tree.insert("", tk.END, values=(
                display_name, ip, mac,
                _fmt_speed(spd["up_speed"]),
                _fmt_speed(spd["down_speed"]),
                _fmt_bytes(stat["upload"]),
                _fmt_bytes(stat["download"]),
                _fmt_bytes(stat["total"]),
                status, first_seen
            ), tags=(tag,))

            if ip == selected_ip:
                new_sel_item = row_id
            if not offline:
                online_count += 1

        if new_sel_item:
            self.tree.selection_set(new_sel_item)

        self._update_stat_cards(online_count, stats_copy)

        total_visible = len(self.tree.get_children())

        # 有设备时隐藏空状态提示
        if hasattr(self, "_empty_state"):
            if total_visible == 0:
                self._empty_state.place(relx=0.5, rely=0.5, anchor="center")
            else:
                self._empty_state.place_forget()

        self.device_count_label.config(
            text=f"在线：{online_count} | 可见：{total_visible}")

        if self.running:
            scapy_ok = SCAPY_AVAILABLE and getattr(self, '_npcap_ok', False)
            if online_count == 0:
                self._set_status("未发现在线设备，等待设备接入...")
            else:
                self._set_status(
                    f"已发现 {online_count} 台在线设备 | "
                    f"更新：{datetime.now().strftime('%H:%M:%S')}"
                    + ("" if scapy_ok else " | ⚠ 流量统计不可用"))

    # ──────── 清空统计 ────────

    def clear_stats(self):
        global _prev_snapshot, _prev_snapshot_time
        with traffic_lock:
            traffic_stats.clear()
            speed_stats.clear()
        _prev_snapshot      = {}
        _prev_snapshot_time = time.time()
        self._session_base  = {}
        with self.device_cache_lock:
            self.device_cache.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.device_count_label.config(text="设备数：0")
        self._set_status("统计已清空（历史记录和流量日志已保留）")

    # ──────── 历史记录 ────────

    def _update_device_history(self, ip: str, mac: str, now_str: str, is_new: bool):
        """更新设备历史记录（线程内调用，已持有 device_cache_lock）"""
        key = mac
        if key not in self._device_history:
            self._device_history[key] = {
                "mac":        mac,
                "name":       self.custom_names.get(ip, ""),
                "last_ip":    ip,
                "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "sessions":   1,
            }
        else:
            entry = self._device_history[key]
            entry["last_ip"]   = ip
            entry["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if entry.get("name") == "" and self.custom_names.get(ip):
                entry["name"] = self.custom_names.get(ip, "")
            if is_new:
                entry["sessions"] = entry.get("sessions", 0) + 1
        # 异步保存（避免频繁IO）
        threading.Thread(target=_save_json,
                         args=(HISTORY_FILE, self._device_history),
                         daemon=True).start()

    def _refresh_history_tab(self):
        """刷新设备历史标签页"""
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)

        data = self._device_history
        sorted_entries = sorted(data.values(),
                                key=lambda x: x.get("last_seen", ""),
                                reverse=True)
        for entry in sorted_entries:
            mac  = entry.get("mac", "")
            name = entry.get("name", "") or self.custom_names.get(entry.get("last_ip", ""), mac)
            self.history_tree.insert("", tk.END, values=(
                name or mac,
                mac,
                entry.get("last_ip", "-"),
                entry.get("first_seen", "-"),
                entry.get("last_seen",  "-"),
                entry.get("sessions", 1),
            ))

    def _clear_history(self):
        if messagebox.askyesno("确认", "确定清空所有设备历史记录？"):
            self._device_history.clear()
            _save_json(HISTORY_FILE, self._device_history)
            self._refresh_history_tab()

    # ──────── 流量日志 ────────

    def _accumulate_traffic_log(self, cache_snap, stats_copy, today: str):
        """将本次会话增量流量写入日志（按日）"""
        if today not in self._traffic_log:
            self._traffic_log[today] = {}
        day_log = self._traffic_log[today]

        for ip, stat in stats_copy.items():
            if stat["upload"] == 0 and stat["download"] == 0:
                continue
            mac = ""
            info = cache_snap.get(ip)
            if info:
                mac = info.get("mac", ip)
            key = mac or ip

            base = self._session_base.get(ip, {"upload": 0, "download": 0})
            delta_up   = max(0, stat["upload"]   - base["upload"])
            delta_down = max(0, stat["download"]  - base["download"])

            if key not in day_log:
                day_log[key] = {"up": 0, "down": 0, "name": ""}
            day_log[key]["up"]   += delta_up
            day_log[key]["down"] += delta_down
            day_log[key]["name"]  = self.custom_names.get(ip, "")

            self._session_base[ip] = {"upload": stat["upload"],
                                       "download": stat["download"]}

        threading.Thread(target=_save_json,
                         args=(TRAFFIC_FILE, self._traffic_log),
                         daemon=True).start()

    def _refresh_traffic_tab(self):
        """刷新流量统计标签页"""
        rng     = self._traffic_range.get()
        ref_str = self._traffic_date_var.get().strip()

        # 日期解析
        try:
            ref_date = date.fromisoformat(ref_str)
        except ValueError:
            ref_date = date.today()
            self._traffic_date_var.set(ref_date.isoformat())

        # 筛选匹配的日期键
        matched_days = []
        for day_key in self._traffic_log:
            try:
                d = date.fromisoformat(day_key)
            except ValueError:
                continue
            if rng == "日" and d == ref_date:
                matched_days.append(day_key)
            elif rng == "月" and d.year == ref_date.year and d.month == ref_date.month:
                matched_days.append(day_key)
            elif rng == "年" and d.year == ref_date.year:
                matched_days.append(day_key)
            elif rng == "全部":
                matched_days.append(day_key)

        # 汇总
        merged = {}  # {key: {up, down, name}}
        for dk in matched_days:
            for key, v in self._traffic_log[dk].items():
                if key not in merged:
                    merged[key] = {"up": 0, "down": 0, "name": v.get("name", "")}
                merged[key]["up"]   += v.get("up", 0)
                merged[key]["down"] += v.get("down", 0)
                if not merged[key]["name"] and v.get("name"):
                    merged[key]["name"] = v["name"]

        # 更新表格
        for item in self.traffic_tree.get_children():
            self.traffic_tree.delete(item)

        sort_key_map = {
            "设备名": lambda x: x[0],
            "MAC地址": lambda x: x[1],
            "上传":    lambda x: merged[x[1]]["up"]   if x[1] in merged else 0,
            "下载":    lambda x: merged[x[1]]["down"]  if x[1] in merged else 0,
            "总流量":  lambda x: (merged[x[1]]["up"] + merged[x[1]]["down"]) if x[1] in merged else 0,
        }

        rows = []
        total_up = total_down = 0
        for key, v in merged.items():
            name = v.get("name") or key
            up   = v["up"]
            down = v["down"]
            total_up   += up
            total_down += down
            rows.append((name, key, up, down, up + down))

        col = self._traffic_sort_col
        reverse = not self._traffic_sort_asc
        if col in ("上传", "下载", "总流量"):
            idx = {"上传": 2, "下载": 3, "总流量": 4}[col]
            rows.sort(key=lambda r: r[idx], reverse=reverse)
        else:
            rows.sort(key=lambda r: r[0], reverse=reverse)

        for i, row in enumerate(rows):
            self.traffic_tree.insert("", tk.END, values=(
                row[0], row[1],
                _fmt_bytes(row[2]),
                _fmt_bytes(row[3]),
                _fmt_bytes(row[4]),
            ), tags=("odd" if i % 2 else "even",))

        label_map = {"日": f"{ref_date}", "月": f"{ref_date.year}-{ref_date.month:02d}",
                     "年": str(ref_date.year), "全部": "全部时间"}
        self._traffic_summary_label.config(
            text=f"  {label_map.get(rng, rng)}  合计：上传 {_fmt_bytes(total_up)}  下载 {_fmt_bytes(total_down)}  共 {_fmt_bytes(total_up+total_down)}")

    def _sort_traffic_tree(self, col):
        if self._traffic_sort_col == col:
            self._traffic_sort_asc = not self._traffic_sort_asc
        else:
            self._traffic_sort_col = col
            self._traffic_sort_asc = False
        self._refresh_traffic_tab()

    def _on_tab_changed(self, event):
        idx = self.notebook.index(self.notebook.select())
        if idx == 1:
            self._refresh_history_tab()
        elif idx == 2:
            self._refresh_traffic_tab()

    # ──────── 工具方法 ────────

    def _set_status(self, text, color=None):
        if color is None:
            color = C["overlay1"]
        self.bottom_label.config(text=text, fg=color)

    def on_close(self):
        """关闭窗口时自动恢复 TTL，保存自定义名称"""
        self.running = False
        if self.campus_mode_on:
            reset_ttl()
        _save_json(NAMES_FILE, self.custom_names)
        _save_json(HISTORY_FILE, self._device_history)
        _save_json(TRAFFIC_FILE, self._traffic_log)
        self.root.destroy()


# ─────────────────────── 格式化工具 ───────────────────────

def _fmt_bytes(b):
    if b < 1024:
        return f"{b} B"
    elif b < 1024 ** 2:
        return f"{b/1024:.1f} KB"
    elif b < 1024 ** 3:
        return f"{b/1024**2:.2f} MB"
    else:
        return f"{b/1024**3:.2f} GB"


def _fmt_speed(bps):
    if bps < 1:
        return "0 B/s"
    elif bps < 1024:
        return f"{bps:.0f} B/s"
    elif bps < 1024 ** 2:
        return f"{bps/1024:.1f} KB/s"
    else:
        return f"{bps/1024**2:.2f} MB/s"


# ─────────────────────── 入口 ───────────────────────

def main():
    root = tk.Tk()
    app  = WifiMonitorApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
