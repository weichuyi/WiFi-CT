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
        self.root.geometry("1100x700")
        self.root.resizable(True, True)
        self.root.configure(bg="#1e1e2e")

        self.running          = False
        self.sniff_thread     = None
        self.refresh_interval = 2000
        self.campus_mode_on   = False

        self.device_cache       = {}
        self.device_cache_lock  = threading.Lock()
        # 从文件加载自定义名称
        self.custom_names       = _load_json(NAMES_FILE, {})
        self._resolving_ips     = set()

        # 设备历史记录：{mac: {name, ip, first_seen, last_seen, sessions:[]}}
        self._device_history    = _load_json(HISTORY_FILE, {})
        # 流量日志：{"YYYY-MM-DD": {mac: {up, down}}, ...}
        self._traffic_log       = _load_json(TRAFFIC_FILE, {})
        # 本次会话每台设备在流量日志里的基准（防止重复累计）
        self._session_base      = {}   # {ip: {upload, download}}
        self._session_date      = date.today().isoformat()

        self._build_ui()
        self._build_context_menu()
        self._check_requirements()
        self._sync_ttl_state()

    # ──────── UI 构建 ────────

    def _build_ui(self):
        # 标题栏
        top = tk.Frame(self.root, bg="#1e1e2e")
        top.pack(fill=tk.X, padx=16, pady=(12, 0))

        tk.Label(top, text="📡  WiFi热点流量监控",
                 font=("微软雅黑", 16, "bold"),
                 fg="#cdd6f4", bg="#1e1e2e").pack(side=tk.LEFT)

        self.status_label = tk.Label(top, text="● 未启动",
                                     font=("微软雅黑", 10),
                                     fg="#f38ba8", bg="#1e1e2e")
        self.status_label.pack(side=tk.RIGHT, padx=8)

        # 校园网模式栏
        campus_bar = tk.Frame(self.root, bg="#2a2a3e")
        campus_bar.pack(fill=tk.X, padx=16, pady=(6, 0))

        tk.Label(campus_bar, text="🏫  校园网模式（解决热点断网）",
                 font=("微软雅黑", 9, "bold"), fg="#f9e2af", bg="#2a2a3e",
                 anchor="w", padx=10, pady=5).pack(side=tk.LEFT)

        tk.Label(campus_bar,
                 text="TTL伪装：让校园网无法通过TTL差异检测多设备  |  ⚠ 代理/VPN会修改HTTP请求头，另需在手机端关闭代理或使用全局透明代理",
                 font=("微软雅黑", 8), fg="#6c7086", bg="#2a2a3e",
                 anchor="w", padx=4).pack(side=tk.LEFT, fill=tk.X, expand=True)

        cbf = tk.Frame(campus_bar, bg="#2a2a3e")
        cbf.pack(side=tk.RIGHT, padx=8, pady=3)

        self.ttl_status_label = tk.Label(
            cbf, text=f"当前TTL：{get_current_ttl()}",
            font=("微软雅黑", 8), fg="#89dceb", bg="#2a2a3e", padx=6)
        self.ttl_status_label.pack(side=tk.LEFT)

        self.campus_btn = tk.Button(
            cbf, text="开启校园网模式",
            font=("微软雅黑", 9, "bold"), bg="#f9e2af", fg="#1e1e2e",
            relief=tk.FLAT, padx=10, pady=3, cursor="hand2",
            command=self.toggle_campus_mode)
        self.campus_btn.pack(side=tk.LEFT, padx=4)

        # 热点信息 + 控制按钮
        info_frame = tk.Frame(self.root, bg="#313244")
        info_frame.pack(fill=tk.X, padx=16, pady=8)

        self.hotspot_info = tk.Label(
            info_frame, text="热点状态：检测中...",
            font=("微软雅黑", 9), fg="#a6e3a1", bg="#313244",
            anchor="w", padx=10, pady=6)
        self.hotspot_info.pack(side=tk.LEFT, fill=tk.X, expand=True)

        btn_frame = tk.Frame(info_frame, bg="#313244")
        btn_frame.pack(side=tk.RIGHT, padx=8, pady=4)

        self.start_btn = tk.Button(
            btn_frame, text="▶ 开始监控",
            font=("微软雅黑", 9, "bold"), bg="#a6e3a1", fg="#1e1e2e",
            relief=tk.FLAT, padx=12, pady=4, cursor="hand2",
            command=self.toggle_monitor)
        self.start_btn.pack(side=tk.LEFT, padx=4)

        for text, color, cmd in [
            ("🔄 刷新设备",  "#89b4fa", self.refresh_devices),
            ("🗑 清空统计",  "#f38ba8", self.clear_stats),
            ("⚡ 断开设备",  "#cba6f7", self.kick_selected_device),
        ]:
            tk.Button(btn_frame, text=text, font=("微软雅黑", 9),
                      bg=color, fg="#1e1e2e", relief=tk.FLAT,
                      padx=10, pady=4, cursor="hand2",
                      command=cmd).pack(side=tk.LEFT, padx=3)

        # ── Notebook 标签页 ──
        nb_style = ttk.Style()
        nb_style.theme_use("clam")
        nb_style.configure("TNotebook", background="#1e1e2e", borderwidth=0)
        nb_style.configure("TNotebook.Tab",
                           background="#313244", foreground="#a6adc8",
                           padding=[12, 4], font=("微软雅黑", 9))
        nb_style.map("TNotebook.Tab",
                     background=[("selected", "#45475a")],
                     foreground=[("selected", "#cdd6f4")])

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 4))

        tab1 = tk.Frame(self.notebook, bg="#1e1e2e")
        tab2 = tk.Frame(self.notebook, bg="#1e1e2e")
        tab3 = tk.Frame(self.notebook, bg="#1e1e2e")

        self.notebook.add(tab1, text="📊 实时监控")
        self.notebook.add(tab2, text="📋 设备历史")
        self.notebook.add(tab3, text="📈 流量统计")

        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        self._build_monitor_tab(tab1)
        self._build_history_tab(tab2)
        self._build_traffic_tab(tab3)

        # 底部状态栏
        bottom = tk.Frame(self.root, bg="#313244")
        bottom.pack(fill=tk.X, side=tk.BOTTOM)

        self.bottom_label = tk.Label(
            bottom, text="就绪 | 需要管理员权限运行以获取完整功能",
            font=("微软雅黑", 8), fg="#6c7086", bg="#313244",
            anchor="w", padx=10, pady=4)
        self.bottom_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.device_count_label = tk.Label(
            bottom, text="设备数：0",
            font=("微软雅黑", 8), fg="#89b4fa", bg="#313244", padx=10)
        self.device_count_label.pack(side=tk.RIGHT)

    def _build_monitor_tab(self, parent):
        """实时监控标签页 - 设备列表"""
        cols       = ("设备名",  "IP地址",   "MAC地址",
                      "↑速率",   "↓速率",
                      "上传总量", "下载总量", "总流量",
                      "状态",    "首次发现")
        col_widths = [155, 120, 155, 90, 90, 90, 90, 90, 55, 120]

        style = ttk.Style()
        style.configure("Dark.Treeview",
                         background="#181825", foreground="#cdd6f4",
                         fieldbackground="#181825", rowheight=27,
                         font=("微软雅黑", 9))
        style.configure("Dark.Treeview.Heading",
                         background="#313244", foreground="#89b4fa",
                         font=("微软雅黑", 9, "bold"), relief=tk.FLAT)
        style.map("Dark.Treeview",
                  background=[("selected", "#45475a")],
                  foreground=[("selected", "#cdd6f4")])

        self.tree = ttk.Treeview(parent, columns=cols, show="headings",
                                  style="Dark.Treeview", selectmode="browse")
        for col, width in zip(cols, col_widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor=tk.CENTER)

        self.tree.tag_configure("offline", foreground="#585b70")
        self.tree.tag_configure("online",  foreground="#cdd6f4")
        self.tree.tag_configure("active",  foreground="#a6e3a1")

        vsb = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<Double-1>",  lambda e: self._rename_device())
        self.tree.bind("<Button-3>",  self._on_right_click)

    def _build_history_tab(self, parent):
        """设备历史标签页"""
        toolbar = tk.Frame(parent, bg="#1e1e2e")
        toolbar.pack(fill=tk.X, pady=(6, 2), padx=8)

        tk.Label(toolbar, text="所有曾连接过的设备（按最后上线时间排序）",
                 font=("微软雅黑", 9), fg="#a6adc8", bg="#1e1e2e").pack(side=tk.LEFT)

        tk.Button(toolbar, text="🗑 清空历史", font=("微软雅黑", 9),
                  bg="#f38ba8", fg="#1e1e2e", relief=tk.FLAT, padx=8, pady=2,
                  cursor="hand2", command=self._clear_history).pack(side=tk.RIGHT, padx=4)

        tk.Button(toolbar, text="🔄 刷新", font=("微软雅黑", 9),
                  bg="#89b4fa", fg="#1e1e2e", relief=tk.FLAT, padx=8, pady=2,
                  cursor="hand2", command=self._refresh_history_tab).pack(side=tk.RIGHT, padx=4)

        h_cols = ("设备名", "MAC地址", "最后IP", "首次连接", "最后连接", "累计上线次数")
        h_widths = [180, 155, 130, 155, 155, 100]

        frame = tk.Frame(parent, bg="#1e1e2e")
        frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 4))

        self.history_tree = ttk.Treeview(frame, columns=h_cols, show="headings",
                                          style="Dark.Treeview", selectmode="browse")
        for col, w in zip(h_cols, h_widths):
            self.history_tree.heading(col, text=col)
            self.history_tree.column(col, width=w, anchor=tk.CENTER)

        vsb2 = ttk.Scrollbar(frame, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=vsb2.set)
        self.history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb2.pack(side=tk.RIGHT, fill=tk.Y)

    def _build_traffic_tab(self, parent):
        """流量统计标签页"""
        top = tk.Frame(parent, bg="#1e1e2e")
        top.pack(fill=tk.X, padx=8, pady=(6, 2))

        tk.Label(top, text="统计范围：", font=("微软雅黑", 9),
                 fg="#a6adc8", bg="#1e1e2e").pack(side=tk.LEFT)

        self._traffic_range = tk.StringVar(value="日")
        for txt in ("日", "月", "年", "全部"):
            tk.Radiobutton(top, text=txt, variable=self._traffic_range, value=txt,
                           font=("微软雅黑", 9), fg="#cdd6f4", bg="#1e1e2e",
                           selectcolor="#313244", activebackground="#1e1e2e",
                           command=self._refresh_traffic_tab).pack(side=tk.LEFT, padx=4)

        # 日期选择
        tk.Label(top, text="  日期(YYYY-MM-DD):",
                 font=("微软雅黑", 9), fg="#a6adc8", bg="#1e1e2e").pack(side=tk.LEFT)
        self._traffic_date_var = tk.StringVar(value=date.today().isoformat())
        date_entry = tk.Entry(top, textvariable=self._traffic_date_var,
                              width=12, font=("微软雅黑", 9),
                              bg="#313244", fg="#cdd6f4",
                              insertbackground="#cdd6f4", relief=tk.FLAT)
        date_entry.pack(side=tk.LEFT, padx=4)

        tk.Button(top, text="查询", font=("微软雅黑", 9),
                  bg="#89b4fa", fg="#1e1e2e", relief=tk.FLAT, padx=8, pady=2,
                  cursor="hand2", command=self._refresh_traffic_tab).pack(side=tk.LEFT, padx=4)

        tk.Button(top, text="🔄", font=("微软雅黑", 9),
                  bg="#313244", fg="#cdd6f4", relief=tk.FLAT, padx=6, pady=2,
                  cursor="hand2", command=self._refresh_traffic_tab).pack(side=tk.LEFT)

        # 合计说明
        self._traffic_summary_label = tk.Label(
            parent, text="", font=("微软雅黑", 9, "bold"),
            fg="#f9e2af", bg="#1e1e2e", anchor="w", padx=12)
        self._traffic_summary_label.pack(fill=tk.X)

        t_cols = ("设备名", "MAC地址", "上传", "下载", "总流量")
        t_widths = [200, 160, 120, 120, 120]

        frame = tk.Frame(parent, bg="#1e1e2e")
        frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 4))

        self.traffic_tree = ttk.Treeview(frame, columns=t_cols, show="headings",
                                          style="Dark.Treeview", selectmode="browse")
        for col, w in zip(t_cols, t_widths):
            self.traffic_tree.heading(col, text=col,
                                      command=lambda c=col: self._sort_traffic_tree(c))
            self.traffic_tree.column(col, width=w, anchor=tk.CENTER)

        vsb3 = ttk.Scrollbar(frame, orient="vertical", command=self.traffic_tree.yview)
        self.traffic_tree.configure(yscrollcommand=vsb3.set)
        self.traffic_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb3.pack(side=tk.RIGHT, fill=tk.Y)

        self._traffic_sort_col = "总流量"
        self._traffic_sort_asc = False

    def _build_context_menu(self):
        self.context_menu = tk.Menu(
            self.root, tearoff=0,
            bg="#313244", fg="#cdd6f4",
            activebackground="#45475a",
            font=("微软雅黑", 9))
        self.context_menu.add_command(label="✏  重命名设备",   command=self._rename_device)
        self.context_menu.add_command(label="📋 复制 IP 地址", command=lambda: self._copy_field(1))
        self.context_menu.add_command(label="📋 复制 MAC 地址", command=lambda: self._copy_field(2))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="⚡ 断开该设备",   command=self.kick_selected_device)

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
        self.ttl_status_label.config(text=f"当前TTL：{current}")
        if current == TTL_CAMPUS:
            self.campus_mode_on = True
            self.campus_btn.config(text="关闭校园网模式", bg="#a6e3a1")
        else:
            self.campus_mode_on = False
            self.campus_btn.config(text="开启校园网模式", bg="#f9e2af")

    def toggle_campus_mode(self):
        if not self.campus_mode_on:
            ok, msg = set_ttl(TTL_CAMPUS)
            if ok:
                self.campus_mode_on = True
                self.campus_btn.config(text="关闭校园网模式", bg="#a6e3a1")
                self.ttl_status_label.config(text=f"当前TTL：{TTL_CAMPUS}")
                self._set_status("✅ 校园网模式已开启（TTL=64），热点设备不再被检测为多设备")
            else:
                messagebox.showerror("失败", msg + "\n\n请右键程序选择【以管理员身份运行】")
        else:
            ok, msg = reset_ttl()
            if ok:
                self.campus_mode_on = False
                self.campus_btn.config(text="开启校园网模式", bg="#f9e2af")
                self.ttl_status_label.config(text=f"当前TTL：{get_current_ttl()}")
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
                color="#f9e2af")
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
        self.start_btn.config(text="⏹ 停止监控", bg="#f38ba8")
        self.status_label.config(text="● 监控中", fg="#a6e3a1")

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
            self._set_status(f"⚠ 抓包错误：{sniff_error[:90]}", color="#f38ba8")
            sniff_error = None
        else:
            self._set_status(
                f"✅ 抓包已启动（接口：{getattr(self, '_scapy_iface_name', '未知')}），流量统计正常")

    def stop_monitor(self):
        self.running = False
        self.start_btn.config(text="▶ 开始监控", bg="#a6e3a1")
        self.status_label.config(text="● 已停止", fg="#fab387")
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
            status       = "离线" if offline else "在线"

            stat = stats_copy.get(ip,  {"upload": 0, "download": 0, "total": 0})
            spd  = speeds_copy.get(ip, {"up_speed": 0.0, "down_speed": 0.0})

            if offline:
                tag = "offline"
            elif spd["up_speed"] > 1024 or spd["down_speed"] > 1024:
                tag = "active"
            else:
                tag = "online"

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

        total_visible = len(self.tree.get_children())
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

        for row in rows:
            self.traffic_tree.insert("", tk.END, values=(
                row[0], row[1],
                _fmt_bytes(row[2]),
                _fmt_bytes(row[3]),
                _fmt_bytes(row[4]),
            ))

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

    def _set_status(self, text, color="#6c7086"):
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
