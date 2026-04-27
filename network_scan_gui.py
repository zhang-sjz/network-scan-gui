#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import concurrent.futures
import datetime
import ipaddress
import platform
import socket
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Dict, List


DEFAULT_PORTS = "21,22,23,25,53,80,110,123,135,139,143,161,389,443,445,3306,3389,5432,6379,8080,8443"
DEFAULT_PROBE_PORTS = "22,80,443,445,3389,8080"
DISCOVERY_MODES = ["ping-only", "ping+tcp", "tcp-only"]

PORT_SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


def html_escape(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def parse_ports(ports_text: str) -> List[int]:
    ports = set()
    for part in ports_text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            start, end = int(a), int(b)
            if start > end:
                start, end = end, start
            for p in range(start, end + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


def parse_target_ips(target_text: str) -> List[str]:
    target_text = target_text.strip()
    if not target_text:
        return []
    if "/" in target_text:
        net = ipaddress.ip_network(target_text, strict=False)
        return [str(ip) for ip in net.hosts()]
    return [x.strip() for x in target_text.split(",") if x.strip()]


def ping_host(ip: str, timeout_ms: int = 800) -> bool:
    system = platform.system().lower()
    if "windows" in system:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        timeout_s = max(1, int(timeout_ms / 1000))
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def scan_port(ip: str, port: int, timeout: float = 0.6) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        sock.close()


def tcp_probe_host(ip: str, ports: List[int], timeout: float = 0.4) -> bool:
    return any(scan_port(ip, p, timeout) for p in ports)


def arp_probe_host(ip: str) -> bool:
    system = platform.system().lower()
    if "windows" in system:
        cmd = ["arp", "-a", ip]
    else:
        cmd = ["arp", "-n", ip]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            check=False,
        )
        out = (result.stdout or "").lower()
        if ip not in out:
            return False
        # 常见未命中关键字，表示没有有效ARP邻居记录
        invalid_tokens = ("incomplete", "failed", "no entries", "无条目", "未找到", "无效")
        return not any(token in out for token in invalid_tokens)
    except Exception:
        return False


def get_local_ipv4_addrs() -> List[str]:
    addrs = set()
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM):
            ip = info[4][0]
            if ip and not ip.startswith("127."):
                addrs.add(ip)
    except Exception:
        pass
    return sorted(addrs)


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "-"


class NetworkScanGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("网络扫描双模块工具")
        self.root.geometry("1180x860")
        self.root.minsize(1080, 820)
        self.root.configure(bg="#0f172a")

        self.ip_results: List[Dict] = []
        self.port_results: List[Dict] = []
        self.is_running = False

        self._setup_styles()
        self._build_ui()

    def _setup_styles(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("App.TFrame", background="#0f172a")
        style.configure(
            "Card.TLabelframe",
            background="#111827",
            foreground="#e5e7eb",
            bordercolor="#334155",
            relief="solid",
            borderwidth=1,
            padding=10,
        )
        style.configure("Card.TLabelframe.Label", background="#111827", foreground="#93c5fd")
        style.configure("Dark.TLabel", background="#111827", foreground="#d1d5db")
        style.configure("Hint.TLabel", background="#111827", foreground="#94a3b8")
        style.configure("Status.TLabel", background="#111827", foreground="#60a5fa")
        style.configure("Dark.TCheckbutton", background="#111827", foreground="#d1d5db")
        style.map(
            "Dark.TCheckbutton",
            background=[("active", "#111827")],
            foreground=[("active", "#f9fafb")],
        )

        style.configure(
            "Dark.TEntry",
            fieldbackground="#1f2937",
            foreground="#f9fafb",
            bordercolor="#334155",
            insertcolor="#f9fafb",
        )
        style.configure(
            "Dark.TCombobox",
            fieldbackground="#1f2937",
            foreground="#f9fafb",
            bordercolor="#334155",
            arrowcolor="#93c5fd",
        )
        style.map(
            "Dark.TCombobox",
            fieldbackground=[("readonly", "#1f2937")],
            foreground=[("readonly", "#f9fafb")],
        )

        style.configure(
            "Primary.TButton",
            background="#2563eb",
            foreground="#ffffff",
            bordercolor="#1d4ed8",
            focusthickness=0,
            padding=(10, 6),
        )
        style.map(
            "Primary.TButton",
            background=[("active", "#1d4ed8"), ("pressed", "#1e40af"), ("disabled", "#475569")],
            foreground=[("disabled", "#cbd5e1")],
        )

    def _build_ui(self) -> None:
        main = ttk.Frame(self.root, padding=10, style="App.TFrame")
        main.pack(fill=tk.BOTH, expand=True)
        main.columnconfigure(0, weight=0)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(0, weight=1)

        left = ttk.LabelFrame(main, text="参数与控制", padding=10, style="Card.TLabelframe")
        left.grid(row=0, column=0, sticky="nsw")

        right = ttk.LabelFrame(main, text="运行日志", padding=10, style="Card.TLabelframe")
        right.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        right.columnconfigure(0, weight=1)
        right.rowconfigure(0, weight=1)

        ttk.Label(left, text="扫描网段 (模块1):", style="Dark.TLabel").grid(row=0, column=0, sticky="w")
        self.network_var = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(left, textvariable=self.network_var, width=38, style="Dark.TEntry").grid(
            row=1, column=0, sticky="we", pady=(2, 8)
        )

        ttk.Label(left, text="扫描端口 (模块2):", style="Dark.TLabel").grid(row=2, column=0, sticky="w")
        self.ports_var = tk.StringVar(value=DEFAULT_PORTS)
        ports_row = ttk.Frame(left, style="App.TFrame")
        ports_row.grid(row=3, column=0, sticky="we", pady=(2, 8))
        ttk.Entry(ports_row, textvariable=self.ports_var, width=28, style="Dark.TEntry").pack(
            side=tk.LEFT, fill=tk.X, expand=True
        )
        ttk.Button(ports_row, text="全端口", command=self.set_full_ports, style="Primary.TButton").pack(
            side=tk.LEFT, padx=(6, 0)
        )

        ttk.Label(left, text="端口目标模式:", style="Dark.TLabel").grid(row=4, column=0, sticky="w")
        self.target_mode_var = tk.StringVar(value="alive")
        mode_box = ttk.Combobox(
            left,
            textvariable=self.target_mode_var,
            values=["alive", "manual"],
            state="readonly",
            style="Dark.TCombobox",
            width=35,
        )
        mode_box.grid(row=5, column=0, sticky="we", pady=(2, 8))

        ttk.Label(left, text="manual目标IP/网段:", style="Dark.TLabel").grid(row=6, column=0, sticky="w")
        self.targets_var = tk.StringVar(value="")
        ttk.Entry(left, textvariable=self.targets_var, width=38, style="Dark.TEntry").grid(
            row=7, column=0, sticky="we", pady=(2, 8)
        )

        ttk.Label(left, text="并发线程(主机):", style="Dark.TLabel").grid(row=8, column=0, sticky="w")
        self.host_workers_var = tk.StringVar(value="128")
        ttk.Entry(left, textvariable=self.host_workers_var, width=38, style="Dark.TEntry").grid(
            row=9, column=0, sticky="we", pady=(2, 8)
        )

        ttk.Label(left, text="Ping超时(ms):", style="Dark.TLabel").grid(row=10, column=0, sticky="w")
        self.ping_timeout_var = tk.StringVar(value="800")
        ttk.Entry(left, textvariable=self.ping_timeout_var, width=38, style="Dark.TEntry").grid(
            row=11, column=0, sticky="we", pady=(2, 8)
        )

        ttk.Label(left, text="主机探测策略:", style="Dark.TLabel").grid(row=12, column=0, sticky="w")
        self.discovery_mode_var = tk.StringVar(value="ping+tcp")
        discover_mode_box = ttk.Combobox(
            left,
            textvariable=self.discovery_mode_var,
            values=DISCOVERY_MODES,
            state="readonly",
            style="Dark.TCombobox",
            width=35,
        )
        discover_mode_box.grid(row=13, column=0, sticky="we", pady=(2, 8))

        ttk.Label(left, text="TCP补探测端口:", style="Dark.TLabel").grid(row=14, column=0, sticky="w")
        self.probe_ports_var = tk.StringVar(value=DEFAULT_PROBE_PORTS)
        ttk.Entry(left, textvariable=self.probe_ports_var, width=38, style="Dark.TEntry").grid(
            row=15, column=0, sticky="we", pady=(2, 8)
        )

        self.arp_local_only_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            left,
            text="仅同网段启用ARP兜底",
            variable=self.arp_local_only_var,
            style="Dark.TCheckbutton",
        ).grid(row=16, column=0, sticky="w", pady=(0, 8))

        ttk.Label(
            left,
            text="提示：ARP主要适用于同网段；跨网段结果可能受网关与缓存影响。",
            style="Hint.TLabel",
        ).grid(row=17, column=0, sticky="w", pady=(0, 8))

        ttk.Label(left, text="端口超时(s):", style="Dark.TLabel").grid(row=18, column=0, sticky="w")
        self.port_timeout_var = tk.StringVar(value="0.6")
        ttk.Entry(left, textvariable=self.port_timeout_var, width=38, style="Dark.TEntry").grid(
            row=19, column=0, sticky="we", pady=(2, 8)
        )

        ttk.Label(left, text="HTML输出文件:", style="Dark.TLabel").grid(row=20, column=0, sticky="w")
        out_row = ttk.Frame(left, style="App.TFrame")
        out_row.grid(row=21, column=0, sticky="we", pady=(2, 10))
        self.output_var = tk.StringVar(value="scan_report_gui.html")
        ttk.Entry(out_row, textvariable=self.output_var, width=28, style="Dark.TEntry").pack(
            side=tk.LEFT, fill=tk.X, expand=True
        )
        ttk.Button(out_row, text="选择", command=self.choose_output_file, style="Primary.TButton").pack(
            side=tk.LEFT, padx=(6, 0)
        )

        btn_row1 = ttk.Frame(left, style="App.TFrame")
        btn_row1.grid(row=22, column=0, sticky="we", pady=(2, 6))
        ttk.Button(btn_row1, text="模块1：IP探测", command=self.run_module1, style="Primary.TButton").pack(
            side=tk.LEFT, fill=tk.X, expand=True
        )
        ttk.Button(btn_row1, text="模块2：端口扫描", command=self.run_module2, style="Primary.TButton").pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 0)
        )

        btn_row2 = ttk.Frame(left, style="App.TFrame")
        btn_row2.grid(row=23, column=0, sticky="we")
        ttk.Button(btn_row2, text="一键全流程", command=self.run_all, style="Primary.TButton").pack(
            side=tk.LEFT, fill=tk.X, expand=True
        )
        ttk.Button(btn_row2, text="生成HTML报告", command=self.export_html_only, style="Primary.TButton").pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 0)
        )

        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(left, textvariable=self.status_var, style="Status.TLabel").grid(row=24, column=0, sticky="w", pady=(10, 0))

        self.log_text = scrolledtext.ScrolledText(right, wrap=tk.WORD, height=40)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        self.log_text.configure(
            bg="#0b1220",
            fg="#e2e8f0",
            insertbackground="#93c5fd",
            selectbackground="#1d4ed8",
            selectforeground="#ffffff",
            relief=tk.FLAT,
            padx=8,
            pady=8,
        )

        self._log("工具已启动。请先配置参数，然后选择模块执行。")

    def _set_running(self, running: bool, status_text: str) -> None:
        self.is_running = running
        self.status_var.set(status_text)

    def _log(self, message: str) -> None:
        now = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{now}] {message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def choose_output_file(self) -> None:
        path = filedialog.asksaveasfilename(
            title="选择HTML输出文件",
            defaultextension=".html",
            filetypes=[("HTML File", "*.html"), ("All Files", "*.*")],
        )
        if path:
            self.output_var.set(path)

    def set_full_ports(self) -> None:
        self.ports_var.set("1-65535")
        self._log("端口范围已设置为全端口: 1-65535")

    def _read_inputs(self):
        try:
            network = self.network_var.get().strip()
            ipaddress.ip_network(network, strict=False)
            ports = parse_ports(self.ports_var.get().strip())
            if not ports:
                raise ValueError("端口列表为空")
            host_workers = int(self.host_workers_var.get().strip())
            ping_timeout = int(self.ping_timeout_var.get().strip())
            discovery_mode = self.discovery_mode_var.get().strip()
            if discovery_mode not in DISCOVERY_MODES:
                raise ValueError(f"无效探测策略: {discovery_mode}")
            probe_ports = parse_ports(self.probe_ports_var.get().strip())
            if discovery_mode != "ping-only" and not probe_ports:
                raise ValueError("TCP探测模式下补探测端口不能为空")
            arp_local_only = bool(self.arp_local_only_var.get())
            port_timeout = float(self.port_timeout_var.get().strip())
            target_mode = self.target_mode_var.get().strip()
            targets = self.targets_var.get().strip()
            output = self.output_var.get().strip() or "scan_report_gui.html"
            return {
                "network": network,
                "ports": ports,
                "ports_spec": self.ports_var.get().strip(),
                "host_workers": host_workers,
                "ping_timeout": ping_timeout,
                "discovery_mode": discovery_mode,
                "probe_ports": probe_ports,
                "probe_ports_spec": self.probe_ports_var.get().strip(),
                "arp_local_only": arp_local_only,
                "port_timeout": port_timeout,
                "target_mode": target_mode,
                "targets": targets,
                "output": output,
            }
        except Exception as exc:
            raise ValueError(f"参数错误: {exc}") from exc

    def _run_in_thread(self, func):
        if self.is_running:
            messagebox.showwarning("提示", "已有任务正在运行，请稍候。")
            return

        t = threading.Thread(target=func, daemon=True)
        t.start()

    def run_module1(self) -> None:
        self._run_in_thread(self._run_module1_impl)

    def run_module2(self) -> None:
        self._run_in_thread(self._run_module2_impl)

    def run_all(self) -> None:
        self._run_in_thread(self._run_all_impl)

    def export_html_only(self) -> None:
        self._run_in_thread(self._export_html_only_impl)

    def _run_module1_impl(self) -> None:
        try:
            cfg = self._read_inputs()
        except ValueError as exc:
            messagebox.showerror("参数错误", str(exc))
            return

        self._set_running(True, "模块1执行中...")
        try:
            self.ip_results = self.module_ip_discovery(
                network=cfg["network"],
                host_workers=cfg["host_workers"],
                ping_timeout=cfg["ping_timeout"],
                discovery_mode=cfg["discovery_mode"],
                probe_ports=cfg["probe_ports"],
                arp_local_only=cfg["arp_local_only"],
            )
            online_count = sum(1 for x in self.ip_results if x.get("status") == "online")
            suspected_count = sum(1 for x in self.ip_results if x.get("status") == "suspected")
            self._log(f"模块1完成：在线IP {online_count} 台，疑似在线 {suspected_count} 台。")
            self._set_running(False, "模块1完成")
        except Exception as exc:
            self._log(f"模块1失败：{exc}")
            self._set_running(False, "模块1失败")
            messagebox.showerror("模块1失败", str(exc))

    def _run_module2_impl(self) -> None:
        try:
            cfg = self._read_inputs()
        except ValueError as exc:
            messagebox.showerror("参数错误", str(exc))
            return

        self._set_running(True, "模块2执行中...")
        try:
            if cfg["target_mode"] == "alive":
                targets = [x["ip"] for x in self.ip_results if x.get("status") in ("online", "suspected")]
                if not targets:
                    self._log("模块2提示：当前没有模块1结果，请先运行模块1。")
                    self._set_running(False, "模块2未执行")
                    return
            else:
                targets = parse_target_ips(cfg["targets"])
                if not targets:
                    raise ValueError("manual模式下未提供有效目标IP/网段。")

            self.port_results = self.module_port_scan(
                target_ips=targets,
                ports=cfg["ports"],
                host_workers=max(16, min(cfg["host_workers"], 256)),
                port_timeout=cfg["port_timeout"],
            )
            self._log(f"模块2完成：扫描IP {len(self.port_results)} 台。")
            self._set_running(False, "模块2完成")
        except Exception as exc:
            self._log(f"模块2失败：{exc}")
            self._set_running(False, "模块2失败")
            messagebox.showerror("模块2失败", str(exc))

    def _run_all_impl(self) -> None:
        try:
            cfg = self._read_inputs()
        except ValueError as exc:
            messagebox.showerror("参数错误", str(exc))
            return

        self._set_running(True, "全流程执行中...")
        try:
            self.ip_results = self.module_ip_discovery(
                network=cfg["network"],
                host_workers=cfg["host_workers"],
                ping_timeout=cfg["ping_timeout"],
                discovery_mode=cfg["discovery_mode"],
                probe_ports=cfg["probe_ports"],
                arp_local_only=cfg["arp_local_only"],
            )

            if cfg["target_mode"] == "alive":
                targets = [x["ip"] for x in self.ip_results if x.get("status") in ("online", "suspected")]
            else:
                targets = parse_target_ips(cfg["targets"])

            if targets:
                self.port_results = self.module_port_scan(
                    target_ips=targets,
                    ports=cfg["ports"],
                    host_workers=max(16, min(cfg["host_workers"], 256)),
                    port_timeout=cfg["port_timeout"],
                )
            else:
                self.port_results = []
                self._log("模块2提示：没有可扫描目标，已跳过。")

            self.generate_html(
                output_file=cfg["output"],
                network=cfg["network"],
                ip_results=self.ip_results,
                port_results=self.port_results,
                ports_spec=cfg["ports_spec"],
            )
            self._log(f"全流程完成，报告已生成：{cfg['output']}")
            self._set_running(False, "全流程完成")
            messagebox.showinfo("完成", f"报告已生成：{cfg['output']}")
        except Exception as exc:
            self._log(f"全流程失败：{exc}")
            self._set_running(False, "全流程失败")
            messagebox.showerror("全流程失败", str(exc))

    def _export_html_only_impl(self) -> None:
        try:
            cfg = self._read_inputs()
        except ValueError as exc:
            messagebox.showerror("参数错误", str(exc))
            return

        self._set_running(True, "生成HTML中...")
        try:
            self.generate_html(
                output_file=cfg["output"],
                network=cfg["network"],
                ip_results=self.ip_results,
                port_results=self.port_results,
                ports_spec=cfg["ports_spec"],
            )
            self._log(f"HTML导出完成：{cfg['output']}")
            self._set_running(False, "HTML已生成")
            messagebox.showinfo("完成", f"HTML已生成：{cfg['output']}")
        except Exception as exc:
            self._log(f"HTML生成失败：{exc}")
            self._set_running(False, "HTML失败")
            messagebox.showerror("HTML失败", str(exc))

    def module_ip_discovery(
        self,
        network: str,
        host_workers: int,
        ping_timeout: int,
        discovery_mode: str = "ping+tcp",
        probe_ports: List[int] = None,
        arp_local_only: bool = True,
    ) -> List[Dict]:
        net = ipaddress.ip_network(network, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
        probe_ports = probe_ports or parse_ports(DEFAULT_PROBE_PORTS)
        states: Dict[str, Dict[str, str]] = {
            ip: {"status": "offline", "method": "-", "hostname": "-"} for ip in hosts
        }

        self._log(
            f"[模块1] 开始扫描网段 {network}，主机总数 {len(hosts)}，策略={discovery_mode}，补探测端口={','.join(str(p) for p in probe_ports)}"
        )

        if discovery_mode in ("ping-only", "ping+tcp"):
            with concurrent.futures.ThreadPoolExecutor(max_workers=host_workers) as executor:
                future_to_ip = {executor.submit(ping_host, ip, ping_timeout): ip for ip in hosts}
                done = 0
                for future in concurrent.futures.as_completed(future_to_ip):
                    done += 1
                    ip = future_to_ip[future]
                    try:
                        if future.result():
                            states[ip]["status"] = "online"
                            states[ip]["method"] = "ping"
                    except Exception:
                        pass
                    if done % 30 == 0:
                        self._log(f"[模块1] ping进度 {done}/{len(hosts)}")

        if discovery_mode == "ping-only":
            not_online = [ip for ip in hosts if states[ip]["status"] != "online"]
        elif discovery_mode == "tcp-only":
            not_online = hosts
            self._log(f"[模块1] 跳过ping，直接对 {len(not_online)} 台进行TCP探测")
        else:
            ping_hit = sum(1 for ip in hosts if states[ip]["status"] == "online")
            not_online = [ip for ip in hosts if states[ip]["status"] != "online"]
            self._log(f"[模块1] ping命中 {ping_hit}，对 {len(not_online)} 台进行TCP补探测")

        if not_online and discovery_mode in ("ping+tcp", "tcp-only"):
            with concurrent.futures.ThreadPoolExecutor(max_workers=host_workers) as executor:
                future_to_ip = {executor.submit(tcp_probe_host, ip, probe_ports, 0.4): ip for ip in not_online}
                done = 0
                for future in concurrent.futures.as_completed(future_to_ip):
                    done += 1
                    ip = future_to_ip[future]
                    try:
                        if future.result():
                            states[ip]["status"] = "online"
                            states[ip]["method"] = "tcp-probe"
                    except Exception:
                        pass
                    if done % 30 == 0:
                        self._log(f"[模块1] TCP补探测进度 {done}/{len(not_online)}")

        remain = [ip for ip in hosts if states[ip]["status"] != "online"]
        should_run_arp = True
        local_ips = get_local_ipv4_addrs()
        same_segment = any(ipaddress.ip_address(local_ip) in net for local_ip in local_ips)
        if arp_local_only and not same_segment:
            should_run_arp = False
            self._log(
                "[模块1] 当前网段与本机非同网段，按配置跳过ARP兜底（跨网段ARP可信度较低）"
            )
        elif not same_segment:
            self._log("[模块1] 提示：当前为跨网段扫描，ARP结果可信度较低，仅供参考")

        if remain and should_run_arp:
            self._log(f"[模块1] 对 {len(remain)} 台执行ARP兜底探测")
            with concurrent.futures.ThreadPoolExecutor(max_workers=host_workers) as executor:
                future_to_ip = {executor.submit(arp_probe_host, ip): ip for ip in remain}
                done = 0
                for future in concurrent.futures.as_completed(future_to_ip):
                    done += 1
                    ip = future_to_ip[future]
                    try:
                        if future.result():
                            states[ip]["status"] = "suspected"
                            states[ip]["method"] = "arp-cache"
                    except Exception:
                        pass
                    if done % 30 == 0:
                        self._log(f"[模块1] ARP兜底进度 {done}/{len(remain)}")

        for ip in hosts:
            if states[ip]["status"] != "offline":
                states[ip]["hostname"] = reverse_dns(ip)

        results = [
            {
                "ip": ip,
                "hostname": states[ip]["hostname"],
                "method": states[ip]["method"],
                "status": states[ip]["status"],
            }
            for ip in hosts
        ]
        results = sorted(results, key=lambda x: tuple(int(n) for n in x["ip"].split(".")))
        online_count = sum(1 for x in results if x["status"] == "online")
        suspected_count = sum(1 for x in results if x["status"] == "suspected")
        offline_count = sum(1 for x in results if x["status"] == "offline")
        self._log(
            f"[模块1] 完成，在线 {online_count} 台，疑似在线 {suspected_count} 台，离线 {offline_count} 台"
        )
        return results

    def module_port_scan(
        self, target_ips: List[str], ports: List[int], host_workers: int, port_timeout: float
    ) -> List[Dict]:
        self._log(f"[模块2] 开始扫描 {len(target_ips)} 台主机，端口数 {len(ports)}")

        def scan_one_ip(ip: str) -> Dict:
            open_ports = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(512, max(50, len(ports)))) as ex:
                fut_map = {ex.submit(scan_port, ip, p, port_timeout): p for p in ports}
                for fut in concurrent.futures.as_completed(fut_map):
                    p = fut_map[fut]
                    try:
                        if fut.result():
                            open_ports.append(p)
                    except Exception:
                        pass
            open_ports.sort()
            return {"ip": ip, "hostname": reverse_dns(ip), "open_ports": open_ports}

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=host_workers) as executor:
            fut_map = {executor.submit(scan_one_ip, ip): ip for ip in target_ips}
            done = 0
            total = len(target_ips)
            for fut in concurrent.futures.as_completed(fut_map):
                done += 1
                ip = fut_map[fut]
                try:
                    item = fut.result()
                    results.append(item)
                    self._log(f"[模块2] [{done}/{total}] {ip} 开放端口 {len(item['open_ports'])} 个")
                except Exception as exc:
                    self._log(f"[模块2] [{done}/{total}] {ip} 扫描失败: {exc}")

        results = sorted(results, key=lambda x: tuple(int(n) for n in x["ip"].split(".")))
        self._log("[模块2] 完成")
        return results

    def build_ip_heatmap_html(self, network: str, ip_results: List[Dict]) -> str:
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError:
            return "<p>网段格式无效，无法生成IP分布图。</p>"

        if not isinstance(net, ipaddress.IPv4Network):
            return "<p>仅IPv4网段支持IP分布图。</p>"

        # 只在 /24 或更小主机范围时展示网格图，避免页面过大
        if net.num_addresses - 2 > 254:
            return "<p>当前网段主机过多，已跳过分布图显示（建议使用 /24）。</p>"

        status_map = {item["ip"]: item.get("status", "online") for item in ip_results}
        cells = []
        for host in net.hosts():
            ip = str(host)
            last = int(ip.split(".")[-1])
            status = status_map.get(ip, "offline")
            if status == "online":
                css = "ip-online"
                status_text = "在线"
            elif status == "suspected":
                css = "ip-suspected"
                status_text = "疑似在线"
            else:
                css = "ip-offline"
                status_text = "离线"
            title = f"{ip} - {status_text}"
            cells.append(
                f'<div class="ip-cell {css}" title="{html_escape(title)}">{last}</div>'
            )

        legend = (
            '<div class="ip-legend">'
            '<span><i class="dot online"></i>在线</span>'
            '<span><i class="dot suspected"></i>疑似在线</span>'
            '<span><i class="dot offline"></i>离线</span>'
            "</div>"
        )
        return legend + '<div class="ip-grid">' + "".join(cells) + "</div>"

    def generate_html(
        self,
        output_file: str,
        network: str,
        ip_results: List[Dict],
        port_results: List[Dict],
        ports_spec: str,
    ) -> None:
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_open = sum(len(i["open_ports"]) for i in port_results)
        ip_heatmap_html = self.build_ip_heatmap_html(network, ip_results)
        online_count = sum(1 for i in ip_results if i.get("status") == "online")
        suspected_count = sum(1 for i in ip_results if i.get("status") == "suspected")
        offline_count = sum(1 for i in ip_results if i.get("status") == "offline")

        ip_rows = []
        for item in ip_results:
            ip_rows.append(
                f"""
                <tr>
                    <td>{html_escape(item['ip'])}</td>
                    <td>{html_escape(item['hostname'])}</td>
                    <td>{html_escape(item.get('status', 'online'))}</td>
                    <td>{html_escape(item['method'])}</td>
                </tr>
                """
            )

        port_rows = []
        for item in port_results:
            if item["open_ports"]:
                detail = ", ".join(f"{p}({PORT_SERVICE_MAP.get(p, 'Unknown')})" for p in item["open_ports"])
            else:
                detail = "-"
            port_rows.append(
                f"""
                <tr>
                    <td>{html_escape(item['ip'])}</td>
                    <td>{html_escape(item['hostname'])}</td>
                    <td>{len(item['open_ports'])}</td>
                    <td>{html_escape(detail)}</td>
                </tr>
                """
            )

        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>网络扫描双模块报告</title>
<style>
body {{
    font-family: Arial, "Microsoft YaHei", sans-serif;
    background: #f6f8fb;
    color: #222;
    margin: 20px;
}}
.container {{
    background: #fff;
    border-radius: 10px;
    box-shadow: 0 2px 10px rgba(0,0,0,.08);
    padding: 20px;
}}
h1, h2 {{
    margin-top: 0;
}}
.meta {{
    background: #eef4ff;
    border-left: 4px solid #4a78ff;
    padding: 10px 12px;
    margin-bottom: 16px;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin: 10px 0 24px;
}}
th, td {{
    border: 1px solid #dce4f1;
    padding: 9px;
    text-align: left;
    vertical-align: top;
}}
th {{
    background: #edf3ff;
}}
tr:nth-child(even) {{
    background: #fafcff;
}}
.footer {{
    font-size: 12px;
    color: #666;
}}
.ip-legend {{
    display: flex;
    gap: 16px;
    margin: 4px 0 8px;
    align-items: center;
}}
.ip-legend .dot {{
    display: inline-block;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    margin-right: 5px;
}}
.ip-legend .dot.online {{
    background: #2db8ff;
}}
.ip-legend .dot.suspected {{
    background: #f59e0b;
}}
.ip-legend .dot.offline {{
    background: #8f98a3;
}}
.ip-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(44px, 1fr));
    gap: 4px;
    margin-bottom: 16px;
}}
.ip-cell {{
    height: 24px;
    border-radius: 4px;
    font-size: 11px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #fff;
}}
.ip-online {{
    background: #2db8ff;
}}
.ip-suspected {{
    background: #f59e0b;
}}
.ip-offline {{
    background: #8f98a3;
}}
</style>
</head>
<body>
<div class="container">
    <h1>网络扫描双模块报告</h1>
    <div class="meta">
        <div><strong>扫描时间:</strong> {html_escape(now)}</div>
        <div><strong>网段:</strong> {html_escape(network)}</div>
        <div><strong>模块1在线IP数量:</strong> {online_count}</div>
        <div><strong>模块1疑似在线数量:</strong> {suspected_count}</div>
        <div><strong>模块1离线数量:</strong> {offline_count}</div>
        <div><strong>模块2总开放端口数:</strong> {total_open}</div>
        <div><strong>模块2端口范围:</strong> {html_escape(ports_spec)}</div>
    </div>

    <h2>模块1：IP使用探测结果</h2>
    {ip_heatmap_html}
    <table>
        <thead>
            <tr>
                <th>IP</th>
                <th>主机名 (DNS反查)</th>
                <th>状态</th>
                <th>探测方式</th>
            </tr>
        </thead>
        <tbody>
            {''.join(ip_rows) if ip_rows else '<tr><td colspan="4">暂无模块1结果</td></tr>'}
        </tbody>
    </table>

    <h2>模块2：端口开放探测结果</h2>
    <table>
        <thead>
            <tr>
                <th>IP</th>
                <th>主机名 (DNS反查)</th>
                <th>开放端口数</th>
                <th>开放端口明细</th>
            </tr>
        </thead>
        <tbody>
            {''.join(port_rows) if port_rows else '<tr><td colspan="4">无端口扫描结果</td></tr>'}
        </tbody>
    </table>

    <div class="footer">说明：仅用于授权环境下的资产探测与运维排查。</div>
</div>
</body>
</html>
"""
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)


def main() -> None:
    root = tk.Tk()
    NetworkScanGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
