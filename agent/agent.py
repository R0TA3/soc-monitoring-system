"""
SOC Employee Agent
Runs on each employee machine. Monitors system activity and reports to the SOC server.
Responds to block/unblock commands from the server.
"""

import asyncio
import json
import logging
import os
import platform
import queue
import socket
import sys
import threading
import time
from datetime import datetime
from typing import Optional

import psutil
import requests
import websockets
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# ─────────────────────────────────────────────
# Config  (override via environment variables)
# ─────────────────────────────────────────────
SOC_SERVER   = os.getenv("SOC_SERVER",   "http://localhost:8000")
SOC_WS       = os.getenv("SOC_WS",       "ws://localhost:8000")
EMP_ID       = os.getenv("SOC_EMP_ID",   f"EMP-{socket.gethostname()}")
EMP_NAME     = os.getenv("SOC_EMP_NAME", socket.gethostname())
DEPARTMENT   = os.getenv("SOC_DEPT",     "General")

HEARTBEAT_INTERVAL  = int(os.getenv("HEARTBEAT_INTERVAL", "30"))   # seconds
MONITOR_INTERVAL    = int(os.getenv("MONITOR_INTERVAL",   "10"))   # seconds

WATCHED_PATHS = os.getenv("WATCHED_PATHS", os.path.expanduser("~")).split(",")

SENSITIVE_EXTENSIONS = {".xlsx", ".xls", ".csv", ".pdf", ".key", ".pem", ".p12", ".pfx", ".env"}
SENSITIVE_DIRS       = {"passwords", "credentials", "keys", "secrets", "private"}

SUSPICIOUS_PROCESSES = {
    "mimikatz", "nmap", "netcat", "nc", "nc.exe", "procdump",
    "meterpreter", "lazagne", "pwdump", "hashcat", "john",
    "aircrack-ng", "wireshark", "tcpdump", "hydra", "medusa"
}

TRUSTED_PORTS = {80, 443, 22, 53, 8080, 8443, 3389, 5900}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("agent.log")]
)
log = logging.getLogger("SOC-Agent")

# ─────────────────────────────────────────────
# Shared state
# ─────────────────────────────────────────────
is_blocked        = False
offline_queue: queue.Queue = queue.Queue()
last_users:    set          = set()
last_procs:    set          = set()
last_connections: set       = set()
my_ip: str = ""


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def severity_from_event(event_type: str) -> str:
    critical = {"INTRUSION_DETECTED", "UNAUTHORIZED_ACCESS", "SUSPICIOUS_PROCESS", "IP_BLOCKED"}
    high     = {"LOGIN_FAILED", "SENSITIVE_FILE_ACCESS", "UNUSUAL_CONNECTION", "USB_CONNECTED"}
    medium   = {"PROCESS_STARTED", "FILE_MODIFIED", "HIGH_CPU", "HIGH_MEMORY"}
    if event_type in critical:
        return "CRITICAL"
    if event_type in high:
        return "HIGH"
    if event_type in medium:
        return "MEDIUM"
    return "INFO"


# ─────────────────────────────────────────────
# Log sender
# ─────────────────────────────────────────────
def send_log(event_type: str, description: str, metadata: Optional[dict] = None, severity: Optional[str] = None):
    payload = {
        "emp_id":      EMP_ID,
        "emp_name":    EMP_NAME,
        "ip_address":  my_ip,
        "event_type":  event_type,
        "severity":    severity or severity_from_event(event_type),
        "description": description,
        "metadata":    metadata or {}
    }

    try:
        r = requests.post(f"{SOC_SERVER}/logs/ingest", json=payload, timeout=5)
        if r.status_code != 200:
            log.warning("Server returned %d — queuing event", r.status_code)
            offline_queue.put(payload)
    except requests.exceptions.ConnectionError:
        log.warning("Server unreachable — queuing event")
        offline_queue.put(payload)
    except Exception as e:
        log.error("send_log error: %s", e)
        offline_queue.put(payload)


def flush_offline_queue():
    """Retry queued events when server comes back online."""
    flushed = 0
    while not offline_queue.empty():
        payload = offline_queue.get()
        try:
            r = requests.post(f"{SOC_SERVER}/logs/ingest", json=payload, timeout=5)
            if r.status_code == 200:
                flushed += 1
            else:
                offline_queue.put(payload)
                break
        except Exception:
            offline_queue.put(payload)
            break
    if flushed:
        log.info("Flushed %d queued events", flushed)


# ─────────────────────────────────────────────
# Monitor: Login/Logout
# ─────────────────────────────────────────────
def monitor_logins():
    global last_users
    try:
        current = {u.name for u in psutil.users()}
        for u in current - last_users:
            log.info("User logged in: %s", u)
            send_log("USER_LOGIN", f"User '{u}' logged in", {"username": u})
        for u in last_users - current:
            log.info("User logged out: %s", u)
            send_log("USER_LOGOUT", f"User '{u}' logged out", {"username": u})
        last_users = current
    except Exception as e:
        log.error("login monitor error: %s", e)


# ─────────────────────────────────────────────
# Monitor: Processes
# ─────────────────────────────────────────────
def monitor_processes():
    global last_procs
    try:
        current = set()
        for proc in psutil.process_iter(["pid", "name", "username", "cmdline"]):
            try:
                name = proc.info["name"] or ""
                current.add(proc.pid)

                if proc.pid not in last_procs:
                    name_lower = name.lower().replace(".exe", "")
                    if name_lower in SUSPICIOUS_PROCESSES:
                        log.warning("Suspicious process: %s (PID %d)", name, proc.pid)
                        send_log(
                            "SUSPICIOUS_PROCESS",
                            f"Suspicious process launched: {name} (PID {proc.pid})",
                            {"process_name": name, "pid": proc.pid, "user": proc.info.get("username")}
                        )
                    else:
                        send_log(
                            "PROCESS_STARTED",
                            f"New process: {name} (PID {proc.pid})",
                            {"process_name": name, "pid": proc.pid},
                            severity="INFO"
                        )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        last_procs = current
    except Exception as e:
        log.error("process monitor error: %s", e)


# ─────────────────────────────────────────────
# Monitor: Network connections
# ─────────────────────────────────────────────
def monitor_network():
    global last_connections
    try:
        current = set()
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "ESTABLISHED" and conn.raddr:
                key = (conn.laddr.port, conn.raddr.ip, conn.raddr.port)
                current.add(key)

                if key not in last_connections:
                    remote_port = conn.raddr.port
                    if remote_port not in TRUSTED_PORTS:
                        log.warning("Unusual connection → %s:%d", conn.raddr.ip, remote_port)
                        send_log(
                            "UNUSUAL_CONNECTION",
                            f"Unusual outbound connection to {conn.raddr.ip}:{remote_port}",
                            {"remote_ip": conn.raddr.ip, "remote_port": remote_port, "local_port": conn.laddr.port}
                        )
        last_connections = current
    except Exception as e:
        log.error("network monitor error: %s", e)


# ─────────────────────────────────────────────
# Monitor: Resource usage
# ─────────────────────────────────────────────
def monitor_resources():
    try:
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().percent

        if cpu > 90:
            send_log("HIGH_CPU", f"CPU usage critical: {cpu:.1f}%", {"cpu_percent": cpu})
        elif cpu > 70:
            send_log("HIGH_CPU", f"CPU usage high: {cpu:.1f}%", {"cpu_percent": cpu}, severity="MEDIUM")

        if mem > 90:
            send_log("HIGH_MEMORY", f"Memory usage critical: {mem:.1f}%", {"mem_percent": mem})

        # Regular heartbeat metrics
        send_log(
            "SYSTEM_METRICS",
            f"CPU: {cpu:.1f}% | RAM: {mem:.1f}%",
            {"cpu_percent": cpu, "mem_percent": mem},
            severity="INFO"
        )
    except Exception as e:
        log.error("resource monitor error: %s", e)


# ─────────────────────────────────────────────
# Monitor: USB / removable media
# ─────────────────────────────────────────────
_last_disk_serials: set = set()

def monitor_usb():
    global _last_disk_serials
    try:
        current = set()
        for disk in psutil.disk_partitions():
            if "removable" in disk.opts.lower() or "cdrom" in disk.opts.lower():
                current.add(disk.device)

        for d in current - _last_disk_serials:
            log.warning("USB/removable media connected: %s", d)
            send_log("USB_CONNECTED", f"Removable media connected: {d}", {"device": d})

        for d in _last_disk_serials - current:
            send_log("USB_REMOVED", f"Removable media removed: {d}", {"device": d}, severity="INFO")

        _last_disk_serials = current
    except Exception as e:
        log.error("USB monitor error: %s", e)


# ─────────────────────────────────────────────
# Monitor: File system (sensitive files)
# ─────────────────────────────────────────────
class SensitiveFileHandler(FileSystemEventHandler):
    def _check_path(self, path: str) -> bool:
        lower = path.lower()
        if any(lower.endswith(ext) for ext in SENSITIVE_EXTENSIONS):
            return True
        if any(d in lower for d in SENSITIVE_DIRS):
            return True
        return False

    def on_modified(self, event):
        if not event.is_directory and self._check_path(event.src_path):
            send_log(
                "SENSITIVE_FILE_ACCESS",
                f"Sensitive file modified: {event.src_path}",
                {"path": event.src_path, "action": "modified"}
            )

    def on_created(self, event):
        if not event.is_directory and self._check_path(event.src_path):
            send_log(
                "FILE_CREATED",
                f"Sensitive file created: {event.src_path}",
                {"path": event.src_path, "action": "created"},
                severity="MEDIUM"
            )

    def on_deleted(self, event):
        if not event.is_directory and self._check_path(event.src_path):
            send_log(
                "FILE_DELETED",
                f"Sensitive file deleted: {event.src_path}",
                {"path": event.src_path, "action": "deleted"}
            )

    def on_moved(self, event):
        if not event.is_directory and self._check_path(event.src_path):
            send_log(
                "FILE_MOVED",
                f"Sensitive file moved: {event.src_path} → {event.dest_path}",
                {"src": event.src_path, "dest": event.dest_path, "action": "moved"}
            )


def start_file_watcher():
    observer = Observer()
    handler  = SensitiveFileHandler()
    for path in WATCHED_PATHS:
        if os.path.exists(path):
            observer.schedule(handler, path, recursive=True)
            log.info("Watching path: %s", path)
    observer.start()
    return observer


# ─────────────────────────────────────────────
# Block handler
# ─────────────────────────────────────────────
def apply_block():
    global is_blocked
    is_blocked = True
    log.critical("⛔  THIS ENDPOINT HAS BEEN BLOCKED BY SOC")

    # On Windows, try to lock the workstation
    if platform.system() == "Windows":
        try:
            import ctypes
            ctypes.windll.user32.LockWorkStation()
        except Exception:
            pass

    # Log the block event
    send_log("ENDPOINT_BLOCKED", "This endpoint was blocked by the SOC server", severity="CRITICAL")


def apply_unblock():
    global is_blocked
    is_blocked = False
    log.info("✅  Endpoint unblocked by SOC")
    send_log("ENDPOINT_UNBLOCKED", "Endpoint unblocked by SOC", severity="INFO")


# ─────────────────────────────────────────────
# Agent registration
# ─────────────────────────────────────────────
def register():
    try:
        r = requests.post(
            f"{SOC_SERVER}/employees/register",
            json={
                "emp_id":     EMP_ID,
                "name":       EMP_NAME,
                "department": DEPARTMENT,
                "ip_address": my_ip
            },
            timeout=10
        )
        if r.status_code == 200:
            log.info("Registered with SOC server ✓")
        else:
            log.warning("Registration failed: %d", r.status_code)
    except Exception as e:
        log.error("Registration error: %s", e)


# ─────────────────────────────────────────────
# WebSocket connection (persistent)
# ─────────────────────────────────────────────
async def websocket_loop():
    ws_url = f"{SOC_WS}/ws/agent/{EMP_ID}"
    reconnect_delay = 5

    while True:
        try:
            log.info("Connecting WebSocket → %s", ws_url)
            async with websockets.connect(ws_url) as ws:
                log.info("WebSocket connected ✓")
                reconnect_delay = 5

                # Heartbeat coroutine
                async def send_heartbeats():
                    while True:
                        try:
                            await ws.send(json.dumps({"type": "HEARTBEAT", "emp_id": EMP_ID}))
                        except Exception:
                            break
                        await asyncio.sleep(HEARTBEAT_INTERVAL)

                asyncio.create_task(send_heartbeats())

                async for raw in ws:
                    try:
                        msg = json.loads(raw)
                        cmd = msg.get("command", "").upper()
                        if cmd == "BLOCK":
                            reason = msg.get("reason", "Blocked by SOC")
                            log.critical("BLOCK command received: %s", reason)
                            apply_block()
                        elif cmd == "UNBLOCK":
                            apply_unblock()
                        elif cmd == "COLLECT_LOGS":
                            log.info("Log collection requested by SOC")
                        else:
                            log.info("Unknown command: %s", cmd)
                    except json.JSONDecodeError:
                        pass

        except Exception as e:
            log.warning("WebSocket error: %s — retrying in %ds", e, reconnect_delay)
            await asyncio.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, 60)


# ─────────────────────────────────────────────
# Main monitor loop (runs in a thread)
# ─────────────────────────────────────────────
def monitor_loop():
    tick = 0
    while True:
        try:
            if not is_blocked:
                monitor_logins()
                monitor_usb()
                monitor_resources()

                # Run these less frequently to avoid spamming
                if tick % 3 == 0:
                    monitor_processes()
                    monitor_network()

                flush_offline_queue()
                tick += 1
        except Exception as e:
            log.error("monitor_loop error: %s", e)

        time.sleep(MONITOR_INTERVAL)


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
def main():
    global my_ip

    log.info("=" * 60)
    log.info("SOC Agent starting — ID: %s | Name: %s", EMP_ID, EMP_NAME)
    log.info("SOC Server: %s", SOC_SERVER)
    log.info("=" * 60)

    my_ip = get_local_ip()
    log.info("Local IP: %s", my_ip)

    # Register with SOC server
    register()

    # Send startup event
    send_log(
        "AGENT_STARTED",
        f"SOC Agent started on {platform.node()} ({platform.system()} {platform.release()})",
        {
            "hostname": platform.node(),
            "os": platform.system(),
            "os_version": platform.release(),
            "python": platform.python_version()
        },
        severity="INFO"
    )

    # Start file watcher
    observer = start_file_watcher()

    # Start monitor loop in background thread
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()

    # Run WebSocket loop in asyncio (blocking)
    try:
        asyncio.run(websocket_loop())
    except KeyboardInterrupt:
        log.info("Agent stopped by user")
    finally:
        observer.stop()
        observer.join()
        send_log("AGENT_STOPPED", "SOC Agent stopped", severity="INFO")


if __name__ == "__main__":
    main()
