"""
SOC Main Server - Security Operations Center Backend
Handles: log ingestion, alerting, IP blocking, real-time WebSocket streaming
"""

import asyncio
import hashlib
import json
import logging
import os
import sqlite3
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import List, Optional

import uvicorn
from fastapi import (
    Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────
SECRET_KEY = os.getenv("SOC_SECRET_KEY", "soc-secret-key-change-in-production-2024")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 12
DB_PATH = os.getenv("SOC_DB_PATH", "soc_database.db")
HOST = os.getenv("SOC_HOST", "0.0.0.0")
PORT = int(os.getenv("SOC_PORT", "8000"))

BRUTE_FORCE_THRESHOLD = 5   # failures before auto-block
BRUTE_FORCE_WINDOW = 60     # seconds

SUSPICIOUS_PROCESSES = {
    "mimikatz", "nmap", "netcat", "nc.exe", "procdump",
    "meterpreter", "cobalt", "empire", "lazagne", "pwdump",
    "wireshark", "tcpdump", "aircrack", "hashcat", "john"
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("soc_server.log")]
)
log = logging.getLogger("SOC-Server")

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)

# ─────────────────────────────────────────────
# In-memory state
# ─────────────────────────────────────────────
# failed_logins[ip] = list of timestamps
failed_logins: dict = defaultdict(list)
# connected WebSocket clients
dashboard_clients: List[WebSocket] = []
# agent WebSocket connections: emp_id -> WebSocket
agent_connections: dict = {}


# ─────────────────────────────────────────────
# Database
# ─────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS analysts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT UNIQUE NOT NULL,
            password  TEXT NOT NULL,
            role      TEXT DEFAULT 'analyst',
            created   TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS employees (
            emp_id       TEXT PRIMARY KEY,
            name         TEXT NOT NULL,
            department   TEXT,
            ip_address   TEXT,
            status       TEXT DEFAULT 'online',
            last_seen    TEXT,
            created      TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS logs (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            emp_id       TEXT,
            emp_name     TEXT,
            ip_address   TEXT,
            event_type   TEXT NOT NULL,
            severity     TEXT DEFAULT 'INFO',
            description  TEXT,
            metadata     TEXT,
            timestamp    TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            emp_id       TEXT,
            emp_name     TEXT,
            ip_address   TEXT,
            alert_type   TEXT NOT NULL,
            severity     TEXT DEFAULT 'HIGH',
            description  TEXT,
            resolved     INTEGER DEFAULT 0,
            resolved_by  TEXT,
            resolved_at  TEXT,
            timestamp    TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS blocked_ips (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address   TEXT UNIQUE NOT NULL,
            emp_id       TEXT,
            reason       TEXT,
            blocked_by   TEXT DEFAULT 'AUTO',
            blocked_at   TEXT DEFAULT (datetime('now')),
            unblocked_at TEXT
        );

        CREATE TABLE IF NOT EXISTS failed_logins (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            emp_id       TEXT,
            ip_address   TEXT,
            attempt_time TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_logs_emp    ON logs(emp_id);
        CREATE INDEX IF NOT EXISTS idx_logs_sev    ON logs(severity);
        CREATE INDEX IF NOT EXISTS idx_logs_ts     ON logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_emp  ON alerts(emp_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_res  ON alerts(resolved);
    """)

    # Seed default admin analyst
    admin_pw = pwd_ctx.hash("admin123")
    cur.execute(
        "INSERT OR IGNORE INTO analysts (username, password, role) VALUES (?, ?, ?)",
        ("admin", admin_pw, "admin")
    )

    conn.commit()
    conn.close()
    log.info("Database initialised at %s", DB_PATH)


# ─────────────────────────────────────────────
# JWT helpers
# ─────────────────────────────────────────────
def create_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


def get_current_analyst(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = verify_token(credentials.credentials)
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ─────────────────────────────────────────────
# WebSocket broadcast
# ─────────────────────────────────────────────
async def broadcast(event: dict):
    """Send real-time event to all connected dashboard clients."""
    dead = []
    msg = json.dumps(event)
    for ws in dashboard_clients:
        try:
            await ws.send_text(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        dashboard_clients.remove(ws)


async def push_to_agent(emp_id: str, command: dict):
    """Send command to a specific employee agent."""
    ws = agent_connections.get(emp_id)
    if ws:
        try:
            await ws.send_text(json.dumps(command))
            return True
        except Exception:
            del agent_connections[emp_id]
    return False


# ─────────────────────────────────────────────
# Auto-block engine
# ─────────────────────────────────────────────
async def check_and_autoblock(emp_id: str, ip: str, event_type: str):
    """Trigger auto-block on brute force or unauthorized access."""
    now = time.time()

    if event_type in ("LOGIN_FAILED", "AUTH_FAILURE"):
        # Slide window
        failed_logins[ip] = [t for t in failed_logins[ip] if now - t < BRUTE_FORCE_WINDOW]
        failed_logins[ip].append(now)

        if len(failed_logins[ip]) >= BRUTE_FORCE_THRESHOLD:
            await block_ip(ip, emp_id, f"Auto-blocked: {len(failed_logins[ip])} failed logins in {BRUTE_FORCE_WINDOW}s", "AUTO")
            failed_logins[ip] = []  # reset after block
            return True

    elif event_type in ("UNAUTHORIZED_ACCESS", "INTRUSION_DETECTED"):
        await block_ip(ip, emp_id, f"Auto-blocked: {event_type} detected", "AUTO")
        return True

    return False


async def block_ip(ip: str, emp_id: str, reason: str, blocked_by: str = "AUTO"):
    """Block an IP across DB, alert, broadcast, and agent push."""
    conn = get_db()
    cur = conn.cursor()

    existing = cur.execute(
        "SELECT id FROM blocked_ips WHERE ip_address=? AND unblocked_at IS NULL", (ip,)
    ).fetchone()

    if not existing:
        cur.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip_address, emp_id, reason, blocked_by) VALUES (?,?,?,?)",
            (ip, emp_id, reason, blocked_by)
        )
        cur.execute(
            "UPDATE employees SET status='blocked' WHERE ip_address=? OR emp_id=?",
            (ip, emp_id)
        )
        cur.execute(
            """INSERT INTO alerts (emp_id, ip_address, alert_type, severity, description)
               VALUES (?,?,?,?,?)""",
            (emp_id, ip, "IP_BLOCKED", "CRITICAL", reason)
        )
        conn.commit()

        log.warning("BLOCKED IP %s | Emp: %s | Reason: %s", ip, emp_id, reason)

        await broadcast({
            "type": "IP_BLOCKED",
            "emp_id": emp_id,
            "ip": ip,
            "reason": reason,
            "blocked_by": blocked_by,
            "timestamp": datetime.now().isoformat()
        })

        # Push block command to the agent
        await push_to_agent(emp_id, {"command": "BLOCK", "reason": reason})

    conn.close()


# ─────────────────────────────────────────────
# Pydantic schemas
# ─────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str


class LogEvent(BaseModel):
    emp_id: str
    emp_name: Optional[str] = None
    ip_address: Optional[str] = None
    event_type: str
    severity: Optional[str] = "INFO"
    description: Optional[str] = None
    metadata: Optional[dict] = None


class AlertCreate(BaseModel):
    emp_id: str
    emp_name: Optional[str] = None
    ip_address: Optional[str] = None
    alert_type: str
    severity: Optional[str] = "HIGH"
    description: Optional[str] = None


class BlockRequest(BaseModel):
    ip_address: str
    emp_id: Optional[str] = None
    reason: Optional[str] = "Manually blocked by analyst"


class EmployeeRegister(BaseModel):
    emp_id: str
    name: str
    department: Optional[str] = None
    ip_address: Optional[str] = None


# ─────────────────────────────────────────────
# App lifecycle
# ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    log.info("SOC Server ready on http://%s:%d", HOST, PORT)
    yield
    log.info("SOC Server shutting down")


app = FastAPI(
    title="SOC Monitoring Server",
    description="Security Operations Center — Log Ingestion, Alerting & IP Blocking",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────
# Auth routes
# ─────────────────────────────────────────────
@app.post("/auth/login")
def login(req: LoginRequest):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM analysts WHERE username=?", (req.username,)
    ).fetchone()
    conn.close()

    if not row or not pwd_ctx.verify(req.password, row["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token({"sub": row["username"], "role": row["role"], "id": row["id"]})
    return {"access_token": token, "token_type": "bearer", "role": row["role"], "username": row["username"]}


@app.get("/auth/me")
def me(analyst=Depends(get_current_analyst)):
    return analyst


# ─────────────────────────────────────────────
# Employee routes
# ─────────────────────────────────────────────
@app.post("/employees/register")
async def register_employee(emp: EmployeeRegister):
    """Called by agent on first startup to register endpoint."""
    conn = get_db()
    conn.execute(
        """INSERT OR REPLACE INTO employees (emp_id, name, department, ip_address, status, last_seen)
           VALUES (?,?,?,?,?,datetime('now'))""",
        (emp.emp_id, emp.name, emp.department, emp.ip_address, "online")
    )
    conn.commit()
    conn.close()

    await broadcast({"type": "EMPLOYEE_ONLINE", "emp_id": emp.emp_id, "name": emp.name, "ip": emp.ip_address})
    return {"status": "registered"}


@app.get("/employees")
def list_employees(analyst=Depends(get_current_analyst)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM employees ORDER BY last_seen DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/employees/{emp_id}/logs")
def employee_logs(emp_id: str, limit: int = 100, analyst=Depends(get_current_analyst)):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM logs WHERE emp_id=? ORDER BY timestamp DESC LIMIT ?",
        (emp_id, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────
# Log ingestion
# ─────────────────────────────────────────────
@app.post("/logs/ingest")
async def ingest_log(event: LogEvent):
    """Primary endpoint called by agents to submit log events."""
    conn = get_db()

    meta_str = json.dumps(event.metadata) if event.metadata else None

    conn.execute(
        """INSERT INTO logs (emp_id, emp_name, ip_address, event_type, severity, description, metadata)
           VALUES (?,?,?,?,?,?,?)""",
        (event.emp_id, event.emp_name, event.ip_address,
         event.event_type, event.severity, event.description, meta_str)
    )

    # Update last seen
    conn.execute(
        "UPDATE employees SET last_seen=datetime('now'), status='online' WHERE emp_id=?",
        (event.emp_id,)
    )
    conn.commit()
    conn.close()

    # Check for suspicious process names in metadata
    if event.event_type == "PROCESS_STARTED" and event.metadata:
        proc = str(event.metadata.get("process_name", "")).lower()
        if proc in SUSPICIOUS_PROCESSES:
            event.severity = "CRITICAL"
            event.description = f"Suspicious process detected: {proc}"
            await create_alert_internal(
                event.emp_id, event.emp_name, event.ip_address,
                "SUSPICIOUS_PROCESS", "CRITICAL", event.description
            )

    # Broadcast to dashboard
    await broadcast({
        "type": "LOG",
        "emp_id": event.emp_id,
        "emp_name": event.emp_name,
        "event_type": event.event_type,
        "severity": event.severity,
        "description": event.description,
        "timestamp": datetime.now().isoformat()
    })

    # Auto-block check
    if event.ip_address:
        await check_and_autoblock(event.emp_id, event.ip_address, event.event_type)

    return {"status": "ingested"}


@app.get("/logs")
def get_logs(
    limit: int = 200,
    severity: Optional[str] = None,
    emp_id: Optional[str] = None,
    event_type: Optional[str] = None,
    analyst=Depends(get_current_analyst)
):
    conn = get_db()
    query = "SELECT * FROM logs WHERE 1=1"
    params = []

    if severity:
        query += " AND severity=?"
        params.append(severity.upper())
    if emp_id:
        query += " AND emp_id=?"
        params.append(emp_id)
    if event_type:
        query += " AND event_type=?"
        params.append(event_type.upper())

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────
# Alerts
# ─────────────────────────────────────────────
async def create_alert_internal(emp_id, emp_name, ip, alert_type, severity, description):
    conn = get_db()
    conn.execute(
        """INSERT INTO alerts (emp_id, emp_name, ip_address, alert_type, severity, description)
           VALUES (?,?,?,?,?,?)""",
        (emp_id, emp_name, ip, alert_type, severity, description)
    )
    conn.commit()
    conn.close()

    await broadcast({
        "type": "ALERT",
        "emp_id": emp_id,
        "alert_type": alert_type,
        "severity": severity,
        "description": description,
        "timestamp": datetime.now().isoformat()
    })


@app.post("/alerts")
async def create_alert(alert: AlertCreate, analyst=Depends(get_current_analyst)):
    await create_alert_internal(
        alert.emp_id, alert.emp_name, alert.ip_address,
        alert.alert_type, alert.severity, alert.description
    )
    return {"status": "alert created"}


@app.get("/alerts")
def get_alerts(
    resolved: Optional[bool] = None,
    severity: Optional[str] = None,
    analyst=Depends(get_current_analyst)
):
    conn = get_db()
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if resolved is not None:
        query += " AND resolved=?"
        params.append(1 if resolved else 0)
    if severity:
        query += " AND severity=?"
        params.append(severity.upper())

    query += " ORDER BY timestamp DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.patch("/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: int, analyst=Depends(get_current_analyst)):
    conn = get_db()
    conn.execute(
        "UPDATE alerts SET resolved=1, resolved_by=?, resolved_at=datetime('now') WHERE id=?",
        (analyst["sub"], alert_id)
    )
    conn.commit()
    conn.close()

    await broadcast({"type": "ALERT_RESOLVED", "alert_id": alert_id, "by": analyst["sub"]})
    return {"status": "resolved"}


# ─────────────────────────────────────────────
# IP Blocking
# ─────────────────────────────────────────────
@app.post("/block")
async def manual_block(req: BlockRequest, analyst=Depends(get_current_analyst)):
    await block_ip(req.ip_address, req.emp_id or "", req.reason, analyst["sub"])
    return {"status": "blocked", "ip": req.ip_address}


@app.post("/unblock/{ip}")
async def unblock_ip(ip: str, analyst=Depends(get_current_analyst)):
    conn = get_db()
    conn.execute(
        "UPDATE blocked_ips SET unblocked_at=datetime('now') WHERE ip_address=? AND unblocked_at IS NULL",
        (ip,)
    )
    row = conn.execute("SELECT emp_id FROM blocked_ips WHERE ip_address=?", (ip,)).fetchone()
    if row:
        conn.execute(
            "UPDATE employees SET status='online' WHERE ip_address=? OR emp_id=?",
            (ip, row["emp_id"])
        )
    conn.commit()
    conn.close()

    await broadcast({"type": "IP_UNBLOCKED", "ip": ip, "by": analyst["sub"], "timestamp": datetime.now().isoformat()})

    if row:
        await push_to_agent(row["emp_id"], {"command": "UNBLOCK"})

    return {"status": "unblocked", "ip": ip}


@app.get("/blocked")
def get_blocked_ips(analyst=Depends(get_current_analyst)):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM blocked_ips WHERE unblocked_at IS NULL ORDER BY blocked_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────
# Stats & Dashboard
# ─────────────────────────────────────────────
@app.get("/stats")
def get_stats(analyst=Depends(get_current_analyst)):
    conn = get_db()
    total_logs = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    critical    = conn.execute("SELECT COUNT(*) FROM logs WHERE severity='CRITICAL'").fetchone()[0]
    unresolved  = conn.execute("SELECT COUNT(*) FROM alerts WHERE resolved=0").fetchone()[0]
    blocked     = conn.execute("SELECT COUNT(*) FROM blocked_ips WHERE unblocked_at IS NULL").fetchone()[0]
    online      = conn.execute("SELECT COUNT(*) FROM employees WHERE status='online'").fetchone()[0]
    total_emp   = conn.execute("SELECT COUNT(*) FROM employees").fetchone()[0]

    recent = conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM logs WHERE timestamp > datetime('now','-1 hour') GROUP BY severity"
    ).fetchall()

    top_events = conn.execute(
        "SELECT event_type, COUNT(*) as cnt FROM logs GROUP BY event_type ORDER BY cnt DESC LIMIT 5"
    ).fetchall()

    conn.close()
    return {
        "total_logs": total_logs,
        "critical_events": critical,
        "unresolved_alerts": unresolved,
        "blocked_ips": blocked,
        "online_employees": online,
        "total_employees": total_emp,
        "last_hour": [dict(r) for r in recent],
        "top_events": [dict(r) for r in top_events]
    }


@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.now().isoformat(), "version": "1.0.0"}


# ─────────────────────────────────────────────
# WebSocket — Dashboard
# ─────────────────────────────────────────────
@app.websocket("/ws/dashboard")
async def ws_dashboard(websocket: WebSocket):
    await websocket.accept()
    dashboard_clients.append(websocket)
    log.info("Dashboard client connected. Total: %d", len(dashboard_clients))
    try:
        while True:
            await websocket.receive_text()   # keep-alive ping
    except WebSocketDisconnect:
        dashboard_clients.remove(websocket)
        log.info("Dashboard client disconnected. Total: %d", len(dashboard_clients))


# ─────────────────────────────────────────────
# WebSocket — Agent
# ─────────────────────────────────────────────
@app.websocket("/ws/agent/{emp_id}")
async def ws_agent(websocket: WebSocket, emp_id: str):
    await websocket.accept()
    agent_connections[emp_id] = websocket
    log.info("Agent connected: %s", emp_id)

    await broadcast({"type": "AGENT_CONNECTED", "emp_id": emp_id, "timestamp": datetime.now().isoformat()})

    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "HEARTBEAT":
                    conn = get_db()
                    conn.execute(
                        "UPDATE employees SET last_seen=datetime('now'), status='online' WHERE emp_id=?",
                        (emp_id,)
                    )
                    conn.commit()
                    conn.close()
                    await websocket.send_text(json.dumps({"type": "HEARTBEAT_ACK"}))
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        if emp_id in agent_connections:
            del agent_connections[emp_id]
        conn = get_db()
        conn.execute("UPDATE employees SET status='offline' WHERE emp_id=?", (emp_id,))
        conn.commit()
        conn.close()
        await broadcast({"type": "AGENT_DISCONNECTED", "emp_id": emp_id, "timestamp": datetime.now().isoformat()})
        log.info("Agent disconnected: %s", emp_id)


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("server:app", host=HOST, port=PORT, reload=False, log_level="info")
