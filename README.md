# SOC Monitoring System — Python Backend

A real-world Security Operations Center (SOC) system with a central FastAPI server
and lightweight agents deployed on every employee machine.

---

## Architecture

```
Employee Machine 1          SOC Server (FastAPI)         SOC Dashboard (React)
  agent.py  ──────────►  POST /logs/ingest          ◄──  WebSocket /ws/dashboard
            ◄────────── WS  /ws/agent/{id}  PUSH
Employee Machine 2
  agent.py  ──────────►  SQLite DB (persistent)
                           └─ logs
                           └─ alerts
                           └─ blocked_ips
                           └─ employees
```

---

## Quick Start

### 1. SOC Server

```bash
cd server
pip install -r requirements.txt
python server.py
```

Server starts at `http://0.0.0.0:8000`  
Default login: `admin` / `admin123`  (change this in production!)

### 2. Employee Agent

Install on **each** employee machine:

```bash
cd agent
pip install -r requirements.txt

# Set environment variables
export SOC_SERVER="http://<YOUR_SERVER_IP>:8000"
export SOC_WS="ws://<YOUR_SERVER_IP>:8000"
export SOC_EMP_ID="EMP001"
export SOC_EMP_NAME="Alice Morgan"
export SOC_DEPT="Engineering"

python agent.py
```

On **Windows**, you can create a `.bat` launcher:
```bat
set SOC_SERVER=http://192.168.1.100:8000
set SOC_WS=ws://192.168.1.100:8000
set SOC_EMP_ID=EMP001
set SOC_EMP_NAME=Alice Morgan
python agent.py
```

---

## Environment Variables

### Server
| Variable         | Default              | Description                        |
|-----------------|---------------------|------------------------------------|
| `SOC_SECRET_KEY` | `soc-secret-key-...` | JWT signing secret (CHANGE THIS)  |
| `SOC_DB_PATH`    | `soc_database.db`   | SQLite database path               |
| `SOC_HOST`       | `0.0.0.0`           | Bind address                       |
| `SOC_PORT`       | `8000`              | Port                               |

### Agent
| Variable            | Default             | Description                        |
|--------------------|--------------------|------------------------------------|
| `SOC_SERVER`        | `http://localhost:8000` | Server HTTP URL               |
| `SOC_WS`            | `ws://localhost:8000`   | Server WebSocket URL          |
| `SOC_EMP_ID`        | hostname            | Unique employee/endpoint ID        |
| `SOC_EMP_NAME`      | hostname            | Display name                       |
| `SOC_DEPT`          | `General`           | Department                         |
| `WATCHED_PATHS`     | home directory      | Comma-separated paths to watch     |
| `HEARTBEAT_INTERVAL`| `30`                | Seconds between heartbeats         |
| `MONITOR_INTERVAL`  | `10`                | Seconds between monitor polls      |

---

## API Reference

### Auth
| Method | Endpoint       | Description         |
|--------|---------------|---------------------|
| POST   | `/auth/login` | Get JWT token       |
| GET    | `/auth/me`    | Current analyst     |

### Logs
| Method | Endpoint            | Description                    |
|--------|--------------------|---------------------------------|
| POST   | `/logs/ingest`     | Submit log event (agent)        |
| GET    | `/logs`            | Fetch logs (filter: severity, emp_id, event_type) |

### Alerts
| Method | Endpoint               | Description              |
|--------|----------------------|---------------------------|
| GET    | `/alerts`            | List alerts               |
| POST   | `/alerts`            | Create manual alert       |
| PATCH  | `/alerts/{id}/resolve` | Resolve an alert        |

### Blocking
| Method | Endpoint        | Description            |
|--------|----------------|------------------------|
| POST   | `/block`        | Block an IP manually   |
| POST   | `/unblock/{ip}` | Unblock an IP          |
| GET    | `/blocked`      | List blocked IPs        |

### Employees
| Method | Endpoint                    | Description           |
|--------|----------------------------|-----------------------|
| POST   | `/employees/register`       | Register endpoint     |
| GET    | `/employees`                | List all employees    |
| GET    | `/employees/{id}/logs`      | Per-employee logs     |

### Dashboard
| Method | Endpoint   | Description         |
|--------|-----------|---------------------|
| GET    | `/stats`   | Overview statistics |
| GET    | `/health`  | Health check        |

### WebSockets
| Endpoint                 | Description                           |
|--------------------------|---------------------------------------|
| `WS /ws/dashboard`       | Real-time event stream for dashboard  |
| `WS /ws/agent/{emp_id}`  | Per-agent command channel             |

---

## Database Schema

**`logs`** — All events from agents  
**`alerts`** — High-severity incidents requiring analyst attention  
**`blocked_ips`** — IPs that have been blocked (with reason and timestamp)  
**`employees`** — Registered endpoints  
**`analysts`** — SOC team accounts  
**`failed_logins`** — Raw failed login records  

---

## Auto-Block Rules

| Trigger                                 | Action                  |
|----------------------------------------|-------------------------|
| ≥ 5 failed logins within 60 seconds    | Auto-block IP + alert   |
| `UNAUTHORIZED_ACCESS` event            | Immediate auto-block    |
| `INTRUSION_DETECTED` event             | Immediate auto-block    |
| Suspicious process detected            | CRITICAL alert          |

---

## Agent Monitors

| Monitor        | What it detects                                              |
|----------------|--------------------------------------------------------------|
| Login          | User login / logout via psutil.users()                       |
| Process        | New processes; flags known malicious names                   |
| Network        | Outbound connections to non-standard ports                   |
| File watcher   | Sensitive file create/modify/delete/move (via watchdog)      |
| USB            | Removable media insertion and removal                        |
| Resources      | CPU > 90% or RAM > 90% (possible cryptominer / DDoS)        |

---

## Production Checklist

- [ ] Change `SOC_SECRET_KEY` to a long random string
- [ ] Change default `admin` password
- [ ] Use HTTPS (nginx + Let's Encrypt) in front of uvicorn
- [ ] Replace SQLite with PostgreSQL for high-volume deployments
- [ ] Run agent as a systemd service (Linux) or Windows Service
- [ ] Restrict `CORS` origins to your dashboard domain
- [ ] Enable firewall rules so agents can only reach the SOC server

---

## Systemd Service (Linux Agent)

```ini
# /etc/systemd/system/soc-agent.service
[Unit]
Description=SOC Employee Agent
After=network.target

[Service]
Type=simple
User=soc
Environment=SOC_SERVER=http://192.168.1.100:8000
Environment=SOC_WS=ws://192.168.1.100:8000
Environment=SOC_EMP_ID=EMP001
Environment=SOC_EMP_NAME=Alice Morgan
ExecStart=/usr/bin/python3 /opt/soc-agent/agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable soc-agent
sudo systemctl start soc-agent
```
