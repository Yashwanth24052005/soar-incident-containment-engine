"""
SOAR Incident Containment Engine - Week 1
FastAPI listener: Webhook ingestion and data normalization
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import uvicorn
import logging

from app.routers import alerts
from app.logger import setup_logging
from app.middleware import RequestLoggingMiddleware

setup_logging(level="INFO")
logger = logging.getLogger("soar.main")

# ─── Swagger UI metadata ──────────────────────────────────────────────────────

description = """
## SOAR Incident Containment Engine

A custom **Security Orchestration, Automation, and Response (SOAR)** engine built for the
Infotact Solutions & Co. Advanced Cybersecurity Internship Program.

---

### What this engine does

- **Ingests** raw security alerts from any SIEM vendor via webhook (Splunk, QRadar, AWS GuardDuty, custom)
- **Normalizes** inconsistent payloads — different timestamp formats, IP field names, severity scales — into one standard schema
- **Enriches** alerts with external threat intelligence *(AbuseIPDB, VirusTotal — Week 2)*
- **Executes** automated defensive playbooks to contain threats without human intervention *(Week 3)*
- **Displays** a full case management dashboard with RBAC *(Week 4)*

---

### Supported Alert Formats

| SIEM Vendor | Timestamp Format | IP Field | Severity Format |
|---|---|---|---|
| Splunk / QRadar | ISO 8601 | `src_ip` | String (low/high/critical) |
| AWS GuardDuty | Millisecond epoch | `sourceIPAddress` | String |
| Legacy SIEM | Apache log format | `source_ip` | Numeric (1–10) |
| Custom in-house | Unix epoch | `src_ip` | Numeric as string |

---

### Weekly Progress

| Week | Module | Status |
|---|---|---|
| Week 1 | Webhook Ingestion & Normalization | ✅ Live |
| Week 2 | Threat Enrichment (AbuseIPDB / VirusTotal) | 🔄 In Progress |
| Week 3 | Playbook Automation (AWS SDK / Firewall API) | ⏳ Upcoming |
| Week 4 | Case Dashboard + RBAC | ⏳ Upcoming |

---

### Key Metric
> **Target MTTR: under 5 seconds** from alert ingestion to threat containment.
"""

tags_metadata = [
    {
        "name": "Alerts",
        "description": (
            "Core alert pipeline endpoints. "
            "Use **POST /ingest** to send raw SIEM webhook payloads. "
            "The engine validates, normalizes, and stores them automatically. "
            "Use **GET /alerts** to retrieve normalized alerts with optional filters. "
            "Use **GET /alerts/stats** to monitor engine health."
        ),
    },
    {
        "name": "Health",
        "description": "Engine status and monitoring endpoints.",
    },
]

app = FastAPI(
    title="SOAR Incident Containment Engine",
    description=description,
    version="1.0.0",
    openapi_tags=tags_metadata,
    contact={
        "name": "Yashwanth — Infotact Cybersecurity Intern",
        "url": "https://github.com/Yashwanth24052005/soar-incident-containment-engine",
    },
    license_info={
        "name": "MIT",
    },
)

app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(alerts.router, prefix="/api/v1", tags=["Alerts"])


# ─── HTML Status Dashboard ────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, tags=["Health"])
def status_dashboard():
    """
    Human-friendly HTML status page for the SOAR engine.
    Shows engine status, available endpoints, and quick links.
    """
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <title>SOAR Engine — Status</title>
        <style>
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body {
                font-family: 'Segoe UI', system-ui, sans-serif;
                background: #0f1117;
                color: #e2e8f0;
                min-height: 100vh;
                padding: 40px 20px;
            }
            .container { max-width: 860px; margin: 0 auto; }
            .header {
                display: flex;
                align-items: center;
                gap: 16px;
                margin-bottom: 36px;
            }
            .shield { font-size: 48px; }
            .header h1 { font-size: 26px; font-weight: 700; color: #f8fafc; }
            .header p { font-size: 13px; color: #94a3b8; margin-top: 4px; }
            .badge {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                background: #16a34a22;
                border: 1px solid #16a34a66;
                color: #4ade80;
                padding: 6px 14px;
                border-radius: 999px;
                font-size: 13px;
                font-weight: 600;
                margin-bottom: 32px;
            }
            .dot {
                width: 8px; height: 8px;
                background: #4ade80;
                border-radius: 50%;
                animation: pulse 1.5s infinite;
            }
            @keyframes pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.3; }
            }
            .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
            @media (max-width: 600px) { .grid { grid-template-columns: 1fr; } }
            .card {
                background: #1e2330;
                border: 1px solid #2d3748;
                border-radius: 12px;
                padding: 20px;
            }
            .card h3 {
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 0.08em;
                color: #64748b;
                margin-bottom: 12px;
            }
            .endpoint {
                display: flex;
                align-items: center;
                gap: 10px;
                padding: 8px 0;
                border-bottom: 1px solid #2d374844;
                font-size: 13px;
            }
            .endpoint:last-child { border-bottom: none; }
            .method {
                font-size: 11px;
                font-weight: 700;
                padding: 2px 7px;
                border-radius: 4px;
                min-width: 42px;
                text-align: center;
            }
            .post { background: #1d4ed822; color: #60a5fa; border: 1px solid #1d4ed855; }
            .get  { background: #16a34a22; color: #4ade80; border: 1px solid #16a34a55; }
            .path { color: #cbd5e1; font-family: 'Cascadia Code', 'Fira Code', monospace; }
            .week-row {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 8px 0;
                border-bottom: 1px solid #2d374844;
                font-size: 13px;
            }
            .week-row:last-child { border-bottom: none; }
            .status-live   { color: #4ade80; font-weight: 600; }
            .status-active { color: #facc15; font-weight: 600; }
            .status-soon   { color: #64748b; }
            .links { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 24px; }
            .link-btn {
                background: #1e2330;
                border: 1px solid #2d3748;
                color: #94a3b8;
                padding: 10px 18px;
                border-radius: 8px;
                text-decoration: none;
                font-size: 13px;
                font-weight: 500;
                transition: border-color 0.2s, color 0.2s;
            }
            .link-btn:hover { border-color: #60a5fa; color: #60a5fa; }
            .link-btn.primary {
                background: #1d4ed8;
                border-color: #1d4ed8;
                color: white;
            }
            .link-btn.primary:hover { background: #2563eb; border-color: #2563eb; }
            .footer { margin-top: 40px; font-size: 12px; color: #475569; text-align: center; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="shield">🛡️</div>
                <div>
                    <h1>SOAR Incident Containment Engine</h1>
                    <p>Infotact Solutions & Co. — Advanced Cybersecurity Internship Program</p>
                </div>
            </div>
            <div class="badge">
                <div class="dot"></div>
                Engine Operational — v1.0.0
            </div>
            <div class="grid">
                <div class="card">
                    <h3>API Endpoints</h3>
                    <div class="endpoint">
                        <span class="method post">POST</span>
                        <span class="path">/api/v1/alerts/ingest</span>
                    </div>
                    <div class="endpoint">
                        <span class="method get">GET</span>
                        <span class="path">/api/v1/alerts</span>
                    </div>
                    <div class="endpoint">
                        <span class="method get">GET</span>
                        <span class="path">/api/v1/alerts/stats</span>
                    </div>
                    <div class="endpoint">
                        <span class="method get">GET</span>
                        <span class="path">/api/v1/alerts/{id}</span>
                    </div>
                </div>
                <div class="card">
                    <h3>4-Week Roadmap</h3>
                    <div class="week-row">
                        <span>Week 1 — Ingestion & Normalization</span>
                        <span class="status-live">✅ Live</span>
                    </div>
                    <div class="week-row">
                        <span>Week 2 — Threat Enrichment</span>
                        <span class="status-active">🔄 Next</span>
                    </div>
                    <div class="week-row">
                        <span>Week 3 — Playbook Automation</span>
                        <span class="status-soon">⏳ Upcoming</span>
                    </div>
                    <div class="week-row">
                        <span>Week 4 — Dashboard & RBAC</span>
                        <span class="status-soon">⏳ Upcoming</span>
                    </div>
                </div>
            </div>
            <div class="links">
                <a class="link-btn primary" href="/docs">📖 Swagger UI</a>
                <a class="link-btn" href="/redoc">📄 ReDoc</a>
                <a class="link-btn" href="/api/v1/alerts/stats">📊 Live Stats</a>
                <a class="link-btn" href="/api/v1/alerts">🔍 View Alerts</a>
                <a class="link-btn" href="https://github.com/Yashwanth24052005/soar-incident-containment-engine" target="_blank">⭐ GitHub</a>
            </div>
            <div class="footer">
                Built by Yashwanth &nbsp;·&nbsp; Infotact Solutions & Co. &nbsp;·&nbsp; Bengaluru 2026
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.get("/health", tags=["Health"])
def health_check():
    """JSON health check endpoint for automated monitoring and uptime checks."""
    return {
        "status": "operational",
        "engine": "SOAR Incident Containment Engine",
        "version": "1.0.0",
        "docs": "http://localhost:8000/docs"
    }


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)