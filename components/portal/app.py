from __future__ import annotations

import asyncio
import csv
import base64
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import shutil
import sqlite3
import struct
import subprocess
import threading
import time
import urllib.parse
import zipfile
import urllib.request
from collections import Counter, defaultdict
from contextlib import asynccontextmanager, closing
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pypdf import PdfReader
from reportlab.graphics import renderPDF
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from starlette.middleware.sessions import SessionMiddleware
from svglib.svglib import svg2rlg

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
DOCUMENTS_DIR = Path(os.getenv("REPORTS_DIR", str(DATA_DIR / "Reports")))
IN_REVIEW_DIR = DOCUMENTS_DIR / "In Review"
REPORTS_REPO_DIR = Path(os.getenv("REPORTS_REPO_DIR", str(Path.home() / "github" / "Reports")))
RAICCOON_PORTABLE_ZIP = Path(os.getenv("RAICCOON_PORTABLE_ZIP", str(Path.home() / "Downloads/RAIccoon_LostBoys_Portable_20260602_200711.zip")))
DB_PATH = DATA_DIR / "portal.db"
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
ANALYST_KIT_DIR = Path(os.getenv("RAICCOON_ANALYST_KIT_DIR", str(Path.home() / "github" / "your-organization-analyst-kit")))
TITLEPAGE_LOGO = ANALYST_KIT_DIR / "assets" / "branding" / "your-organization-logo-titlepage.svg"
REPORT_PRIMARY_BLUE = colors.HexColor("#123d63")
REPORT_RULE_BLUE = colors.HexColor("#75a9cf")
REPORT_CALLOUT_FILL = colors.HexColor("#eaf4fb")
REPORT_TABLE_FILL = colors.HexColor("#f3f6f8")
DEFAULT_DOCUMENT_CATEGORIES = (
    "Threat Reports",
    "Purple Team Exercise",
    "Malware Analysis",
    "Vulnerabilities",
    "Executive Summaries",
    "Threat Actor Profiles",
)
REPORT_ID_PREFIXES = {
    "Executive Summaries": "RPT-ES",
    "Malware Analysis": "RPT-MA",
    "Purple Team Exercise": "RPT-PTE",
    "Threat Reports": "RPT-TR",
    "Threat Actor Profiles": "RPT-AP",
    "Vulnerabilities": "RPT-VTI",
    "Detection Engineering": "RPT-DE",
    "Threat Hunting": "RPT-TH",
    "IOC Enrichment": "RPT-IOC",
    "IR Triage": "RPT-IR",
    "Uncategorized": "RPT-RPT",
}
ANALYST_KIT_REPORT_CATEGORY_DIRS = {
    "Executive Summaries": "executive-summaries",
    "Malware Analysis": "malware-analysis",
    "Purple Team Exercise": "purple-team-exercise",
    "Threat Reports": "threat-reports",
    "Threat Actor Profiles": "threat-actor-profiles",
    "Vulnerabilities": "vulnerabilities",
    "Detection Engineering": "detection-engineering",
    "Threat Hunting": "threat-hunting",
    "IOC Enrichment": "ioc-enrichment",
    "IR Triage": "ir-triage",
    "Uncategorized": "research-reports",
}

APP_TITLE = "Your Organization // RAIccoon Operations Portal"
APP_SUBTITLE = "Threat intelligence, detection engineering, research workflows, and AI operations."
DEFAULT_ALLOWED_CIDRS = "127.0.0.1/32,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10"
DEFAULT_SECRET = "your-organization-change-me"
TRUST_X_FORWARDED_FOR = os.getenv("SECOPS_TRUST_X_FORWARDED_FOR", "false").strip().lower() in {"1", "true", "yes", "on"}
PORTAL_KANBAN_BOARD = os.getenv("PORTAL_KANBAN_BOARD", "default")
PORTAL_KANBAN_ASSIGNEE = os.getenv("PORTAL_KANBAN_ASSIGNEE", "default")
PORTAL_DEFAULT_WORKER_PROFILE = os.getenv("PORTAL_DEFAULT_WORKER_PROFILE", "default")
PORTAL_KANBAN_DB = Path(os.getenv("PORTAL_KANBAN_DB", str(Path.home() / ".hermes/kanban.db")))
OPEN_PATHS = {"/login", "/healthz"}
OPEN_PREFIXES = ("/static/",)
PORTAL_TASK_STATUSES = ("todo", "in_progress", "blocked", "in_review", "accepted", "rejected")
PORTAL_TASK_BOARD_STATUSES = ("todo", "in_progress", "blocked", "in_review", "accepted")
REPORT_AUTO_PUBLISH_MIN_SCORE = 90
PORTAL_TASK_LABELS = {
    "todo": "Todo",
    "in_progress": "In Progress",
    "blocked": "Blocked",
    "in_review": "In Review",
    "accepted": "Acceptance",
    "rejected": "Rejected",
}
PORTAL_TASK_FLOW = {
    "todo": {"in_progress", "blocked"},
    "in_progress": {"blocked", "in_review"},
    "blocked": {"todo", "in_progress"},
    "in_review": {"in_progress", "blocked", "accepted"},
    "accepted": set(),
    "rejected": set(),
}
TASK_STALE_HOURS_DEFAULT = int(os.getenv("PORTAL_TASK_STALE_HOURS", "24"))
TASK_TEMPLATE_CATALOG = (
    {
        "key": "threat-intel-report",
        "label": "Threat intel report",
        "task_type": "research",
        "research_workflow": "threat-intel",
        "document_category": "Threat Reports",
        "priority": 8,
        "description": "Produce a Your Organization threat intelligence report with source review, TTPs, IOCs, detections, hunt queries, recommendations, and references.",
        "acceptance_criteria": "Final PDF passes report QA, includes IOC list, detection/hunt queries, ATT&CK mapping, and OpenCTI-ready summary.",
    },
    {
        "key": "malware-analysis-report",
        "label": "Malware analysis report",
        "task_type": "research",
        "research_workflow": "malware-analysis",
        "document_category": "Malware Analysis",
        "priority": 9,
        "description": "Perform static/code/dynamic malware analysis, route every uploaded sample through RAIccoon Local Sandbox, reverse through GhidraMCP when code is present, and produce the full Your Organization malware report package.",
        "acceptance_criteria": "Final PDF includes hashes, triage, static analysis, GhidraMCP-backed code analysis/reversing, RAIccoon Local Sandbox dynamic behavior, process tree, IOCs, detections, and hunt queries.",
    },
    {
        "key": "detection-engineering",
        "label": "Detection engineering package",
        "task_type": "research",
        "research_workflow": "detection-engineering",
        "document_category": "Detection Engineering",
        "priority": 7,
        "description": "Create detection logic mapped to ATT&CK with validation notes and SOC-ready implementation guidance.",
        "acceptance_criteria": "Includes Sigma/KQL/SPL/YARA as applicable, telemetry assumptions, false-positive notes, validation plan, and hunt pivots.",
    },
    {
        "key": "client-brief",
        "label": "Client brief",
        "task_type": "research",
        "research_workflow": "threat-intel",
        "document_category": "Executive Summaries",
        "priority": 8,
        "description": "Prepare a private client-ready brief scoped to the linked engagement profile and current priority requirements.",
        "acceptance_criteria": "Brief references relevant reports/detections, maps to client technologies, and lists concrete recommended actions.",
    },
    {
        "key": "opencti-upload-remediation",
        "label": "OpenCTI upload/remediation",
        "task_type": "general",
        "research_workflow": "general",
        "document_category": "",
        "priority": 6,
        "description": "Close an OpenCTI upload or reconciliation gap using analyst-kit registry/upload state evidence.",
        "acceptance_criteria": "Portal task history records the upload/reconciliation outcome and any remaining blocker.",
    },
    {
        "key": "registry-remediation",
        "label": "Registry remediation",
        "task_type": "general",
        "research_workflow": "general",
        "document_category": "",
        "priority": 6,
        "description": "Resolve analyst-kit registry hygiene gaps such as duplicate report IDs or missing final PDFs.",
        "acceptance_criteria": "Registry artifact is regenerated and the board/history identifies the corrected report IDs and files.",
    },
)
PAGE_TITLES = {
    "dashboard": "Command dashboard",
    "security": "Portal security",
    "chat": "Hermes chat",
    "research": "Research workspace",
    "documents": "Threat research documents",
    "costs": "AI cost tracking",
    "works": "Published works tracker",
    "clients": "Private client readiness",
    "tasks": "Tasks board",
    "deploy": "Deployment artifacts",
}
NAV_ITEMS = [
    {"key": "dashboard", "label": "Dashboard", "path": "/dashboard"},
    {"key": "security", "label": "Security", "path": "/security"},
    {"key": "chat", "label": "Chat", "path": "/chat"},
    {"key": "research", "label": "Research", "path": "/research"},
    {"key": "documents", "label": "Documents", "path": "/documents"},
    {"key": "costs", "label": "AI Costs", "path": "/costs"},
    {"key": "works", "label": "Published Works", "path": "/works"},
    {"key": "clients", "label": "Clients", "path": "/clients"},
    {"key": "tasks", "label": "Tasks", "path": "/tasks"},
    {"key": "deploy", "label": "Deployment", "path": "/deploy"},
]
NAV_GROUPS = [
    {
        "label": "Command",
        "items": ["dashboard", "tasks", "research", "chat"],
    },
    {
        "label": "Delivery",
        "items": ["documents", "works", "costs", "clients"],
    },
    {
        "label": "Admin",
        "items": ["security", "deploy"],
    },
]
RESEARCH_WORKFLOWS = {
    "general": {
        "label": "General research",
        "description": "Standard Hermes analyst workflow for mixed research, reporting, and uploads.",
        "portal_default": False,
    },
    "threat-intel": {
        "label": "Threat intel triage",
        "description": "Use RAIccoon to extract TTPs, trends, references, and defensive recommendations from CTI content.",
        "portal_default": True,
    },
    "detection-engineering": {
        "label": "Detection engineering",
        "description": "Use RAIccoon to move from threat model to ATT&CK mapping, hypothesis, and Sigma/KQL/SPL/YARA outputs.",
        "portal_default": True,
    },
    "purple-team-exercise": {
        "label": "Purple team exercise",
        "description": "Use RAIccoon to build adversary-emulation plans, injects, detection validation, safety guardrails, and after-action criteria.",
        "portal_default": True,
    },
    "threat-hunting": {
        "label": "Threat hunting",
        "description": "Use RAIccoon to frame hunt hypotheses, data sources, hunt queries, and closure criteria.",
        "portal_default": True,
    },
    "ioc-enrichment": {
        "label": "IOC enrichment",
        "description": "Use RAIccoon to pivot, cluster, score, and recommend actions for domains, IPs, hashes, and URLs.",
        "portal_default": True,
    },
    "malware-analysis": {
        "label": "Malware analysis",
        "description": "Detonate every uploaded sample in the local RAIccoon Local Sandbox sandbox first, then use RAIccoon and GhidraMCP-backed reversing on the generated evidence.",
        "portal_default": True,
    },
    "ir-triage": {
        "label": "IR triage",
        "description": "Use RAIccoon to scope incidents, prioritize evidence, and build triage/timeline guidance.",
        "portal_default": True,
    },
}
TOTP_ISSUER = "Your Organization Portal"
TOTP_PERIOD_SECONDS = 30
TOTP_DIGITS = 6
MFA_RECOVERY_CODE_COUNT = 8
AUTH_LOCKOUT_THRESHOLD = 5
AUTH_LOCKOUT_MINUTES = 15
RAICCOON_KEYWORDS = (
    "sigma",
    "kql",
    "spl",
    "yara",
    "mitre",
    "attack",
    "threat report",
    "threat intel",
    "ioc",
    "cve",
    "malware",
    "sandbox",
    "incident response",
    "ir triage",
    "hunt hypothesis",
)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    ensure_report_library()
    bootstrap_admin_user()
    yield


app = FastAPI(title=APP_TITLE, lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=os.getenv("PORTAL_SECRET_KEY", DEFAULT_SECRET), same_site="lax")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def get_allowed_networks() -> list[ipaddress._BaseNetwork]:
    cidr_string = os.getenv("SECOPS_ALLOWED_CIDRS", DEFAULT_ALLOWED_CIDRS)
    networks = []
    for raw in cidr_string.split(","):
        raw = raw.strip()
        if raw:
            networks.append(ipaddress.ip_network(raw, strict=False))
    return networks


def client_ip(request: Request) -> str:
    if TRUST_X_FORWARDED_FOR:
        forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        if forwarded:
            return forwarded
    return request.client.host if request.client else "127.0.0.1"


@app.middleware("http")
async def restrict_to_local_network(request: Request, call_next):
    ip_text = client_ip(request)
    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except ValueError:
        return JSONResponse(status_code=403, content={"detail": f"Invalid client IP: {ip_text}"})

    if not any(ip_obj in network for network in get_allowed_networks()):
        return JSONResponse(status_code=403, content={"detail": f"Access denied for {ip_text}"})

    path = request.url.path
    session = request.scope.get("session") or {}
    if (
        bool(session.get("mfa_setup_required"))
        and path not in {"/security", "/logout"}
        and not path.startswith("/security/")
        and path not in OPEN_PATHS
        and not any(path.startswith(prefix) for prefix in OPEN_PREFIXES)
    ):
        return RedirectResponse(url="/security", status_code=303)

    return await call_next(request)


def authenticated(request: Request) -> bool:
    return bool(request.session.get("user_id")) and bool(request.session.get("mfa_ok"))


def admin_authenticated(request: Request) -> bool:
    return authenticated(request) and request.session.get("role") == "admin"


def require_auth(request: Request, *, allow_mfa_setup: bool = False) -> RedirectResponse | None:
    if not authenticated(request):
        return login_redirect()
    if request.session.get("mfa_setup_required") and not allow_mfa_setup:
        return RedirectResponse(url="/security", status_code=303)
    return None


def login_redirect() -> RedirectResponse:
    return RedirectResponse(url="/login", status_code=303)


def connect_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def connect_kanban_db() -> sqlite3.Connection:
    connection = sqlite3.connect(PORTAL_KANBAN_DB)
    connection.row_factory = sqlite3.Row
    return connection


def ensure_column(connection: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    with closing(connect_db()) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                password_hash TEXT NOT NULL,
                mfa_secret TEXT DEFAULT '',
                mfa_enabled INTEGER NOT NULL DEFAULT 0,
                mfa_created_at TEXT DEFAULT '',
                mfa_recovery_codes TEXT DEFAULT '[]',
                mfa_recovery_generated_at TEXT DEFAULT '',
                mfa_required INTEGER NOT NULL DEFAULT 0,
                login_fail_count INTEGER NOT NULL DEFAULT 0,
                login_locked_until TEXT DEFAULT '',
                mfa_fail_count INTEGER NOT NULL DEFAULT 0,
                mfa_locked_until TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                last_login TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS searches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query TEXT NOT NULL,
                response TEXT NOT NULL,
                uploaded_files TEXT DEFAULT '',
                workflow TEXT DEFAULT 'general',
                created_at TEXT NOT NULL,
                duration_seconds REAL NOT NULL,
                requested_by TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS hermes_chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                requested_by TEXT DEFAULT '',
                duration_seconds REAL NOT NULL DEFAULT 0,
                metadata TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS ai_costs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                category TEXT NOT NULL,
                amount_usd REAL NOT NULL,
                period_start TEXT NOT NULL,
                notes TEXT DEFAULT '',
                source TEXT DEFAULT 'manual',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cost_sync_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL,
                status TEXT NOT NULL,
                detail TEXT DEFAULT '',
                imported_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS published_works (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                status TEXT NOT NULL,
                outlet TEXT NOT NULL,
                url TEXT DEFAULT '',
                publication_date TEXT NOT NULL,
                due_date TEXT DEFAULT '',
                owner TEXT DEFAULT '',
                artifact_type TEXT DEFAULT 'report',
                audience TEXT DEFAULT 'internal',
                tags TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS portal_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'todo',
                priority INTEGER NOT NULL DEFAULT 0,
                requested_by TEXT DEFAULT '',
                assignee TEXT DEFAULT '',
                worker_profile TEXT DEFAULT '',
                task_type TEXT DEFAULT 'general',
                source_page TEXT DEFAULT '',
                research_workflow TEXT DEFAULT '',
                document_category TEXT DEFAULT '',
                uploaded_files TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                kanban_task_id TEXT DEFAULT '',
                kanban_status TEXT DEFAULT '',
                last_result TEXT DEFAULT '',
                review_document_path TEXT DEFAULT '',
                final_document_path TEXT DEFAULT '',
                published_work_id INTEGER NOT NULL DEFAULT 0,
                client_profile_id INTEGER NOT NULL DEFAULT 0,
                review_notes TEXT DEFAULT '',
                reviewer TEXT DEFAULT '',
                reviewer_signed_at TEXT DEFAULT '',
                review_signoff INTEGER NOT NULL DEFAULT 0,
                due_date TEXT DEFAULT '',
                sla_hours INTEGER NOT NULL DEFAULT 0,
                started_at TEXT DEFAULT '',
                blocked_reason TEXT DEFAULT '',
                blocked_at TEXT DEFAULT '',
                parent_task_id INTEGER NOT NULL DEFAULT 0,
                acceptance_criteria TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS portal_task_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                author TEXT NOT NULL,
                comment TEXT NOT NULL,
                created_at TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'portal',
                source_ref TEXT DEFAULT '',
                FOREIGN KEY(task_id) REFERENCES portal_tasks(id)
            );

            CREATE TABLE IF NOT EXISTS portal_task_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                detail TEXT NOT NULL,
                created_at TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'portal',
                source_ref TEXT DEFAULT '',
                FOREIGN KEY(task_id) REFERENCES portal_tasks(id)
            );

            CREATE TABLE IF NOT EXISTS portal_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL DEFAULT 'general',
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                task_id INTEGER NOT NULL DEFAULT 0,
                notification_key TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                read_at TEXT DEFAULT '',
                FOREIGN KEY(task_id) REFERENCES portal_tasks(id)
            );

            CREATE TABLE IF NOT EXISTS portal_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL DEFAULT '',
                target_id TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS client_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_alias TEXT NOT NULL,
                sector TEXT DEFAULT '',
                priority_requirements TEXT DEFAULT '',
                technologies TEXT DEFAULT '',
                delivery_cadence TEXT DEFAULT '',
                allowed_tlp TEXT DEFAULT 'TLP:AMBER',
                active_reports INTEGER NOT NULL DEFAULT 0,
                detections_delivered INTEGER NOT NULL DEFAULT 0,
                opencti_collections TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT DEFAULT ''
            );
            """
        )

        ensure_column(connection, "users", "role", "TEXT NOT NULL DEFAULT 'user'")
        ensure_column(connection, "users", "mfa_secret", "TEXT DEFAULT ''")
        ensure_column(connection, "users", "mfa_enabled", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "users", "mfa_created_at", "TEXT DEFAULT ''")
        ensure_column(connection, "users", "mfa_recovery_codes", "TEXT DEFAULT '[]'")
        ensure_column(connection, "users", "mfa_recovery_generated_at", "TEXT DEFAULT ''")
        ensure_column(connection, "users", "mfa_required", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "users", "login_fail_count", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "users", "login_locked_until", "TEXT DEFAULT ''")
        ensure_column(connection, "users", "mfa_fail_count", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "users", "mfa_locked_until", "TEXT DEFAULT ''")
        ensure_column(connection, "searches", "requested_by", "TEXT DEFAULT ''")
        ensure_column(connection, "searches", "workflow", "TEXT DEFAULT 'general'")
        ensure_column(connection, "ai_costs", "source", "TEXT DEFAULT 'manual'")
        ensure_column(connection, "published_works", "due_date", "TEXT DEFAULT ''")
        ensure_column(connection, "published_works", "owner", "TEXT DEFAULT ''")
        ensure_column(connection, "published_works", "artifact_type", "TEXT DEFAULT 'report'")
        ensure_column(connection, "published_works", "audience", "TEXT DEFAULT 'internal'")
        ensure_column(connection, "published_works", "tags", "TEXT DEFAULT ''")
        ensure_column(connection, "published_works", "updated_at", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_tasks", "task_type", "TEXT DEFAULT 'general'")
        ensure_column(connection, "portal_tasks", "source_page", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_tasks", "research_workflow", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_tasks", "document_category", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_tasks", "uploaded_files", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_tasks", "priority", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "portal_tasks", "assignee", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_tasks", "worker_profile", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_tasks", "kanban_task_id", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_tasks", "kanban_status", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_tasks", "last_result", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_tasks", "review_document_path", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_tasks", "final_document_path", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_tasks", "published_work_id", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "portal_tasks", "client_profile_id", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "portal_tasks", "review_notes", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_tasks", "reviewer", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_tasks", "reviewer_signed_at", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_tasks", "review_signoff", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "portal_tasks", "due_date", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_tasks", "sla_hours", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "portal_tasks", "started_at", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_tasks", "blocked_reason", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_tasks", "blocked_at", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_tasks", "parent_task_id", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "portal_tasks", "acceptance_criteria", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_task_comments", "source", "TEXT NOT NULL DEFAULT 'portal'")
        ensure_column(connection, "portal_task_comments", "source_ref", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_task_history", "source", "TEXT NOT NULL DEFAULT 'portal'")
        ensure_column(connection, "portal_task_history", "source_ref", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_notifications", "category", "TEXT NOT NULL DEFAULT 'general'")
        ensure_column(connection, "portal_notifications", "title", "TEXT NOT NULL DEFAULT ''")
        ensure_column(connection, "portal_notifications", "body", "TEXT NOT NULL DEFAULT ''")
        ensure_column(connection, "portal_notifications", "task_id", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "portal_notifications", "notification_key", "TEXT NOT NULL DEFAULT ''")
        ensure_column(connection, "portal_notifications", "created_at", "TEXT NOT NULL DEFAULT ''")
        ensure_column(connection, "portal_notifications", "read_at", "TEXT DEFAULT ''")
        ensure_column(connection, "portal_audit_log", "actor", "TEXT NOT NULL DEFAULT ''")
        ensure_column(connection, "portal_audit_log", "action", "TEXT NOT NULL DEFAULT ''")
        ensure_column(connection, "portal_audit_log", "target_type", "TEXT NOT NULL DEFAULT ''")
        ensure_column(connection, "portal_audit_log", "target_id", "TEXT NOT NULL DEFAULT ''")
        ensure_column(connection, "portal_audit_log", "detail", "TEXT NOT NULL DEFAULT ''")
        ensure_column(connection, "portal_audit_log", "created_at", "TEXT NOT NULL DEFAULT ''")
        ensure_column(connection, "client_profiles", "sector", "TEXT DEFAULT ''")
        ensure_column(connection, "client_profiles", "priority_requirements", "TEXT DEFAULT ''")
        ensure_column(connection, "client_profiles", "technologies", "TEXT DEFAULT ''")
        ensure_column(connection, "client_profiles", "delivery_cadence", "TEXT DEFAULT ''")
        ensure_column(connection, "client_profiles", "allowed_tlp", "TEXT DEFAULT 'TLP:AMBER'")
        ensure_column(connection, "client_profiles", "active_reports", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "client_profiles", "detections_delivered", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(connection, "client_profiles", "opencti_collections", "TEXT DEFAULT ''")
        ensure_column(connection, "client_profiles", "notes", "TEXT DEFAULT ''")
        ensure_column(connection, "client_profiles", "updated_at", "TEXT DEFAULT ''")
        connection.execute("UPDATE portal_tasks SET status = 'accepted' WHERE status = 'complete'")
        dedupe_open_todo_tasks(connection)
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_portal_tasks_unique_todo_payload
            ON portal_tasks (lower(trim(title)), lower(trim(description)))
            WHERE status = 'todo'
            """
        )
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_portal_notifications_key
            ON portal_notifications (notification_key)
            WHERE notification_key <> ''
            """
        )
        connection.commit()


def dedupe_open_todo_tasks(connection: sqlite3.Connection) -> None:
    """Remove exact duplicate Todo cards created by browser resubmits/retries.

    Keep the oldest matching Todo task and delete later unlinked duplicates with
    the same normalized title and description. In-progress/review/accepted tasks
    are deliberately left alone because they represent real workflow history.
    """
    duplicates = connection.execute(
        """
        SELECT lower(trim(title)) AS title_key, lower(trim(description)) AS description_key, MIN(id) AS keep_id
        FROM portal_tasks
        WHERE status = 'todo'
        GROUP BY lower(trim(title)), lower(trim(description))
        HAVING COUNT(*) > 1
        """
    ).fetchall()
    for duplicate in duplicates:
        duplicate_rows = connection.execute(
            """
            SELECT id
            FROM portal_tasks
            WHERE status = 'todo'
              AND lower(trim(title)) = ?
              AND lower(trim(description)) = ?
              AND id <> ?
              AND COALESCE(kanban_task_id, '') = ''
            ORDER BY id ASC
            """,
            [duplicate["title_key"], duplicate["description_key"], duplicate["keep_id"]],
        ).fetchall()
        for row in duplicate_rows:
            duplicate_id = int(row["id"])
            connection.execute("DELETE FROM portal_task_comments WHERE task_id = ?", [duplicate_id])
            connection.execute("DELETE FROM portal_task_history WHERE task_id = ?", [duplicate_id])
            connection.execute("DELETE FROM portal_tasks WHERE id = ?", [duplicate_id])


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or os.urandom(16).hex()
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, expected = stored.split("$", 1)
    except ValueError:
        return False
    computed = hash_password(password, salt).split("$", 1)[1]
    return hmac.compare_digest(expected, computed)


def bootstrap_admin_user() -> None:
    username = os.getenv("RAICCOON_ADMIN_USERNAME", "admin")
    password = os.getenv("RAICCOON_ADMIN_PASSWORD", "change-me-now")
    display_name = os.getenv("RAICCOON_ADMIN_DISPLAY_NAME", "Portal Admin")

    with closing(connect_db()) as connection:
        existing = connection.execute("SELECT id FROM users WHERE username = ?", [username]).fetchone()
        if existing:
            return

        count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            connection.execute(
                "INSERT INTO users (username, display_name, role, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                [username, display_name, "admin", hash_password(password), now_utc().isoformat()],
            )
            connection.commit()


def fetch_all(query: str, params: Iterable | None = None) -> list[sqlite3.Row]:
    with closing(connect_db()) as connection:
        cursor = connection.execute(query, params or [])
        return cursor.fetchall()


def fetch_one(query: str, params: Iterable | None = None) -> sqlite3.Row | None:
    with closing(connect_db()) as connection:
        cursor = connection.execute(query, params or [])
        return cursor.fetchone()


def execute(query: str, params: Iterable | None = None) -> None:
    with closing(connect_db()) as connection:
        connection.execute(query, params or [])
        connection.commit()


def normalize_totp_code(raw: str) -> str:
    return re.sub(r"\D", "", raw or "")


def normalize_recovery_code(raw: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", raw or "").upper()


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def generate_recovery_codes(count: int = MFA_RECOVERY_CODE_COUNT) -> list[str]:
    codes: list[str] = []
    while len(codes) < count:
        code = f"{secrets.randbelow(10000):04d}-{secrets.randbelow(10000):04d}"
        if code not in codes:
            codes.append(code)
    return codes


def hash_recovery_code(code: str) -> str:
    normalized = normalize_recovery_code(code)
    if not normalized:
        raise ValueError("Recovery code cannot be empty")
    return hash_password(normalized)


def serialize_recovery_code_hashes(codes: list[str]) -> str:
    return json.dumps([hash_recovery_code(code) for code in codes])


def load_recovery_code_hashes(raw: str) -> list[str]:
    try:
        parsed = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed if isinstance(item, str)]


def recovery_code_count(raw: str) -> int:
    return len(load_recovery_code_hashes(raw))


def hotp(secret: str, counter: int, digits: int = TOTP_DIGITS) -> str:
    padding = "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode((secret + padding).encode("ascii"), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code_int = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10**digits)).zfill(digits)


def verify_totp_code(secret: str, code: str, *, at_time: int | None = None, window: int = 1) -> bool:
    normalized = normalize_totp_code(code)
    if len(normalized) != TOTP_DIGITS or not secret:
        return False
    timestamp = at_time if at_time is not None else int(time.time())
    counter = timestamp // TOTP_PERIOD_SECONDS
    for offset in range(-window, window + 1):
        if hmac.compare_digest(hotp(secret, counter + offset), normalized):
            return True
    return False


def totp_uri(username: str, secret: str) -> str:
    label = urllib.parse.quote(f"{TOTP_ISSUER}:{username}")
    issuer = urllib.parse.quote(TOTP_ISSUER)
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={issuer}"
        f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD_SECONDS}"
    )


def parse_utc_timestamp(raw: str) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def lock_is_active(raw: str) -> bool:
    locked_until = parse_utc_timestamp(raw)
    return bool(locked_until and locked_until > now_utc())


def format_lockout_message(raw: str, label: str) -> str:
    locked_until = parse_utc_timestamp(raw)
    if not locked_until:
        return f"Too many {label} attempts. Try again later."
    return f"Too many {label} attempts. Try again after {locked_until.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}."


def clear_login_failures(user_id: int) -> None:
    execute("UPDATE users SET login_fail_count = 0, login_locked_until = '' WHERE id = ?", [user_id])


def record_login_failure(user: sqlite3.Row) -> str:
    count = int(user["login_fail_count"] or 0) + 1
    locked_until = ""
    if count >= AUTH_LOCKOUT_THRESHOLD:
        locked_until = (now_utc() + timedelta(minutes=AUTH_LOCKOUT_MINUTES)).isoformat()
        count = 0
    execute(
        "UPDATE users SET login_fail_count = ?, login_locked_until = ? WHERE id = ?",
        [count, locked_until, user["id"]],
    )
    return locked_until


def clear_mfa_failures(user_id: int) -> None:
    execute("UPDATE users SET mfa_fail_count = 0, mfa_locked_until = '' WHERE id = ?", [user_id])


def record_mfa_failure(user: sqlite3.Row) -> str:
    count = int(user["mfa_fail_count"] or 0) + 1
    locked_until = ""
    if count >= AUTH_LOCKOUT_THRESHOLD:
        locked_until = (now_utc() + timedelta(minutes=AUTH_LOCKOUT_MINUTES)).isoformat()
        count = 0
    execute(
        "UPDATE users SET mfa_fail_count = ?, mfa_locked_until = ? WHERE id = ?",
        [count, locked_until, user["id"]],
    )
    return locked_until


def consume_recovery_code(user: sqlite3.Row, candidate: str) -> bool:
    normalized = normalize_recovery_code(candidate)
    if len(normalized) < 8:
        return False
    stored_hashes = load_recovery_code_hashes(user["mfa_recovery_codes"] if "mfa_recovery_codes" in user.keys() else "[]")
    for index, stored_hash in enumerate(stored_hashes):
        if verify_password(normalized, stored_hash):
            remaining = stored_hashes[:index] + stored_hashes[index + 1 :]
            execute(
                "UPDATE users SET mfa_recovery_codes = ?, mfa_fail_count = 0, mfa_locked_until = '' WHERE id = ?",
                [json.dumps(remaining), user["id"]],
            )
            return True
    return False


def set_authenticated_session(request: Request, user: sqlite3.Row) -> None:
    request.session.clear()
    mfa_enabled = bool(user["mfa_enabled"]) if "mfa_enabled" in user.keys() else False
    mfa_required = bool(user["mfa_required"]) if "mfa_required" in user.keys() else False
    request.session["user_id"] = user["id"]
    request.session["username"] = user["username"]
    request.session["display_name"] = user["display_name"]
    request.session["role"] = user["role"] if "role" in user.keys() else "user"
    request.session["mfa_enabled"] = mfa_enabled
    request.session["mfa_required"] = mfa_required
    request.session["mfa_setup_required"] = bool(mfa_required and not mfa_enabled)
    request.session["mfa_ok"] = True


def set_pending_mfa_session(request: Request, user: sqlite3.Row) -> None:
    request.session.clear()
    request.session["pending_mfa_user_id"] = user["id"]
    request.session["pending_mfa_username"] = user["username"]


def clear_pending_mfa_session(request: Request) -> None:
    for key in ["pending_mfa_user_id", "pending_mfa_username", "pending_mfa_secret"]:
        request.session.pop(key, None)


def current_user(request: Request) -> dict:
    return {
        "id": request.session.get("user_id"),
        "username": request.session.get("username", ""),
        "display_name": request.session.get("display_name", ""),
        "role": request.session.get("role", "user"),
        "mfa_enabled": bool(request.session.get("mfa_enabled", False)),
        "mfa_required": bool(request.session.get("mfa_required", False)),
        "mfa_setup_required": bool(request.session.get("mfa_setup_required", False)),
    }


def pending_mfa_user(request: Request) -> dict:
    return {
        "id": request.session.get("pending_mfa_user_id"),
        "username": request.session.get("pending_mfa_username", ""),
    }


def dashboard_summary() -> dict:
    with closing(connect_db()) as connection:
        total_searches = connection.execute("SELECT COUNT(*) FROM searches").fetchone()[0]
        total_uploads = connection.execute(
            "SELECT COALESCE(SUM(CASE WHEN uploaded_files = '' THEN 0 ELSE (LENGTH(uploaded_files) - LENGTH(REPLACE(uploaded_files, '|', '')) + 1) END), 0) FROM searches"
        ).fetchone()[0]
        total_cost = connection.execute("SELECT COALESCE(SUM(amount_usd), 0) FROM ai_costs").fetchone()[0]
        published_count = connection.execute("SELECT COUNT(*) FROM published_works WHERE status = 'published'").fetchone()[0]
        in_flight = connection.execute(
            "SELECT COUNT(*) FROM published_works WHERE status IN ('draft', 'review', 'scheduled')"
        ).fetchone()[0]
        open_tasks = connection.execute(
            "SELECT COUNT(*) FROM portal_tasks WHERE status IN ('todo', 'in_progress', 'in_review')"
        ).fetchone()[0]
        document_count = report_document_count()
        latest_sync = connection.execute(
            "SELECT provider, status, detail, created_at, imported_count FROM cost_sync_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()

    return {
        "total_searches": total_searches,
        "total_uploads": total_uploads,
        "total_cost": round(total_cost or 0, 2),
        "published_count": published_count,
        "in_flight": in_flight,
        "open_tasks": open_tasks,
        "document_count": document_count,
        "latest_sync": dict(latest_sync) if latest_sync else None,
    }


def monthly_cost_breakdown() -> list[dict]:
    rows = fetch_all(
        """
        SELECT substr(period_start, 1, 7) AS month, provider, SUM(amount_usd) AS total
        FROM ai_costs
        GROUP BY substr(period_start, 1, 7), provider
        ORDER BY month DESC, total DESC
        """
    )
    grouped: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        grouped[row["month"]].append({"provider": row["provider"], "total": round(row["total"], 2)})
    return [{"month": month, "providers": providers} for month, providers in grouped.items()]


def publication_status_breakdown() -> list[dict]:
    rows = fetch_all(
        "SELECT status, COUNT(*) AS total FROM published_works GROUP BY status ORDER BY total DESC, status ASC"
    )
    return [dict(row) for row in rows]


def search_operator_breakdown() -> list[dict]:
    rows = fetch_all(
        "SELECT requested_by, COUNT(*) AS total FROM searches GROUP BY requested_by ORDER BY total DESC, requested_by ASC"
    )
    return [dict(row) for row in rows]


def fetch_research_tasks(limit: int = 50) -> list[dict]:
    rows = fetch_all(
        "SELECT * FROM portal_tasks WHERE task_type = 'research' ORDER BY id DESC LIMIT ?",
        [limit],
    )
    items: list[dict] = []
    for row in rows:
        item = dict(row)
        item["status_label"] = PORTAL_TASK_LABELS.get(item.get("status", "todo"), "Todo")
        item["review_document_name"] = Path(item["review_document_path"]).name if item.get("review_document_path") else ""
        item["final_document_name"] = Path(item["final_document_path"]).name if item.get("final_document_path") else ""
        item["uploaded_file_list"] = task_uploaded_files(item)
        items.append(item)
    return items


def create_notification(category: str, title: str, body: str, *, task_id: int = 0, notification_key: str = "") -> None:
    with closing(connect_db()) as connection:
        try:
            connection.execute(
                """
                INSERT INTO portal_notifications (category, title, body, task_id, notification_key, created_at, read_at)
                VALUES (?, ?, ?, ?, ?, ?, '')
                """,
                [
                    (category or "general").strip() or "general",
                    title.strip(),
                    body.strip(),
                    task_id,
                    notification_key.strip(),
                    now_utc().isoformat(),
                ],
            )
            connection.commit()
        except sqlite3.IntegrityError:
            return


def fetch_notifications(*, unread_only: bool = False, limit: int = 8) -> list[dict]:
    if unread_only:
        rows = fetch_all(
            "SELECT * FROM portal_notifications WHERE read_at = '' ORDER BY id DESC LIMIT ?",
            [limit],
        )
    else:
        rows = fetch_all("SELECT * FROM portal_notifications ORDER BY id DESC LIMIT ?", [limit])
    return [dict(row) for row in rows]


def unread_notification_count() -> int:
    row = fetch_one("SELECT COUNT(*) AS total FROM portal_notifications WHERE read_at = ''")
    return int(row["total"] if row else 0)


def mark_notification_read(notification_id: int) -> None:
    execute(
        "UPDATE portal_notifications SET read_at = CASE WHEN read_at = '' THEN ? ELSE read_at END WHERE id = ?",
        [now_utc().isoformat(), notification_id],
    )


def due_soon_works() -> list[sqlite3.Row]:
    today = date.today().isoformat()
    soon = (date.today() + timedelta(days=14)).isoformat()
    return fetch_all(
        """
        SELECT *
        FROM published_works
        WHERE due_date <> '' AND due_date >= ? AND due_date <= ? AND status <> 'published'
        ORDER BY due_date ASC, id DESC
        LIMIT 10
        """,
        [today, soon],
    )


def is_final_pdf_report(path: Path) -> bool:
    """Return True only for final PDF deliverables shown in the Documents tab."""
    if path.suffix.lower() != ".pdf":
        return False
    lowered = path.stem.lower()
    non_final_markers = (
        "_draft",
        "-draft",
        " draft",
        "_original",
        "-original",
        " original",
        "_pre_patch",
        "-pre-patch",
        " pre patch",
        "_prepatch",
        "-prepatch",
        "_addendum",
        "-addendum",
        " addendum",
        "_review",
        "-review",
        " review",
    )
    return not any(marker in lowered for marker in non_final_markers)


def ensure_report_library() -> None:
    """Seed the local report library from the portable RAIccoon bundle when present.

    Only final PDF deliverables are copied into/displayed by the Documents tab;
    markdown notes, HTML/TXT exports, drafts, originals, pre-patch copies, and
    addenda stay out of the portal library.
    """
    DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)
    has_existing_final_pdfs = any(is_final_pdf_report(path) for path in DOCUMENTS_DIR.rglob("*") if path.is_file())
    if not has_existing_final_pdfs and RAICCOON_PORTABLE_ZIP.exists():
        prefix = "RAIccoon_LostBoys_Portable_20260602_200711/Reports/"
        with zipfile.ZipFile(RAICCOON_PORTABLE_ZIP) as archive:
            for member in archive.infolist():
                if member.is_dir() or not member.filename.startswith(prefix):
                    continue
                relative = Path(member.filename[len(prefix):])
                if not relative.parts or ".." in relative.parts or not is_final_pdf_report(relative):
                    continue
                destination = DOCUMENTS_DIR / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as src, destination.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
    sync_report_library_from_archive_repo()


def sync_report_library_from_archive_repo() -> int:
    repo_dir = REPORTS_REPO_DIR
    if not repo_dir.exists() or not repo_dir.is_dir():
        return 0
    try:
        if repo_dir.resolve() == DOCUMENTS_DIR.resolve():
            return 0
    except FileNotFoundError:
        pass

    copied = 0
    for path in repo_dir.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(repo_dir)
        if not relative.parts or ".." in relative.parts:
            continue
        if relative.parts[0] == IN_REVIEW_DIR.name:
            continue
        if not is_final_pdf_report(relative):
            continue
        destination = DOCUMENTS_DIR / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        should_copy = (
            not destination.exists()
            or path.stat().st_size != destination.stat().st_size
            or path.stat().st_mtime > destination.stat().st_mtime
        )
        if should_copy:
            shutil.copy2(path, destination)
            copied += 1
    return copied


def document_kind(path: Path) -> str:
    suffix = path.suffix.lower().lstrip(".")
    return suffix.upper() if suffix else "FILE"


def human_size(size: int) -> str:
    units = ("B", "KB", "MB", "GB")
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def report_document_categories() -> list[dict]:
    ensure_report_library()
    categories: list[dict] = []
    for category_dir in sorted((p for p in DOCUMENTS_DIR.iterdir() if p.is_dir()), key=lambda p: p.name.lower()):
        if category_dir.name == IN_REVIEW_DIR.name:
            continue
        documents = []
        for path in sorted((p for p in category_dir.iterdir() if p.is_file()), key=lambda p: p.stat().st_mtime, reverse=True):
            if not is_final_pdf_report(path):
                continue
            stat = path.stat()
            documents.append({
                "name": path.name,
                "kind": document_kind(path),
                "size": human_size(stat.st_size),
                "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                "url": f"/documents/open?category={urllib.parse.quote(category_dir.name)}&file={urllib.parse.quote(path.name)}",
            })
        categories.append({
            "name": category_dir.name,
            "count": len(documents),
            "documents": documents,
        })
    root_documents = []
    if DOCUMENTS_DIR.exists():
        for path in sorted((p for p in DOCUMENTS_DIR.iterdir() if p.is_file()), key=lambda p: p.stat().st_mtime, reverse=True):
            if not is_final_pdf_report(path):
                continue
            stat = path.stat()
            root_documents.append({
                "name": path.name,
                "kind": document_kind(path),
                "size": human_size(stat.st_size),
                "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                "url": f"/documents/open?category=&file={urllib.parse.quote(path.name)}",
            })
    if root_documents:
        categories.insert(0, {"name": "Uncategorized", "count": len(root_documents), "documents": root_documents})
    return categories


def report_document_count() -> int:
    return sum(category["count"] for category in report_document_categories())


def resolve_document_path(category: str, filename: str) -> Path | None:
    ensure_report_library()
    base = DOCUMENTS_DIR.resolve()
    normalized_category = category.strip()
    raw_parts = []
    if normalized_category:
        raw_parts.append(normalized_category)
    raw_parts.append(filename.strip())
    if not filename.strip() or any(".." in part or "/" in part or "\\" in part for part in raw_parts):
        return None
    candidate = (DOCUMENTS_DIR / Path(*raw_parts)).resolve()
    if not str(candidate).startswith(str(base)) or not candidate.is_file():
        return None
    if normalized_category == IN_REVIEW_DIR.name:
        return candidate if candidate.suffix.lower() == ".pdf" else None
    if not is_final_pdf_report(candidate):
        return None
    return candidate


def safe_filename(name: str) -> str:
    return "".join(char if char.isalnum() or char in {".", "-", "_"} else "_" for char in name)


def slugify_report_title(title: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", (title or "").strip().lower())
    return normalized.strip("-") or "untitled-report"


def cleaned_report_title(title: str) -> str:
    normalized = (title or "").strip()
    normalized = re.sub(r"(?i)^review\s+intake\s+draft\s*:\s*", "", normalized)
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized or "Untitled Report"


def _task_value(task: sqlite3.Row | dict, key: str, default: str = "") -> str:
    if isinstance(task, sqlite3.Row):
        return str(task[key] if key in task.keys() and task[key] is not None else default)
    return str(task.get(key, default) or default)


def task_workflow(task: sqlite3.Row | dict) -> str:
    return normalize_workflow(_task_value(task, "research_workflow", "general"))


def is_malware_analysis_task(task: sqlite3.Row | dict) -> bool:
    return task_workflow(task) == "malware-analysis"


def normalize_malware_family(value: str) -> str:
    family = re.sub(r"\s+", " ", (value or "").strip().strip('"\''))
    family = re.sub(r"(?i)\s+(?:malware analysis|malware report|analysis report|report)$", "", family).strip()
    if not family or family.lower() in {"unknown", "unknown family", "n/a", "na", "none", "tbd", "replace with malware family"}:
        return ""
    return family


def extract_malware_family_from_text(text: str) -> str:
    source = text or ""
    patterns = [
        r"(?im)^\s*malware_family\s*:\s*[\"']?([^\n\"']+)",
        r"(?im)^\s*malware family\s*:\s*([^\n]+)",
        r"(?im)^\s*family\s*:\s*([^\n]+)",
        r"(?im)^\s*\|\s*(?:malware\s+family(?:\s*/\s*cluster)?|family)\s*\|\s*([^|\n]+?)\s*\|",
        r"(?im)^\s*[-*]\s*(?:malware\s+family(?:\s*/\s*cluster)?|family)\s*:\s*([^\n]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, source)
        if match:
            family = normalize_malware_family(match.group(1))
            if family:
                return family
    heading = re.search(r"(?im)^#\s+(.+?)\s+(?:Malware Analysis|Malware Report)\s*$", source)
    if heading:
        return normalize_malware_family(heading.group(1))
    return ""


def malware_family_for_task(task: sqlite3.Row | dict, report_text: str = "") -> str:
    if not is_malware_analysis_task(task):
        return ""
    for key in ("malware_family", "family"):
        family = normalize_malware_family(_task_value(task, key, ""))
        if family:
            return family
    root = canonical_report_root_from_task(task) if "canonical_report_root_from_task" in globals() else None
    if root:
        metadata = _parse_simple_yaml(root / "metadata.yaml") if root.is_dir() else _parse_simple_yaml(root.parent / "metadata.yaml")
        family = normalize_malware_family(str(metadata.get("malware_family") or ""))
        if family:
            return family
    for text in (report_text, _task_value(task, "last_result", ""), task_description_text(task) if "task_description_text" in globals() else ""):
        family = extract_malware_family_from_text(text)
        if family:
            return family
    return ""


def report_display_title_for_task(task: sqlite3.Row | dict, report_text: str = "") -> str:
    if is_malware_analysis_task(task):
        family = malware_family_for_task(task, report_text)
        if family:
            return f"{family} Malware Analysis"
    return cleaned_report_title(_task_value(task, "title", "Untitled Report"))


def report_id_prefix_for_task(task: sqlite3.Row | dict) -> str:
    category = ((task["document_category"] if isinstance(task, sqlite3.Row) else task.get("document_category", "")) or "Uncategorized").strip() or "Uncategorized"
    if category in REPORT_ID_PREFIXES:
        return REPORT_ID_PREFIXES[category]

    workflow = normalize_workflow((task["research_workflow"] if isinstance(task, sqlite3.Row) else task.get("research_workflow", "")) or "general")
    workflow_map = {
        "malware-analysis": "RPT-MA",
        "detection-engineering": "RPT-DE",
        "purple-team-exercise": "RPT-PTE",
        "threat-hunting": "RPT-TH",
        "ioc-enrichment": "RPT-IOC",
        "ir-triage": "RPT-IR",
        "threat-intel": "RPT-TR",
        "general": "RPT-RPT",
    }
    return workflow_map.get(workflow, "RPT-RPT")


def report_year_for_task(task: sqlite3.Row | dict) -> int:
    raw_created = (task["created_at"] if isinstance(task, sqlite3.Row) else task.get("created_at", "")) or ""
    if raw_created:
        try:
            return datetime.fromisoformat(raw_created.replace("Z", "+00:00")).year
        except ValueError:
            pass
    return now_utc().year


def existing_report_path_for_task(task: sqlite3.Row | dict) -> Path | None:
    raw = (task["final_document_path"] if isinstance(task, sqlite3.Row) else task.get("final_document_path", "")) or ""
    if not raw.strip():
        return None
    return Path(raw.strip())


def report_filename_matches_raiccoon_convention(path: Path) -> bool:
    return bool(re.fullmatch(r"RPT-[A-Z]+-\d{4}-\d{3}_[a-z0-9]+(?:-[a-z0-9]+)*\.pdf", path.name))


def allocate_raiccoon_report_filename(task: sqlite3.Row | dict) -> str:
    prefix = report_id_prefix_for_task(task)
    year = report_year_for_task(task)
    category = ((task["document_category"] if isinstance(task, sqlite3.Row) else task.get("document_category", "")) or "Uncategorized").strip() or "Uncategorized"
    category_dir = DOCUMENTS_DIR / category
    slug = slugify_report_title(report_display_title_for_task(task))
    pattern = re.compile(rf"{re.escape(prefix)}-{year}-(\d{{3}})_.+\.pdf$")
    max_sequence = 0
    if category_dir.exists():
        for candidate in category_dir.glob(f"{prefix}-{year}-*.pdf"):
            match = pattern.fullmatch(candidate.name)
            if match:
                max_sequence = max(max_sequence, int(match.group(1)))
    return f"{prefix}-{year}-{max_sequence + 1:03d}_{slug}.pdf"


def final_report_filename_for_task(task: sqlite3.Row | dict) -> str:
    existing = existing_report_path_for_task(task)
    if existing and report_filename_matches_raiccoon_convention(existing):
        return existing.name
    return allocate_raiccoon_report_filename(task)


def normalize_workflow(value: str) -> str:
    workflow = (value or "general").strip().lower()
    return workflow if workflow in RESEARCH_WORKFLOWS else "general"


def normalize_task_type(value: str) -> str:
    task_type = (value or "general").strip().lower()
    return "research" if task_type == "research" else "general"


def normalize_due_date(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    try:
        return date.fromisoformat(raw[:10]).isoformat()
    except ValueError:
        return ""


def normalize_sla_hours(value: int | str) -> int:
    try:
        parsed = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return max(0, min(parsed, 8760))


def parse_portal_datetime(value: str | None) -> datetime | None:
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def hours_since(value: str | None) -> float:
    parsed = parse_portal_datetime(value)
    if not parsed:
        return 0.0
    return max(0.0, round((now_utc() - parsed).total_seconds() / 3600, 1))


def due_state(due_date: str | None) -> str:
    normalized = normalize_due_date(due_date or "")
    if not normalized:
        return "none"
    due = date.fromisoformat(normalized)
    today = now_utc().date()
    if due < today:
        return "overdue"
    if due == today:
        return "due_today"
    if due <= today + timedelta(days=3):
        return "due_soon"
    return "scheduled"


def task_templates() -> list[dict]:
    return [dict(template) for template in TASK_TEMPLATE_CATALOG]


def board_quick_views() -> list[dict[str, str]]:
    return [
        {"key": "my-tasks", "label": "My Tasks", "filter": "assignee=current"},
        {"key": "blocked", "label": "Blocked / Needs Human", "filter": "status=blocked"},
        {"key": "ready-for-review", "label": "Ready for Review", "filter": "status=in_review"},
        {"key": "client-deliverables", "label": "Client Deliverables", "filter": "client=linked"},
        {"key": "opencti-registry", "label": "OpenCTI / Registry Ops", "filter": "source=opencti-upload,registry-remediation"},
        {"key": "qa-failing", "label": "Report QA Failing", "filter": "qa=fail"},
        {"key": "stale", "label": "Stale In Progress", "filter": "stale=true"},
    ]


def normalize_report_task_fields(
    task_type: str,
    research_workflow: str,
    document_category: str,
    *,
    source_page: str = "",
) -> tuple[str, str, str, str]:
    normalized_task_type = normalize_task_type(task_type)
    normalized_source_page = (source_page or "").strip().lower()
    normalized_research_workflow = normalize_workflow(research_workflow) if normalized_task_type == "research" else ""
    normalized_document_category = (document_category or "").strip() if normalized_task_type == "research" else ""
    if normalized_task_type == "research" and not normalized_source_page:
        normalized_source_page = "research"
    return (
        normalized_task_type,
        normalized_source_page,
        normalized_research_workflow,
        normalized_document_category,
    )


def workflow_options() -> list[dict[str, str | bool]]:
    return [
        {"key": key, **value}
        for key, value in RESEARCH_WORKFLOWS.items()
    ]


def report_category_options() -> list[str]:
    categories: list[str] = []
    for category in DEFAULT_DOCUMENT_CATEGORIES:
        if category not in categories:
            categories.append(category)
    if DOCUMENTS_DIR.exists():
        for path in sorted((p for p in DOCUMENTS_DIR.iterdir() if p.is_dir()), key=lambda p: p.name.lower()):
            if path.name == IN_REVIEW_DIR.name:
                continue
            if path.name not in categories:
                categories.append(path.name)
    return categories


def report_family_for_task(task: sqlite3.Row | dict) -> str:
    workflow = normalize_workflow((task["research_workflow"] if isinstance(task, sqlite3.Row) else task.get("research_workflow", "")) or "general")
    category = ((task["document_category"] if isinstance(task, sqlite3.Row) else task.get("document_category", "")) or "").strip()
    workflow_map = {
        "malware-analysis": "Malware Analysis Report",
        "detection-engineering": "Detection Engineering Report",
        "purple-team-exercise": "Purple Team Exercise",
        "threat-hunting": "Threat Hunting Report",
        "ioc-enrichment": "IOC Enrichment Report",
        "ir-triage": "IR Triage Report",
        "threat-intel": "Threat Intelligence Report",
    }
    if category == "Executive Summaries":
        return "Executive Summary"
    if category == "Threat Actor Profiles":
        return "Threat Actor Profile"
    if category == "Vulnerabilities":
        return "Vulnerability Report"
    return workflow_map.get(workflow, "Research Report")


def opencti_report_type_for_task(task: sqlite3.Row | dict) -> str:
    """OpenCTI report_types value for portal-produced research artifacts.

    Purple-team exercises are tracked as RFIs in OpenCTI so they show up as
    requests/intelligence requirements rather than completed threat reports.
    Every other research workflow stays in the report lane using the same
    family label rendered on the PDF cover.
    """
    workflow = normalize_workflow((task["research_workflow"] if isinstance(task, sqlite3.Row) else task.get("research_workflow", "")) or "general")
    if workflow == "purple-team-exercise":
        return "Request for Information"
    return report_family_for_task(task)


def report_section_outline(task: sqlite3.Row | dict) -> list[str]:
    workflow = normalize_workflow((task["research_workflow"] if isinstance(task, sqlite3.Row) else task.get("research_workflow", "")) or "general")
    if workflow == "malware-analysis":
        return [
            "1. Executive Summary",
            "2. Sample Metadata",
            "3. Source Review & Confidence",
            "4. Initial Triage and Delivery Assessment",
            "5. Static Analysis",
            "6. Code Analysis",
            "7. Dynamic Analysis",
            "8. Process Tree and Execution Chain",
            "9. Persistence and System Modification",
            "10. Network and Infrastructure Analysis",
            "11. Indicators of Compromise",
            "12. MITRE ATT&CK Mapping",
            "13. Detection Engineering",
            "14. Threat Hunting",
            "15. Triage and Incident Response",
            "16. Validation and Emulation",
            "17. Recommendations",
            "18. References and Refresh Notes",
        ]
    if workflow == "detection-engineering":
        return [
            "1. Executive Summary",
            "2. Detection Objective",
            "3. Threat Context",
            "4. Data Sources and Assumptions",
            "5. Detection Logic",
            "6. ATT&CK Mapping",
            "7. Validation Guidance",
            "8. Hunting Opportunities",
            "9. Recommendations",
            "10. References",
        ]
    if workflow == "purple-team-exercise":
        return [
            "1. Executive Summary",
            "2. Exercise Objective and Scope",
            "3. Source Review and Confidence",
            "4. Threat Context and Emulation Narrative",
            "5. Exercise Phases and Injects",
            "6. MITRE ATT&CK Mapping",
            "7. Detection and Hunting Validation",
            "8. Safety Guardrails and Rules of Engagement",
            "9. After-Action Review Criteria",
            "10. Recommendations",
            "11. References",
        ]
    if workflow == "threat-hunting":
        return [
            "1. Executive Summary",
            "2. Hunt Objective",
            "3. Threat Context",
            "4. Hypotheses",
            "5. Data Sources",
            "6. Hunt Queries and Analytics",
            "7. Findings and Interpretation",
            "8. Recommendations",
            "9. References",
        ]
    if workflow == "ioc-enrichment":
        return [
            "1. Executive Summary",
            "2. Enriched Indicators",
            "3. Source Review and Confidence",
            "4. Infrastructure and Relationships",
            "5. Defensive Relevance",
            "6. Detection and Hunting",
            "7. Recommended Actions",
            "8. References",
        ]
    if workflow == "ir-triage":
        return [
            "1. Executive Summary",
            "2. Incident Context",
            "3. Evidence Review",
            "4. Initial Findings",
            "5. Scope Assessment",
            "6. Containment and Eradication Guidance",
            "7. Detection and Hunt Opportunities",
            "8. Recommendations",
            "9. References",
        ]
    return [
        "1. Executive Summary",
        "2. Intelligence Requirement",
        "3. Source Review and Confidence",
        "4. Key Findings",
        "5. Threat Context",
        "6. Detection and Hunting",
        "7. Recommendations",
        "8. References",
    ]


def workflow_prompt_prefix(workflow: str) -> str:

    prompts = {
        "general": "Work this like a versatile internal analyst request. Be concise, useful, and evidence-aware.",
        "threat-intel": "Use the threat-intel workflow: extract the core campaign/activity, notable TTPs, IOCs, references, and prioritized defensive recommendations.",
        "detection-engineering": "Use the detection-engineering workflow: build a threat model, map to ATT&CK, form detection hypotheses, and provide actionable Sigma/KQL/SPL/YARA guidance where appropriate.",
        "purple-team-exercise": "Use the purple-team-exercise workflow: translate threat intelligence into a safe adversary-emulation plan with scope, rules of engagement, injects, telemetry expectations, detections/hunts, cleanup, success criteria, and after-action review guidance. Use benign simulators only; do not provide destructive payloads, credential theft, or real malware instructions.",
        "threat-hunting": "Use the threat-hunting workflow: define hypotheses, required telemetry, hunt queries/logic, triage guidance, and closure criteria.",
        "ioc-enrichment": "Use the IOC-enrichment workflow: pivot, cluster, confidence-score, summarize related infrastructure, and recommend operational actions.",
        "malware-analysis": "Use the malware-analysis workflow: every uploaded sample must be covered by RAIccoon Local Sandbox sandbox evidence, static triage, GhidraMCP/Ghidra-backed code analysis and reversing notes when code is present, dynamic behavior, process tree, persistence, network IOCs, ATT&CK mapping, detection opportunities, and analyst next steps.",
        "ir-triage": "Use the IR-triage workflow: scope the incident, identify likely blast radius, prioritize evidence, recommend containment sequencing, and build timeline-oriented guidance.",
    }
    return prompts[workflow]


def fetch_chat_messages(limit: int = 80) -> list[sqlite3.Row]:
    return fetch_all(
        "SELECT * FROM hermes_chat_messages ORDER BY id DESC LIMIT ?",
        [limit],
    )[::-1]


def build_chat_prompt(message: str, username: str, recent_messages: list[sqlite3.Row]) -> str:
    lines = [
        "You are Hermes inside the Your Organization internal command portal.",
        "The user is chatting with you through a desktop-style portal tab modeled after Claude Desktop/Codex Desktop.",
        "Act like Your Organization's third team member: practical, security-aware, and focused on execution.",
        "Default to a more verbose, useful response style than a quick chat reply: explain your reasoning enough to be actionable, include assumptions, trade-offs, concrete next steps, and security/operations context when relevant.",
        "Use clear structure with short sections or bullets for anything non-trivial. For simple confirmations, stay brief; for analysis, planning, reports, detections, incident response, or troubleshooting, be thorough.",
        "If the user asks for code, detection logic, report copy, or a workflow, include complete examples or templates instead of terse summaries.",
        "Use the conversation history below for continuity. Do not claim access to Discord history or portal state unless it is shown here.",
        f"Current operator: {username}",
        "",
        "Recent portal chat history:",
    ]
    for row in recent_messages[-16:]:
        role = "Assistant" if row["role"] == "assistant" else "User"
        lines.append(f"{role} ({row['requested_by'] or 'portal'}): {row['content']}")
    lines.extend(["", f"Current user message: {message}"])
    return "\n".join(lines)


def run_chat_hermes(message: str, username: str) -> tuple[str, float]:
    hermes_cli = hermes_executable()
    # Portal chat runs Hermes from a non-interactive background worker. Give real
    # operational requests enough time to finish, and prevent CLI approval/hook
    # prompts from stalling until the browser sees only a timeout error.
    hermes_timeout = int(os.getenv("HERMES_CHAT_TIMEOUT", os.getenv("HERMES_TIMEOUT", "900")))
    prompt = build_chat_prompt(message, username, fetch_chat_messages(limit=32))
    command = [
        hermes_cli,
        "chat",
        "-Q",
        "--yolo",
        "--accept-hooks",
        "--source",
        "portal-chat",
        "-q",
        prompt,
    ]
    child_env = os.environ.copy()
    child_env.setdefault("HERMES_YOLO_MODE", "1")
    child_env.setdefault("HERMES_ACCEPT_HOOKS", "1")
    start = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            cwd=str(BASE_DIR),
            env=child_env,
            capture_output=True,
            text=True,
            timeout=hermes_timeout,
            check=False,
        )
    except FileNotFoundError:
        return f"ERROR: Hermes CLI was not found. Set HERMES_CLI to the absolute hermes executable path. Attempted: {hermes_cli}", round(time.perf_counter() - start, 2)
    except subprocess.TimeoutExpired as exc:
        parts = []
        for part in (exc.stdout, exc.stderr):
            if isinstance(part, bytes):
                part = part.decode("utf-8", errors="replace")
            if part and str(part).strip():
                parts.append(str(part).strip())
        detail = f" after {hermes_timeout}s"
        if parts:
            detail += ". Partial output:\n" + "\n".join(parts)
        return f"ERROR: Hermes chat timed out{detail}", round(time.perf_counter() - start, 2)
    duration = round(time.perf_counter() - start, 2)
    output = (completed.stdout or "").strip()
    if completed.returncode != 0:
        error_text = (completed.stderr or output or "Hermes chat failed").strip()
        return f"ERROR: {error_text}", duration
    cleaned = []
    for line in output.splitlines():
        if line.startswith("session_id:"):
            continue
        cleaned.append(line)
    return "\n".join(cleaned).strip() or "No response returned.", duration


def add_chat_message(role: str, content: str, requested_by: str, duration_seconds: float = 0, metadata: str = "") -> None:
    execute(
        "INSERT INTO hermes_chat_messages (role, content, created_at, requested_by, duration_seconds, metadata) VALUES (?, ?, ?, ?, ?, ?)",
        [role, content, now_utc().isoformat(), requested_by, duration_seconds, metadata],
    )


def chat_has_pending_reply() -> bool:
    latest = fetch_one("SELECT role FROM hermes_chat_messages ORDER BY id DESC LIMIT 1")
    return bool(latest and latest["role"] == "user")


def queue_chat_response(message: str, username: str) -> None:
    def worker() -> None:
        try:
            response_text, duration = run_chat_hermes(message, username)
        except Exception as exc:  # noqa: BLE001
            response_text = f"ERROR: Hermes chat worker failed: {exc}"
            duration = 0
        add_chat_message("assistant", response_text, "Hermes", duration_seconds=duration)

    thread = threading.Thread(target=worker, name="portal-hermes-chat", daemon=True)
    thread.start()


def hermes_executable() -> str:
    configured = os.getenv("HERMES_CLI", "").strip()
    if configured:
        return configured
    discovered = shutil.which("hermes")
    if discovered:
        return discovered
    fallback = Path.home() / ".local/bin/hermes"
    if fallback.exists():
        return str(fallback)
    return "hermes"


def sandbox_python() -> Path:
    return Path(os.getenv("TRASHCAN_PYTHON", str(Path.home() / "RAIccoon_Local_Sandbox/.venv/bin/python")))


def sandbox_project_dir() -> Path:
    return Path(os.getenv("TRASHCAN_DIR", str(Path.home() / "RAIccoon_Local_Sandbox")))


def sandbox_run_root() -> Path:
    return Path(os.getenv("TRASHCAN_RUN_ROOT", str(DATA_DIR / "sandbox-runs")))


def run_sandbox(sample_path: str) -> tuple[bool, str, float, list[str]]:
    project_dir = sandbox_project_dir()
    python_bin = sandbox_python()
    run_root = sandbox_run_root()
    run_root.mkdir(parents=True, exist_ok=True)
    duration = os.getenv("TRASHCAN_DURATION", "180")
    password = os.getenv("TRASHCAN_SAMPLE_PASSWORD", "infected")
    command = [
        str(python_bin),
        "-m",
        "raiccoon_sandbox.local_vbox_detonate",
        sample_path,
        "--run-root",
        str(run_root),
        "--duration",
        duration,
        "--password",
        password,
    ]
    start = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=str(project_dir),
        capture_output=True,
        text=True,
        timeout=int(os.getenv("TRASHCAN_TIMEOUT", "1800")),
        check=False,
    )
    elapsed = round(time.perf_counter() - start, 2)
    output = "\n".join(part.strip() for part in (completed.stdout or "", completed.stderr or "") if part.strip()).strip()
    if completed.returncode != 0:
        return False, output or "Sandbox execution failed.", elapsed, []

    artifact_paths: list[str] = []
    report_path: Path | None = None
    for line in reversed(output.splitlines()):
        candidate = Path(line.strip())
        if candidate.name == "analysis.md" and candidate.exists():
            report_path = candidate
            break
    if report_path is None:
        reports = sorted(run_root.glob("*/analysis.md"), key=lambda p: p.stat().st_mtime, reverse=True)
        if reports:
            report_path = reports[0]
    if report_path:
        run_dir = report_path.parent
        for name in (
            "analysis.md",
            "summary.json",
            "behavior_summary.json",
            "static_triage.json",
            "rule.yar",
            "sigma_dns.yml",
            "sigma_behavior.yml",
        ):
            path = run_dir / name
            if path.exists():
                artifact_paths.append(str(path))
    return True, output or "Sandbox completed successfully.", elapsed, artifact_paths


def _truncate_detail(value: str, limit: int = 4000) -> str:
    text = (value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit]}\n... [truncated]"


def process_malware_sandbox_task(task_id: int, sample_paths: str | list[str], username: str) -> None:
    """Run RAIccoon Local Sandbox for a malware-analysis task outside the request path.

    The research form should create a durable portal task immediately. RAIccoon Local Sandbox is
    allowed to be slow or fail, but it must not leave the browser waiting forever
    or prevent the operator from seeing/retrying the task from the board.
    """
    samples = [sample_paths] if isinstance(sample_paths, str) else list(sample_paths)
    samples = [path for path in samples if path]
    if not samples:
        samples = []
    sandbox_ok = True
    sandbox_duration = 0.0
    sandbox_outputs: list[str] = []
    sandbox_artifacts: list[str] = []
    add_task_history(task_id, "sandbox_started", username, f"RAIccoon Local Sandbox sandbox started for {len(samples)} uploaded sample(s).", source="raiccoon")
    for sample_path in samples:
        sample_name = Path(sample_path).name
        add_task_history(task_id, "sandbox_sample_started", username, f"RAIccoon Local Sandbox sandbox started for {sample_name}.", source="raiccoon")
        try:
            sample_ok, sample_output, sample_duration, sample_artifacts = run_sandbox(sample_path)
        except Exception as exc:  # noqa: BLE001
            sample_ok = False
            sample_duration = 0.0
            sample_output = f"RAIccoon Local Sandbox sandbox raised an exception for {sample_name}: {exc}"
            sample_artifacts = []
        sandbox_duration += sample_duration
        sandbox_outputs.append(f"[{sample_name}] {sample_output or 'Sandbox completed with no output.'}")
        sandbox_artifacts.extend(path for path in sample_artifacts if path not in sandbox_artifacts)
        if not sample_ok:
            sandbox_ok = False
            break

    task = fetch_portal_task(task_id)
    if task is None:
        return

    if not sandbox_ok:
        detail = _truncate_detail("\n\n".join(sandbox_outputs) or "RAIccoon Local Sandbox sandbox failed.")
        execute(
            """
            UPDATE portal_tasks
            SET status = 'blocked', blocked_reason = ?, blocked_at = ?, updated_at = ?
            WHERE id = ?
            """,
            [f"RAIccoon Local Sandbox sandbox failed before Hermes dispatch:\n{detail}", now_utc().isoformat(), now_utc().isoformat(), task_id],
        )
        add_task_history(task_id, "sandbox_failed", username, detail, source="raiccoon")
        create_notification(
            "sandbox",
            f"RAIccoon Local Sandbox sandbox failed for task #{task_id}",
            "The research task was created and blocked instead of leaving the browser loading. Open the task to review the sandbox error and retry after fixing the VM.",
            task_id=task_id,
            notification_key=f"sandbox-failed:{task_id}",
        )
        return

    saved_paths = task_uploaded_files(task)
    for artifact_path in sandbox_artifacts:
        if artifact_path not in saved_paths:
            saved_paths.append(artifact_path)
    queue_notes = [
        f"RAIccoon Local Sandbox sandbox total duration across {len(samples)} sample(s): {sandbox_duration}s",
        "RAIccoon Local Sandbox sandbox artifacts for every uploaded sample were generated and attached by path for the Hermes worker.",
        "The Hermes worker must treat static analysis, GhidraMCP/Ghidra code analysis, and RAIccoon Local Sandbox dynamic analysis as required malware-report evidence lanes.",
    ]
    updated_description = "\n".join([task["description"].strip(), "", "Portal context:", *queue_notes]).strip()
    execute(
        "UPDATE portal_tasks SET description = ?, uploaded_files = ?, updated_at = ? WHERE id = ?",
        [updated_description, "|".join(saved_paths), now_utc().isoformat(), task_id],
    )
    add_task_history(task_id, "sandbox_completed", username, f"RAIccoon Local Sandbox sandbox completed for {len(samples)} sample(s) in {sandbox_duration}s and produced {len(sandbox_artifacts)} attached artifacts.", source="raiccoon")

    updated_task = fetch_portal_task(task_id)
    if updated_task is None:
        return
    try:
        snapshot = move_portal_task_to_in_progress(updated_task, username)
        linked_id = (snapshot.get("id") if snapshot else None) or updated_task["kanban_task_id"] or ""
        add_task_history(task_id, "dispatch", username, f"Sandbox passed; dispatched to Hermes Kanban task {linked_id or 'pending dispatch'}.")
    except Exception as exc:  # noqa: BLE001
        execute("UPDATE portal_tasks SET status = 'todo', updated_at = ? WHERE id = ?", [now_utc().isoformat(), task_id])
        add_task_history(task_id, "dispatch_error", username, f"Automatic Kanban dispatch after sandbox failed: {exc}")
        create_notification(
            "dispatch",
            f"Hermes dispatch failed for task #{task_id}",
            "RAIccoon Local Sandbox completed, but automatic Kanban dispatch failed. The task was left in Todo for manual retry.",
            task_id=task_id,
            notification_key=f"dispatch-failed:{task_id}",
        )


def queue_malware_sandbox_task(task_id: int, sample_paths: str | list[str], username: str) -> None:
    thread = threading.Thread(
        target=process_malware_sandbox_task,
        args=(task_id, sample_paths, username),
        name=f"portal-raiccoon-task-{task_id}",
        daemon=True,
    )
    thread.start()


def should_use_raiccoon(workflow: str, query: str) -> bool:
    workflow = normalize_workflow(workflow)
    if workflow != "general":
        return True
    lowered = (query or "").lower()
    return any(keyword in lowered for keyword in RAICCOON_KEYWORDS)


def save_uploads(files: list[UploadFile]) -> list[str]:
    saved_paths: list[str] = []
    if not files:
        return saved_paths

    stamp = now_utc().strftime("%Y%m%d_%H%M%S_%f")
    target_dir = UPLOAD_DIR / stamp
    target_dir.mkdir(parents=True, exist_ok=True)

    for upload in files:
        if not upload.filename:
            continue
        filename = safe_filename(upload.filename)
        destination = target_dir / filename
        with destination.open("wb") as handle:
            shutil.copyfileobj(upload.file, handle)
        saved_paths.append(str(destination))
    return saved_paths


def build_hermes_prompt(
    query: str,
    paths: list[str],
    username: str,
    workflow: str,
    extra_context: list[str] | None = None,
) -> str:
    workflow = normalize_workflow(workflow)
    lines = [
        "You are supporting Your Organization, an internal cybersecurity company portal.",
        f"Requesting analyst: {username}",
        f"Selected workflow: {RESEARCH_WORKFLOWS[workflow]['label']}",
        "Respond with concise, useful, analyst-grade output.",
        "If uploaded files are relevant, inspect them directly by path before answering.",
        workflow_prompt_prefix(workflow),
        "",
        f"User request: {query}",
    ]
    if paths:
        lines.append("")
        lines.append("Uploaded files:")
        lines.extend(f"- {path}" for path in paths)
    if extra_context:
        lines.append("")
        lines.append("Additional execution context:")
        lines.extend(f"- {item}" for item in extra_context if item)
    return "\n".join(lines)


def run_hermes(
    query: str,
    uploaded_paths: list[str],
    username: str,
    workflow: str,
    extra_context: list[str] | None = None,
) -> tuple[str, float, bool]:
    hermes_cli = hermes_executable()
    hermes_timeout = int(os.getenv("HERMES_TIMEOUT", "240"))
    workflow = normalize_workflow(workflow)
    use_raiccoon = should_use_raiccoon(workflow=workflow, query=query)
    prompt = build_hermes_prompt(
        query=query,
        paths=uploaded_paths,
        username=username,
        workflow=workflow,
        extra_context=extra_context,
    )
    command = [hermes_cli, "chat", "-Q"]
    if use_raiccoon:
        command.extend(["-s", "raiccoon"])
    command.extend(["-q", prompt])
    start = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=hermes_timeout,
            check=False,
        )
    except FileNotFoundError:
        duration = round(time.perf_counter() - start, 2)
        return (
            f"ERROR: Hermes CLI was not found. Set HERMES_CLI to the absolute hermes executable path. Attempted: {hermes_cli}",
            duration,
            use_raiccoon,
        )
    except subprocess.TimeoutExpired as exc:
        duration = round(time.perf_counter() - start, 2)
        parts = []
        for part in (exc.stdout, exc.stderr):
            if isinstance(part, bytes):
                part = part.decode("utf-8", errors="replace")
            if part and str(part).strip():
                parts.append(str(part).strip())
        detail = f" after {hermes_timeout}s"
        if parts:
            partial_output = "\n".join(parts)
            detail += f". Partial output:\n{partial_output}"
        return f"ERROR: Hermes query timed out{detail}", duration, use_raiccoon
    duration = round(time.perf_counter() - start, 2)

    output = (completed.stdout or "").strip()
    if completed.returncode != 0:
        error_text = (completed.stderr or output or "Hermes query failed").strip()
        return f"ERROR: {error_text}", duration, use_raiccoon

    cleaned = []
    for line in output.splitlines():
        if line.startswith("session_id:"):
            continue
        cleaned.append(line)
    return "\n".join(cleaned).strip() or "No response returned.", duration, use_raiccoon


def add_cost_entry(provider: str, model: str, category: str, amount_usd: float, period_start: str, notes: str, source: str) -> None:
    execute(
        "INSERT INTO ai_costs (provider, model, category, amount_usd, period_start, notes, source, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [provider, model, category, amount_usd, period_start, notes, source, now_utc().isoformat()],
    )


def log_cost_sync(provider: str, status: str, detail: str, imported_count: int) -> None:
    execute(
        "INSERT INTO cost_sync_runs (provider, status, detail, imported_count, created_at) VALUES (?, ?, ?, ?, ?)",
        [provider, status, detail, imported_count, now_utc().isoformat()],
    )


def import_cost_csv(upload: UploadFile) -> tuple[int, str]:
    raw = upload.file.read().decode("utf-8")
    reader = csv.DictReader(raw.splitlines())
    required = {"provider", "model", "category", "amount_usd", "period_start"}
    if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
        raise HTTPException(status_code=400, detail="CSV must contain provider, model, category, amount_usd, period_start")

    count = 0
    for row in reader:
        add_cost_entry(
            provider=(row.get("provider") or "Unknown").strip(),
            model=(row.get("model") or "Unknown").strip(),
            category=(row.get("category") or "Operations").strip(),
            amount_usd=float(row.get("amount_usd") or 0),
            period_start=(row.get("period_start") or date.today().isoformat()).strip(),
            notes=(row.get("notes") or "Imported from CSV").strip(),
            source=(row.get("source") or "csv_import").strip(),
        )
        count += 1

    log_cost_sync("CSV", "success", f"Imported {count} cost rows from {upload.filename}", count)
    return count, raw


def fetch_openai_costs(days: int = 30) -> int:
    api_key = os.getenv("OPENAI_ADMIN_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        log_cost_sync("OpenAI", "skipped", "OPENAI_ADMIN_API_KEY or OPENAI_API_KEY not set", 0)
        return 0

    start_time = int((now_utc() - timedelta(days=days)).timestamp())
    end_time = int(now_utc().timestamp())
    params = urllib.parse.urlencode({"start_time": start_time, "end_time": end_time, "bucket_width": "1d", "limit": days})
    request = urllib.request.Request(
        f"https://api.openai.com/v1/organization/costs?{params}",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
    )

    with urllib.request.urlopen(request, timeout=60) as response:
        payload = json.loads(response.read().decode("utf-8"))

    buckets = payload.get("data", [])
    imported = 0
    for bucket in buckets:
        bucket_start = datetime.fromtimestamp(bucket.get("start_time", start_time), tz=timezone.utc).date().isoformat()
        for result in bucket.get("results", []):
            amount = result.get("amount", {}) or {}
            value = amount.get("value")
            if value in (None, 0, 0.0):
                continue
            line_item = result.get("line_item") or result.get("project_id") or "organization"
            add_cost_entry(
                provider="OpenAI",
                model=str(line_item),
                category="API usage",
                amount_usd=float(value),
                period_start=bucket_start,
                notes="Imported from OpenAI organization costs endpoint",
                source="openai_api",
            )
            imported += 1

    log_cost_sync("OpenAI", "success", f"Imported {imported} entries from OpenAI costs API", imported)
    return imported


def task_is_research(task: sqlite3.Row | dict) -> bool:
    if isinstance(task, sqlite3.Row):
        return (task["task_type"] or "").strip().lower() == "research" or (task["source_page"] or "").strip().lower() == "research"
    return (task.get("task_type", "") or "").strip().lower() == "research" or (task.get("source_page", "") or "").strip().lower() == "research"


def task_uploaded_files(task: sqlite3.Row | dict) -> list[str]:
    raw = task["uploaded_files"] if isinstance(task, sqlite3.Row) else task.get("uploaded_files", "")
    return [item for item in (raw or "").split("|") if item.strip()]


def review_document_path_for_task(task: sqlite3.Row | dict) -> Path:
    family = report_family_for_task(task).replace(" ", "_")
    display_title = report_display_title_for_task(task)
    filename = safe_filename(f"{display_title}_{family}_Review.pdf")
    return IN_REVIEW_DIR / filename


def final_document_path_for_task(task: sqlite3.Row | dict) -> Path:
    category = ((task["document_category"] if isinstance(task, sqlite3.Row) else task.get("document_category", "")) or "Uncategorized").strip() or "Uncategorized"
    filename = final_report_filename_for_task(task)
    return DOCUMENTS_DIR / category / filename


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    for index in range(2, 1000):
        candidate = path.with_name(f"{path.stem}_{index}{path.suffix}")
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"Unable to allocate unique path for {path}")


def report_archive_repo_relative_path(task: sqlite3.Row | dict, final_document_path: Path) -> Path:
    category = ((task["document_category"] if isinstance(task, sqlite3.Row) else task.get("document_category", "")) or "Uncategorized").strip() or "Uncategorized"
    return Path(category) / final_document_path.name


def git_run(repo_dir: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    completed = subprocess.run(
        ["git", *args],
        cwd=str(repo_dir),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if check and completed.returncode != 0:
        error_text = (completed.stderr or completed.stdout or f"git {' '.join(args)} failed").strip()
        raise RuntimeError(error_text)
    return completed


def sync_report_to_archive_repo(task: sqlite3.Row | dict, final_document_path: Path) -> Path:
    repo_dir = REPORTS_REPO_DIR
    if not repo_dir.exists():
        raise RuntimeError(f"Reports repo not found at {repo_dir}")
    if not (repo_dir / ".git").exists():
        raise RuntimeError(f"Reports path is not a git repo: {repo_dir}")
    if not final_document_path.exists():
        raise RuntimeError(f"Final PDF not found for archive sync: {final_document_path}")

    relative_path = report_archive_repo_relative_path(task, final_document_path)
    destination = repo_dir / relative_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(final_document_path, destination)

    branch = (git_run(repo_dir, "branch", "--show-current").stdout or "").strip()
    if not branch:
        raise RuntimeError(f"Could not determine current branch for {repo_dir}")

    rel_text = str(relative_path)
    git_run(repo_dir, "add", rel_text)
    staged = git_run(repo_dir, "diff", "--cached", "--quiet", "--", rel_text, check=False)
    if staged.returncode == 0:
        return destination
    if staged.returncode != 1:
        error_text = (staged.stderr or staged.stdout or f"git diff --cached failed for {rel_text}").strip()
        raise RuntimeError(error_text)

    title = (task["title"] if isinstance(task, sqlite3.Row) else task.get("title", "Untitled Report")) or "Untitled Report"
    git_run(repo_dir, "commit", "-m", f"Add accepted report: {title}", "--", rel_text)
    git_run(repo_dir, "push", "origin", branch)
    return destination


def analyst_kit_root() -> Path:
    configured = os.getenv("RAICCOON_ANALYST_KIT_ROOT")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / "github" / "your-organization-analyst-kit"


def analyst_kit_render_script() -> Path:
    return analyst_kit_root() / "scripts" / "render_report.py"


def opencti_audit_dir() -> Path:
    return Path(os.getenv("OPENCTI_AUDIT_DIR", "/opt/raiccoon/services/opencti-deploy/audit"))


def opencti_upload_state_path() -> Path:
    configured = os.getenv("OPENCTI_UPLOAD_STATE_PATH")
    if configured:
        return Path(configured).expanduser()
    return analyst_kit_root() / ".cache" / "opencti-cron" / "uploaded-published-state.json"


def opencti_credentials_file() -> Path:
    return Path(os.getenv("OPENCTI_CREDENTIALS_FILE", "/opt/raiccoon/services/opencti-deploy/credentials.txt")).expanduser()


def opencti_landscape_cache_path() -> Path:
    configured = os.getenv("OPENCTI_LANDSCAPE_CACHE_PATH", "").strip()
    if configured:
        return Path(configured).expanduser()
    return DATA_DIR / "intel-ops" / "latest-opencti-landscape.json"


def _parse_opencti_credentials_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    parsed: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in raw_line:
            continue
        key, value = raw_line.split(":", 1)
        parsed[key.strip().lower()] = value.strip()
    return parsed


def opencti_api_config() -> tuple[str, str]:
    graphql_url = os.getenv("OPENCTI_URL", "").strip()
    token = os.getenv("OPENCTI_TOKEN", "").strip()
    if not (graphql_url and token):
        credentials = _parse_opencti_credentials_file(opencti_credentials_file())
        graphql_url = graphql_url or credentials.get("opencti url", "")
        token = token or credentials.get("admin token", "")
    graphql_url = graphql_url.strip()
    token = token.strip()
    if graphql_url and not graphql_url.endswith("/graphql"):
        graphql_url = graphql_url.rstrip("/") + "/graphql"
    if not graphql_url or not token:
        raise ValueError("OpenCTI API credentials are not configured for the portal.")
    return graphql_url, token


def opencti_graphql(query: str, variables: dict | None = None, timeout: int = 120) -> dict:
    graphql_url, token = opencti_api_config()
    request = urllib.request.Request(
        graphql_url,
        data=json.dumps({"query": query, "variables": variables or {}}).encode("utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if payload.get("errors"):
        message = "; ".join(str(item.get("message") or item) for item in payload["errors"])
        raise RuntimeError(f"OpenCTI GraphQL query failed: {message}")
    return payload.get("data") or {}


def _parse_opencti_datetime(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def fetch_opencti_recent_reports(
    *,
    max_reports: int | None = None,
    window_days: int | None = None,
    page_size: int | None = None,
    objects_per_report: int | None = None,
) -> list[dict]:
    max_reports = max_reports or int(os.getenv("OPENCTI_LANDSCAPE_MAX_REPORTS", "300"))
    window_days = window_days or int(os.getenv("OPENCTI_LANDSCAPE_WINDOW_DAYS", "90"))
    page_size = page_size or int(os.getenv("OPENCTI_LANDSCAPE_PAGE_SIZE", "25"))
    objects_per_report = objects_per_report or int(os.getenv("OPENCTI_LANDSCAPE_OBJECTS_PER_REPORT", "120"))
    cutoff = now_utc() - timedelta(days=max(1, window_days))
    after: str | None = None
    reports: list[dict] = []
    query = """
    query DashboardRecentReports($first: Int, $after: ID, $objectsFirst: Int) {
      reports(first: $first, after: $after, orderBy: published, orderMode: desc) {
        pageInfo {
          endCursor
          hasNextPage
        }
        edges {
          node {
            id
            name
            published
            report_types
            objects(first: $objectsFirst) {
              edges {
                node {
                  ... on StixObject {
                    id
                    entity_type
                  }
                  ... on StixCoreObject {
                    representative {
                      main
                    }
                  }
                  ... on Country {
                    latitude
                    longitude
                  }
                }
              }
            }
          }
        }
      }
    }
    """
    while len(reports) < max_reports:
        payload = opencti_graphql(query, {"first": min(page_size, max_reports - len(reports)), "after": after, "objectsFirst": objects_per_report})
        connection = payload.get("reports") or {}
        stop = False
        for edge in connection.get("edges") or []:
            node = (edge or {}).get("node") or {}
            published_at = _parse_opencti_datetime(node.get("published", ""))
            if published_at and published_at < cutoff:
                stop = True
                break
            reports.append(node)
            if len(reports) >= max_reports:
                stop = True
                break
        if stop or not ((connection.get("pageInfo") or {}).get("hasNextPage")):
            break
        after = (connection.get("pageInfo") or {}).get("endCursor")
        if not after:
            break
    return reports


def _opencti_landscape_empty(*, generated_at: str | None = None, source: str = "unavailable") -> dict:
    return {
        "generated_at": generated_at or now_utc().isoformat(),
        "source": source,
        "window_days": int(os.getenv("OPENCTI_LANDSCAPE_WINDOW_DAYS", "90")),
        "report_count": 0,
        "latest_report_published": "",
        "threats": [],
        "victims": [],
        "malware": [],
        "vulnerabilities": [],
        "countries": [],
        "country_map_points": [],
        "sample_reports": [],
    }


def _world_map_coordinates(latitude: float, longitude: float) -> tuple[float, float]:
    x = ((longitude + 180.0) / 360.0) * 1000.0
    y = ((90.0 - latitude) / 180.0) * 520.0
    return round(x, 2), round(y, 2)


def build_opencti_landscape_summary(reports: list[dict], *, generated_at: str | None = None) -> dict:
    generated_at = generated_at or now_utc().isoformat()
    groups = {
        "threats": {"Threat-Actor", "Intrusion-Set", "Campaign"},
        "victims": {"Organization", "Sector", "Individual", "System"},
        "malware": {"Malware", "Tool"},
        "vulnerabilities": {"Vulnerability"},
        "countries": {"Country"},
    }
    counters: dict[str, Counter] = {name: Counter() for name in groups}
    metadata: dict[str, dict[str, dict]] = {name: {} for name in groups}
    latest_report_published = ""
    latest_dt: datetime | None = None
    sample_reports: list[dict] = []

    for report in reports:
        if not isinstance(report, dict):
            continue
        published = str(report.get("published") or "").strip()
        published_dt = _parse_opencti_datetime(published)
        if published_dt and (latest_dt is None or published_dt > latest_dt):
            latest_dt = published_dt
            latest_report_published = published
        if len(sample_reports) < 6:
            sample_reports.append({
                "name": str(report.get("name") or "Untitled report").strip() or "Untitled report",
                "published": published,
                "report_types": [str(item) for item in (report.get("report_types") or []) if str(item).strip()],
            })
        seen_per_group: dict[str, set[str]] = {name: set() for name in groups}
        for edge in (report.get("objects") or {}).get("edges") or []:
            node = (edge or {}).get("node") or {}
            entity_type = str(node.get("entity_type") or "").strip()
            representative = ((node.get("representative") or {}).get("main") or "").strip()
            if not entity_type or not representative:
                continue
            for group_name, entity_types in groups.items():
                if entity_type not in entity_types or representative in seen_per_group[group_name]:
                    continue
                seen_per_group[group_name].add(representative)
                counters[group_name][representative] += 1
                bucket = metadata[group_name].setdefault(representative, {
                    "name": representative,
                    "entity_types": set(),
                    "sample_reports": [],
                })
                bucket["entity_types"].add(entity_type)
                if len(bucket["sample_reports"]) < 3 and report.get("name"):
                    bucket["sample_reports"].append(str(report.get("name")))
                if group_name == "countries":
                    if isinstance(node.get("latitude"), (int, float)) and isinstance(node.get("longitude"), (int, float)):
                        bucket["latitude"] = float(node["latitude"])
                        bucket["longitude"] = float(node["longitude"])

    summary = _opencti_landscape_empty(generated_at=generated_at, source="live")
    summary["report_count"] = len([report for report in reports if isinstance(report, dict)])
    summary["latest_report_published"] = latest_report_published
    summary["sample_reports"] = sample_reports

    for group_name, counter in counters.items():
        items: list[dict] = []
        for name, count in sorted(counter.items(), key=lambda item: (-item[1], item[0].lower()))[:8]:
            bucket = metadata[group_name].get(name, {})
            item = {
                "name": name,
                "count": count,
                "entity_types": sorted(bucket.get("entity_types") or []),
                "sample_reports": list(bucket.get("sample_reports") or []),
            }
            if group_name == "countries" and isinstance(bucket.get("latitude"), (int, float)) and isinstance(bucket.get("longitude"), (int, float)):
                latitude = float(bucket["latitude"])
                longitude = float(bucket["longitude"])
                x, y = _world_map_coordinates(latitude, longitude)
                item.update({"latitude": latitude, "longitude": longitude, "map_x": x, "map_y": y})
            items.append(item)
        summary[group_name] = items
    summary["country_map_points"] = [
        {
            "name": item["name"],
            "count": item["count"],
            "latitude": item["latitude"],
            "longitude": item["longitude"],
            "x": item["map_x"],
            "y": item["map_y"],
            "radius": max(6, min(22, 5 + (item["count"] * 2))),
        }
        for item in summary["countries"]
        if "map_x" in item and "map_y" in item
    ]
    return summary


def opencti_threat_landscape_summary(*, force_refresh: bool = False) -> dict:
    cache_path = opencti_landscape_cache_path()
    ttl_seconds = int(os.getenv("OPENCTI_LANDSCAPE_CACHE_TTL_SECONDS", "1800"))
    cached = _read_json_file(cache_path)
    cache_age = None
    if cache_path.exists():
        cache_age = max(0.0, time.time() - cache_path.stat().st_mtime)
    if cached and not force_refresh and cache_age is not None and cache_age <= ttl_seconds:
        cached.setdefault("source", "cache")
        cached["cache_age_seconds"] = round(cache_age, 1)
        cached["cache_path"] = str(cache_path)
        return cached
    try:
        reports = fetch_opencti_recent_reports()
        summary = build_opencti_landscape_summary(reports)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        summary["cache_age_seconds"] = 0.0
        summary["cache_path"] = str(cache_path)
        return summary
    except Exception as exc:  # noqa: BLE001
        if cached:
            cached.setdefault("source", "cache")
            cached["warning"] = f"Live OpenCTI refresh failed: {exc}"
            cached["cache_age_seconds"] = round(cache_age or 0.0, 1)
            cached["cache_path"] = str(cache_path)
            return cached
        empty = _opencti_landscape_empty(source="unavailable")
        empty["error"] = str(exc)
        empty["cache_path"] = str(cache_path)
        return empty


def _read_json_file(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _count_status_actions(results: list[dict], status: str) -> int:
    return sum(1 for item in results if item.get("status") == status)


def opencti_curation_candidates_path(audit_dir: Path | None = None) -> Path:
    return (audit_dir or opencti_audit_dir()) / "latest-opencti-cleanup-candidates.json"


def opencti_curation_candidates(audit_dir: Path | None = None) -> dict:
    payload = _read_json_file(opencti_curation_candidates_path(audit_dir))
    candidates = payload.get("candidates") or []
    return {
        "schema_version": payload.get("schema_version", 0),
        "generated_at": payload.get("generated_at", ""),
        "summary": payload.get("summary") or {},
        "candidates": candidates if isinstance(candidates, list) else [],
        "source_file": str(opencti_curation_candidates_path(audit_dir)),
    }


def _candidate_stable_id(candidate: dict) -> str:
    existing = str(candidate.get("candidate_id") or "").strip()
    if existing:
        return existing
    basis = json.dumps({
        "type": candidate.get("candidate_type") or candidate.get("category") or "opencti-curation",
        "title": candidate.get("title") or "",
        "objects": candidate.get("opencti_object_ids") or candidate.get("objects") or [],
    }, sort_keys=True, default=str)
    return f"opencti-curation-{hashlib.sha256(basis.encode()).hexdigest()[:16]}"


def _candidate_task_description(candidate: dict, candidate_id: str, source_file: str) -> str:
    objects = candidate.get("opencti_object_ids") or []
    if not objects:
        objects = [obj.get("id") for obj in candidate.get("objects") or [] if isinstance(obj, dict) and obj.get("id")]
    object_text = ", ".join(str(obj) for obj in objects[:10]) or "No object IDs supplied"
    return "\n".join([
        "Private OpenCTI curation review candidate.",
        f"- Candidate ID: `{candidate_id}`",
        f"- Category: `{candidate.get('category') or candidate.get('candidate_type') or 'opencti-curation'}`",
        f"- Severity: `{candidate.get('severity') or 'medium'}`",
        f"- Proposed action: `{candidate.get('proposed_action') or candidate.get('recommended_action') or 'review'}`",
        f"- Safe mode: `{candidate.get('safe_mode', True)}`",
        f"- Source artifact: `{candidate.get('source_artifact') or source_file}`",
        f"- OpenCTI object IDs: {object_text}",
        "",
        "Rationale:",
        str(candidate.get("rationale") or "Review this candidate before making any OpenCTI changes."),
        "",
        "Operator guidance:",
        str(candidate.get("recommended_action") or "Review, document decision, and only run destructive cleanup from an explicit operator-approved apply workflow."),
        "",
        "Tags: opencti-curation, private-source-of-truth",
    ])


def import_opencti_curation_candidates(audit_dir: Path | None = None, requested_by: str = "opencti-hygiene") -> dict:
    payload = opencti_curation_candidates(audit_dir)
    imported: list[int] = []
    skipped: list[str] = []
    source_file = payload["source_file"]
    for candidate in payload["candidates"]:
        if not isinstance(candidate, dict):
            continue
        candidate_id = _candidate_stable_id(candidate)
        existing = fetch_one(
            "SELECT id FROM portal_tasks WHERE description LIKE ? ORDER BY id ASC LIMIT 1",
            [f"%- Candidate ID: `{candidate_id}`%"],
        )
        if existing:
            skipped.append(candidate_id)
            continue
        title = f"OpenCTI curation: {str(candidate.get('title') or candidate_id).strip()[:140]}"
        description = _candidate_task_description(candidate, candidate_id, source_file)
        task_id = create_portal_task(
            title=title,
            description=description,
            priority={"critical": 9, "high": 8, "medium": 5, "low": 3}.get(str(candidate.get("severity") or "medium").lower(), 5),
            requested_by=requested_by,
            assignee="analyst",
            worker_profile="default",
            task_type="research",
            source_page="opencti-curation",
            research_workflow="threat-intel",
            document_category="Threat Reports",
        )
        add_task_history(task_id, "opencti_curation_import", requested_by, f"Imported OpenCTI curation candidate {candidate_id} from {source_file}.", source="opencti", source_ref=candidate_id)
        create_notification("opencti-curation", title, f"Imported candidate {candidate_id} for manual review before any cleanup apply.", task_id=task_id, notification_key=f"opencti-curation:{candidate_id}")
        imported.append(task_id)
    return {
        "source_file": source_file,
        "candidate_count": len(payload["candidates"]),
        "imported_count": len(imported),
        "skipped_existing_count": len(skipped),
        "imported_task_ids": imported,
        "skipped_candidate_ids": skipped,
    }


def _uploaded_opencti_report_ids(upload_state: dict) -> set[str]:
    uploaded = upload_state.get("uploaded") or {}
    report_ids: set[str] = set()
    if isinstance(uploaded, dict):
        for key, value in uploaded.items():
            if isinstance(value, dict):
                report_id = str(value.get("report_id") or value.get("id") or "").strip()
                if report_id:
                    report_ids.add(report_id)
            key_text = str(key).strip()
            if key_text.startswith("RPT-"):
                report_ids.add(key_text)
    return report_ids


def _report_ready_for_opencti_upload(report: dict) -> bool:
    status = str(report.get("status") or "").strip().lower()
    has_pdf = bool(report.get("final_pdf_path") or report.get("has_final_pdf"))
    return has_pdf and status in {"published", "complete", "accepted", "ready"}


def opencti_upload_gap_reports(root: Path | None = None, upload_state_path: Path | None = None) -> dict:
    registry = analyst_report_registry(root)
    upload_state_path = upload_state_path or opencti_upload_state_path()
    upload_state = _read_json_file(upload_state_path)
    uploaded_ids = _uploaded_opencti_report_ids(upload_state)
    gaps: list[dict] = []
    skipped_uploaded = 0
    skipped_not_ready = 0
    for report in registry.get("reports") or []:
        if not isinstance(report, dict):
            continue
        report_id = str(report.get("report_id") or "").strip()
        if not report_id:
            continue
        if report.get("opencti_id") or report_id in uploaded_ids:
            skipped_uploaded += 1
            continue
        if not _report_ready_for_opencti_upload(report):
            skipped_not_ready += 1
            continue
        gaps.append(report)
    return {
        "source_file": registry.get("source_file", ""),
        "upload_state_path": str(upload_state_path),
        "missing_opencti_uploads": len(gaps),
        "skipped_uploaded_count": skipped_uploaded,
        "skipped_not_ready_count": skipped_not_ready,
        "reports": gaps,
    }


def _opencti_upload_task_description(report: dict, source_file: str, upload_state_path: str) -> str:
    report_id = str(report.get("report_id") or "unknown").strip()
    report_path = str(report.get("path") or report.get("report_path") or "").strip()
    source_path = str(report.get("source_path") or "").strip()
    if not report_path and source_path:
        report_path = str(Path(source_path).parent)
    final_pdf = str(report.get("final_pdf_path") or "").strip()
    make_hint = f"make opencti-upload REPORT={report_path}" if report_path else "make opencti-upload REPORT=<analyst-kit-report-path>"
    return "\n".join([
        "Private OpenCTI upload/re-upload work item.",
        f"- Report ID: `{report_id}`",
        f"- Title: `{report.get('title') or report_id}`",
        f"- Status: `{report.get('status') or 'unknown'}`",
        f"- Analyst-kit report path: `{report_path or 'not supplied'}`",
        f"- Final PDF path: `{final_pdf or 'not supplied'}`",
        f"- Registry source: `{source_file}`",
        f"- Upload state source: `{upload_state_path}`",
        "",
        "Operator guidance:",
        "1. Confirm the final PDF and metadata are approved for private OpenCTI publication.",
        f"2. From analyst-kit, run `{make_hint}`.",
        "3. Verify the uploader returns an OpenCTI report ID and updates metadata/state.",
        "4. Refresh `make registry` so the portal sees the new OpenCTI linkage.",
        "",
        "Tags: opencti-upload, private-source-of-truth",
    ])


def queue_opencti_upload_tasks(root: Path | None = None, upload_state_path: Path | None = None, requested_by: str = "opencti-upload") -> dict:
    gaps = opencti_upload_gap_reports(root, upload_state_path)
    queued: list[int] = []
    skipped_existing: list[str] = []
    for report in gaps["reports"]:
        report_id = str(report.get("report_id") or "").strip()
        if not report_id:
            continue
        existing = fetch_one(
            "SELECT id FROM portal_tasks WHERE description LIKE ? ORDER BY id ASC LIMIT 1",
            [f"%- Report ID: `{report_id}`%"],
        )
        if existing:
            skipped_existing.append(report_id)
            continue
        title = f"OpenCTI upload: {report_id} {str(report.get('title') or '').strip()}".strip()[:180]
        description = _opencti_upload_task_description(report, gaps.get("source_file", ""), gaps.get("upload_state_path", ""))
        task_id = create_portal_task(
            title=title,
            description=description,
            priority=7,
            requested_by=requested_by,
            assignee="analyst",
            worker_profile="default",
            task_type="research",
            source_page="opencti-upload",
            research_workflow="threat-intel",
            document_category="Threat Reports",
        )
        add_task_history(task_id, "opencti_upload_queue", requested_by, f"Queued OpenCTI upload review for {report_id}.", source="opencti", source_ref=report_id)
        create_notification("opencti-upload", title, f"Queued {report_id} for private OpenCTI upload/re-upload review.", task_id=task_id, notification_key=f"opencti-upload:{report_id}")
        queued.append(task_id)
    return {
        "source_file": gaps.get("source_file", ""),
        "upload_state_path": gaps.get("upload_state_path", ""),
        "candidate_count": len(gaps["reports"]),
        "queued_count": len(queued),
        "skipped_existing_count": len(skipped_existing),
        "skipped_uploaded_count": gaps.get("skipped_uploaded_count", 0),
        "skipped_not_ready_count": gaps.get("skipped_not_ready_count", 0),
        "queued_task_ids": queued,
        "skipped_existing_report_ids": skipped_existing,
    }


def opencti_dashboard_summary(audit_dir: Path | None = None, upload_state_path: Path | None = None) -> dict:
    audit_dir = audit_dir or opencti_audit_dir()
    upload_state_path = upload_state_path or opencti_upload_state_path()
    hygiene = _read_json_file(audit_dir / "latest-opencti-hygiene-audit.json")
    cleanup = _read_json_file(audit_dir / "latest-opencti-cleanup-apply.json")
    candidate_payload = opencti_curation_candidates(audit_dir)
    upload_state = _read_json_file(upload_state_path)
    connectors = hygiene.get("connectors") or []
    counts = hygiene.get("counts") or hygiene.get("entity_counts") or {}
    hygiene_block = hygiene.get("hygiene") or hygiene.get("summary") or {}
    cleanup_results = cleanup.get("results") or []
    cleanup_queue = [item for item in cleanup_results if item.get("status") == "skipped"]
    candidate_queue = candidate_payload.get("candidates") or []
    curation_queue = (candidate_queue + cleanup_queue)[:50]
    uploaded = upload_state.get("uploaded") or {}
    upload_gaps = opencti_upload_gap_reports(upload_state_path=upload_state_path)
    landscape = opencti_threat_landscape_summary()
    return {
        "generated_at": now_utc().isoformat(),
        "audit_generated_at": hygiene.get("generated_at", ""),
        "cleanup_generated_at": cleanup.get("generated_at", ""),
        "upload_last_run_at": upload_state.get("last_run_at", ""),
        "reports": int(counts.get("reports") or counts.get("Report") or 0),
        "labels": int(counts.get("labels") or counts.get("Label") or 0),
        "connectors": len(connectors),
        "active_connectors": sum(1 for connector in connectors if connector.get("active")),
        "inactive_connectors": [connector.get("name", "unknown") for connector in connectors if not connector.get("active")],
        "duplicate_report_candidates": int(hygiene_block.get("duplicate_report_candidates") or 0),
        "label_normalization_candidates": int(hygiene_block.get("label_normalization_candidates") or 0),
        "curation_candidate_count": len(candidate_queue),
        "cleanup_deleted": _count_status_actions(cleanup_results, "deleted"),
        "cleanup_skipped": _count_status_actions(cleanup_results, "skipped"),
        "uploaded_reports": len(uploaded),
        "missing_opencti_uploads": upload_gaps["missing_opencti_uploads"],
        "opencti_upload_queue": upload_gaps["reports"][:25],
        "curation_queue": curation_queue,
        "landscape": landscape,
        "source_files": {
            "hygiene": str(audit_dir / "latest-opencti-hygiene-audit.json"),
            "cleanup": str(audit_dir / "latest-opencti-cleanup-apply.json"),
            "curation_candidates": candidate_payload.get("source_file", ""),
            "upload_state": str(upload_state_path),
        },
    }


def _parse_simple_yaml(path: Path) -> dict:
    data: dict[str, str] = {}
    if not path.exists():
        return data
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#") or raw_line.startswith((" ", "-")):
            continue
        if ":" not in raw_line:
            continue
        key, value = raw_line.split(":", 1)
        data[key.strip()] = value.strip().strip('"\'')
    return data


def analyst_report_registry_artifact_path(root: Path | None = None) -> Path:
    return (root or analyst_kit_root()) / "build" / "registry" / "report-registry.json"


def _registry_from_artifact(root: Path, artifact_path: Path) -> dict | None:
    payload = _read_json_file(artifact_path)
    if not payload.get("reports") and not payload.get("summary"):
        return None
    summary = payload.get("summary") or {}
    reports = payload.get("reports") or []
    return {
        "generated_at": payload.get("generated_at") or now_utc().isoformat(),
        "root": payload.get("root") or str(root),
        "source_file": str(artifact_path),
        "schema_version": payload.get("schema_version", 1),
        "total_reports": int(summary.get("total_reports") or len(reports)),
        "published_reports": int(summary.get("published_reports") or sum(1 for report in reports if report.get("status") == "published" or report.get("final_pdf_path") or report.get("has_final_pdf"))),
        "missing_final_pdf": int(summary.get("missing_final_pdf") or sum(1 for report in reports if not (report.get("final_pdf_path") or report.get("has_final_pdf")))),
        "ioc_count": int(summary.get("ioc_count") or sum(int(report.get("ioc_count") or 0) for report in reports)),
        "detection_count": int(summary.get("detection_count") or sum(int(report.get("detection_count") or 0) for report in reports)),
        "detections_by_type": summary.get("detections_by_type") or {},
        "detections_by_status": summary.get("detections_by_status") or {},
        "duplicate_report_ids": summary.get("duplicate_report_ids") or [],
        "reports": reports,
        "detections": payload.get("detections") or [],
    }


def analyst_report_registry(root: Path | None = None) -> dict:
    root = root or analyst_kit_root()
    artifact_registry = _registry_from_artifact(root, analyst_report_registry_artifact_path(root))
    if artifact_registry:
        return artifact_registry
    reports_root = root / "reports"
    reports: list[dict] = []
    ioc_count = 0
    detection_count = 0
    if reports_root.exists():
        for report_md in sorted(reports_root.glob("*/*/report.md")):
            report_dir = report_md.parent
            metadata = _parse_simple_yaml(report_dir / "metadata.yaml")
            final_files = sorted((report_dir / "final").glob("*.pdf")) if (report_dir / "final").exists() else []
            detections = [p for p in (report_dir / "detections").rglob("*") if p.is_file()] if (report_dir / "detections").exists() else []
            iocs = 0
            iocs_path = report_dir / "iocs.csv"
            if iocs_path.exists():
                with iocs_path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
                    iocs = sum(1 for row in csv.DictReader(handle) if any((value or "").strip() for value in row.values()))
            ioc_count += iocs
            detection_count += len(detections)
            relative = report_dir.relative_to(root).as_posix()
            reports.append({
                "path": relative,
                "report_id": metadata.get("report_id") or report_dir.name.split("_", 1)[0],
                "title": metadata.get("title") or report_dir.name.replace("_", " "),
                "status": metadata.get("status") or ("published" if final_files else "draft"),
                "category": report_dir.parent.name,
                "has_final_pdf": bool(final_files),
                "ioc_count": iocs,
                "detection_count": len(detections),
            })
    published_reports = [report for report in reports if report.get("status") == "published" or report.get("has_final_pdf")]
    return {
        "generated_at": now_utc().isoformat(),
        "root": str(root),
        "total_reports": len(reports),
        "published_reports": len(published_reports),
        "ioc_count": ioc_count,
        "detection_count": detection_count,
        "detections_by_type": {},
        "detections_by_status": {},
        "duplicate_report_ids": [],
        "reports": reports,
        "detections": [],
    }


def _detection_matches_query(detection: dict, terms: list[str]) -> bool:
    if not terms:
        return True
    searchable = " ".join(
        str(value) for value in [
            detection.get("report_id", ""),
            detection.get("report_title", ""),
            detection.get("detection_type", ""),
            detection.get("file_path", ""),
            detection.get("telemetry_source", ""),
            detection.get("target_platform", ""),
            detection.get("status", ""),
            " ".join(str(item) for item in detection.get("attack_techniques") or []),
            " ".join(str(item) for item in detection.get("telemetry_sources") or []),
            " ".join(str(item) for item in detection.get("target_platforms") or []),
        ]
    ).lower()
    return all(term in searchable for term in terms)


def analyst_detection_library(root: Path | None = None, query: str = "", limit: int = 50) -> dict:
    root = root or analyst_kit_root()
    registry = analyst_report_registry(root)
    detections = registry.get("detections") or []
    terms = [term.lower() for term in query.split() if term.strip()]
    filtered = [detection for detection in detections if isinstance(detection, dict) and _detection_matches_query(detection, terms)]
    return {
        "generated_at": registry.get("generated_at") or now_utc().isoformat(),
        "root": registry.get("root") or str(root),
        "source_file": registry.get("source_file") or str(analyst_report_registry_artifact_path(root)),
        "query": query,
        "total_detections": len(detections),
        "filtered_count": len(filtered),
        "detections_by_type": registry.get("detections_by_type") or {},
        "detections_by_status": registry.get("detections_by_status") or {},
        "detections": filtered[:limit],
    }


def build_daily_intel_brief(opencti: dict, registry: dict, generated_at: str | None = None) -> dict:
    generated_at = generated_at or now_utc().isoformat()
    reports = registry.get("reports") or []
    reports_needing_review = [
        report for report in reports
        if report.get("status") not in {"published", "accepted"} or not report.get("has_final_pdf")
    ][:10]
    high_value_reports = sorted(
        [report for report in reports if report.get("has_final_pdf")],
        key=lambda item: (int(item.get("detection_count") or 0), int(item.get("ioc_count") or 0)),
        reverse=True,
    )[:5]
    hygiene_drift: list[str] = []
    inactive = opencti.get("inactive_connectors") or []
    if inactive:
        hygiene_drift.append(f"Inactive connectors: {', '.join(str(item) for item in inactive[:5])}.")
    if opencti.get("duplicate_report_candidates"):
        hygiene_drift.append(f"{opencti['duplicate_report_candidates']} duplicate OpenCTI report candidates need review.")
    if opencti.get("cleanup_skipped"):
        hygiene_drift.append(f"{opencti['cleanup_skipped']} conservative cleanup items are queued for curation.")
    if not hygiene_drift:
        hygiene_drift.append("No OpenCTI hygiene drift requiring immediate operator action was detected.")

    actions: list[str] = []
    if reports_needing_review:
        actions.append(f"Review and finalize {len(reports_needing_review)} report(s) missing publication-ready state or final PDFs.")
    if opencti.get("cleanup_skipped") or opencti.get("curation_queue"):
        actions.append("Work the OpenCTI curation queue before applying any destructive cleanup changes.")
    if inactive:
        actions.append("Check inactive OpenCTI connectors and restart or disable intentionally idle feeds.")
    if high_value_reports:
        actions.append("Promote high-value finished reports into client-relevant briefs, OpenCTI collections, and detection handoff packages.")
    while len(actions) < 3:
        actions.append("Continue private source-of-truth maintenance: keep reports, IOCs, detections, and OpenCTI objects aligned.")

    return {
        "generated_at": generated_at,
        "visibility": "private_internal",
        "top_new_intake_candidates": high_value_reports,
        "reports_needing_review": reports_needing_review,
        "opencti_hygiene_drift": hygiene_drift,
        "attribution_maintenance_findings": ["Review relationship gaps and confidence drift in OpenCTI before treating imported feed data as analytic truth."],
        "client_sector_relevance_flags": [report for report in high_value_reports if report.get("detection_count") or report.get("ioc_count")],
        "recommended_actions": actions[:5],
    }


def daily_intel_brief_path() -> Path:
    return DATA_DIR / "intel-ops" / "latest-daily-brief.json"


def write_latest_daily_intel_brief(brief: dict) -> Path:
    path = daily_intel_brief_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(brief, indent=2), encoding="utf-8")
    return path


def latest_daily_intel_brief() -> dict:
    brief = _read_json_file(daily_intel_brief_path())
    if brief:
        return brief
    summary = {"opencti": opencti_dashboard_summary(), "analyst_registry": analyst_report_registry()}
    return build_daily_intel_brief(summary["opencti"], summary["analyst_registry"])


def generate_daily_intel_brief_artifact() -> dict:
    summary = {"opencti": opencti_dashboard_summary(), "analyst_registry": analyst_report_registry()}
    brief = build_daily_intel_brief(summary["opencti"], summary["analyst_registry"])
    path = write_latest_daily_intel_brief(brief)
    return {"brief": brief, "path": str(path)}


def create_client_profile(
    org_alias: str,
    sector: str = "",
    priority_requirements: str = "",
    technologies: str = "",
    delivery_cadence: str = "",
    allowed_tlp: str = "TLP:AMBER",
    active_reports: int = 0,
    detections_delivered: int = 0,
    opencti_collections: str = "",
    notes: str = "",
) -> int:
    alias = org_alias.strip()
    if not alias:
        raise ValueError("Client/org alias is required.")
    now = now_utc().isoformat()
    with closing(connect_db()) as connection:
        cursor = connection.execute(
            """
            INSERT INTO client_profiles
            (org_alias, sector, priority_requirements, technologies, delivery_cadence, allowed_tlp,
             active_reports, detections_delivered, opencti_collections, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                alias,
                sector.strip(),
                priority_requirements.strip(),
                technologies.strip(),
                delivery_cadence.strip(),
                allowed_tlp.strip() or "TLP:AMBER",
                int(active_reports or 0),
                int(detections_delivered or 0),
                opencti_collections.strip(),
                notes.strip(),
                now,
                now,
            ],
        )
        connection.commit()
        return int(cursor.lastrowid or 0)


def client_profile_by_id(client_profile_id: int) -> dict | None:
    if not client_profile_id:
        return None
    row = fetch_one("SELECT * FROM client_profiles WHERE id = ?", [int(client_profile_id)])
    return dict(row) if row else None


def refresh_client_profile_counts(client_profile_id: int) -> None:
    if not client_profile_id:
        return
    row = fetch_one(
        """
        SELECT COUNT(*) AS active_reports
        FROM portal_tasks
        WHERE client_profile_id = ?
          AND task_type = 'research'
          AND status NOT IN ('rejected')
        """,
        [int(client_profile_id)],
    )
    execute(
        "UPDATE client_profiles SET active_reports = ?, updated_at = ? WHERE id = ?",
        [int(row["active_reports"] if row else 0), now_utc().isoformat(), int(client_profile_id)],
    )


def update_task_client_association(task_id: int, client_profile_id: int, actor: str = "system") -> None:
    task = fetch_portal_task(task_id)
    if not task:
        raise ValueError("Task not found.")
    previous_client_id = int(task["client_profile_id"] or 0) if "client_profile_id" in task.keys() else 0
    normalized_client_id = int(client_profile_id or 0)
    profile = client_profile_by_id(normalized_client_id) if normalized_client_id else None
    if normalized_client_id and not profile:
        raise ValueError("Client profile not found.")
    execute(
        "UPDATE portal_tasks SET client_profile_id = ?, updated_at = ? WHERE id = ?",
        [normalized_client_id, now_utc().isoformat(), int(task_id)],
    )
    if previous_client_id and previous_client_id != normalized_client_id:
        refresh_client_profile_counts(previous_client_id)
    if normalized_client_id:
        refresh_client_profile_counts(normalized_client_id)
    label = profile["org_alias"] if profile else "unassigned"
    add_task_history(
        int(task_id),
        "client_association_updated",
        actor,
        f"Task associated with private client profile: {label}.",
    )


def client_profiles() -> list[dict]:
    return [dict(row) for row in fetch_all("SELECT * FROM client_profiles ORDER BY updated_at DESC, id DESC")]


def add_audit_log(actor: str, action: str, target_type: str = "", target_id: str | int = "", detail: str = "") -> None:
    execute(
        "INSERT INTO portal_audit_log (actor, action, target_type, target_id, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        [str(actor or "system"), str(action or ""), str(target_type or ""), str(target_id or ""), str(detail or ""), now_utc().isoformat()],
    )


def fetch_audit_logs(limit: int = 200) -> list[dict]:
    return [dict(row) for row in fetch_all("SELECT * FROM portal_audit_log ORDER BY id DESC LIMIT ?", [int(limit)])]


def _text_terms(*values: str) -> list[str]:
    terms: list[str] = []
    for value in values:
        for term in re.split(r"[^a-zA-Z0-9_.:-]+", value or ""):
            term = term.strip().lower()
            if len(term) >= 3:
                terms.append(term)
    return sorted(set(terms))


def _report_matches_client(report: dict, client: dict) -> bool:
    haystack = " ".join(str(report.get(key, "")) for key in ("title", "category", "report_id", "path", "description")).lower()
    return any(term in haystack for term in _text_terms(client.get("sector", ""), client.get("priority_requirements", ""), client.get("technologies", ""), client.get("opencti_collections", "")))


def client_engagement_export(client_profile_id: int, root: Path | None = None) -> dict:
    client = client_profile_by_id(client_profile_id)
    if not client:
        raise ValueError("Client profile not found.")
    registry = analyst_report_registry(root)
    tasks = [dict(row) for row in fetch_all("SELECT * FROM portal_tasks WHERE client_profile_id = ? ORDER BY updated_at DESC, id DESC", [int(client_profile_id)])]
    task_report_ids = {m.group(1) for task in tasks for m in re.finditer(r"\b(RPT-[A-Z]+-\d{4}-\d{3,})\b", (task.get("description") or "") + " " + (task.get("title") or ""))}
    reports = [r for r in registry.get("reports") or [] if r.get("report_id") in task_report_ids or _report_matches_client(r, client)]
    detection_report_ids = {str(r.get("report_id")) for r in reports if r.get("report_id")}
    detections = [d for d in registry.get("detections") or [] if str(d.get("report_id")) in detection_report_ids]
    return {
        "generated_at": now_utc().isoformat(),
        "visibility": "private_internal",
        "client": client,
        "tasks": tasks,
        "reports": reports,
        "detections": detections,
        "summary": {
            "task_count": len(tasks),
            "report_count": len(reports),
            "detection_count": len(detections),
            "opencti_collections": client.get("opencti_collections", ""),
        },
    }


def build_client_brief(client_profile_id: int, root: Path | None = None) -> dict:
    export = client_engagement_export(client_profile_id, root)
    client = export["client"]
    reports = export["reports"][:8]
    detections = export["detections"][:12]
    actions = []
    if reports:
        actions.append(f"Package {len(reports)} relevant report(s) for {client['org_alias']} under {client.get('allowed_tlp') or 'configured TLP'}.")
    if detections:
        actions.append(f"Deliver or validate {len(detections)} mapped detection artifact(s) against the client technology stack.")
    if client.get("opencti_collections"):
        actions.append(f"Cross-check OpenCTI collections: {client['opencti_collections']}.")
    if not actions:
        actions.append("No matching report artifacts found yet; create a scoped research task from the client PIRs.")
    return {
        "generated_at": now_utc().isoformat(),
        "visibility": "private_internal",
        "client": client,
        "executive_summary": f"Private brief for {client['org_alias']} focused on {client.get('sector') or 'the configured engagement scope'} and PIRs: {client.get('priority_requirements') or 'not yet set'}.",
        "relevant_reports": reports,
        "detection_handoff": detections,
        "recommended_actions": actions[:5],
    }


def registry_remediation_candidates(root: Path | None = None) -> dict:
    registry = analyst_report_registry(root)
    reports = registry.get("reports") or []
    missing_pdf = [r for r in reports if not (r.get("final_pdf_path") or r.get("has_final_pdf"))]
    by_id: dict[str, list[dict]] = {}
    for report in reports:
        rid = str(report.get("report_id") or "").strip()
        if rid:
            by_id.setdefault(rid, []).append(report)
    duplicates = {rid: items for rid, items in by_id.items() if len(items) > 1 or rid in set(registry.get("duplicate_report_ids") or [])}
    return {"generated_at": now_utc().isoformat(), "missing_final_pdf": missing_pdf, "duplicate_report_ids": sorted(duplicates), "duplicate_reports": duplicates, "source_file": registry.get("source_file", "")}


def queue_registry_remediation_tasks(root: Path | None = None, requested_by: str = "registry-remediation") -> dict:
    c = registry_remediation_candidates(root)
    created=[]; skipped=[]
    for report in c["missing_final_pdf"]:
        key=f"registry-missing-pdf:{report.get('path') or report.get('report_id')}"
        if fetch_one("SELECT id FROM portal_tasks WHERE description LIKE ? LIMIT 1", [f"%{key}%"]):
            skipped.append(key); continue
        tid=create_portal_task(title=f"Registry remediation: missing final PDF for {report.get('report_id') or report.get('title')}", description=f"Repair analyst-kit registry missing-PDF gap.\n- Remediation key: `{key}`\n- Report path: `{report.get('path','')}`\n- Source registry: `{c.get('source_file','')}`\nTags: registry-remediation, missing-final-pdf", priority=7, requested_by=requested_by, assignee="analyst", worker_profile="default", task_type="research", source_page="registry-remediation", research_workflow="threat-intel", document_category=report.get("category") or "Threat Reports")
        add_task_history(tid,"registry_remediation_queue",requested_by,f"Queued missing PDF remediation for {key}.",source="registry",source_ref=key); created.append(tid)
    for rid, items in c["duplicate_reports"].items():
        key=f"registry-duplicate-report-id:{rid}"
        if fetch_one("SELECT id FROM portal_tasks WHERE description LIKE ? LIMIT 1", [f"%{key}%"]):
            skipped.append(key); continue
        paths=", ".join(str(i.get("path") or i.get("title")) for i in items)
        tid=create_portal_task(title=f"Registry remediation: duplicate report ID {rid}", description=f"Resolve duplicate analyst-kit report ID before OpenCTI/publication sync.\n- Remediation key: `{key}`\n- Conflicting reports: {paths}\n- Source registry: `{c.get('source_file','')}`\nTags: registry-remediation, duplicate-report-id", priority=8, requested_by=requested_by, assignee="analyst", worker_profile="default", task_type="research", source_page="registry-remediation", research_workflow="threat-intel", document_category="Threat Reports")
        add_task_history(tid,"registry_remediation_queue",requested_by,f"Queued duplicate report-id remediation for {rid}.",source="registry",source_ref=key); created.append(tid)
    return {"created_count": len(created), "skipped_existing_count": len(skipped), "created_task_ids": created, "skipped_keys": skipped, **c}


def reconcile_opencti_upload_results(upload_state_path: Path | None = None, actor: str = "opencti-upload") -> dict:
    state = _read_json_file(upload_state_path or opencti_upload_state_path())
    uploaded = state.get("uploaded") or {}
    reconciled=[]
    if isinstance(uploaded, dict):
        for value in uploaded.values():
            if not isinstance(value, dict) or not value.get("opencti_id"):
                continue
            rid=str(value.get("report_id") or "").strip()
            if not rid:
                continue
            rows=fetch_all("SELECT * FROM portal_tasks WHERE source_page = 'opencti-upload' AND description LIKE ?", [f"%{rid}%"] )
            for row in rows:
                detail=f"OpenCTI upload reconciled for {rid}: {value.get('opencti_id')}"
                if not fetch_one("SELECT id FROM portal_task_history WHERE task_id = ? AND event_type = 'opencti_upload_reconciled' AND detail LIKE ?", [row["id"], f"%{value.get('opencti_id')}%"]):
                    add_task_history(row["id"], "opencti_upload_reconciled", actor, detail, source="opencti", source_ref=str(value.get("opencti_id")))
                    reconciled.append({"task_id": row["id"], "report_id": rid, "opencti_id": value.get("opencti_id")})
    return {"reconciled_count": len(reconciled), "reconciled": reconciled}


def intel_ops_summary() -> dict:
    return {
        "opencti": opencti_dashboard_summary(),
        "analyst_registry": analyst_report_registry(),
        "detection_library": analyst_detection_library(limit=10),
        "daily_brief": latest_daily_intel_brief(),
        "clients": client_profiles(),
    }


def generated_report_sources_root() -> Path:
    return DATA_DIR / "generated-report-sources"


def report_bundle_dir_for_task(task: sqlite3.Row | dict) -> Path:
    task_id = int(task["id"] if isinstance(task, sqlite3.Row) else task.get("id", 0) or 0)
    title = report_display_title_for_task(task)
    slug = slugify_report_title(title)[:80].strip("-") or "untitled-report"
    return generated_report_sources_root() / f"task-{task_id:05d}_{slug}"


def report_bundle_markdown_path(task: sqlite3.Row | dict) -> Path:
    return report_bundle_dir_for_task(task) / "report.md"


def task_description_text(task: sqlite3.Row | dict) -> str:
    if isinstance(task, sqlite3.Row):
        return task["description"] if "description" in task.keys() else ""
    return task.get("description", "") or ""


def canonical_report_root_from_task(task: sqlite3.Row | dict) -> Path | None:
    description = task_description_text(task).strip()
    if not description:
        return None

    match = re.search(r"(?im)^\s*[-*]\s*Report path:\s*`([^`]+)`\s*$", description)
    if not match:
        return None

    raw_path = match.group(1).strip()
    if not raw_path:
        return None

    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = analyst_kit_root() / candidate
    return candidate


def canonical_report_markdown_path_from_task(task: sqlite3.Row | dict) -> Path | None:
    root = canonical_report_root_from_task(task)
    if not root:
        return None
    if root.is_dir():
        report_md = root / "report.md"
        if report_md.exists():
            return report_md
    elif root.name == "report.md" and root.exists():
        return root
    return None


def _expected_top_level_report_headings(task: sqlite3.Row | dict) -> set[str]:
    return {heading.strip() for heading in report_section_outline(task) if heading.strip()}


def _strip_report_heading_number_prefix(text: str) -> str:
    return re.sub(r"^\d+(?:\.\d+)*\.?\s+", "", text).strip()


def _normalize_purple_team_report_markdown_for_renderer(report_text: str) -> str:
    """Keep PTE source semantic and let the analyst-kit renderer own numbering/TOC.

    Older portal prompts asked workers to hard-code headings like ``## 6. Detection``
    and ``### 6.1 Hunt``.  The gold-standard renderer already strips and
    regenerates numbering for the body and TOC; preserving those source numbers can
    create stale numbering or, worse, demote real sections into list items when the
    preferred outline changes.  PTE reports are especially prone to this because
    inject sections grow over time.  Normalize only heading syntax here; fenced code
    blocks and numbered inject tables/lists are left untouched.
    """
    normalized_lines: list[str] = []
    in_code = False
    for raw_line in report_text.splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("```"):
            in_code = not in_code
            normalized_lines.append(raw_line.rstrip())
            continue
        if in_code:
            normalized_lines.append(raw_line.rstrip())
            continue

        heading = re.match(r"^(#{1,6})\s+(.*?)\s*$", raw_line)
        if heading:
            hashes, title = heading.groups()
            normalized_lines.append(f"{hashes} {_strip_report_heading_number_prefix(title)}".rstrip())
            continue

        demoted_section = re.match(r"^\s*[-*]\s+(\d+(?:\.\d+)*\.?\s+[^|].*?)\s*$", raw_line)
        if demoted_section:
            title = _strip_report_heading_number_prefix(demoted_section.group(1))
            if title and len(title) <= 90:
                level = "###" if re.match(r"^\s*[-*]\s+\d+\.\d+", raw_line) else "##"
                normalized_lines.append(f"{level} {title}")
                continue

        plain_section = re.match(r"^\s*(\d+(?:\.\d+)*\.?\s+[^|].*?)\s*$", raw_line)
        if plain_section:
            title = _strip_report_heading_number_prefix(plain_section.group(1))
            if title and len(title) <= 90:
                level = "###" if re.match(r"^\s*\d+\.\d+", raw_line) else "##"
                normalized_lines.append(f"{level} {title}")
                continue

        normalized_lines.append(raw_line.rstrip())
    return "\n".join(normalized_lines).strip() + "\n"


def renderable_report_markdown(task: sqlite3.Row | dict, report_text: str) -> str:
    text = (report_text or "").replace("\r\n", "\n").strip()
    if not text:
        return text

    workflow = normalize_workflow((task["research_workflow"] if isinstance(task, sqlite3.Row) else task.get("research_workflow", "")) or "general")
    if workflow == "purple-team-exercise":
        return _normalize_purple_team_report_markdown_for_renderer(text)

    expected_headings = _expected_top_level_report_headings(task)
    normalized_lines: list[str] = []
    saw_heading = False
    last_heading_level = 0
    last_numbered_heading_number: int | None = None
    forcing_pseudo_heading_list = False
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        pseudo_heading = re.fullmatch(r"-\s+(\d+\.\s+.*)", stripped)
        if pseudo_heading:
            candidate_heading = pseudo_heading.group(1).strip()
            if candidate_heading in expected_headings:
                normalized_lines.append(f"## {candidate_heading}")
                saw_heading = True
                last_heading_level = 2
                forcing_pseudo_heading_list = False
                numbered = re.match(r"(\d+)\.", candidate_heading)
                if numbered:
                    last_numbered_heading_number = int(numbered.group(1))
                continue
        if stripped.startswith("#"):
            level = len(stripped) - len(stripped.lstrip("#"))
            heading_text = stripped.lstrip("#").strip()
            integer_heading = re.fullmatch(r"(\d+)\.\s+.*", heading_text)
            if integer_heading:
                current_number = int(integer_heading.group(1))
                keep_as_heading = heading_text in expected_headings or (
                    (
                        not forcing_pseudo_heading_list
                        and (last_numbered_heading_number is None or current_number == last_numbered_heading_number + 1)
                    )
                    and last_heading_level < 3
                )
                if not keep_as_heading:
                    normalized_lines.append(f"- {heading_text}")
                    forcing_pseudo_heading_list = True
                    continue
                forcing_pseudo_heading_list = False
                last_numbered_heading_number = current_number
            saw_heading = True
            last_heading_level = level
            normalized_lines.append(raw_line.rstrip())
            continue
        if re.fullmatch(r"\d+\.\s+.*", stripped):
            if stripped in expected_headings or len(stripped) <= 60:
                normalized_lines.append(f"## {stripped}")
                saw_heading = True
                last_heading_level = 2
                forcing_pseudo_heading_list = False
                numbered = re.match(r"(\d+)\.", stripped)
                if numbered:
                    last_numbered_heading_number = int(numbered.group(1))
                continue
            normalized_lines.append(f"- {stripped}")
            continue
        normalized_lines.append(raw_line.rstrip())

    if not saw_heading:
        report_family = report_family_for_task(task)
        normalized_lines = [f"# {report_family}", "", *normalized_lines]
    return "\n".join(normalized_lines).strip() + "\n"


def report_cover_metadata(task: sqlite3.Row | dict, report_text: str = "") -> dict:
    title = report_display_title_for_task(task, report_text)
    report_family = report_family_for_task(task)
    return {
        "title": title,
        "short_title": preview(title, 70),
        "report_type": report_family,
        "opencti_report_type": opencti_report_type_for_task(task),
        "classification": "TLP:CLEAR",
        "published_date": now_utc().date().isoformat(),
        "version": "1.0",
        "author": "Your Organization",
    }


def verify_rendered_report(task: sqlite3.Row | dict, pdf_path: Path, report_text: str) -> str:
    reader = PdfReader(str(pdf_path))
    extracted = "\n".join((page.extract_text() or "").strip() for page in reader.pages).strip()
    if not reader.pages or not extracted:
        raise RuntimeError(f"Generated PDF failed verification: {pdf_path}")

    missing: list[str] = []
    for expected in ("Table of Contents", "AI Generation", "Your Organization"):
        if expected not in extracted:
            missing.append(expected)

    if not re.search(r"\b1\.\s+Executive Summary\b", extracted):
        missing.append("1. Executive Summary")

    workflow = normalize_workflow((task["research_workflow"] if isinstance(task, sqlite3.Row) else task.get("research_workflow", "")) or "general")
    if workflow in {"detection-engineering", "threat-hunting", "ioc-enrichment", "ir-triage", "malware-analysis", "threat-intel"}:
        has_table = "|" in report_text or "Field" in extracted or "Signal" in extracted
        if not has_table:
            missing.append("structured table content")
    if workflow in {"detection-engineering", "threat-hunting", "malware-analysis", "ir-triage", "threat-intel"}:
        query_markers = ("DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents", "DeviceEvents", "index=", "```sigma", "```kusto", "```spl", "```yara")
        if not any(marker in report_text or marker in extracted for marker in query_markers):
            missing.append("detection/hunt query content")

    if missing:
        raise RuntimeError(
            f"Generated report did not meet the Your Organization gold-standard QA checks ({', '.join(missing)}): {pdf_path}"
        )
    return extracted


def report_text_meets_portal_gold_standard(task: sqlite3.Row | dict, report_text: str) -> bool:
    normalized = renderable_report_markdown(task, report_text)
    workflow = normalize_workflow((task["research_workflow"] if isinstance(task, sqlite3.Row) else task.get("research_workflow", "")) or "general")
    if len(normalized) < 600:
        return False
    if "Executive Summary" not in normalized:
        return False
    if "|" not in normalized:
        return False
    if workflow in {"detection-engineering", "threat-hunting", "malware-analysis", "ir-triage", "threat-intel"}:
        query_markers = ("DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents", "DeviceEvents", "index=", "```sigma", "```kusto", "```spl", "```yara")
        if not any(marker in normalized for marker in query_markers):
            return False
    return True


def report_text_is_structured_report(task: sqlite3.Row | dict, report_text: str) -> bool:
    normalized = renderable_report_markdown(task, report_text)
    if len(normalized) < 250:
        return False
    if "Executive Summary" not in normalized:
        return False
    return "|" in normalized or "```" in normalized


def _report_text_for_quality(task: sqlite3.Row | dict) -> tuple[str, str]:
    candidates: list[tuple[str, str]] = []
    bundle_report_md = report_bundle_markdown_path(task)
    if bundle_report_md.exists():
        candidates.append(("portal_bundle_report_md", bundle_report_md.read_text(encoding="utf-8", errors="replace")))
    canonical_report_md = canonical_report_markdown_path_from_task(task)
    if canonical_report_md and canonical_report_md.exists():
        candidates.append(("analyst_kit_report_md", canonical_report_md.read_text(encoding="utf-8", errors="replace")))
    last_result = (task["last_result"] if isinstance(task, sqlite3.Row) else task.get("last_result", "")) or ""
    if last_result.strip():
        candidates.append(("portal_last_result", last_result))
    for source, text in candidates:
        if text.strip():
            return source, text
    return "missing", ""


def score_report_quality(task: sqlite3.Row | dict, report_text: str) -> dict:
    normalized = renderable_report_markdown(task, report_text or "") if (report_text or "").strip() else ""
    workflow = normalize_workflow((task["research_workflow"] if isinstance(task, sqlite3.Row) else task.get("research_workflow", "")) or "general")
    indicator_pattern = (
        r"(?i)Indicators of Compromise|\bIOCs?\b|Observable Artifacts?|\bObservables?\b|"
        r"Infrastructure and Indicators|Exploit IOCs?|attacker-owned indicators|"
        r"No known public exploit infrastructure|No known exploit infrastructure|CVE-\d{4}-\d{4,}"
    )
    checks = [
        ("Executive summary", bool(re.search(r"(?im)^#{1,3}\s+\d*\.?\s*Executive Summary\b", normalized))),
        ("Source review and confidence", bool(re.search(r"(?i)source review|confidence", normalized))),
        ("Structured table", "|" in normalized),
        ("Indicators of compromise", bool(re.search(indicator_pattern, normalized))),
        ("MITRE ATT&CK mapping", bool(re.search(r"(?i)MITRE|ATT&CK|T\d{4}(?:\.\d{3})?", normalized))),
        ("Recommendations", bool(re.search(r"(?im)^(?:#{1,3}\s+|-\s*)\d*\.?\s*(?:Recommendations|Recommended Actions(?: Summary)?)\b", normalized))),
        ("References", bool(re.search(r"(?im)^#{1,3}\s+\d*\.?\s*References\b|https?://", normalized))),
    ]
    query_markers = (
        "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents", "DeviceEvents",
        "index=", "```sigma", "```kusto", "```spl", "```yara", "title:", "logsource:",
    )
    query_ok = any(marker in normalized for marker in query_markers)
    checks.append(("Detection or hunt query", query_ok))
    if workflow == "malware-analysis":
        checks.extend([
            ("Static analysis", bool(re.search(r"(?i)Static Analysis|strings|imports?|hash|capa|floss|yara", normalized))),
            ("GhidraMCP code analysis", bool(re.search(r"(?i)GhidraMCP|Ghidra|decompil|function|xref|offset|renamed symbol|recovered config|code analysis", normalized))),
            ("RAIccoon Local Sandbox dynamic analysis", bool(re.search(r"(?i)RAIccoon Local Sandbox|Sandbox|Dynamic Analysis|process|execution|registry|filesystem|network flow", normalized))),
            ("Process tree", bool(re.search(r"(?i)Process Tree|Execution Chain|parent process|child process", normalized))),
            ("Sample coverage", bool(re.search(r"(?i)sample coverage|uploaded sample|all samples|per-sample|each sample|sample metadata", normalized))),
        ])
    length_score = min(20, len(normalized) // 300)
    passed_checks = [name for name, ok in checks if ok]
    missing_required = [name for name, ok in checks if not ok]
    score = min(100, length_score + int((len(passed_checks) / max(1, len(checks))) * 80))
    all_required_passed = len(passed_checks) == len(checks)
    if all_required_passed and len(normalized) >= 600:
        score = 100
    elif all_required_passed:
        score = max(score, 90)
    if len(normalized) < 600:
        score = min(score, 45)
    if "executive summary" not in {name.lower() for name in passed_checks}:
        score = min(score, 60)
    if not query_ok and workflow in {"detection-engineering", "threat-hunting", "malware-analysis", "ir-triage", "threat-intel"}:
        score = min(score, 70)
    grade = "ready" if score >= REPORT_AUTO_PUBLISH_MIN_SCORE and not missing_required else "review" if score >= 65 else "needs_work"
    return {
        "score": int(score),
        "grade": grade,
        "pass_gate": grade == "ready",
        "passed_checks": passed_checks,
        "missing_required": missing_required,
        "word_count": len(re.findall(r"\w+", normalized)),
        "workflow": workflow,
    }


def task_report_quality(task: sqlite3.Row | dict) -> dict:
    source, text = _report_text_for_quality(task)
    score = score_report_quality(task, text)
    score["source"] = source
    return score


def select_report_render_source(task: sqlite3.Row | dict, snapshot: dict | None = None) -> tuple[str, str]:
    task_kanban_id = task["kanban_task_id"] if isinstance(task, sqlite3.Row) else task.get("kanban_task_id", "")
    snapshot = snapshot or (fetch_kanban_task_snapshot(task_kanban_id) if task_kanban_id else None)
    candidates = [
        ("kanban_result", (snapshot or {}).get("result") or ""),
        ("kanban_latest_summary", (snapshot or {}).get("latest_summary") or ""),
        ("portal_last_result", task["last_result"] if isinstance(task, sqlite3.Row) else task.get("last_result", "")),
    ]
    for source_name, candidate in candidates:
        text = (candidate or "").strip()
        if text and (report_text_meets_portal_gold_standard(task, text) or report_text_is_structured_report(task, text)):
            return source_name, text

    bundle_report_md = report_bundle_markdown_path(task)
    if bundle_report_md.exists():
        bundled = bundle_report_md.read_text(encoding="utf-8").strip()
        if bundled and (report_text_meets_portal_gold_standard(task, bundled) or report_text_is_structured_report(task, bundled)):
            return "existing_bundle_report_md", bundled

    canonical_report_md = canonical_report_markdown_path_from_task(task)
    if canonical_report_md and canonical_report_md.exists():
        bundled = canonical_report_md.read_text(encoding="utf-8").strip()
        if bundled and (report_text_meets_portal_gold_standard(task, bundled) or report_text_is_structured_report(task, bundled)):
            return "canonical_analyst_kit_report_md", bundled

    raise RuntimeError(
        f"No structured report text found for portal task {task['id']}; latest Hermes sync result looks like a summary rather than a reviewable report body."
    )


def write_report_bundle(task: sqlite3.Row | dict, report_text: str) -> tuple[Path, Path, Path]:
    bundle_dir = report_bundle_dir_for_task(task)
    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "final").mkdir(parents=True, exist_ok=True)
    extracted_text_dir = bundle_dir / "evidence" / "extracted-text"
    extracted_text_dir.mkdir(parents=True, exist_ok=True)

    metadata_path = bundle_dir / "metadata.yaml"
    report_md_path = bundle_dir / "report.md"
    metadata_path.write_text(json.dumps(report_cover_metadata(task, report_text), indent=2), encoding="utf-8")
    report_md_path.write_text(renderable_report_markdown(task, report_text), encoding="utf-8")

    folder_name = bundle_dir.name
    docx_path = bundle_dir / "final" / f"{folder_name}.docx"
    pdf_path = bundle_dir / "final" / f"{folder_name}.pdf"
    return bundle_dir, docx_path, pdf_path


def render_report_bundle(bundle_dir: Path, docx_path: Path, pdf_path: Path) -> None:
    root = analyst_kit_root()
    script_path = analyst_kit_render_script()
    if not root.exists():
        raise RuntimeError(f"Analyst kit root not found: {root}")
    if not script_path.exists():
        raise RuntimeError(f"Report renderer not found: {script_path}")

    command = [
        "uv",
        "run",
        "python",
        str(script_path),
        str(bundle_dir),
        "--output",
        str(pdf_path),
        "--docx-output",
        str(docx_path),
    ]
    completed = subprocess.run(
        command,
        cwd=str(root),
        capture_output=True,
        text=True,
        timeout=int(os.getenv("PORTAL_REPORT_RENDER_TIMEOUT", "600")),
        check=False,
    )
    if completed.returncode != 0:
        detail = "\n".join(part.strip() for part in (completed.stdout or "", completed.stderr or "") if part.strip()).strip()
        raise RuntimeError(detail or "Report rendering failed")
    if not docx_path.exists() or not pdf_path.exists():
        raise RuntimeError(f"Expected rendered report outputs were not created under {bundle_dir / 'final'}")


def extract_report_headings(report_text: str) -> list[str]:
    headings: list[str] = []
    for raw_line in (report_text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            title = line.lstrip("#").strip()
            if title:
                headings.append(title)
            continue
        if line and line[0].isdigit() and "." in line:
            headings.append(line)
    if headings:
        return headings
    return ["1. Executive Summary"]


def report_styles():
    styles = getSampleStyleSheet()
    styles["Normal"].fontName = "Times-Roman"
    styles["Normal"].fontSize = 10
    styles["Normal"].leading = 14
    styles.add(ParagraphStyle(name="ReportCoverTitle", parent=styles["Title"], fontName="Times-Bold", fontSize=16, leading=20, textColor=REPORT_PRIMARY_BLUE, spaceAfter=10))
    styles.add(ParagraphStyle(name="LBSubtitle", parent=styles["Normal"], fontName="Times-Roman", fontSize=10.5, leading=14, spaceAfter=10))
    styles.add(ParagraphStyle(name="LBHeading1", parent=styles["Heading1"], fontName="Times-Bold", fontSize=13, leading=17, textColor=REPORT_PRIMARY_BLUE, spaceBefore=12, spaceAfter=6))
    styles.add(ParagraphStyle(name="LBHeading2", parent=styles["Heading2"], fontName="Times-Bold", fontSize=11, leading=14, textColor=REPORT_PRIMARY_BLUE, spaceBefore=8, spaceAfter=4))
    styles.add(ParagraphStyle(name="LBMeta", parent=styles["Normal"], fontName="Times-Roman", fontSize=9.5, leading=12))
    styles.add(ParagraphStyle(name="ReportCallout", parent=styles["Normal"], fontName="Times-Roman", fontSize=9.5, leading=13))
    styles.add(ParagraphStyle(name="ReportCentered", parent=styles["Normal"], fontName="Times-Roman", fontSize=10, leading=13, alignment=TA_CENTER))
    return styles


def draw_report_logo(canvas, doc) -> None:
    if not TITLEPAGE_LOGO.exists():
        return
    drawing = svg2rlg(str(TITLEPAGE_LOGO))
    if drawing is None:
        return
    max_width = 3.1 * inch
    scale = min(max_width / drawing.width, 1.0) if drawing.width else 1.0
    drawing.width *= scale
    drawing.height *= scale
    drawing.scale(scale, scale)
    x = (LETTER[0] - drawing.width) / 2
    y = LETTER[1] - 1.45 * inch
    renderPDF.draw(drawing, canvas, x, y)


def report_page_footer(canvas, doc, short_title: str) -> None:
    canvas.saveState()
    canvas.setFont("Times-Roman", 9)
    canvas.setFillColor(colors.black)
    canvas.drawCentredString(LETTER[0] / 2, 0.45 * inch, str(canvas.getPageNumber()))
    if canvas.getPageNumber() > 1:
        canvas.setStrokeColor(REPORT_RULE_BLUE)
        canvas.setLineWidth(0.6)
        canvas.line(doc.leftMargin, LETTER[1] - 0.58 * inch, LETTER[0] - doc.rightMargin, LETTER[1] - 0.58 * inch)
        canvas.setFont("Times-Roman", 8.5)
        canvas.drawString(doc.leftMargin, LETTER[1] - 0.42 * inch, f"TLP:CLEAR | Your Organization | {preview(short_title, 70)}")
    canvas.restoreState()


def is_markdown_table_row(line: str) -> bool:
    stripped = (line or "").strip()
    return stripped.count("|") >= 2 and stripped.startswith("|") and stripped.endswith("|")


def is_markdown_table_separator(line: str) -> bool:
    stripped = (line or "").strip()
    if not is_markdown_table_row(stripped):
        return False
    parts = [part.strip() for part in stripped.strip("|").split("|")]
    if not parts:
        return False
    for part in parts:
        if not part:
            continue
        if not re.fullmatch(r":?-{3,}:?", part):
            return False
    return True


def parse_markdown_table(lines: list[str], styles) -> Table | None:
    if len(lines) < 2 or not is_markdown_table_row(lines[0]) or not is_markdown_table_separator(lines[1]):
        return None
    raw_rows = []
    expected_cols = None
    for raw_line in [lines[0], *lines[2:]]:
        parts = [part.strip() for part in raw_line.strip().strip("|").split("|")]
        if expected_cols is None:
            expected_cols = len(parts)
        if len(parts) != expected_cols or expected_cols == 0:
            return None
        raw_rows.append(parts)
    table_rows = []
    for row in raw_rows:
        table_rows.append([Paragraph(html.escape(cell) or "&nbsp;", styles["LBMeta"]) for cell in row])
    col_width = 6.0 * inch / max(len(table_rows[0]), 1)
    table = Table(table_rows, colWidths=[col_width] * len(table_rows[0]), repeatRows=1)
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, REPORT_RULE_BLUE),
        ("BACKGROUND", (0, 0), (-1, 0), REPORT_TABLE_FILL),
        ("FONTNAME", (0, 0), (-1, 0), "Times-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, REPORT_TABLE_FILL]),
    ]))
    return table


def build_report_story(task: sqlite3.Row | dict, report_text: str, review_path: Path) -> list:
    styles = report_styles()
    story: list = []
    report_family = report_family_for_task(task)
    title = html.escape(report_display_title_for_task(task, report_text))
    generated_date = now_utc().date().isoformat()
    metadata_rows = [
        [Paragraph("<b>Classification</b>", styles["LBMeta"]), Paragraph("TLP:CLEAR", styles["LBMeta"])],
        [Paragraph("<b>Published</b>", styles["LBMeta"]), Paragraph(generated_date, styles["LBMeta"])],
        [Paragraph("<b>Version</b>", styles["LBMeta"]), Paragraph("1.0", styles["LBMeta"])],
        [Paragraph("<b>Author</b>", styles["LBMeta"]), Paragraph("Your Organization", styles["LBMeta"])],
        [Paragraph("<b>Report Type</b>", styles["LBMeta"]), Paragraph(html.escape(report_family), styles["LBMeta"])],
    ]
    story.extend([
        Spacer(1, 2.2 * inch),
        Paragraph(title, styles["ReportCoverTitle"]),
        Paragraph(html.escape(report_family), styles["LBSubtitle"]),
    ])
    meta_table = Table(metadata_rows, colWidths=[1.5 * inch, 4.2 * inch])
    meta_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, REPORT_RULE_BLUE),
        ("BACKGROUND", (0, 0), (-1, 0), REPORT_TABLE_FILL),
        ("BACKGROUND", (0, 2), (-1, 2), REPORT_TABLE_FILL),
        ("BACKGROUND", (0, 4), (-1, 4), REPORT_TABLE_FILL),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.extend([
        meta_table,
        Spacer(1, 0.18 * inch),
        Paragraph(f"TLP:CLEAR | Your Organization | {title} - {html.escape(report_family)}", styles["LBMeta"]),
        Paragraph(f"Published: {generated_date} | TLP:CLEAR | Version: 1.0 | Author: Your Organization", styles["LBMeta"]),
        Spacer(1, 0.24 * inch),
    ])
    callout = Table([[Paragraph("<b>AI Generation:</b> This report was generated with AI assistance and is provided for informational purposes only. All findings, IOCs, detection rules, hunting queries, attribution assessments, and recommendations must be independently reviewed and validated by a qualified security professional before operational use.", styles["ReportCallout"]) ]], colWidths=[6.0 * inch])
    callout.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), REPORT_CALLOUT_FILL),
        ("BOX", (0, 0), (-1, -1), 0.75, REPORT_RULE_BLUE),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.extend([callout, PageBreak(), Paragraph("Table of Contents", styles["LBHeading1"])])
    toc_rows = [[Paragraph(html.escape(heading), styles["Normal"])] for heading in extract_report_headings(report_text)]
    toc_table = Table(toc_rows, colWidths=[6.0 * inch])
    toc_table.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, REPORT_RULE_BLUE),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.extend([toc_table, Spacer(1, 0.2 * inch)])
    lines = (report_text or "").splitlines()
    index = 0
    while index < len(lines):
        raw_line = lines[index]
        line = raw_line.strip()
        if not line:
            story.append(Spacer(1, 0.08 * inch))
            index += 1
            continue
        if is_markdown_table_row(line):
            block = [line]
            lookahead = index + 1
            while lookahead < len(lines) and is_markdown_table_row(lines[lookahead].strip()):
                block.append(lines[lookahead].strip())
                lookahead += 1
            parsed_table = parse_markdown_table(block, styles)
            if parsed_table is not None:
                story.extend([parsed_table, Spacer(1, 0.12 * inch)])
                index = lookahead
                continue
        if line.startswith("# "):
            story.append(Paragraph(html.escape(line[2:].strip()), styles["LBHeading1"]))
            index += 1
            continue
        if line.startswith("## "):
            story.append(Paragraph(html.escape(line[3:].strip()), styles["LBHeading2"]))
            index += 1
            continue
        if line and line[0].isdigit() and "." in line:
            story.append(Paragraph(html.escape(line), styles["LBHeading1"]))
            index += 1
            continue
        if line.startswith("- "):
            story.append(Paragraph(f"• {html.escape(line[2:].strip())}", styles["Normal"]))
            index += 1
            continue
        story.append(Paragraph(html.escape(line), styles["Normal"]))
        index += 1
    story.extend([
        Spacer(1, 0.2 * inch),
        Paragraph(f"Review artifact path: {html.escape(str(review_path))}", styles["LBMeta"]),
    ])
    return story


def render_review_pdf_for_task(task: sqlite3.Row | dict, report_text: str) -> Path:
    IN_REVIEW_DIR.mkdir(parents=True, exist_ok=True)
    output_path = review_document_path_for_task(task)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    bundle_dir, docx_path, pdf_path = write_report_bundle(task, report_text)
    render_report_bundle(bundle_dir, docx_path, pdf_path)
    extracted = verify_rendered_report(task, pdf_path, renderable_report_markdown(task, report_text))
    extracted_path = bundle_dir / "evidence" / "extracted-text" / "rendered_pdf.txt"
    extracted_path.write_text(extracted + "\n", encoding="utf-8")
    shutil.copy2(pdf_path, output_path)
    return output_path


def maybe_generate_review_document(task: sqlite3.Row, snapshot: dict | None = None) -> Path | None:
    if not task_is_research(task):
        return None
    full_task = fetch_one("SELECT * FROM portal_tasks WHERE id = ?", [task["id"]]) or task
    snapshot = snapshot or (fetch_kanban_task_snapshot(task["kanban_task_id"]) if task["kanban_task_id"] else None)
    if not snapshot:
        return None
    if snapshot.get("status") not in {"done", "blocked"}:
        return None
    source_name, report_text = select_report_render_source(full_task, snapshot)
    if not report_text:
        return None
    review_path = render_review_pdf_for_task(full_task, report_text)
    execute(
        "UPDATE portal_tasks SET review_document_path = ?, updated_at = ? WHERE id = ?",
        [str(review_path), now_utc().isoformat(), task["id"]],
    )
    add_task_history(int(task["id"]), "review_document", "portal", f"Generated review PDF at {review_path} using source {source_name}.")
    create_notification(
        "review_ready",
        f"Report ready for review: {task['title']}",
        f"Research task #{task['id']} generated an In Review PDF at {review_path}.",
        task_id=int(task["id"]),
        notification_key=f"review-ready:{task['id']}:{review_path.name}",
    )
    return review_path


def analyst_kit_report_dir_for_final_pdf(task: sqlite3.Row | dict, final_pdf: Path) -> Path:
    category = ((task["document_category"] if isinstance(task, sqlite3.Row) else task.get("document_category", "")) or "Uncategorized").strip() or "Uncategorized"
    category_dir = ANALYST_KIT_REPORT_CATEGORY_DIRS.get(category, ANALYST_KIT_REPORT_CATEGORY_DIRS["Uncategorized"])
    return ANALYST_KIT_DIR / "reports" / category_dir / final_pdf.stem


def extract_pdf_text_for_markdown(pdf_path: Path, *, max_chars: int = 30000) -> str:
    try:
        reader = PdfReader(str(pdf_path))
        chunks: list[str] = []
        total = 0
        for page in reader.pages:
            text = (page.extract_text() or "").strip()
            if not text:
                continue
            if total + len(text) > max_chars:
                remaining = max_chars - total
                if remaining > 0:
                    chunks.append(text[:remaining].rstrip())
                break
            chunks.append(text)
            total += len(text)
        return "\n\n".join(chunks).strip()
    except Exception:
        return ""


def stage_final_report_for_opencti(task: sqlite3.Row, final_pdf: Path) -> Path:
    report_dir = analyst_kit_report_dir_for_final_pdf(task, final_pdf)
    report_id = final_pdf.stem.split("_", 1)[0]
    display_title = report_display_title_for_task(task)
    report_dir.mkdir(parents=True, exist_ok=True)
    final_dir = report_dir / "final"
    final_dir.mkdir(parents=True, exist_ok=True)
    staged_pdf = final_dir / final_pdf.name
    shutil.copy2(final_pdf, staged_pdf)

    body_text = extract_pdf_text_for_markdown(final_pdf)
    if not body_text:
        body_text = f"Portal-generated final PDF staged for OpenCTI ingestion. See attached artifact: {final_pdf.name}."
    (report_dir / "report.md").write_text(f"# {display_title}\n\n{body_text.strip()}\n", encoding="utf-8")
    (report_dir / "sources.md").write_text(
        "# Sources\n\n- Portal task #{task_id}\n- Final PDF: {pdf}\n".format(task_id=task["id"], pdf=final_pdf),
        encoding="utf-8",
    )

    metadata = report_cover_metadata(task)
    metadata.update(
        {
            "report_id": report_id,
            "title": display_title,
            "primary_topic": slugify_report_title(display_title),
            "status": "published",
            "client_visible": True,
            "published_date": date.today().isoformat(),
            "date": date.today().isoformat(),
            "created_by": "Your Organization",
            "portal_task_id": int(task["id"]),
            "portal_final_pdf": str(final_pdf),
            "final_artifacts": {"pdf": str(staged_pdf.relative_to(report_dir))},
        }
    )
    (report_dir / "metadata.yaml").write_text(json.dumps(metadata, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return report_dir


def promote_review_document(task: sqlite3.Row) -> tuple[Path, int]:
    review_path = Path((task["review_document_path"] or "").strip())
    if not review_path.exists():
        raise RuntimeError("Review PDF not found. Generate the report before publishing.")
    display_title = report_display_title_for_task(task)
    destination = unique_path(final_document_path_for_task(task))
    destination.parent.mkdir(parents=True, exist_ok=True)
    created_destination = False
    try:
        shutil.copy2(review_path, destination)
        created_destination = True
        archive_repo_path = sync_report_to_archive_repo(task, destination)
        opencti_report_dir = stage_final_report_for_opencti(task, destination)
    except Exception:
        if created_destination and destination.exists():
            destination.unlink(missing_ok=True)
        raise
    review_path.unlink(missing_ok=True)
    published_work_id = int(task["published_work_id"] or 0)
    notes = f"Accepted through portal task {task['id']}. Final PDF: {destination}. Archive repo copy: {archive_repo_path}. OpenCTI staging dir: {opencti_report_dir}"
    tags = ", ".join(filter(None, [task["research_workflow"], task["document_category"]]))
    if published_work_id:
        execute(
            "UPDATE published_works SET status = 'published', outlet = ?, url = ?, publication_date = ?, owner = ?, artifact_type = 'report', audience = 'internal', tags = ?, notes = ?, updated_at = ? WHERE id = ?",
            [task["document_category"] or "Internal Research", str(destination), date.today().isoformat(), task["requested_by"], tags, notes, now_utc().isoformat(), published_work_id],
        )
        execute("UPDATE published_works SET title = ? WHERE id = ?", [display_title, published_work_id])
    else:
        with closing(connect_db()) as connection:
            cursor = connection.execute(
                """
                INSERT INTO published_works (
                    title, status, outlet, url, publication_date, due_date, owner,
                    artifact_type, audience, tags, notes, created_at, updated_at
                ) VALUES (?, 'published', ?, ?, ?, '', ?, 'report', 'internal', ?, ?, ?, ?)
                """,
                [display_title, task["document_category"] or "Internal Research", str(destination), date.today().isoformat(), task["requested_by"], tags, notes, now_utc().isoformat(), now_utc().isoformat()],
            )
            published_work_id = int(cursor.lastrowid)
            connection.commit()
    execute(
        "UPDATE portal_tasks SET final_document_path = ?, review_document_path = '', published_work_id = ?, updated_at = ? WHERE id = ?",
        [str(destination), published_work_id, now_utc().isoformat(), task["id"]],
    )
    add_task_history(int(task["id"]), "accepted_document", "portal", f"Promoted final PDF to {destination}, synced archive repo copy to {archive_repo_path}, staged OpenCTI upload metadata at {opencti_report_dir}, and recorded published-work entry {published_work_id}.")
    return destination, published_work_id


def normalize_portal_task_status(value: str) -> str:
    status = (value or "todo").strip().lower()
    if status == "complete":
        return "accepted"
    return status if status in PORTAL_TASK_STATUSES else "todo"


def portal_profile_options() -> list[str]:
    options = ["default"]
    profiles_dir = Path.home() / ".hermes" / "profiles"
    if profiles_dir.exists():
        for path in sorted(profiles_dir.iterdir()):
            if path.is_dir() and not path.name.startswith(".") and path.name not in options:
                options.append(path.name)
    return options


def normalize_task_assignee(value: str, fallback: str = "") -> str:
    normalized = (value or fallback or PORTAL_KANBAN_ASSIGNEE).strip()
    return normalized or PORTAL_KANBAN_ASSIGNEE


def normalize_worker_profile(value: str) -> str:
    normalized = (value or PORTAL_DEFAULT_WORKER_PROFILE or "default").strip()
    return normalized or "default"


def add_task_history(
    task_id: int,
    event_type: str,
    actor: str,
    detail: str,
    *,
    source: str = "portal",
    source_ref: str = "",
) -> None:
    execute(
        "INSERT INTO portal_task_history (task_id, event_type, actor, detail, created_at, source, source_ref) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            task_id,
            event_type.strip(),
            actor.strip() or "system",
            detail.strip(),
            now_utc().isoformat(),
            source.strip() or "portal",
            source_ref.strip(),
        ],
    )


def create_portal_task(
    title: str,
    description: str,
    priority: int,
    requested_by: str,
    assignee: str,
    worker_profile: str,
    task_type: str = "general",
    source_page: str = "",
    research_workflow: str = "",
    document_category: str = "",
    uploaded_files: str = "",
    due_date: str = "",
    sla_hours: int = 0,
    parent_task_id: int = 0,
    acceptance_criteria: str = "",
) -> int:
    stamp = now_utc().isoformat()
    normalized_title = title.strip()
    normalized_description = description.strip()
    normalized_assignee = normalize_task_assignee(assignee, requested_by)
    normalized_profile = normalize_worker_profile(worker_profile)
    (
        normalized_task_type,
        normalized_source_page,
        normalized_research_workflow,
        normalized_document_category,
    ) = normalize_report_task_fields(
        task_type,
        research_workflow,
        document_category,
        source_page=source_page,
    )
    normalized_uploaded_files = (uploaded_files or "").strip()
    normalized_due_date = normalize_due_date(due_date)
    normalized_sla_hours = normalize_sla_hours(sla_hours)
    normalized_parent_task_id = max(0, int(parent_task_id or 0))
    normalized_acceptance_criteria = (acceptance_criteria or "").strip()
    with closing(connect_db()) as connection:
        existing = connection.execute(
            """
            SELECT id
            FROM portal_tasks
            WHERE status = 'todo'
              AND lower(trim(title)) = lower(trim(?))
              AND lower(trim(description)) = lower(trim(?))
            ORDER BY id ASC
            LIMIT 1
            """,
            [normalized_title, normalized_description],
        ).fetchone()
        if existing:
            return int(existing["id"])
        try:
            cursor = connection.execute(
                """
                INSERT INTO portal_tasks (
                    title, description, status, priority, requested_by, assignee, worker_profile,
                    task_type, source_page, research_workflow, document_category, uploaded_files,
                    created_at, updated_at, kanban_task_id, kanban_status, last_result,
                    review_document_path, final_document_path, published_work_id,
                    review_notes, reviewer, reviewer_signed_at, review_signoff,
                    due_date, sla_hours, started_at, blocked_reason, blocked_at, parent_task_id, acceptance_criteria
                ) VALUES (?, ?, 'todo', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', '', '', '', 0, '', '', '', 0, ?, ?, '', '', '', ?, ?)
                """,
                [
                    normalized_title,
                    normalized_description,
                    priority,
                    requested_by.strip(),
                    normalized_assignee,
                    normalized_profile,
                    normalized_task_type,
                    normalized_source_page,
                    normalized_research_workflow,
                    normalized_document_category,
                    normalized_uploaded_files,
                    stamp,
                    stamp,
                    normalized_due_date,
                    normalized_sla_hours,
                    normalized_parent_task_id,
                    normalized_acceptance_criteria,
                ],
            )
            task_id = int(cursor.lastrowid)
            connection.commit()
        except sqlite3.IntegrityError:
            existing = connection.execute(
                """
                SELECT id
                FROM portal_tasks
                WHERE status = 'todo'
                  AND lower(trim(title)) = lower(trim(?))
                  AND lower(trim(description)) = lower(trim(?))
                ORDER BY id ASC
                LIMIT 1
                """,
                [normalized_title, normalized_description],
            ).fetchone()
            if not existing:
                raise
            return int(existing["id"])
    detail = f"Task created in Todo. Assignee: {normalized_assignee}. Hermes profile: {normalized_profile}."
    if normalized_task_type == "research":
        detail += f" Research workflow: {normalized_research_workflow or 'general'}. Final category: {normalized_document_category or 'Uncategorized'}."
    add_task_history(
        task_id,
        "created",
        requested_by,
        detail,
    )
    return task_id


def fetch_portal_task(task_id: int) -> sqlite3.Row | None:
    return fetch_one("SELECT * FROM portal_tasks WHERE id = ?", [task_id])


def fetch_task_comments(task_id: int) -> list[dict]:
    rows = fetch_all(
        "SELECT id, task_id, author, comment, created_at, source, source_ref FROM portal_task_comments WHERE task_id = ? ORDER BY id DESC",
        [task_id],
    )
    return [dict(row) for row in rows]


def fetch_task_history(task_id: int) -> list[dict]:
    rows = fetch_all(
        "SELECT id, task_id, event_type, actor, detail, created_at, source, source_ref FROM portal_task_history WHERE task_id = ? ORDER BY id DESC",
        [task_id],
    )
    return [dict(row) for row in rows]


def task_detail_maps(task_ids: list[int]) -> tuple[dict[int, list[dict]], dict[int, list[dict]]]:
    if not task_ids:
        return {}, {}
    placeholders = ",".join("?" for _ in task_ids)
    comments_rows = fetch_all(
        f"SELECT id, task_id, author, comment, created_at, source, source_ref FROM portal_task_comments WHERE task_id IN ({placeholders}) ORDER BY id DESC",
        task_ids,
    )
    history_rows = fetch_all(
        f"SELECT id, task_id, event_type, actor, detail, created_at, source, source_ref FROM portal_task_history WHERE task_id IN ({placeholders}) ORDER BY id DESC",
        task_ids,
    )
    comments_by_task: dict[int, list[dict]] = defaultdict(list)
    history_by_task: dict[int, list[dict]] = defaultdict(list)
    for row in comments_rows:
        comments_by_task[int(row["task_id"])].append(dict(row))
    for row in history_rows:
        history_by_task[int(row["task_id"])].append(dict(row))
    return comments_by_task, history_by_task


def revision_feedback_summary(task_id: int, limit: int = 6) -> list[str]:
    rows = fetch_all(
        """
        SELECT author, comment, created_at, source
        FROM portal_task_comments
        WHERE task_id = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        [task_id, limit],
    )
    items: list[str] = []
    for row in reversed(rows):
        author = (row["author"] or row["source"] or "portal").strip()
        comment = preview((row["comment"] or "").strip(), 260)
        if comment:
            items.append(f"- {author}: {comment}")
    return items


def fetch_kanban_task_snapshot(task_id: str) -> dict | None:
    if not task_id or not PORTAL_KANBAN_DB.exists():
        return None
    try:
        with closing(connect_kanban_db()) as connection:
            row = connection.execute(
                """
                SELECT
                    t.id,
                    t.title,
                    t.status,
                    t.result,
                    t.assignee,
                    t.created_at,
                    t.started_at,
                    t.completed_at,
                    t.last_failure_error,
                    (
                        SELECT summary
                        FROM task_runs tr
                        WHERE tr.task_id = t.id
                        ORDER BY tr.id DESC
                        LIMIT 1
                    ) AS latest_summary,
                    (
                        SELECT outcome
                        FROM task_runs tr
                        WHERE tr.task_id = t.id
                        ORDER BY tr.id DESC
                        LIMIT 1
                    ) AS latest_outcome
                FROM tasks t
                WHERE t.id = ?
                """,
                [task_id],
            ).fetchone()
            comments = connection.execute(
                """
                SELECT id, author, body, created_at
                FROM task_comments
                WHERE task_id = ?
                ORDER BY id ASC
                """,
                [task_id],
            ).fetchall()
            events = connection.execute(
                """
                SELECT id, kind, payload, created_at
                FROM task_events
                WHERE task_id = ?
                ORDER BY id ASC
                """,
                [task_id],
            ).fetchall()
    except sqlite3.Error:
        return None
    if not row:
        return None
    snapshot = dict(row)
    snapshot["comments"] = [dict(comment) for comment in comments]
    snapshot["events"] = [dict(event) for event in events]
    return snapshot


def sync_hermes_comments_to_portal(task_id: int, kanban_task_id: str, snapshot: dict) -> None:
    for comment in snapshot.get("comments", []):
        source_ref = f"hermes-comment:{comment['id']}"
        exists = fetch_one(
            "SELECT id FROM portal_task_comments WHERE task_id = ? AND source_ref = ?",
            [task_id, source_ref],
        )
        if exists:
            continue
        execute(
            "INSERT INTO portal_task_comments (task_id, author, comment, created_at, source, source_ref) VALUES (?, ?, ?, ?, ?, ?)",
            [
                task_id,
                (comment.get("author") or "hermes").strip(),
                (comment.get("body") or "").strip(),
                datetime.fromtimestamp(comment.get("created_at") or 0, tz=timezone.utc).isoformat(),
                "hermes",
                source_ref,
            ],
        )
        add_task_history(
            task_id,
            "hermes_comment",
            (comment.get("author") or "hermes").strip(),
            f"Synced Hermes comment from {kanban_task_id}: {preview((comment.get('body') or '').strip(), 180)}",
            source="hermes",
            source_ref=f"hermes-comment-history:{comment['id']}",
        )


def sync_hermes_events_to_portal(task_id: int, kanban_task_id: str, snapshot: dict) -> None:
    interesting = {"blocked", "commented", "done", "failed", "released"}
    for event in snapshot.get("events", []):
        if event.get("kind") not in interesting:
            continue
        source_ref = f"hermes-event:{event['id']}"
        exists = fetch_one(
            "SELECT id FROM portal_task_history WHERE task_id = ? AND source_ref = ?",
            [task_id, source_ref],
        )
        if exists:
            continue
        payload = event.get("payload")
        if isinstance(payload, str) and payload:
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                pass
        detail = f"Hermes event {event.get('kind')} on {kanban_task_id}."
        if isinstance(payload, dict):
            if payload.get("reason"):
                detail = f"Hermes event {event.get('kind')} on {kanban_task_id}: {payload['reason']}"
            elif payload.get("author"):
                detail = f"Hermes event {event.get('kind')} on {kanban_task_id} by {payload['author']}."
            elif payload:
                detail = f"Hermes event {event.get('kind')} on {kanban_task_id}: {preview(json.dumps(payload, sort_keys=True), 180)}"
        add_task_history(
            task_id,
            f"hermes_{event.get('kind')}",
            "hermes",
            detail,
            source="hermes",
            source_ref=source_ref,
        )


def auto_publish_completed_task(task_id: int, actor: str = "portal") -> sqlite3.Row | None:
    """Move a completed portal task through review staging and into published/accepted state."""
    task = fetch_portal_task(task_id)
    if not task or normalize_portal_task_status(task["status"]) in {"accepted", "rejected"}:
        return task

    if task_is_research(task):
        review_path = Path((task["review_document_path"] or "").strip()) if task["review_document_path"] else None
        if not review_path or not review_path.exists():
            raise RuntimeError("Auto-publish requires a generated review PDF.")

    if normalize_portal_task_status(task["status"]) != "in_review":
        ok, reason = validate_task_transition(task, "in_review")
        if not ok:
            raise RuntimeError(reason)
        task = update_portal_task_status(task_id, "in_review", actor) or fetch_portal_task(task_id)
        if not task:
            raise RuntimeError("Task disappeared while moving to publish staging.")

    if task_is_research(task):
        quality = task_report_quality(task)
        if not quality.get("pass_gate"):
            missing = ", ".join(quality.get("missing_required") or []) or "insufficient report depth"
            detail = (
                f"Auto-publish deferred: report quality score {quality.get('score', 0)}/100 is below "
                f"the {REPORT_AUTO_PUBLISH_MIN_SCORE}/100 auto-publish threshold or has missing checks ({missing}). "
                "Task remains in Review for human QA."
            )
            add_task_history(task_id, "auto_publish_deferred", actor, detail)
            create_notification(
                "review_required",
                f"Report needs review: {task['title']}",
                f"Portal task #{task_id} scored {quality.get('score', 0)}/100 and was left in Review. Missing/weak checks: {missing}.",
                task_id=task_id,
                notification_key=f"auto-publish-deferred:{task_id}:{quality.get('score', 0)}",
            )
            return fetch_portal_task(task_id)

    if not (task["review_notes"] or "").strip():
        task = update_task_review(task, "Auto-published after Hermes completed and portal quality gates passed.", False, actor)

    ok, reason = validate_task_transition(task, "accepted")
    if not ok:
        raise RuntimeError(reason)
    published = update_portal_task_status(task_id, "accepted", actor)
    create_notification(
        "auto_published",
        f"Auto-published: {task['title']}",
        f"Portal task #{task_id} was automatically moved through Review and published after Hermes completed.",
        task_id=task_id,
        notification_key=f"auto-published:{task_id}",
    )
    return published


def sync_portal_tasks_with_kanban() -> None:
    rows = fetch_all(
        "SELECT id, kanban_task_id, status, kanban_status, last_result, review_document_path, task_type, source_page, research_workflow, document_category, uploaded_files, title, requested_by, published_work_id FROM portal_tasks WHERE kanban_task_id <> '' AND status NOT IN ('accepted', 'rejected')"
    )
    timestamp = now_utc().isoformat()
    for row in rows:
        snapshot = fetch_kanban_task_snapshot(row["kanban_task_id"])
        if not snapshot:
            continue
        latest_result = (snapshot.get("latest_summary") or snapshot.get("result") or snapshot.get("last_failure_error") or "").strip()
        latest_status = (snapshot.get("status") or "").strip()
        previous_status = (row["kanban_status"] or "").strip()
        previous_result = (row["last_result"] or "").strip()
        task_id = int(row["id"])
        sync_hermes_comments_to_portal(task_id, row["kanban_task_id"], snapshot)
        sync_hermes_events_to_portal(task_id, row["kanban_task_id"], snapshot)
        if latest_status != previous_status or latest_result != previous_result:
            execute(
                "UPDATE portal_tasks SET kanban_status = ?, last_result = ?, updated_at = ? WHERE id = ?",
                [latest_status, latest_result, timestamp, task_id],
            )
            if latest_status != previous_status:
                add_task_history(
                    task_id,
                    "kanban_status",
                    "hermes",
                    f"Linked Hermes task {row['kanban_task_id']} status changed from {previous_status or 'unknown'} to {latest_status or 'unknown'}.",
                )
            if latest_result and latest_result != previous_result and latest_status in {"done", "failed", "blocked"}:
                add_task_history(
                    task_id,
                    "kanban_result",
                    "hermes",
                    f"Latest Hermes result: {preview(latest_result, 260)}",
                )
        if task_is_research(row) and latest_status in {"done", "blocked"} and latest_result:
            review_path = Path((row["review_document_path"] or "").strip()) if row["review_document_path"] else None
            if latest_result != previous_result or not review_path or not review_path.exists():
                try:
                    maybe_generate_review_document(row, snapshot)
                except Exception as exc:
                    detail = preview(str(exc), 400)
                    add_task_history(
                        task_id,
                        "review_document_error",
                        "portal",
                        f"Automatic review PDF generation failed: {detail}",
                    )
                    create_notification(
                        "review_error",
                        f"Review generation failed: {row['title']}",
                        f"Research task #{task_id} could not generate an In Review PDF automatically. {detail}",
                        task_id=task_id,
                        notification_key=f"review-error:{task_id}:{hashlib.sha256(str(exc).encode('utf-8')).hexdigest()[:16]}",
                    )
        if latest_status == "done":
            try:
                auto_publish_completed_task(task_id)
            except Exception as exc:
                detail = preview(str(exc), 400)
                add_task_history(
                    task_id,
                    "auto_publish_error",
                    "portal",
                    f"Automatic publish failed: {detail}",
                )
                create_notification(
                    "publish_error",
                    f"Auto-publish failed: {row['title']}",
                    f"Portal task #{task_id} could not be auto-published after Hermes completed. {detail}",
                    task_id=task_id,
                    notification_key=f"auto-publish-error:{task_id}:{hashlib.sha256(str(exc).encode('utf-8')).hexdigest()[:16]}",
                )


def is_active_kanban_status(status: str) -> bool:
    return (status or "").strip().lower() in {"ready", "running", "queued", "retry", "pending"}


def serialize_portal_task(task: sqlite3.Row, comments: list[dict], history: list[dict]) -> dict:
    item = dict(task)
    item["status_label"] = PORTAL_TASK_LABELS[item["status"]]
    item["comments"] = comments
    item["history"] = history
    item["comment_count"] = len(comments)
    item["history_count"] = len(history)
    item["review_signoff"] = bool(item.get("review_signoff"))
    item["is_active"] = item["status"] == "in_progress" and is_active_kanban_status(item.get("kanban_status", ""))
    item["is_blocked"] = item["status"] == "blocked" or (item.get("kanban_status", "").strip().lower() == "blocked")
    item["is_research"] = task_is_research(item)
    item["uploaded_file_list"] = task_uploaded_files(item)
    item["review_document_name"] = Path(item["review_document_path"]).name if item.get("review_document_path") else ""
    item["final_document_name"] = Path(item["final_document_path"]).name if item.get("final_document_path") else ""
    item["client_profile"] = client_profile_by_id(int(item.get("client_profile_id") or 0))
    item["report_quality"] = task_report_quality(item) if item["is_research"] else None
    item["qa_state"] = "pass" if (item.get("report_quality") or {}).get("pass_gate") else ("fail" if item.get("report_quality") else "none")
    item["due_state"] = due_state(item.get("due_date", ""))
    item["is_overdue"] = item["due_state"] == "overdue"
    item["lane_age_hours"] = hours_since(item.get("started_at") or item.get("updated_at") or item.get("created_at"))
    item["updated_age_hours"] = hours_since(item.get("updated_at"))
    stale_threshold = int(item.get("sla_hours") or 0) or TASK_STALE_HOURS_DEFAULT
    item["is_stale"] = item["status"] in {"in_progress", "blocked", "in_review"} and item["updated_age_hours"] >= stale_threshold
    item["source_label"] = (item.get("source_page") or "manual").replace("-", " ").title()
    item["dependency_label"] = f"Depends on #{item['parent_task_id']}" if int(item.get("parent_task_id") or 0) else ""
    return item


def task_matches_filters(task: dict, filters: dict[str, str]) -> bool:
    if not filters:
        return True
    search = (filters.get("q") or "").strip().lower()
    if search:
        haystack = " ".join(
            str(task.get(key, ""))
            for key in ("title", "description", "assignee", "source_page", "research_workflow", "kanban_task_id", "kanban_status")
        ).lower()
        client = task.get("client_profile") or {}
        haystack += " " + str(client.get("org_alias", "")).lower()
        if search not in haystack:
            return False
    for key, task_key in (("status", "status"), ("assignee", "assignee"), ("workflow", "research_workflow"), ("source", "source_page"), ("kanban", "kanban_status"), ("qa", "qa_state")):
        value = (filters.get(key) or "").strip()
        if value and value != "all":
            allowed_values = {part.strip() for part in value.split(",") if part.strip()}
            if str(task.get(task_key, "")) not in allowed_values:
                return False
    client_filter = (filters.get("client") or "").strip()
    if client_filter == "linked" and not task.get("client_profile"):
        return False
    if client_filter and client_filter not in {"all", "linked"} and str(task.get("client_profile_id") or "") != client_filter:
        return False
    if (filters.get("stale") or "").lower() in {"1", "true", "yes"} and not task.get("is_stale"):
        return False
    return True


def board_filter_options(tasks: list[dict]) -> dict:
    def sorted_values(key: str) -> list[str]:
        return sorted({str(task.get(key) or "") for task in tasks if str(task.get(key) or "").strip()})

    clients = []
    seen_clients = set()
    for task in tasks:
        client = task.get("client_profile") or {}
        client_id = client.get("id")
        if client_id and client_id not in seen_clients:
            seen_clients.add(client_id)
            clients.append({"id": client_id, "label": client.get("org_alias", f"Client {client_id}")})
    return {
        "statuses": [{"key": status, "label": PORTAL_TASK_LABELS[status]} for status in PORTAL_TASK_BOARD_STATUSES],
        "assignees": sorted_values("assignee"),
        "workflows": sorted_values("research_workflow"),
        "source_pages": sorted_values("source_page"),
        "kanban_statuses": sorted_values("kanban_status"),
        "clients": clients,
        "qa_states": ["pass", "fail", "none"],
    }


def board_analytics(tasks: list[dict]) -> dict:
    by_status = {status: 0 for status in PORTAL_TASK_BOARD_STATUSES}
    by_assignee: dict[str, int] = defaultdict(int)
    for task in tasks:
        if task["status"] in by_status:
            by_status[task["status"]] += 1
        by_assignee[task.get("assignee") or "unassigned"] += 1
    return {
        "open_count": len(tasks),
        "blocked_count": sum(1 for task in tasks if task.get("is_blocked")),
        "stale_count": sum(1 for task in tasks if task.get("is_stale")),
        "overdue_count": sum(1 for task in tasks if task.get("is_overdue")),
        "review_count": by_status.get("in_review", 0),
        "qa_failing_count": sum(1 for task in tasks if task.get("qa_state") == "fail"),
        "client_linked_count": sum(1 for task in tasks if task.get("client_profile")),
        "active_hermes_count": sum(1 for task in tasks if task.get("is_active")),
        "by_status": by_status,
        "wip_by_assignee": dict(sorted(by_assignee.items())),
    }


def task_sort_key(task: dict) -> tuple:
    urgent = 1 if task.get("is_blocked") or task.get("kanban_status") in {"failed", "blocked"} else 0
    review_ready = 1 if task.get("status") == "in_review" and task.get("qa_state") in {"pass", "none"} else 0
    due_rank = {"overdue": 4, "due_today": 3, "due_soon": 2, "scheduled": 1, "none": 0}.get(str(task.get("due_state") or "none"), 0)
    return (urgent, review_ready, int(task.get("priority") or 0), due_rank, float(task.get("lane_age_hours") or 0), int(task.get("id") or 0))


def task_board_payload(selected_task_id: int | None = None, filters: dict[str, str] | None = None) -> dict:
    sync_portal_tasks_with_kanban()
    rows = fetch_all("SELECT * FROM portal_tasks WHERE status NOT IN ('accepted', 'rejected') ORDER BY priority DESC, id DESC")
    task_ids = [int(row["id"]) for row in rows]
    comments_by_task, history_by_task = task_detail_maps(task_ids)
    all_tasks = [
        serialize_portal_task(row, comments_by_task.get(int(row["id"]), []), history_by_task.get(int(row["id"]), []))
        for row in rows
    ]
    all_tasks.sort(key=task_sort_key, reverse=True)
    normalized_filters = {key: str(value).strip() for key, value in (filters or {}).items() if str(value).strip()}
    tasks = [task for task in all_tasks if task_matches_filters(task, normalized_filters)]
    grouped: dict[str, list[dict]] = {status: [] for status in PORTAL_TASK_BOARD_STATUSES}
    for task in tasks:
        if task["status"] in grouped:
            grouped[task["status"]].append(task)
    fingerprint_source = [
        {
            "id": task["id"],
            "status": task["status"],
            "updated_at": task["updated_at"],
            "kanban_status": task.get("kanban_status", ""),
            "last_result": task.get("last_result", ""),
            "review_notes": task.get("review_notes", ""),
            "review_signoff": task.get("review_signoff", False),
            "reviewer": task.get("reviewer", ""),
            "reviewer_signed_at": task.get("reviewer_signed_at", ""),
            "assignee": task.get("assignee", ""),
            "worker_profile": task.get("worker_profile", ""),
            "comment_count": task["comment_count"],
            "history_count": task["history_count"],
            "review_document_path": task.get("review_document_path", ""),
            "final_document_path": task.get("final_document_path", ""),
            "published_work_id": task.get("published_work_id", 0),
            "due_date": task.get("due_date", ""),
            "blocked_reason": task.get("blocked_reason", ""),
            "parent_task_id": task.get("parent_task_id", 0),
        }
        for task in all_tasks
    ]
    fingerprint = hashlib.sha256(json.dumps(fingerprint_source, sort_keys=True).encode("utf-8")).hexdigest()[:16]
    visible_ids = [int(task["id"]) for task in tasks]
    selected = selected_task_id if selected_task_id in visible_ids else (visible_ids[0] if visible_ids else None)
    return {
        "columns": [{"key": status, "label": PORTAL_TASK_LABELS[status], "items": grouped[status]} for status in PORTAL_TASK_BOARD_STATUSES],
        "tasks": tasks,
        "all_task_count": len(all_tasks),
        "visible_task_count": len(tasks),
        "analytics": board_analytics(all_tasks),
        "filter_options": board_filter_options(all_tasks),
        "quick_views": board_quick_views(),
        "templates": task_templates(),
        "filters": normalized_filters,
        "fingerprint": fingerprint,
        "has_active_tasks": any(task["is_active"] for task in all_tasks),
        "selected_task_id": selected,
        "generated_at": now_utc().isoformat(),
    }


def workflow_focus_queue(board_payload: dict, limit: int = 6) -> list[dict]:
    tasks = list(board_payload.get("tasks") or [])

    def focus_rank(task: dict) -> tuple:
        blocked = 1 if task.get("is_blocked") else 0
        qa_fail = 1 if task.get("qa_state") == "fail" else 0
        overdue = 1 if task.get("is_overdue") else 0
        stale = 1 if task.get("is_stale") else 0
        review = 1 if task.get("status") == "in_review" else 0
        priority = int(task.get("priority") or 0)
        age = float(task.get("updated_age_hours") or 0)
        return (blocked, qa_fail, overdue, stale, review, priority, age, int(task.get("id") or 0))

    focus_tasks = sorted(tasks, key=focus_rank, reverse=True)[:limit]
    return [
        {
            "id": int(task.get("id") or 0),
            "title": task.get("title", ""),
            "status": task.get("status", ""),
            "status_label": task.get("status_label", ""),
            "priority": int(task.get("priority") or 0),
            "assignee": task.get("assignee", ""),
            "client": (task.get("client_profile") or {}).get("org_alias", ""),
            "workflow": task.get("research_workflow", ""),
            "is_blocked": bool(task.get("is_blocked")),
            "is_stale": bool(task.get("is_stale")),
            "is_overdue": bool(task.get("is_overdue")),
            "qa_state": task.get("qa_state", "none"),
            "href": f"/tasks#task-{int(task.get('id') or 0)}",
        }
        for task in focus_tasks
    ]


def portal_workflow_steps(board_payload: dict) -> list[dict]:
    analytics = board_payload.get("analytics") or {}
    by_status = analytics.get("by_status") or {}
    return [
        {
            "key": "intake",
            "label": "Intake",
            "count": int(by_status.get("todo", 0)),
            "href": "/tasks?status=todo",
            "hint": "Scope, assign, link client, and confirm acceptance criteria.",
        },
        {
            "key": "execute",
            "label": "Execute",
            "count": int(by_status.get("in_progress", 0)) + int(by_status.get("blocked", 0)),
            "href": "/tasks?status=in_progress",
            "secondary_href": "/tasks?status=blocked",
            "hint": "Hermes/RAIccoon Local Sandbox/OpenCTI work, with blocked work surfaced first.",
        },
        {
            "key": "review",
            "label": "Review",
            "count": int(by_status.get("in_review", 0)) + int(analytics.get("qa_failing_count", 0)),
            "href": "/tasks?status=in_review",
            "hint": "QA gates, reviewer notes, revision loops, and signoff.",
        },
        {
            "key": "deliver",
            "label": "Deliver",
            "count": int(by_status.get("accepted", 0)),
            "href": "/documents",
            "hint": "Final PDFs/document packages only; sources stay in analyst-kit.",
        },
    ]


def workflow_context(active_page: str, board_payload: dict) -> dict:
    focus_queue = workflow_focus_queue(board_payload)
    workflow_steps = portal_workflow_steps(board_payload)
    analytics = board_payload.get("analytics") or {}
    metrics = [
        {"label": "Visible", "value": board_payload.get("visible_task_count", 0)},
        {"label": "Blocked", "value": analytics.get("blocked_count", 0)},
        {"label": "Stale", "value": analytics.get("stale_count", 0)},
        {"label": "QA failing", "value": analytics.get("qa_failing_count", 0)},
    ]
    status_line = " · ".join(f"{metric['value']} {metric['label'].lower()}" for metric in metrics)
    action_cards = [
        {
            "label": "Unblock work",
            "count": int(analytics.get("blocked_count", 0)),
            "href": "/tasks?status=blocked",
            "hint": "Tasks waiting on data, decision, rerun, or dependency recovery.",
        },
        {
            "label": "Review queue",
            "count": int(analytics.get("review_count", 0)),
            "href": "/tasks?status=in_review",
            "hint": "Work ready for QA, revision, or client handoff approval.",
        },
        {
            "label": "SLA risk",
            "count": int(analytics.get("stale_count", 0)) + int(analytics.get("overdue_count", 0)),
            "href": "/tasks?stale=true",
            "hint": "Stale and overdue cards that need operator attention.",
        },
        {
            "label": "Quality gates",
            "count": int(analytics.get("qa_failing_count", 0)),
            "href": "/tasks?qa=fail",
            "hint": "Reports blocked by Your Organization report-quality checks.",
        },
    ]
    return {
        "active_page": active_page,
        "focus_queue": focus_queue,
        "workflow_steps": workflow_steps,
        "action_cards": action_cards,
        "status_line": status_line,
        "metrics": metrics,
        "workspace_name": "Private client workflow",
        "operator_mode": "internal single-client delivery",
        "generated_at": now_utc().isoformat(),
    }


def build_portal_kanban_body(task: sqlite3.Row, username: str) -> str:
    lines = [
        "This task was created from the Your Organization internal portal tasks board.",
        f"Portal task id: {task['id']}",
        f"Requested by: {username}",
        f"Portal assignee: {task['assignee'] or username}",
        f"Hermes profile: {task['worker_profile'] or PORTAL_DEFAULT_WORKER_PROFILE}",
        "",
        f"Title: {task['title']}",
    ]
    description = (task["description"] or "").strip()
    if description:
        lines.extend(["", "Description:", description])
    prior_kanban_task_id = (task["kanban_task_id"] or "").strip()
    prior_result = (task["last_result"] or "").strip()
    review_notes = (task["review_notes"] or "").strip()
    revision_feedback = revision_feedback_summary(int(task["id"]))
    if prior_kanban_task_id or prior_result or review_notes or revision_feedback:
        lines.extend(["", "Revision / reviewer context:"])
        if prior_kanban_task_id:
            lines.append(f"Previous Hermes task: {prior_kanban_task_id}")
        if prior_result:
            lines.append(f"Previous result summary: {preview(prior_result, 500)}")
        if review_notes:
            lines.extend(["", "Saved review notes:", review_notes])
        if revision_feedback:
            lines.extend(["", "Recent portal comments to address:", *revision_feedback])
        lines.extend(
            [
                "",
                "Treat this as a revision pass.",
                "Address the reviewer comments directly in your updated deliverable.",
            ]
        )
    if task_is_research(task):
        client_profile = client_profile_by_id(int(task["client_profile_id"] or 0)) if "client_profile_id" in task.keys() else None
        if client_profile:
            lines.extend(
                [
                    "",
                    "Private client / engagement context:",
                    f"Client alias: {client_profile['org_alias']}",
                    f"Sector: {client_profile.get('sector') or 'unspecified'}",
                    f"Priority intelligence requirements: {client_profile.get('priority_requirements') or 'unspecified'}",
                    f"Technologies/products of interest: {client_profile.get('technologies') or 'unspecified'}",
                    f"Allowed marking: {client_profile.get('allowed_tlp') or 'TLP:AMBER'}",
                    "Keep this context private/internal and do not add public-company publicity language.",
                ]
            )
        lines.extend(
            [
                "",
                "This is a research-report task.",
                f"Research workflow: {task['research_workflow'] or 'general'}",
                f"Final document category: {task['document_category'] or 'Uncategorized'}",
                f"Portal review folder: {IN_REVIEW_DIR}",
                f"Gold-standard exemplar: /opt/raiccoon/Lost_Boys_Cyber_Malware_Report_dba90bd5fdf0_restyled.pdf",
                "",
                "The portal will convert your final result into the approved Your Organization gold-standard DOCX/PDF layout using the analyst-kit renderer.",
                "The analyst-kit source bundle becomes the canonical portal report artifact, so your final result MUST be the finished report body itself, not a meta-summary, handoff note, or review-required status update.",
                "Write the report in clean markdown with real markdown headings and tables.",
                "For Purple Team Exercise reports, use semantic markdown headings without hard-coded numbering, such as `## Executive Summary`, `## Exercise Phases and Injects`, and `### Purple team injects`; the analyst-kit renderer owns final section numbering and the table of contents.",
                "For other report workflows, use markdown section headings like `## 1. Executive Summary`, `## 2. ...`, and `### 4.1 ...` where needed.",
                "Only use numbered H1/H2 headings for the actual report sections in the preferred outline. For judgments, hypotheses, scenarios, assumptions, or references inside a section, use bullets or tables instead of extra numbered pseudo-headings like `## 1. ...`.",
                "Do not ask follow-up questions. Make reasonable assumptions and state them in the report when needed.",
                "Do not wrap the whole report in code fences.",
                f"Use this report family: {report_family_for_task(task)}",
                "Preferred section outline:",
            ]
        )
        for heading in report_section_outline(task):
            lines.append(f"- {heading}")
        uploaded = task_uploaded_files(task)
        if uploaded:
            lines.extend(["", "Evidence files available by path:"])
            lines.extend(f"- {path}" for path in uploaded)
        lines.extend(
            [
                "",
                "Gold-standard content requirements for the report body:",
                "- Match the approved Your Organization house style and the gold-standard exemplar in substance, not just section names.",
                "- Be content-rich: avoid thin prose-only writeups.",
                "- Include compact markdown tables for metadata, findings, recommendations, detection coverage, and/or exposure details where relevant.",
                "- Include detection engineering and threat-hunting content when relevant to the workflow.",
                "- Include embedded query content in fenced code blocks when detections or hunts are relevant (KQL/SPL/Sigma/YARA/etc.).",
                "- Include MITRE ATT&CK mapping when the workflow supports it.",
                "- Use a formal analyst tone with actionable findings, defensive implications, and recommendations.",
                "- If evidence is incomplete, state assumptions and confidence clearly instead of asking questions.",
            ]
        )
        if normalize_workflow(task["research_workflow"] or "general") == "malware-analysis":
            lines.extend(
                [
                    "",
                    "Mandatory malware sample-analysis requirements:",
                    "- Title the malware report from the malware family or cluster name, not from the intake/request wording or a hash. Use the canonical form `<Malware Family> Malware Analysis`; if the family is unknown, state `Unknown family / cluster` in the sample metadata and do not invent one.",
                    "- Treat every uploaded sample and every attached RAIccoon Local Sandbox artifact path as in-scope evidence; do not analyze only the first sample unless all others are explicitly duplicates.",
                    "- Include distinct static analysis, code analysis/reversing, and dynamic analysis sections with evidence-backed findings, not placeholders.",
                    "- Use GhidraMCP/Ghidra for reversing when executable code is present; cite function names, offsets/xrefs, decompiled snippets, renamed symbols, recovered config, or MCP/Ghidra notes that support the finding.",
                    "- Use RAIccoon Local Sandbox output for dynamic behavior; cite sandbox run artifacts, process trees, file/registry/network changes, memory/network findings, and any failure/coverage limitations.",
                    "- If a sample cannot be reversed or detonated, clearly mark the affected sample, explain the blocker, and keep the task/report in review rather than implying full coverage.",
                ]
            )
    else:
        lines.extend(
            [
                "",
                "Instructions:",
                "- Do the requested work directly when possible.",
                "- If blocked, say exactly what is blocking completion.",
                "- End with a concise summary of outcomes and any follow-up needed.",
            ]
        )
    return "\n".join(lines)


def create_linked_kanban_task(task: sqlite3.Row, username: str) -> dict:
    body = build_portal_kanban_body(task, username)
    command = [
        hermes_executable(),
        "kanban",
        "--board",
        PORTAL_KANBAN_BOARD,
        "create",
        "--assignee",
        normalize_worker_profile(task["worker_profile"]),
        "--created-by",
        f"portal:{username}",
        "--goal",
        "--goal-max-turns",
        "8",
        "--json",
        "--body",
        body,
        task["title"],
    ]
    completed = subprocess.run(command, cwd=str(BASE_DIR), capture_output=True, text=True, timeout=120, check=False)
    if completed.returncode != 0:
        error_text = (completed.stderr or completed.stdout or "Kanban task creation failed").strip()
        raise RuntimeError(error_text)
    payload = json.loads(completed.stdout)
    if not isinstance(payload, dict) or "id" not in payload:
        raise RuntimeError("Kanban task creation returned invalid JSON")
    return payload


def dispatch_kanban() -> dict:
    command = [hermes_executable(), "kanban", "--board", PORTAL_KANBAN_BOARD, "dispatch", "--max", "1", "--json"]
    completed = subprocess.run(command, cwd=str(BASE_DIR), capture_output=True, text=True, timeout=120, check=False)
    if completed.returncode != 0:
        error_text = (completed.stderr or completed.stdout or "Kanban dispatch failed").strip()
        raise RuntimeError(error_text)
    output = (completed.stdout or "").strip()
    if not output:
        return {}
    try:
        parsed = json.loads(output)
    except json.JSONDecodeError:
        return {"raw": output}
    return parsed if isinstance(parsed, dict) else {"value": parsed}


def move_portal_task_to_in_progress(task: sqlite3.Row, username: str) -> dict:
    linked_id = (task["kanban_task_id"] or "").strip()
    kanban_status = (task["kanban_status"] or "").strip()
    last_result = (task["last_result"] or "").strip()
    prior_status = normalize_portal_task_status(task["status"])
    if prior_status == "in_review" and linked_id:
        add_task_history(
            int(task["id"]),
            "revision_requested",
            username,
            f"Sent task back to In Progress for revision. Previous Hermes task {linked_id} kept in history; spawning a fresh revision run with saved comments and review notes.",
        )
        kanban_status = ""
        last_result = ""
        linked_id = ""
    if not linked_id:
        created = create_linked_kanban_task(task, username)
        linked_id = created["id"]
        kanban_status = created.get("status", "ready")
        dispatch_kanban()
    execute(
        """
        UPDATE portal_tasks
        SET status = 'in_progress',
            kanban_task_id = ?,
            kanban_status = ?,
            last_result = ?,
            review_document_path = '',
            reviewer = '',
            reviewer_signed_at = '',
            review_signoff = 0,
            updated_at = ?
        WHERE id = ?
        """,
        [linked_id, kanban_status, last_result, now_utc().isoformat(), task["id"]],
    )
    detail = f"Moved task to In Progress and linked Hermes task {linked_id} using profile {normalize_worker_profile(task['worker_profile'])}."
    if prior_status == "in_review":
        detail = f"Returned task to In Progress for revision and linked fresh Hermes task {linked_id} using profile {normalize_worker_profile(task['worker_profile'])}."
    add_task_history(
        int(task["id"]),
        "transition",
        username,
        detail,
    )
    return fetch_kanban_task_snapshot(linked_id) or {"id": linked_id, "status": kanban_status}


def validate_task_transition(task: sqlite3.Row, target_status: str, *, allow_quality_override: bool = False) -> tuple[bool, str]:
    current_status = normalize_portal_task_status(task["status"])
    target_status = normalize_portal_task_status(target_status)
    if target_status == current_status:
        return True, "Task already in that lane."
    allowed = PORTAL_TASK_FLOW[current_status]
    if target_status not in allowed:
        if current_status == "todo":
            return False, "Todo tasks can move to In Progress or Blocked."
        if current_status == "in_review":
            return False, "In Review tasks can move back to In Progress for revision or forward to Acceptance."
        return False, f"Tasks can only move from {PORTAL_TASK_LABELS[current_status]} to its allowed next lane."
    if target_status in {"in_review", "accepted"} and task["kanban_task_id"]:
        snapshot = fetch_kanban_task_snapshot(task["kanban_task_id"])
        allowed_terminal_statuses = {"done", "blocked"}
        if snapshot and snapshot.get("status") not in allowed_terminal_statuses:
            return False, f"Linked Hermes task {task['kanban_task_id']} is still {snapshot.get('status')}"
    if task_is_research(task) and target_status in {"in_review", "accepted"}:
        review_path = Path((task["review_document_path"] or "").strip()) if task["review_document_path"] else None
        if not review_path or not review_path.exists():
            return False, "Research tasks need a generated review PDF before they can move to In Review or Acceptance."
    if target_status == "accepted":
        if task_is_research(task):
            quality = task_report_quality(task)
            if not quality.get("pass_gate") and not allow_quality_override:
                missing = ", ".join(quality.get("missing_required") or []) or "insufficient report depth"
                return False, f"Report quality gate failed ({quality.get('score', 0)}/100): {missing}."
    return True, ""


def update_portal_task_status(task_id: int, target_status: str, actor: str) -> sqlite3.Row | None:
    target_status = normalize_portal_task_status(target_status)
    current = fetch_portal_task(task_id)
    if not current:
        return None
    if target_status == "accepted" and task_is_research(current):
        promote_review_document(current)
    stamp = now_utc().isoformat()
    started_at = current["started_at"] or (stamp if target_status == "in_progress" else "")
    blocked_at = stamp if target_status == "blocked" else (current["blocked_at"] if current["status"] == "blocked" and target_status == "blocked" else "")
    blocked_reason = current["blocked_reason"] if target_status == "blocked" else ""
    execute(
        "UPDATE portal_tasks SET status = ?, updated_at = ?, started_at = ?, blocked_at = ?, blocked_reason = ? WHERE id = ?",
        [target_status, stamp, started_at, blocked_at, blocked_reason, task_id],
    )
    add_task_history(task_id, "transition", actor, f"Moved task to {PORTAL_TASK_LABELS[target_status]}.")
    return fetch_portal_task(task_id)


def update_task_ownership(
    task: sqlite3.Row,
    assignee: str,
    worker_profile: str,
    actor: str,
    *,
    task_type: str | None = None,
    research_workflow: str | None = None,
    document_category: str | None = None,
) -> sqlite3.Row:
    normalized_assignee = normalize_task_assignee(assignee, task["requested_by"])
    normalized_profile = normalize_worker_profile(worker_profile)
    current_profile = normalize_worker_profile(task["worker_profile"])
    if task["kanban_task_id"] and normalized_profile != current_profile:
        raise RuntimeError("Hermes profile cannot be changed after a linked task has been created.")
    (
        normalized_task_type,
        normalized_source_page,
        normalized_research_workflow,
        normalized_document_category,
    ) = normalize_report_task_fields(
        task_type if task_type is not None else task["task_type"],
        research_workflow if research_workflow is not None else task["research_workflow"],
        document_category if document_category is not None else task["document_category"],
        source_page=task["source_page"],
    )
    execute(
        "UPDATE portal_tasks SET assignee = ?, worker_profile = ?, task_type = ?, source_page = ?, research_workflow = ?, document_category = ?, updated_at = ? WHERE id = ?",
        [
            normalized_assignee,
            normalized_profile,
            normalized_task_type,
            normalized_source_page,
            normalized_research_workflow,
            normalized_document_category,
            now_utc().isoformat(),
            task["id"],
        ],
    )
    metadata_changed = (
        normalized_task_type != normalize_task_type(task["task_type"])
        or normalized_research_workflow != ((task["research_workflow"] or "").strip())
        or normalized_document_category != ((task["document_category"] or "").strip())
    )
    if normalized_assignee != (task["assignee"] or "") or normalized_profile != current_profile or metadata_changed:
        detail = f"Updated assignee to {normalized_assignee} and Hermes profile to {normalized_profile}."
        if normalized_task_type == "research":
            detail += f" Report task metadata: workflow {normalized_research_workflow or 'general'}, category {normalized_document_category or 'Uncategorized'}."
        elif metadata_changed:
            detail += " Cleared report-task metadata and marked task as general work."
        add_task_history(
            int(task["id"]),
            "assignment",
            actor,
            detail,
        )
    updated = fetch_portal_task(int(task["id"]))
    if not updated:
        raise RuntimeError("Task not found after ownership update.")
    return updated


def add_comment_to_task(task_id: int, author: str, comment: str) -> None:
    execute(
        "INSERT INTO portal_task_comments (task_id, author, comment, created_at, source, source_ref) VALUES (?, ?, ?, ?, ?, ?)",
        [task_id, author.strip(), comment.strip(), now_utc().isoformat(), "portal", ""],
    )
    add_task_history(task_id, "comment", author, f"Added comment: {preview(comment, 180)}")


def update_task_review(task: sqlite3.Row, review_notes: str, signoff: bool, actor: str) -> sqlite3.Row:
    normalized_notes = review_notes.strip()
    reviewer = actor if signoff else ""
    signed_at = now_utc().isoformat() if signoff else ""
    execute(
        "UPDATE portal_tasks SET review_notes = ?, reviewer = ?, reviewer_signed_at = ?, review_signoff = ?, updated_at = ? WHERE id = ?",
        [normalized_notes, reviewer, signed_at, 1 if signoff else 0, now_utc().isoformat(), task["id"]],
    )
    detail = "Saved review notes."
    if signoff:
        detail = f"Saved review notes and recorded reviewer signoff by {actor}."
    add_task_history(int(task["id"]), "review", actor, detail)
    updated = fetch_portal_task(int(task["id"]))
    if not updated:
        raise RuntimeError("Task not found after review update.")
    return updated


def render(
    request: Request,
    *,
    active_page: str,
    search_result: str = "",
    search_query: str = "",
    selected_workflow: str = "general",
    message: str = "",
    error: str = "",
    selected_task_id: int | None = None,
) -> HTMLResponse:
    searches = fetch_all("SELECT * FROM searches ORDER BY id DESC LIMIT 20")
    research_tasks = fetch_research_tasks(limit=50)
    chat_messages = fetch_chat_messages(limit=100)
    costs = fetch_all("SELECT * FROM ai_costs ORDER BY period_start DESC, id DESC LIMIT 100")
    works = fetch_all("SELECT * FROM published_works ORDER BY COALESCE(NULLIF(due_date, ''), publication_date) ASC, id DESC LIMIT 100")
    document_categories = report_document_categories()
    sync_runs = fetch_all("SELECT * FROM cost_sync_runs ORDER BY id DESC LIMIT 20")
    query_params = getattr(request, "query_params", {})
    board_filters = {key: query_params.get(key, "") for key in ("q", "status", "assignee", "workflow", "source", "kanban", "qa", "client", "stale")} if active_page == "tasks" else None
    board_payload = task_board_payload(selected_task_id if active_page == "tasks" else None, filters=board_filters)
    notifications = fetch_notifications(unread_only=True, limit=8)
    security_profile_row = fetch_one(
        "SELECT id, username, display_name, role, mfa_enabled, mfa_created_at, mfa_recovery_codes, mfa_recovery_generated_at, mfa_required FROM users WHERE id = ?",
        [request.session.get("user_id")],
    ) if request.session.get("user_id") else None
    pending_secret = request.session.get("pending_mfa_secret", "")
    pending_recovery_codes = list(request.session.get("pending_mfa_recovery_codes", []))
    security_users = []
    if request.session.get("role") == "admin":
        for row in fetch_all(
            "SELECT id, username, display_name, role, mfa_enabled, mfa_created_at, mfa_recovery_codes, mfa_recovery_generated_at, mfa_required FROM users ORDER BY role DESC, username ASC"
        ):
            payload = dict(row)
            payload["recovery_code_count"] = recovery_code_count(payload.get("mfa_recovery_codes", "[]"))
            security_users.append(payload)
    security_profile = dict(security_profile_row) if security_profile_row else None
    if security_profile is not None:
        security_profile["recovery_code_count"] = recovery_code_count(security_profile.get("mfa_recovery_codes", "[]"))
    context = {
        "request": request,
        "title": APP_TITLE,
        "subtitle": APP_SUBTITLE,
        "active_page": active_page,
        "page_title": PAGE_TITLES.get(active_page, APP_TITLE),
        "nav_items": NAV_ITEMS,
        "nav_groups": NAV_GROUPS,
        "summary": dashboard_summary(),
        "searches": searches,
        "research_tasks": research_tasks,
        "chat_messages": chat_messages,
        "chat_pending": chat_has_pending_reply(),
        "costs": costs,
        "works": works,
        "document_categories": document_categories,
        "documents_root": str(DOCUMENTS_DIR),
        "document_total": sum(category["count"] for category in document_categories),
        "sync_runs": sync_runs,
        "monthly_costs": monthly_cost_breakdown(),
        "publication_statuses": publication_status_breakdown(),
        "search_operators": search_operator_breakdown(),
        "due_soon": due_soon_works(),
        "search_result": search_result,
        "search_query": search_query,
        "selected_workflow": normalize_workflow(selected_workflow),
        "workflow_options": workflow_options(),
        "report_category_options": report_category_options(),
        "today": date.today().isoformat(),
        "client_ip": client_ip(request),
        "allowed_cidrs": os.getenv("SECOPS_ALLOWED_CIDRS", DEFAULT_ALLOWED_CIDRS),
        "current_user": current_user(request),
        "message": message,
        "error": error,
        "task_columns": board_payload["columns"],
        "task_board_payload": board_payload,
        "workflow_context": workflow_context(active_page, board_payload),
        "selected_task_id": board_payload["selected_task_id"],
        "profile_options": portal_profile_options(),
        "portal_kanban_board": PORTAL_KANBAN_BOARD,
        "portal_default_worker_profile": PORTAL_DEFAULT_WORKER_PROFILE,
        "notifications": notifications,
        "notification_unread_count": unread_notification_count(),
        "intel_ops": intel_ops_summary(),
        "client_profiles": client_profiles(),
        "security_profile": security_profile,
        "security_users": security_users,
        "mfa_setup_secret": pending_secret,
        "mfa_setup_uri": totp_uri(security_profile_row["username"], pending_secret) if security_profile_row and pending_secret else "",
        "pending_mfa_recovery_codes": pending_recovery_codes,
    }
    return templates.TemplateResponse(request, "index.html", context)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if authenticated(request):
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"request": request, "title": APP_TITLE, "error": ""})


@app.post("/login", response_class=HTMLResponse)
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = fetch_one("SELECT * FROM users WHERE username = ?", [username.strip()])
    if user and lock_is_active(user["login_locked_until"] if "login_locked_until" in user.keys() else ""):
        request.session.clear()
        return templates.TemplateResponse(
            request,
            "login.html",
            {"request": request, "title": APP_TITLE, "error": format_lockout_message(user["login_locked_until"], "sign-in")},
            status_code=423,
        )

    if not user or not verify_password(password, user["password_hash"]):
        request.session.clear()
        if user:
            locked_until = record_login_failure(user)
            error = format_lockout_message(locked_until, "sign-in") if locked_until else "Invalid username or password"
        else:
            error = "Invalid username or password"
        return templates.TemplateResponse(
            request,
            "login.html",
            {"request": request, "title": APP_TITLE, "error": error},
            status_code=423 if user and lock_is_active(fetch_one("SELECT login_locked_until FROM users WHERE id = ?", [user["id"]])["login_locked_until"]) else 401,
        )

    clear_login_failures(user["id"])
    request.session.pop("pending_mfa_recovery_codes", None)

    if bool(user["mfa_enabled"]) if "mfa_enabled" in user.keys() else False:
        set_pending_mfa_session(request, user)
        return RedirectResponse(url="/mfa/challenge", status_code=303)

    set_authenticated_session(request, user)
    execute("UPDATE users SET last_login = ? WHERE id = ?", [now_utc().isoformat(), user["id"]])
    target = "/security" if request.session.get("mfa_setup_required") else "/dashboard"
    return RedirectResponse(url=target, status_code=303)


@app.get("/mfa/challenge", response_class=HTMLResponse)
def mfa_challenge_page(request: Request):
    pending = pending_mfa_user(request)
    if not pending["id"]:
        return RedirectResponse(url="/login", status_code=303)
    user = fetch_one("SELECT mfa_locked_until FROM users WHERE id = ?", [pending["id"]])
    error = ""
    if user and lock_is_active(user["mfa_locked_until"] if "mfa_locked_until" in user.keys() else ""):
        error = format_lockout_message(user["mfa_locked_until"], "MFA verification")
    return templates.TemplateResponse(
        request,
        "mfa_challenge.html",
        {"request": request, "title": APP_TITLE, "error": error, "pending_user": pending},
        status_code=423 if error else 200,
    )


@app.post("/mfa/challenge", response_class=HTMLResponse)
def mfa_challenge_verify(request: Request, code: str = Form(...)):
    pending = pending_mfa_user(request)
    if not pending["id"]:
        return RedirectResponse(url="/login", status_code=303)

    user = fetch_one("SELECT * FROM users WHERE id = ?", [pending["id"]])
    if not user or not bool(user["mfa_enabled"]):
        request.session.clear()
        return RedirectResponse(url="/login", status_code=303)
    if lock_is_active(user["mfa_locked_until"] if "mfa_locked_until" in user.keys() else ""):
        return templates.TemplateResponse(
            request,
            "mfa_challenge.html",
            {"request": request, "title": APP_TITLE, "error": format_lockout_message(user["mfa_locked_until"], "MFA verification"), "pending_user": pending},
            status_code=423,
        )

    if not (verify_totp_code(user["mfa_secret"], code) or consume_recovery_code(user, code)):
        locked_until = record_mfa_failure(user)
        error = format_lockout_message(locked_until, "MFA verification") if locked_until else "Invalid authenticator or recovery code"
        return templates.TemplateResponse(
            request,
            "mfa_challenge.html",
            {"request": request, "title": APP_TITLE, "error": error, "pending_user": pending},
            status_code=423 if locked_until else 401,
        )

    clear_mfa_failures(user["id"])
    user = fetch_one("SELECT * FROM users WHERE id = ?", [pending["id"]])
    set_authenticated_session(request, user)
    execute("UPDATE users SET last_login = ? WHERE id = ?", [now_utc().isoformat(), user["id"]])
    return RedirectResponse(url="/dashboard", status_code=303)


@app.get("/security", response_class=HTMLResponse)
def security_page(request: Request):
    guard = require_auth(request, allow_mfa_setup=True)
    if guard:
        return guard
    message = ""
    if request.session.get("mfa_setup_required"):
        message = "Your account is required to enable MFA before you can continue to the rest of the portal."
    return render(request, active_page="security", message=message)


@app.post("/security/mfa/start")
def security_mfa_start(request: Request):
    guard = require_auth(request, allow_mfa_setup=True)
    if guard:
        return guard
    request.session["pending_mfa_secret"] = generate_totp_secret()
    request.session.pop("pending_mfa_recovery_codes", None)
    return RedirectResponse(url="/security", status_code=303)


@app.post("/security/mfa/confirm", response_class=HTMLResponse)
def security_mfa_confirm(request: Request, code: str = Form(...)):
    guard = require_auth(request, allow_mfa_setup=True)
    if guard:
        return guard
    secret = request.session.get("pending_mfa_secret", "")
    user = current_user(request)
    if not secret:
        return render(request, active_page="security", error="Start MFA setup first.")
    if not verify_totp_code(secret, code):
        return render(request, active_page="security", error="Invalid authenticator code.")

    recovery_codes = generate_recovery_codes()
    execute(
        "UPDATE users SET mfa_secret = ?, mfa_enabled = 1, mfa_created_at = ?, mfa_recovery_codes = ?, mfa_recovery_generated_at = ? WHERE id = ?",
        [secret, now_utc().isoformat(), serialize_recovery_code_hashes(recovery_codes), now_utc().isoformat(), user["id"]],
    )
    request.session["mfa_enabled"] = True
    request.session["mfa_setup_required"] = False
    request.session.pop("pending_mfa_secret", None)
    request.session["pending_mfa_recovery_codes"] = recovery_codes
    return render(request, active_page="security", message="Authenticator MFA enabled. Save your backup recovery codes now.")


@app.post("/security/mfa/recovery/regenerate", response_class=HTMLResponse)
def security_mfa_recovery_regenerate(request: Request, password: str = Form(...), code: str = Form(...)):
    guard = require_auth(request, allow_mfa_setup=True)
    if guard:
        return guard
    user = fetch_one("SELECT * FROM users WHERE id = ?", [request.session.get("user_id")])
    if not user:
        request.session.clear()
        return RedirectResponse(url="/login", status_code=303)
    if not verify_password(password, user["password_hash"]):
        return render(request, active_page="security", error="Current password is incorrect.")
    if not bool(user["mfa_enabled"]):
        return render(request, active_page="security", error="Authenticator MFA is not enabled.")
    if not verify_totp_code(user["mfa_secret"], code):
        return render(request, active_page="security", error="Invalid authenticator code.")

    recovery_codes = generate_recovery_codes()
    execute(
        "UPDATE users SET mfa_recovery_codes = ?, mfa_recovery_generated_at = ? WHERE id = ?",
        [serialize_recovery_code_hashes(recovery_codes), now_utc().isoformat(), user["id"]],
    )
    request.session["pending_mfa_recovery_codes"] = recovery_codes
    return render(request, active_page="security", message="Backup recovery codes regenerated. Store the new set now.")


@app.post("/security/mfa/disable", response_class=HTMLResponse)
def security_mfa_disable(request: Request, password: str = Form(...), code: str = Form(...)):
    guard = require_auth(request, allow_mfa_setup=True)
    if guard:
        return guard
    user = fetch_one("SELECT * FROM users WHERE id = ?", [request.session.get("user_id")])
    if not user:
        request.session.clear()
        return RedirectResponse(url="/login", status_code=303)
    if not verify_password(password, user["password_hash"]):
        return render(request, active_page="security", error="Current password is incorrect.")
    if not bool(user["mfa_enabled"]):
        return render(request, active_page="security", error="Authenticator MFA is not enabled.")
    if not verify_totp_code(user["mfa_secret"], code):
        return render(request, active_page="security", error="Invalid authenticator code.")

    execute(
        "UPDATE users SET mfa_secret = '', mfa_enabled = 0, mfa_created_at = '', mfa_recovery_codes = '[]', mfa_recovery_generated_at = '' WHERE id = ?",
        [user["id"]],
    )
    request.session["mfa_enabled"] = False
    request.session["mfa_setup_required"] = bool(request.session.get("mfa_required"))
    request.session.pop("pending_mfa_secret", None)
    request.session.pop("pending_mfa_recovery_codes", None)
    return render(request, active_page="security", message="Authenticator MFA disabled.")


@app.post("/security/admin/mfa-required")
def security_admin_mfa_required(request: Request, user_id: int = Form(...), required: int = Form(...)):
    if not admin_authenticated(request):
        return login_redirect()
    target = fetch_one("SELECT * FROM users WHERE id = ?", [user_id])
    if not target:
        return render(request, active_page="security", error="User not found.")
    required_value = 1 if int(required) else 0
    execute("UPDATE users SET mfa_required = ? WHERE id = ?", [required_value, user_id])
    if request.session.get("user_id") == user_id:
        request.session["mfa_required"] = bool(required_value)
        request.session["mfa_setup_required"] = bool(required_value and not request.session.get("mfa_enabled"))
    message = f"MFA requirement {'enabled' if required_value else 'cleared'} for @{target['username']}."
    return render(request, active_page="security", message=message)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.post("/notifications/{notification_id}/read")
def read_notification(request: Request, notification_id: int, next: str = Form(default="/dashboard")):
    guard = require_auth(request)
    if guard:
        return guard
    mark_notification_read(notification_id)
    next_path = (next or "/dashboard").strip()
    if not next_path.startswith("/"):
        next_path = "/dashboard"
    return RedirectResponse(url=next_path, status_code=303)


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    guard = require_auth(request)
    if guard:
        return guard
    return RedirectResponse(url="/dashboard", status_code=303)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(request: Request):
    guard = require_auth(request)
    if guard:
        return guard
    return render(request, active_page="dashboard")


@app.get("/chat", response_class=HTMLResponse)
def chat_page(request: Request):
    guard = require_auth(request)
    if guard:
        return guard
    return render(request, active_page="chat")


@app.get("/research", response_class=HTMLResponse)
def research_page(request: Request):
    guard = require_auth(request)
    if guard:
        return guard
    return render(request, active_page="research")


@app.get("/documents", response_class=HTMLResponse)
def documents_page(request: Request):
    guard = require_auth(request)
    if guard:
        return guard
    return render(request, active_page="documents")


@app.get("/documents/open")
def open_document(request: Request, category: str = "", file: str = ""):
    guard = require_auth(request)
    if guard:
        return guard
    path = resolve_document_path(category, file)
    if path is None:
        raise HTTPException(status_code=404, detail="Document not found")
    return FileResponse(path, filename=path.name)


@app.get("/costs", response_class=HTMLResponse)
def costs_page(request: Request):
    guard = require_auth(request)
    if guard:
        return guard
    return render(request, active_page="costs")


@app.get("/works", response_class=HTMLResponse)
def works_page(request: Request):
    guard = require_auth(request)
    if guard:
        return guard
    return render(request, active_page="works")


@app.get("/clients", response_class=HTMLResponse)
def clients_page(request: Request):
    guard = require_auth(request)
    if guard:
        return guard
    return render(request, active_page="clients")


@app.get("/tasks", response_class=HTMLResponse)
def tasks_page(request: Request):
    guard = require_auth(request)
    if guard:
        return guard
    return render(request, active_page="tasks")


@app.get("/deploy", response_class=HTMLResponse)
def deploy_page(request: Request):
    guard = require_auth(request)
    if guard:
        return guard
    return render(request, active_page="deploy")


@app.get("/healthz")
def healthz():
    return {"status": "ok", "app": APP_TITLE}


@app.post("/chat", response_class=HTMLResponse)
def create_chat_message(request: Request, message_text: str = Form(...)):
    guard = require_auth(request)
    if guard:
        return guard
    message_text = message_text.strip()
    if not message_text:
        return render(request, active_page="chat", error="Chat message is required.")
    user = current_user(request)
    add_chat_message("user", message_text, user["username"])
    queue_chat_response(message_text, user["username"])
    return RedirectResponse(url="/chat?queued=1", status_code=303)


@app.post("/chat/clear", response_class=HTMLResponse)
def clear_chat_messages(request: Request):
    guard = require_auth(request)
    if guard:
        return guard
    execute("DELETE FROM hermes_chat_messages")
    return render(request, active_page="chat", message="Portal chat history cleared.")


@app.post("/searches", response_class=HTMLResponse)
async def create_search(
    request: Request,
    query: str = Form(...),
    workflow: str = Form(default="general"),
    title: str = Form(default=""),
    document_category: str = Form(default=""),
    priority: int = Form(default=1),
    assignee: str = Form(default=""),
    worker_profile: str = Form(default="default"),
    files: list[UploadFile] = File(default=[]),
):
    guard = require_auth(request)
    if guard:
        return guard
    query = query.strip()
    workflow = normalize_workflow(workflow)
    title = title.strip()
    document_category = document_category.strip()
    if not query:
        return render(request, active_page="research", selected_workflow=workflow, error="Research task prompt is required")
    if not document_category:
        return render(request, active_page="research", selected_workflow=workflow, search_query=query, error="Choose a final document category.")

    saved_paths = save_uploads(files)
    user = current_user(request)
    if workflow == "malware-analysis" and not saved_paths:
        return render(
            request,
            active_page="research",
            selected_workflow=workflow,
            search_query=query,
            error="Malware analysis requires at least one uploaded sample file.",
        )

    description_lines = [query]
    if workflow == "malware-analysis":
        description_lines.extend([
            "",
            "Portal context:",
            "RAIccoon Local Sandbox sandbox was queued by the portal for every uploaded sample and will dispatch the Hermes worker only after sandbox artifacts are ready.",
            "The final report must include static analysis, GhidraMCP/Ghidra code analysis/reversing, and RAIccoon Local Sandbox dynamic analysis evidence lanes.",
        ])
    if not title:
        title = preview(query.replace("\n", " "), 72)
    task_id = create_portal_task(
        title=title,
        description="\n".join(description_lines).strip(),
        priority=priority,
        requested_by=user["username"],
        assignee=assignee,
        worker_profile=worker_profile,
        task_type="research",
        source_page="research",
        research_workflow=workflow,
        document_category=document_category,
        uploaded_files="|".join(saved_paths),
    )
    task = fetch_portal_task(task_id)
    if task is None:
        return render(request, active_page="research", selected_workflow=workflow, search_query=query, error="Research task was created but could not be loaded.")

    if workflow == "malware-analysis":
        queue_malware_sandbox_task(task_id, saved_paths, user["username"])
        response_text = f"Queued malware-analysis task '{title}' as portal task #{task_id}. RAIccoon Local Sandbox is running all uploaded samples in the background; Hermes Kanban dispatch will start only if sandbox prep succeeds."
        execute(
            "INSERT INTO searches (query, response, uploaded_files, workflow, created_at, duration_seconds, requested_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [query, response_text, "|".join(saved_paths), workflow, now_utc().isoformat(), 0.0, user["username"]],
        )
        add_task_history(task_id, "sandbox_queued", user["username"], f"RAIccoon Local Sandbox sandbox queued in the background for {len(saved_paths)} sample(s) before Hermes dispatch.", source="raiccoon")
        return render(
            request,
            active_page="research",
            search_result=response_text,
            search_query=query,
            selected_workflow=workflow,
            message=f"Research task #{task_id} created. RAIccoon Local Sandbox is running every uploaded sample in the background; this page no longer waits on the VM.",
        )

    try:
        snapshot = move_portal_task_to_in_progress(task, user["username"])
        linked_id = (snapshot.get("id") if snapshot else None) or task["kanban_task_id"] or ""
        response_text = f"Queued research task '{title}' as portal task #{task_id}. Hermes task: {linked_id or 'pending dispatch'}. Final PDF will be generated into {IN_REVIEW_DIR} after the worker completes."
        execute(
            "INSERT INTO searches (query, response, uploaded_files, workflow, created_at, duration_seconds, requested_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [query, response_text, "|".join(saved_paths), workflow, now_utc().isoformat(), 0.0, user["username"]],
        )
        return render(
            request,
            active_page="research",
            search_result=response_text,
            search_query=query,
            selected_workflow=workflow,
            message=f"Research task #{task_id} created, moved to In Progress, and dispatched to Hermes Kanban.",
        )
    except Exception as exc:  # noqa: BLE001
        add_task_history(task_id, "dispatch_error", user["username"], f"Automatic Kanban dispatch failed: {exc}")
        execute("UPDATE portal_tasks SET status = 'todo', updated_at = ? WHERE id = ?", [now_utc().isoformat(), task_id])
        return render(
            request,
            active_page="research",
            search_query=query,
            selected_workflow=workflow,
            error=f"Research task #{task_id} was created but could not be dispatched automatically: {exc}",
            message=f"Task #{task_id} was left in Todo for manual retry from the Tasks page.",
        )


@app.post("/costs", response_class=HTMLResponse)
def create_cost(
    request: Request,
    provider: str = Form(...),
    model: str = Form(...),
    category: str = Form(...),
    amount_usd: float = Form(...),
    period_start: str = Form(...),
    notes: str = Form(default=""),
):
    guard = require_auth(request)
    if guard:
        return guard
    add_cost_entry(provider.strip(), model.strip(), category.strip(), amount_usd, period_start, notes.strip(), "manual")
    return render(request, active_page="costs", message="Manual AI cost entry added.")


@app.post("/costs/import", response_class=HTMLResponse)
def upload_cost_csv(request: Request, csv_file: UploadFile = File(...)):
    guard = require_auth(request)
    if guard:
        return guard
    count, _ = import_cost_csv(csv_file)
    return render(request, active_page="costs", message=f"Imported {count} cost rows from CSV.")


@app.post("/costs/sync/openai", response_class=HTMLResponse)
def sync_openai_costs(request: Request, days: int = Form(default=30)):
    guard = require_auth(request)
    if guard:
        return guard
    try:
        imported = fetch_openai_costs(days=days)
        if imported == 0 and not (os.getenv("OPENAI_ADMIN_API_KEY") or os.getenv("OPENAI_API_KEY")):
            return render(request, active_page="costs", error="OpenAI sync skipped: no API key configured. CSV/manual import is still available.")
        return render(request, active_page="costs", message=f"OpenAI sync imported {imported} entries.")
    except Exception as exc:  # noqa: BLE001
        log_cost_sync("OpenAI", "error", str(exc), 0)
        return render(request, active_page="costs", error=f"OpenAI sync failed: {exc}")


@app.post("/works", response_class=HTMLResponse)
def create_work(
    request: Request,
    title: str = Form(...),
    status: str = Form(...),
    outlet: str = Form(...),
    publication_date: str = Form(...),
    due_date: str = Form(default=""),
    owner: str = Form(default=""),
    artifact_type: str = Form(default="report"),
    audience: str = Form(default="internal"),
    tags: str = Form(default=""),
    url: str = Form(default=""),
    notes: str = Form(default=""),
):
    guard = require_auth(request)
    if guard:
        return guard
    execute(
        """
        INSERT INTO published_works (
            title, status, outlet, url, publication_date, due_date, owner,
            artifact_type, audience, tags, notes, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            title.strip(),
            status.strip(),
            outlet.strip(),
            url.strip(),
            publication_date,
            due_date.strip(),
            owner.strip(),
            artifact_type.strip(),
            audience.strip(),
            tags.strip(),
            notes.strip(),
            now_utc().isoformat(),
            now_utc().isoformat(),
        ],
    )
    return render(request, active_page="works", message="Published-work record added.")


@app.post("/tasks", response_class=HTMLResponse)
def create_task(
    request: Request,
    title: str = Form(...),
    description: str = Form(default=""),
    priority: int = Form(default=0),
    assignee: str = Form(default=""),
    worker_profile: str = Form(default="default"),
    task_type: str = Form(default="general"),
    research_workflow: str = Form(default="general"),
    document_category: str = Form(default=""),
    due_date: str = Form(default=""),
    sla_hours: int = Form(default=0),
    acceptance_criteria: str = Form(default=""),
    parent_task_id: int = Form(default=0),
):
    guard = require_auth(request)
    if guard:
        return guard
    title = title.strip()
    if not title:
        return render(request, active_page="tasks", error="Task title is required.")
    user = current_user(request)
    task_id = create_portal_task(
        title=title,
        description=description,
        priority=priority,
        requested_by=user["username"],
        assignee=assignee,
        worker_profile=worker_profile,
        task_type=task_type,
        research_workflow=research_workflow,
        document_category=document_category,
        due_date=due_date,
        sla_hours=sla_hours,
        parent_task_id=parent_task_id,
        acceptance_criteria=acceptance_criteria,
    )
    task = fetch_portal_task(task_id)
    if task is not None:
        try:
            move_portal_task_to_in_progress(task, user["username"])
        except Exception as exc:  # noqa: BLE001
            add_task_history(task_id, "dispatch_error", user["username"], f"Automatic Kanban dispatch failed: {exc}")
            return render(
                request,
                active_page="tasks",
                error=f"Task #{task_id} was created but could not be dispatched automatically: {exc}",
                message="Task was left in Todo for retry from the Tasks board.",
                selected_task_id=task_id,
            )
    return RedirectResponse(url=f"/tasks#task-{task_id}", status_code=303)


@app.get("/tasks/board-data")
def tasks_board_data(request: Request):
    if not authenticated(request):
        return JSONResponse({"ok": False, "error": "Authentication required."}, status_code=401)
    filters = {key: request.query_params.get(key, "") for key in ("q", "status", "assignee", "workflow", "source", "kanban", "qa", "client", "stale")}
    return JSONResponse({"ok": True, **task_board_payload(filters=filters)})


@app.get("/workflow-data")
def workflow_data(request: Request):
    if not authenticated(request):
        return JSONResponse({"ok": False, "error": "Authentication required."}, status_code=401)
    query_params = getattr(request, "query_params", {})
    filters = {key: query_params.get(key, "") for key in ("q", "status", "assignee", "workflow", "source", "kanban", "qa", "client", "stale")}
    board_payload = task_board_payload(filters=filters)
    active_page = query_params.get("active", "dashboard") if hasattr(query_params, "get") else "dashboard"
    return JSONResponse({"ok": True, "workflow": workflow_context(active_page, board_payload), "board": board_payload})


@app.post("/tasks/bulk")
def bulk_update_tasks(
    request: Request,
    task_ids: list[int] = Form(default=[]),
    action: str = Form(default=""),
    assignee: str = Form(default=""),
    comment: str = Form(default=""),
    status: str = Form(default=""),
    priority: int = Form(default=0),
    due_date: str = Form(default=""),
    blocked_reason: str = Form(default=""),
):
    if not authenticated(request):
        return JSONResponse({"ok": False, "error": "Authentication required."}, status_code=401)
    user = current_user(request)
    normalized_action = (action or "").strip().lower()
    normalized_ids = sorted({int(task_id) for task_id in task_ids if int(task_id or 0) > 0})
    if not normalized_ids:
        return JSONResponse({"ok": False, "error": "Select at least one task."}, status_code=400)
    updated_count = 0
    for task_id in normalized_ids:
        task = fetch_portal_task(task_id)
        if not task:
            continue
        if normalized_action == "assign":
            updated = update_task_ownership(task, assignee, task["worker_profile"], user["username"])
            updated_count += 1 if updated else 0
        elif normalized_action == "comment":
            if not comment.strip():
                return JSONResponse({"ok": False, "error": "Comment text is required."}, status_code=400)
            add_comment_to_task(task_id, user["username"], comment)
            updated_count += 1
        elif normalized_action == "block":
            reason = (blocked_reason or comment or "Blocked by operator.").strip()
            stamp = now_utc().isoformat()
            execute(
                "UPDATE portal_tasks SET status = 'blocked', blocked_reason = ?, blocked_at = ?, updated_at = ? WHERE id = ?",
                [reason, stamp, stamp, task_id],
            )
            add_task_history(task_id, "blocked", user["username"], f"Blocked task: {reason}")
            create_notification("task_blocked", f"Task blocked: {task['title']}", reason, task_id=task_id, notification_key=f"task-blocked:{task_id}:{hashlib.sha256(reason.encode('utf-8')).hexdigest()[:12]}")
            updated_count += 1
        elif normalized_action == "move":
            target_status = normalize_portal_task_status(status)
            if target_status not in PORTAL_TASK_FLOW.get(task["status"], set()):
                return JSONResponse({"ok": False, "error": f"Cannot move task #{task_id} from {task['status']} to {target_status}."}, status_code=409)
            updated = update_portal_task_status(task_id, target_status, user["username"])
            updated_count += 1 if updated else 0
        elif normalized_action == "set_priority":
            execute("UPDATE portal_tasks SET priority = ?, updated_at = ? WHERE id = ?", [int(priority), now_utc().isoformat(), task_id])
            add_task_history(task_id, "priority", user["username"], f"Set priority to {int(priority)}.")
            updated_count += 1
        elif normalized_action == "set_due_date":
            normalized_due = normalize_due_date(due_date)
            execute("UPDATE portal_tasks SET due_date = ?, updated_at = ? WHERE id = ?", [normalized_due, now_utc().isoformat(), task_id])
            add_task_history(task_id, "due_date", user["username"], f"Set due date to {normalized_due or 'none'}.")
            updated_count += 1
        else:
            return JSONResponse({"ok": False, "error": "Unknown bulk action."}, status_code=400)
    board_payload = task_board_payload()
    return JSONResponse({"ok": True, "updated_count": updated_count, "message": f"Updated {updated_count} task(s).", **board_payload})


@app.get("/intel-ops-data")
def intel_ops_data(request: Request):
    if not authenticated(request):
        return JSONResponse({"ok": False, "error": "Authentication required."}, status_code=401)
    return JSONResponse({"ok": True, **intel_ops_summary()})


@app.get("/detections-data")
def detections_data(request: Request, q: str = ""):
    if not authenticated(request):
        return JSONResponse({"ok": False, "error": "Authentication required."}, status_code=401)
    return JSONResponse({"ok": True, **analyst_detection_library(query=q, limit=100)})


@app.post("/intel-ops/daily-brief")
def generate_daily_intel_brief_route(request: Request):
    if not authenticated(request):
        return JSONResponse({"ok": False, "error": "Authentication required."}, status_code=401)
    artifact = generate_daily_intel_brief_artifact()
    return JSONResponse({"ok": True, **artifact})


@app.post("/opencti/curation/import")
def import_opencti_curation_route(request: Request):
    if not authenticated(request):
        return JSONResponse({"ok": False, "error": "Authentication required."}, status_code=401)
    if not admin_authenticated(request):
        return JSONResponse({"ok": False, "error": "Admin role required."}, status_code=403)
    user = current_user(request)
    result = import_opencti_curation_candidates(requested_by=user["username"])
    add_audit_log(user["username"], "opencti_curation_import", "opencti", "curation", json.dumps(result, sort_keys=True))
    return JSONResponse({"ok": True, **result})


@app.post("/opencti/uploads/queue")
def queue_opencti_upload_route(request: Request):
    if not authenticated(request):
        return JSONResponse({"ok": False, "error": "Authentication required."}, status_code=401)
    if not admin_authenticated(request):
        return JSONResponse({"ok": False, "error": "Admin role required."}, status_code=403)
    user = current_user(request)
    result = queue_opencti_upload_tasks(requested_by=user["username"])
    add_audit_log(user["username"], "opencti_upload_queue", "opencti", "uploads", json.dumps(result, sort_keys=True))
    return JSONResponse({"ok": True, **result})


@app.post("/opencti/uploads/reconcile")
def reconcile_opencti_upload_route(request: Request):
    if not authenticated(request):
        return JSONResponse({"ok": False, "error": "Authentication required."}, status_code=401)
    if not admin_authenticated(request):
        return JSONResponse({"ok": False, "error": "Admin role required."}, status_code=403)
    user = current_user(request)
    result = reconcile_opencti_upload_results(actor=user["username"])
    add_audit_log(user["username"], "opencti_upload_reconcile", "opencti", "uploads", json.dumps(result, sort_keys=True))
    return JSONResponse({"ok": True, **result})


@app.post("/registry/remediation/queue")
def queue_registry_remediation_route(request: Request):
    if not authenticated(request):
        return JSONResponse({"ok": False, "error": "Authentication required."}, status_code=401)
    if not admin_authenticated(request):
        return JSONResponse({"ok": False, "error": "Admin role required."}, status_code=403)
    user = current_user(request)
    result = queue_registry_remediation_tasks(requested_by=user["username"])
    add_audit_log(user["username"], "registry_remediation_queue", "registry", "analyst-kit", json.dumps({"created_count": result["created_count"], "skipped_existing_count": result["skipped_existing_count"]}, sort_keys=True))
    return JSONResponse({"ok": True, **result})


@app.post("/clients", response_class=HTMLResponse)
def create_client_profile_route(
    request: Request,
    org_alias: str = Form(...),
    sector: str = Form(default=""),
    priority_requirements: str = Form(default=""),
    technologies: str = Form(default=""),
    delivery_cadence: str = Form(default=""),
    allowed_tlp: str = Form(default="TLP:AMBER"),
    opencti_collections: str = Form(default=""),
    notes: str = Form(default=""),
):
    guard = require_auth(request)
    if guard:
        return guard
    try:
        if not admin_authenticated(request):
            return render(request, active_page="clients", error="Admin role required to create or change private client profiles.")
        user = current_user(request)
        client_id = create_client_profile(
            org_alias=org_alias,
            sector=sector,
            priority_requirements=priority_requirements,
            technologies=technologies,
            delivery_cadence=delivery_cadence,
            allowed_tlp=allowed_tlp,
            opencti_collections=opencti_collections,
            notes=notes,
        )
        add_audit_log(user["username"], "client_profile_create", "client_profile", client_id, org_alias.strip())
    except ValueError as exc:
        return render(request, active_page="clients", error=str(exc))
    return render(request, active_page="clients", message="Private client readiness profile saved.")


@app.get("/clients/{client_profile_id}/export")
def export_client_engagement(request: Request, client_profile_id: int):
    if not authenticated(request):
        return JSONResponse({"ok": False, "error": "Authentication required."}, status_code=401)
    try:
        return JSONResponse({"ok": True, **client_engagement_export(client_profile_id)})
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=404)


@app.get("/clients/{client_profile_id}/brief")
def client_brief_data(request: Request, client_profile_id: int):
    if not authenticated(request):
        return JSONResponse({"ok": False, "error": "Authentication required."}, status_code=401)
    try:
        return JSONResponse({"ok": True, **build_client_brief(client_profile_id)})
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=404)


@app.post("/tasks/{task_id}/client", response_class=HTMLResponse)
def update_task_client_route(request: Request, task_id: int, client_profile_id: int = Form(default=0)):
    guard = require_auth(request)
    if guard:
        return guard
    user = current_user(request)
    try:
        update_task_client_association(task_id, client_profile_id, actor=user["username"])
        add_audit_log(user["username"], "task_client_association_update", "portal_task", task_id, f"client_profile_id={client_profile_id}")
    except ValueError as exc:
        return render(request, active_page="tasks", error=str(exc), selected_task_id=task_id)
    return render(request, active_page="tasks", message="Task client association updated.", selected_task_id=task_id)


@app.post("/tasks/{task_id}/comments", response_class=HTMLResponse)
def add_task_comment_route(request: Request, task_id: int, comment: str = Form(...)):
    guard = require_auth(request)
    if guard:
        return guard
    task = fetch_portal_task(task_id)
    if not task:
        return render(request, active_page="tasks", error="Task not found.")
    if not comment.strip():
        return render(request, active_page="tasks", error="Comment text is required.", selected_task_id=task_id)
    user = current_user(request)
    add_comment_to_task(task_id, user["username"], comment)
    return render(request, active_page="tasks", message="Comment added.", selected_task_id=task_id)


@app.post("/tasks/{task_id}/ownership", response_class=HTMLResponse)
def update_task_ownership_route(
    request: Request,
    task_id: int,
    assignee: str = Form(default=""),
    worker_profile: str = Form(default="default"),
    task_type: str = Form(default="general"),
    research_workflow: str = Form(default="general"),
    document_category: str = Form(default=""),
):
    guard = require_auth(request)
    if guard:
        return guard
    task = fetch_portal_task(task_id)
    if not task:
        return render(request, active_page="tasks", error="Task not found.")
    user = current_user(request)
    try:
        update_task_ownership(
            task,
            assignee,
            worker_profile,
            user["username"],
            task_type=task_type,
            research_workflow=research_workflow,
            document_category=document_category,
        )
        return render(request, active_page="tasks", message="Task routing updated.", selected_task_id=task_id)
    except Exception as exc:  # noqa: BLE001
        return render(request, active_page="tasks", error=str(exc), selected_task_id=task_id)


@app.post("/tasks/{task_id}/review", response_class=HTMLResponse)
def update_task_review_route(
    request: Request,
    task_id: int,
    review_notes: str = Form(default=""),
    reviewer_signoff: str = Form(default=""),
):
    guard = require_auth(request)
    if guard:
        return guard
    task = fetch_portal_task(task_id)
    if not task:
        return render(request, active_page="tasks", error="Task not found.")
    user = current_user(request)
    update_task_review(task, review_notes, False, user["username"])
    message = "Review notes saved."
    return render(request, active_page="tasks", message=message, selected_task_id=task_id)


@app.post("/tasks/{task_id}/approve-publish")
def approve_and_publish_task(
    request: Request,
    task_id: int,
    review_notes: str = Form(default=""),
    reviewer_signoff: str = Form(default=""),
):
    if not authenticated(request):
        return JSONResponse({"ok": False, "error": "Authentication required."}, status_code=401)
    sync_portal_tasks_with_kanban()
    task = fetch_portal_task(task_id)
    if not task:
        return JSONResponse({"ok": False, "error": "Task not found."}, status_code=404)
    if normalize_portal_task_status(task["status"]) != "in_review":
        return JSONResponse({"ok": False, "error": "Publish is only available once the task is in In Review."}, status_code=409)

    user = current_user(request)
    submitted_notes = review_notes.strip()
    existing_notes = (task["review_notes"] or "").strip()
    normalized_notes = submitted_notes or existing_notes or "Published via one-click portal action."

    try:
        updated_review = update_task_review(task, normalized_notes, False, user["username"])
        quality: dict = {}
        quality_override = False
        if task_is_research(updated_review):
            quality = task_report_quality(updated_review)
            quality_override = not quality.get("pass_gate")
        ok, reason = validate_task_transition(updated_review, "accepted", allow_quality_override=True)
        if not ok:
            return JSONResponse({"ok": False, "error": reason}, status_code=409)
        if quality_override:
            add_task_history(
                task_id,
                "quality_override",
                user["username"],
                f"Manual QA override approved publication despite report quality gate failure ({quality.get('score', 0)}/100). Missing/weak checks: {', '.join(quality.get('missing_required') or []) or 'insufficient report depth'}.",
            )
        updated = update_portal_task_status(task_id, "accepted", user["username"])
        board_payload = task_board_payload()
        final_document_path = updated["final_document_path"] if updated else ""
        message = f"Task published. Final PDF moved to {final_document_path}."
        if quality_override:
            message = f"Manual QA override accepted. {message}"
        return JSONResponse(
            {
                "ok": True,
                "task_id": task_id,
                "status": updated["status"] if updated else "accepted",
                "message": message,
                "fingerprint": board_payload["fingerprint"],
                "has_active_tasks": board_payload["has_active_tasks"],
            }
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@app.post("/tasks/{task_id}/move")
def move_task(request: Request, task_id: int, status: str = Form(...)):
    if not authenticated(request):
        return JSONResponse({"ok": False, "error": "Authentication required."}, status_code=401)
    sync_portal_tasks_with_kanban()
    task = fetch_portal_task(task_id)
    if not task:
        return JSONResponse({"ok": False, "error": "Task not found."}, status_code=404)
    target_status = normalize_portal_task_status(status)
    allow_quality_override = target_status == "accepted" and task_is_research(task)
    quality_override = False
    quality: dict = {}
    if allow_quality_override:
        quality = task_report_quality(task)
        quality_override = not quality.get("pass_gate")
    ok, reason = validate_task_transition(task, target_status, allow_quality_override=allow_quality_override)
    if not ok:
        return JSONResponse({"ok": False, "error": reason}, status_code=409)

    user = current_user(request)
    try:
        if target_status == "in_progress":
            snapshot = move_portal_task_to_in_progress(task, user["username"])
            updated = fetch_portal_task(task_id)
            board_payload = task_board_payload(task_id)
            message = "Task moved to In Progress and dispatched to Hermes Kanban."
            if normalize_portal_task_status(task["status"]) == "in_review":
                message = "Task sent back to In Progress for revision and dispatched as a fresh Hermes run with the saved comments/review notes."
            return JSONResponse(
                {
                    "ok": True,
                    "task_id": task_id,
                    "status": updated["status"] if updated else target_status,
                    "kanban_task_id": (updated["kanban_task_id"] if updated else "") or "",
                    "kanban_status": (snapshot.get("status") if snapshot else "") or "",
                    "message": message,
                    "fingerprint": board_payload["fingerprint"],
                    "has_active_tasks": board_payload["has_active_tasks"],
                }
            )

        if quality_override:
            add_task_history(
                task_id,
                "quality_override",
                user["username"],
                f"Manual QA override approved publication despite report quality gate failure ({quality.get('score', 0)}/100). Missing/weak checks: {', '.join(quality.get('missing_required') or []) or 'insufficient report depth'}.",
            )
        updated = update_portal_task_status(task_id, target_status, user["username"])
        refreshed = fetch_kanban_task_snapshot(updated["kanban_task_id"]) if updated and updated["kanban_task_id"] else None
        if refreshed:
            execute(
                "UPDATE portal_tasks SET kanban_status = ?, last_result = ?, updated_at = ? WHERE id = ?",
                [
                    refreshed.get("status") or "",
                    (refreshed.get("latest_summary") or refreshed.get("result") or refreshed.get("last_failure_error") or "").strip(),
                    now_utc().isoformat(),
                    task_id,
                ],
            )
        updated = fetch_portal_task(task_id)
        board_payload = task_board_payload(task_id)
        message = f"Task moved to {PORTAL_TASK_LABELS[target_status]}."
        if updated and target_status == "accepted" and updated["final_document_path"]:
            message = f"Task published. Final PDF moved to {updated['final_document_path']} and published-work tracking was updated."
        if quality_override:
            message = f"Manual QA override accepted. {message}"
        return JSONResponse(
            {
                "ok": True,
                "task_id": task_id,
                "status": updated["status"] if updated else target_status,
                "kanban_task_id": (updated["kanban_task_id"] if updated else "") or "",
                "kanban_status": (refreshed.get("status") if refreshed else (updated["kanban_status"] if updated else "")) or "",
                "message": message,
                "fingerprint": board_payload["fingerprint"],
                "has_active_tasks": board_payload["has_active_tasks"],
            }
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@app.get("/export/searches")
def export_searches(request: Request):
    guard = require_auth(request)
    if guard:
        return guard
    rows = fetch_all("SELECT * FROM searches ORDER BY id DESC")
    return [dict(row) for row in rows]


@app.get("/export/costs")
def export_costs(request: Request):
    guard = require_auth(request)
    if guard:
        return guard
    rows = fetch_all("SELECT * FROM ai_costs ORDER BY id DESC")
    return [dict(row) for row in rows]


@app.get("/export/works")
def export_works(request: Request):
    guard = require_auth(request)
    if guard:
        return guard
    rows = fetch_all("SELECT * FROM published_works ORDER BY id DESC")
    return [dict(row) for row in rows]


@app.get("/export/sync-runs")
def export_sync_runs(request: Request):
    guard = require_auth(request)
    if guard:
        return guard
    rows = fetch_all("SELECT * FROM cost_sync_runs ORDER BY id DESC")
    return [dict(row) for row in rows]


@app.get("/export/audit-logs")
def export_audit_logs(request: Request):
    if not authenticated(request):
        return JSONResponse({"ok": False, "error": "Authentication required."}, status_code=401)
    if not admin_authenticated(request):
        return JSONResponse({"ok": False, "error": "Admin role required."}, status_code=403)
    return JSONResponse({"export": "portal_audit_log", "rows": fetch_audit_logs(limit=1000)})


def nl2br(text: str) -> str:
    return html.escape(text).replace("\n", "<br>")


def basename(value: str) -> str:
    return Path(value).name if value else ""


def pretty_dt(value: str) -> str:
    if not value:
        return "—"
    return value.replace("T", " ")[:19]


def short_tags(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def preview(value: str, limit: int = 220) -> str:
    text = (value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


templates.env.filters["nl2br"] = nl2br
templates.env.filters["basename"] = basename
templates.env.filters["pretty_dt"] = pretty_dt
templates.env.filters["short_tags"] = short_tags
templates.env.filters["preview"] = preview


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("SECOPS_PORTAL_HOST", "127.0.0.1")
    port = int(os.getenv("SECOPS_PORTAL_PORT", "8008"))
    uvicorn.run("app:app", host=host, port=port, reload=False)
