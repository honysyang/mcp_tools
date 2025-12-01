"""
multi_func_security_mcp.py

Enhanced MCP tool with logging to file and HTTP API access for findings and tasks.
Preserves all logs including MCP tool calls and allows real-time access via HTTP.

Features:
- 5 core tools: log_analysis, security_check, traceability_analysis, baseline_check, miner_analysis
- Tool manifest exposed at /api/tools_manifest
- Task orchestration, decision engine, feedback/event SSE stream
- Visualization endpoints (HTML dashboard, JSON APIs)
- Safe subprocess handling and robust psutil usage
- Graceful degradation if optional libs (fastmcp, whois, aiohttp) are missing
- Robust parameter normalization
- Debounce/inflight protection and cooldown for followups
- Graceful shutdown of web runner, MCP thread and executor
- Safe MCP tool wrappers and MCP runner with exponential backoff
- **NEW**: Comprehensive logging to 'mcp.log' file
- **NEW**: HTTP API endpoints for real-time access to findings and tasks
- **NEW**: Real-time event stream accessible via HTTP
"""
from __future__ import annotations
import asyncio
import concurrent.futures
import json
import logging
import os
import re
import sys
import time
import threading
import hashlib
import glob
import subprocess
import shlex
import traceback
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import signal
from base64 import b64encode
from aiohttp import web, BasicAuth

# Optional external libs
try:
    from mcp.server.fastmcp import FastMCP
except Exception:
    FastMCP = None
    print("Warning: fastmcp not available. MCP server will be disabled.", file=sys.stderr)

try:
    import whois
except Exception:
    whois = None
    print("Warning: python-whois not available. Whois lookups will be disabled.", file=sys.stderr)

try:
    from aiohttp import web
except Exception:
    web = None
    print("Warning: aiohttp not available. Web UI will be disabled.", file=sys.stderr)

import psutil
import yaml

# ----------------------------
# Logging Setup (to file and console)
# ----------------------------
logger = logging.getLogger("multi-security-mcp")
if not logger.handlers:
    # Create a file handler
    file_handler = logging.FileHandler("mcp.log", mode='a', encoding='utf-8')
    file_formatter = logging.Formatter(
        "[%(levelname)s] %(asctime)s [%(name)s.%(module)s.%(funcName)s:%(lineno)d] %(message)s"
    )
    file_handler.setFormatter(file_formatter)
    
    # Create a console handler
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter(
        "[%(levelname)s] %(asctime)s [%(name)s.%(module)s.%(funcName)s:%(lineno)d] %(message)s"
    )
    console_handler.setFormatter(console_formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

# The level will be set later based on command-line args
logger.setLevel(logging.INFO) # Default to INFO

# Also configure the root logger or other potentially chatty loggers if needed
logging.getLogger("mcp").setLevel(logging.DEBUG) # Example: if MCP library has its own logger
logging.getLogger("aiohttp").setLevel(logging.WARNING) # Example: reduce aiohttp verbosity if desired

# ----------------------------
# Defaults / IOCs / Baseline
# ----------------------------
@dataclass
class SecurityIOCs:
    MINER_PROCS: List[str] = field(default_factory=lambda: [r"xmrig", r"progpowz", r"rigel", r"dns-filter"])
    MINER_CMD_PATTERNS: List[str] = field(default_factory=lambda: [r"stratum\+tcp:", r"-u [A-Za-z0-9]{30,}"])
    MINER_PATHS: List[str] = field(default_factory=lambda: [r"/tmp/.*", r"/var/tmp/.*"])
    MINER_POOLS: List[str] = field(default_factory=lambda: ["eu.zano.k1pool.com", "gulf.moneroocean.stream"])
    STRATUM_PORTS: Set[int] = field(default_factory=lambda: {3333, 4444, 5555, 8866})
    MALICIOUS_SCRIPTS: List[str] = field(default_factory=lambda: [r"mon1\.sh", r"xd\.sh"])
    MALICIOUS_SOURCES: List[str] = field(default_factory=lambda: [r"45\.61\.150\.83"])
    VULN_PORTS: Dict[str, str] = field(default_factory=lambda: {"8265": "CVE-2024-57000 (Ray RCE)", "22": "SSH risk"})
    VULN_PROCS: List[str] = field(default_factory=lambda: [r"ray", r"python3.*ray"])
    LOG_ABNORMAL_KEYWORDS: List[str] = field(default_factory=lambda: ["Failed password", "Invalid user", "crontab changed", "permission denied"])

IOCS = SecurityIOCs()

SECURITY_BASELINE = {
    "user_management": {"min_password_length": 12, "disable_root_ssh_login": True, "no_empty_password": True},
    "file_permissions": {"/etc/passwd": 0o644, "/etc/shadow": 0o000},
    "service_management": {"forbidden_services": ["telnet", "rsh", "ftp"], "required_services": ["ssh"]},
    "network_security": {"allow_icmp_echo": False, "tcp_syncookies": True}
}

# ----------------------------
# Authentication Configuration
# ----------------------------
AUTH_USER = "admin" # Default user
AUTH_PASS = "password" # Default password
AUTH_CREDENTIALS = None # Will be set later based on args

# ----------------------------
# Utilities
# ----------------------------
def safe_hash(file_path: str, algo: str = "sha256") -> Optional[str]:
    try:
        if not os.path.isfile(file_path):
            logger.debug("File does not exist for hashing: %s", file_path)
            return None
        algo = algo.lower()
        if algo not in hashlib.algorithms_available:
            algo = "sha256"
        h = hashlib.new(algo)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        logger.debug("Hashed file %s using %s", file_path, algo)
        return h.hexdigest()
    except Exception:
        logger.exception("safe_hash failed for %s", file_path)
        return None

def match_patterns(patterns: List[str], text: str, case_insensitive: bool = True) -> Tuple[bool, List[str]]:
    if not text:
        logger.debug("Empty text provided for pattern matching.")
        return False, []
    flags = re.IGNORECASE if case_insensitive else 0
    matches = []
    for p in patterns:
        try:
            compiled_p = re.compile(p, flags=flags)
            if compiled_p.search(text):
                matches.append(p)
        except re.error:
            logger.warning("Invalid regex pattern '%s', falling back to string search.", p)
            try:
                if (p.lower() in text.lower()) if case_insensitive else (p in text):
                    matches.append(p)
            except Exception:
                continue
    found = bool(matches)
    if found:
        logger.debug("Pattern match found in text: %s", matches)
    return found, matches

def execute_command_safe(cmd: Any, timeout: int = 10) -> Tuple[int, str, str]:
    """
    Execute a subprocess command safely. Accepts list or string.
    Returns (rc, stdout, stderr). Does not raise on failure.
    Logs command execution.
    """
    if not cmd:
        logger.warning("No command provided to execute_command_safe.")
        return -1, "", "no command"
    if isinstance(cmd, str):
        try:
            cmd_list = shlex.split(cmd)
        except Exception as e:
            logger.error("Failed to split command string '%s': %s", cmd, e)
            cmd_list = [cmd]
    else:
        cmd_list = list(cmd)
    
    logger.debug("Executing command: %s with timeout %d", cmd_list, timeout)
    try:
        proc = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout, check=False)
        logger.debug("Command '%s' completed with return code %d", cmd_list, proc.returncode)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        logger.warning("Command '%s' timed out after %ds", cmd_list, timeout)
        return -1, "", f"timeout after {timeout}s"
    except FileNotFoundError:
        logger.error("Command not found: %s", cmd_list[0] if cmd_list else '')
        return -127, "", f"command not found: {cmd_list[0] if cmd_list else ''}"
    except Exception as e:
        logger.exception("Failed to execute command '%s': %s", cmd_list, e)
        return -2, "", str(e)

def whois_lookup(entity: str) -> Optional[Dict[str, Any]]:
    if not whois:
        logger.debug("Whois library not available, skipping lookup for %s", entity)
        return None
    try:
        logger.debug("Performing whois lookup for %s", entity)
        w = whois.whois(entity)
        if isinstance(w, dict):
            result = {"registrar": w.get("registrar"), "creation_date": str(w.get("creation_date")), "country": w.get("country")}
        else:
            result = {"registrar": getattr(w, "registrar", None)}
        logger.debug("Whois lookup for %s successful: %s", entity, result)
        return result
    except Exception:
        logger.exception("Whois lookup failed for %s", entity)
        return None

def expand_path_patterns(pattern: str) -> List[str]:
    logger.debug("Expanding path pattern: %s", pattern)
    p = os.path.expanduser(pattern)
    gl = glob.glob(p)
    expanded = [x for x in gl if os.path.exists(x)]
    logger.debug("Expanded pattern %s to %s", pattern, expanded)
    return expanded

# ----------------------------
# Parameter normalization (robust)
# ----------------------------
def _deep_unwrap_params(obj: Any) -> Any:
    """
    Recursively unwrap common wrappers:
    - JSON string -> parse
    - dict with keys 'kwargs'/'parameters'/'params'/'payload' -> unwrap
    """
    logger.debug("Unwrapping parameters: %s", type(obj))
    if isinstance(obj, str):
        s = obj.strip()
        if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
            try:
                parsed = json.loads(s)
                logger.debug("Parsed string parameter to: %s", parsed)
                return parsed
            except Exception:
                logger.debug("Failed to parse string parameter as JSON: %s", s)
                return obj
        return obj

    if isinstance(obj, dict):
        for wrapper in ("kwargs", "parameters", "params", "payload"):
            if wrapper in obj:
                logger.debug("Found wrapper key '%s', unwrapping.", wrapper)
                return _deep_unwrap_params(obj[wrapper])
        return obj

    return obj

def normalize_to_kwargs(obj: Any) -> Dict[str, Any]:
    """
    Return a dict that can be safely used as keyword args.
    Handles nested wrappers and JSON-encoded strings.
    Logs normalization process.
    """
    logger.debug("Normalizing parameters: %s", obj)
    try:
        if obj is None:
            logger.debug("Parameter object is None, returning empty dict.")
            return {}
        unwrapped = _deep_unwrap_params(obj)
        if isinstance(unwrapped, dict):
            res: Dict[str, Any] = {}
            for k, v in unwrapped.items():
                if isinstance(v, str):
                    s = v.strip()
                    if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
                        try:
                            parsed = json.loads(s)
                            res[k] = parsed
                            logger.debug("Parsed value for key '%s' from string to JSON object.", k)
                            continue
                        except Exception:
                            logger.debug("Failed to parse value for key '%s' as JSON, keeping as string.", k)
                res[k] = v
            logger.debug("Normalized parameters to: %s", res)
            return res
        if isinstance(unwrapped, str):
            try:
                parsed = json.loads(unwrapped)
                if isinstance(parsed, dict):
                    logger.debug("Parsed entire parameter string to JSON object: %s", parsed)
                    return parsed
            except Exception:
                logger.debug("Failed to parse entire parameter string as JSON.")
        if isinstance(obj, dict):
            cleaned = {k: v for k, v in obj.items() if k not in ("kwargs", "parameters", "params", "payload")}
            for k, v in list(cleaned.items()):
                if isinstance(v, str):
                    try:
                        cleaned[k] = json.loads(v)
                        logger.debug("Parsed value for key '%s' from string to JSON object within cleaned dict.", k)
                    except Exception:
                        logger.debug("Failed to parse value for key '%s' as JSON, keeping as string.", k)
                        pass
            logger.debug("Cleaned and processed dict parameters: %s", cleaned)
            return cleaned
    except Exception:
        logger.exception("normalize_to_kwargs failed for object: %s", obj)
    logger.debug("Parameter normalization failed, returning empty dict.")
    return {}

# ----------------------------
# Lazy capability detection
# ----------------------------
@dataclass
class Capabilities:
    has_whois: bool = False
    has_nvidia: bool = False
    has_systemctl: bool = False
    is_root: bool = False

_caps_cache: Optional[Capabilities] = None

def get_capabilities() -> Capabilities:
    global _caps_cache
    if _caps_cache is not None:
        logger.debug("Returning cached capabilities.")
        return _caps_cache
    logger.debug("Detecting system capabilities...")
    caps = Capabilities()
    caps.has_whois = whois is not None
    caps.is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
    rc, _, _ = execute_command_safe(["nvidia-smi"], timeout=2)
    caps.has_nvidia = (rc == 0)
    rc, _, _ = execute_command_safe(["systemctl", "--version"], timeout=2)
    caps.has_systemctl = (rc == 0)
    _caps_cache = caps
    logger.info("Capabilities detected: whois=%s, nvidia=%s, systemctl=%s, root=%s", caps.has_whois, caps.has_nvidia, caps.has_systemctl, caps.is_root)
    return caps

# Expose caps for convenience
CAPS = None  # will be filled on first use via get_capabilities()

# ----------------------------
# Data models
# ----------------------------
@dataclass
class Finding:
    id: str
    function: str
    severity: str
    confidence: float
    detail: Dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

@dataclass
class Task:
    name: str
    func: Callable[..., Any]
    schedule_seconds: Optional[int] = None
    retries: int = 0
    last_run: Optional[str] = None
    status: str = "pending"
    params: Dict[str, Any] = field(default_factory=dict)
    # Minimum seconds between ad-hoc/followup invocations (None -> fallback to schedule_seconds or default)
    min_interval: Optional[int] = None

# ----------------------------
# Decision engine
# ----------------------------
class DecisionEngine:
    def __init__(self, high_threshold: int = 1):
        self.high_threshold = high_threshold

    def evaluate(self, findings: List[Finding]) -> Dict[str, Any]:
        logger.debug("Evaluating %d findings with high threshold %d", len(findings), self.high_threshold)
        high_count = sum(1 for f in findings if f.severity == "high")
        miner_related = any("miner" in (f.function or "").lower() or "wallet" in json.dumps(f.detail) for f in findings)
        actions = {"escalate": False, "followups": [], "confidence_score": 0.0}
        if high_count >= self.high_threshold:
            logger.info("High severity findings (%d) meet or exceed threshold (%d), escalating.", high_count, self.high_threshold)
            actions["escalate"] = True
            actions["followups"].append(("isolate_suspected_processes", {}))
        if miner_related:
            logger.info("Miner-related findings detected, adding remediation followup.")
            actions["followups"].append(("miner_remediation", {}))
        actions["confidence_score"] = min(1.0, high_count / max(1, self.high_threshold))
        logger.debug("Decision engine actions: %s", actions)
        return actions

DECISION_ENGINE = DecisionEngine(high_threshold=1)

# ----------------------------
# Task manager (with inflight/debounce and graceful shutdown)
# ----------------------------
class TaskManager:
    def __init__(self, max_workers: int = 6):
        self.tasks: Dict[str, Task] = {}
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        self.metrics = {"tasks_ran": 0, "findings_count": 0}
        self.findings: Dict[str, Finding] = {}
        self.subscribers: Set[asyncio.Queue] = set()
        self._inflight: Set[str] = set()
        self._last_scheduled: Dict[str, float] = {}
        self._shutdown = False
        self._lock = threading.Lock()

        # followup debounce / dedupe
        self._followup_task: Optional[asyncio.Task] = None
        self._followup_debounce_seconds: float = 0.25  # short window to aggregate findings

    def register(self, task: Task):
        self.tasks[task.name] = task
        logger.info("Task registered: %s", task.name)

    def _normalize_params(self, params: Any, task: Task) -> Dict[str, Any]:
        normalized = normalize_to_kwargs(params)
        if not normalized and isinstance(params, dict):
            cleaned = {k: v for k, v in params.items() if k not in ("kwargs", "parameters", "params", "payload")}
            for k, v in list(cleaned.items()):
                if isinstance(v, str):
                    try:
                        cleaned[k] = json.loads(v)
                        logger.debug("Parsed value for key '%s' in cleaned params from string.", k)
                    except Exception:
                        logger.debug("Failed to parse value for key '%s' in cleaned params, keeping as string.", k)
                        pass
            return cleaned
        if not normalized:
            logger.debug("No parameters provided or normalization failed, using default task params: %s", task.params)
            return task.params or {}
        logger.debug("Final parameters for task: %s", normalized)
        return normalized

    async def run_task(self, name: str, params: Any = None):
        logger.debug("Request to run task: %s", name)
        if self._shutdown:
            logger.warning("TaskManager is shutting down; refusing to run %s", name)
            return None
        if name not in self.tasks:
            logger.error("Unknown task requested: %s", name)
            return None
        task = self.tasks[name]

        now = time.time()

        # Prevent concurrent duplicate runs
        if name in self._inflight:
            logger.debug("Task %s is already running; skipping duplicate invocation", name)
            return None

        # Determine last run ts
        last_ts = 0.0
        if task.last_run:
            try:
                last_ts = datetime.fromisoformat(task.last_run.replace("Z", "+00:00")).timestamp()
            except Exception:
                logger.debug("Failed to parse last run timestamp for task %s, using _last_scheduled.", name)
                last_ts = self._last_scheduled.get(name, 0.0)

        default_cooldown = 300
        cooldown = task.min_interval if task.min_interval is not None else (task.schedule_seconds if task.schedule_seconds is not None else default_cooldown)

        # Ad-hoc/followup invoked too soon?
        if last_ts and (now - last_ts) < cooldown:
            logger.debug("Task %s invoked too recently (%.1fs < %ss); skipping", name, now - last_ts, cooldown)
            return None

        # Mark running and record schedule time
        with self._lock:
            self._inflight.add(name)
            task.status = "running"
            task.last_run = datetime.utcnow().isoformat() + "Z"
            self._last_scheduled[name] = now
        logger.info("Starting task: %s", name)

        params_to_use = self._normalize_params(params, task)
        try:
            loop = asyncio.get_running_loop()
            logger.debug("Running task %s with params %s", name, params_to_use)
            # Support coroutine functions too
            if asyncio.iscoroutinefunction(task.func):
                result = await task.func(**(params_to_use or {}))
            else:
                # Run sync tasks in threadpool to avoid blocking event loop
                result = await loop.run_in_executor(self._executor, lambda: task.func(**(params_to_use or {})))
            task.status = "success"
            self.metrics["tasks_ran"] += 1
            logger.info("Task %s completed successfully. Metrics: tasks_ran=%d", name, self.metrics["tasks_ran"])
            if isinstance(result, dict) and result.get("findings"):
                self._ingest_findings(result)
            # Decision engine actions will be scheduled from debounced processor
            return result
        except Exception as e:
            task.status = "failed"
            logger.exception("Task %s failed: %s", name, e)
            return None
        finally:
            with self._lock:
                self._inflight.discard(name)
            logger.debug("Task %s finished, inflight set now: %s", name, self._inflight)

    def _ingest_findings(self, result: Dict[str, Any]):
        """
        Ingest findings from a tool execution. Publish events and schedule a debounced
        followup evaluation so multiple near-simultaneous results are coalesced.
        Note: this can be called from worker threads; use event loop thread-safe calls.
        """
        logger.debug("Ingesting findings from result: %s", result.get("function"))
        new_count = 0
        for f in result.get("findings", []):
            try:
                base = f.get("id") or f.get("detail", {}).get("pid") or f.get("type") or str(len(self.findings) + 1)
                fid = f"{result.get('function','tool')}:{base}:{int(time.time())}"
                finding = Finding(id=fid, function=result.get("function", f.get("type", "tool")), severity=f.get("severity", "medium"), confidence=float(f.get("confidence", 0.7)), detail=f.get("detail", f))
                self.findings[fid] = finding
                new_count += 1
                logger.info("New finding ingested: ID=%s, Function=%s, Severity=%s", fid, finding.function, finding.severity)
                # publish event (thread-safe schedule)
                try:
                    loop = asyncio.get_event_loop()
                    loop.call_soon_threadsafe(asyncio.create_task, self._publish_event({"type": "finding", "finding": asdict(finding)}))
                except Exception:
                    logger.exception("Failed to schedule finding event publication from thread.")
                    try:
                        loop = asyncio.get_running_loop()
                        asyncio.create_task(self._publish_event({"type": "finding", "finding": asdict(finding)}))
                    except Exception:
                        logger.exception("Failed to schedule finding event publication from event loop.")
            except Exception:
                logger.exception("Failed to ingest a finding from result: %s", result)
        if new_count:
            self.metrics["findings_count"] = len(self.findings)
            logger.info("Ingested %d new findings. Total findings: %d", new_count, self.metrics["findings_count"])
            # schedule a debounced followup evaluation on the event loop thread
            try:
                loop = asyncio.get_event_loop()
                loop.call_soon_threadsafe(self._ensure_followup_debounce_scheduled)
            except Exception:
                logger.exception("Failed to schedule followup evaluation from thread.")
                try:
                    asyncio.create_task(self._ensure_followup_debounce_scheduled())
                except Exception:
                    logger.exception("Failed to schedule followup evaluation from event loop.")

    def _ensure_followup_debounce_scheduled(self):
        """
        Called on the event loop thread (via call_soon_threadsafe).
        Ensures a single debounced followup processor task is scheduled.
        """
        if self._followup_task and not self._followup_task.done():
            logger.debug("Followup task already scheduled and pending.")
            return
        try:
            loop = asyncio.get_event_loop()
            self._followup_task = loop.create_task(self._debounced_process_followups())
            logger.debug("Scheduled new debounced followup task.")
        except Exception:
            logger.exception("Failed to schedule debounced followup processor from event loop.")
            try:
                asyncio.create_task(self._debounced_process_followups())
            except Exception:
                logger.exception("Failed to schedule debounced followup processor via create_task.")

    async def _debounced_process_followups(self):
        """
        Wait a short debounce interval, then evaluate DecisionEngine once and schedule
        unique followups. This greatly reduces duplicate scheduling/noise.
        """
        try:
            logger.debug("Waiting for debounce interval (%.2fs) before processing followups.", self._followup_debounce_seconds)
            await asyncio.sleep(self._followup_debounce_seconds)
            logger.debug("Processing followups after debounce.")
            try:
                actions = DECISION_ENGINE.evaluate(list(self.findings.values()))
            except Exception:
                logger.exception("DecisionEngine evaluation failed during followup processing.")
                actions = {"followups": [], "escalate": False}
            followups = actions.get("followups", []) or []
            # dedupe by followup name (keep params of last occurrence)
            deduped: Dict[str, Dict[str, Any]] = {}
            for name, params in followups:
                deduped[name] = params or {}
            logger.info("Scheduling %d unique followup tasks: %s", len(deduped), list(deduped.keys()))
            for follow_name, follow_params in deduped.items():
                if follow_name in self.tasks:
                    logger.debug("Scheduling followup task '%s' with params %s", follow_name, follow_params)
                    asyncio.create_task(self.run_task(follow_name, follow_params))
                else:
                    logger.warning("Followup task '%s' not found in registered tasks.", follow_name)
            if actions.get("escalate"):
                logger.warning("Decision engine triggered escalation based on findings.")
                await self._publish_event({"type": "escalation", "timestamp": datetime.utcnow().isoformat() + "Z"})
        except asyncio.CancelledError:
            logger.info("Debounced followup task was cancelled.")
        except Exception:
            logger.exception("Error in debounced followup processing.")

    async def _publish_event(self, event: Dict[str, Any]):
        logger.debug("Publishing event: %s", event.get("type"))
        for q in list(self.subscribers):
            try:
                await q.put(event)
            except Exception:
                logger.exception("Failed to put event into subscriber queue.")
                continue

    async def subscribe(self):
        q = asyncio.Queue(maxsize=100)
        self.subscribers.add(q)
        logger.debug("New event subscriber added. Total subscribers: %d", len(self.subscribers))
        try:
            while True:
                event = await q.get()
                yield event
        finally:
            self.subscribers.discard(q)
            logger.debug("Event subscriber removed. Total subscribers: %d", len(self.subscribers))

    async def periodic_scheduler(self):
        logger.info("Periodic scheduler started.")
        while not self._shutdown:
            now = time.time()
            to_run = []
            for name, task in list(self.tasks.items()):
                if task.schedule_seconds:
                    if not task.last_run:
                        logger.debug("Task %s scheduled for first run.", name)
                        to_run.append((name, {}))
                    else:
                        try:
                            last_ts = datetime.fromisoformat(task.last_run.replace("Z", "+00:00")).timestamp()
                        except Exception:
                            logger.warning("Could not parse last run time for task %s, scheduling now.", name)
                            last_ts = 0
                        if now - last_ts >= task.schedule_seconds:
                            logger.info("Task %s scheduled for periodic run (last run: %s).", name, task.last_run)
                            to_run.append((name, {}))
            for name, params in to_run:
                logger.debug("Triggering scheduled run for task: %s", name)
                asyncio.create_task(self.run_task(name, params))
            await asyncio.sleep(1)
        logger.info("Periodic scheduler stopped.")

    async def shutdown(self):
        logger.info("TaskManager shutting down...")
        self._shutdown = True
        for q in list(self.subscribers):
            try:
                await q.put({"type": "shutdown", "timestamp": datetime.utcnow().isoformat() + "Z"})
            except Exception:
                logger.exception("Failed to send shutdown event to subscriber.")
                pass
        self.subscribers.clear()
        self._executor.shutdown(wait=True)
        logger.info("TaskManager shutdown complete")

TASK_MANAGER = TaskManager()

# ----------------------------
# Core tools (sync functions used by tasks)
# ----------------------------
def analyze_system_logs_task(log_paths: Optional[List[str]] = None, time_range_hours: int = 72, keywords: Optional[List[str]] = None) -> Dict[str, Any]:
    logger.info("Starting log analysis task.")
    results = {"function": "log_analysis", "findings": []}
    default_logs = ["/var/log/auth.log", "/var/log/syslog", "/var/log/secure", "/var/log/cron", "/var/log/messages"]
    paths = log_paths if log_paths else [p for p in default_logs if os.path.exists(p)]
    keywords = keywords if keywords else IOCS.LOG_ABNORMAL_KEYWORDS
    cutoff_ts = time.time() - (time_range_hours * 3600)
    logger.debug("Scanning logs: %s with keywords: %s", paths, keywords)
    for p in paths:
        try:
            logger.debug("Scanning log file: %s", p)
            with open(p, "r", errors="ignore") as fh:
                for i, line in enumerate(fh, 1):
                    if not line.strip():
                        continue
                    matched, mats = match_patterns(keywords, line)
                    if matched:
                        finding_detail = {"log_path": p, "line_number": i, "log_content": line.strip()[:1000]}
                        results["findings"].append({"type": "log_anomaly", "detail": finding_detail, "severity": "medium", "confidence": 0.7})
                        logger.info("Log anomaly found in %s line %d: %s", p, i, line.strip()[:100])
            if len(results["findings"]) > 1000:
                logger.warning("Log analysis hit maximum finding limit (1000), stopping scan.")
                break
        except PermissionError:
            logger.warning("No permission to read log file: %s", p)
            continue
        except Exception:
            logger.exception("Failed scanning log file: %s", p)
            continue
    logger.info("Log analysis task completed with %d findings.", len(results["findings"]))
    return results

def perform_security_check_task(check_vuln: bool = True, check_malicious_proc: bool = True, check_network: bool = True, check_malicious_file: bool = True) -> Dict[str, Any]:
    logger.info("Starting security check task.")
    res = {"function": "security_check", "findings": []}
    if check_vuln:
        logger.debug("Checking for vulnerable listening ports...")
        try:
            listening = set()
            try:
                conns = psutil.net_connections(kind="tcp")
            except Exception:
                conns = []
            for c in conns:
                try:
                    if c.status == psutil.CONN_LISTEN and getattr(c, "laddr", None):
                        port = getattr(c.laddr, "port", None)
                        if port:
                            listening.add(int(port))
                except Exception:
                    continue
            for port_str, desc in IOCS.VULN_PORTS.items():
                try:
                    p = int(port_str)
                except Exception:
                    continue
                if p in listening:
                    finding_detail = {"port": p, "vulnerability": desc}
                    res["findings"].append({"type": "vulnerable_port", "detail": finding_detail, "severity": "high", "confidence": 0.95})
                    logger.warning("Vulnerable port %d (%s) is listening.", p, desc)
        except Exception:
            logger.exception("Vulnerability check failed")
    if check_malicious_proc:
        logger.debug("Checking for malicious processes...")
        try:
            for proc in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
                try:
                    name = proc.info.get("name", "") or ""
                    cmd = " ".join(proc.info.get("cmdline") or [])
                    nmatch, _ = match_patterns(IOCS.MINER_PROCS + IOCS.VULN_PROCS, name)
                    cmatch, _ = match_patterns(IOCS.MINER_CMD_PATTERNS + IOCS.MALICIOUS_SCRIPTS, cmd)
                    if nmatch or cmatch:
                        finding_detail = {"pid": proc.info.get("pid"), "process_name": name, "cmdline": cmd}
                        severity = "high" if nmatch else "medium"
                        confidence = 0.9 if nmatch else 0.75
                        res["findings"].append({"type": "malicious_process", "detail": finding_detail, "severity": severity, "confidence": confidence})
                        logger.warning("Malicious process detected: PID=%d, Name=%s, Cmd=%s", finding_detail["pid"], name, cmd)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            logger.exception("Process check failed")
    logger.info("Security check task completed with %d findings.", len(res["findings"]))
    return res

def miner_analysis_task(cpu_threshold: float = 30.0, gpu_check: bool = True, persistence_check: bool = True, detailed: bool = True) -> Dict[str, Any]:
    logger.info("Starting miner analysis task.")
    res = {"function": "miner_analysis", "findings": [], "miner_detected": False, "miner_info": {"processes": [], "pools": [], "wallets": []}}
    try:
        procs = []
        logger.debug("Collecting process list...")
        for p in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
            try:
                procs.append(p)
                try:
                    p.cpu_percent(interval=None) # Pre-call for accurate subsequent measurement
                except Exception:
                    pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        time.sleep(0.05) # Small delay to allow CPU measurement
        logger.debug("Analyzing %d processes for mining activity (CPU threshold: %.1f%%)...", len(procs), cpu_threshold)
        for p in procs:
            try:
                try:
                    cpu = p.cpu_percent(interval=None)
                except Exception:
                    cpu = 0.0
                name = (p.info.get("name") or "") if isinstance(p.info, dict) else ""
                cmd = " ".join(p.info.get("cmdline") or []) if isinstance(p.info, dict) else ""
                name_match, _ = match_patterns(IOCS.MINER_PROCS, name)
                cmd_match, _ = match_patterns(IOCS.MINER_CMD_PATTERNS, cmd)
                if (name_match or cmd_match) and cpu >= cpu_threshold:
                    finding_detail = {"pid": p.pid if hasattr(p, "pid") else p.info.get("pid"), "process_name": name, "cmdline": cmd, "cpu": cpu}
                    res["findings"].append({"type": "cpu_miner_process", "detail": finding_detail, "severity": "high", "confidence": 0.9})
                    res["miner_detected"] = True
                    res["miner_info"]["processes"].append(name or (cmd.split()[0] if cmd else ""))
                    w = re.search(r"-u\s+([A-Za-z0-9]{30,})", cmd)
                    if w:
                        res["miner_info"]["wallets"].append(w.group(1))
                    poolm = re.search(r"-o\s+([a-zA-Z0-9\.\-:\/\+]+)", cmd)
                    if poolm:
                        res["miner_info"]["pools"].append(poolm.group(1))
                    logger.warning("Miner process detected: PID=%d, CPU=%.1f%%, Name=%s, Cmd=%s", finding_detail["pid"], cpu, name, cmd)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        logger.exception("Miner analysis failed")
    logger.info("Miner analysis task completed. Miner detected: %s, Findings: %d", res["miner_detected"], len(res["findings"]))
    return res

def isolate_suspected_processes() -> Dict[str, Any]:
    logger.info("Starting isolation suggestion task.")
    findings = []
    for fid, f in list(TASK_MANAGER.findings.items()):
        try:
            if f.severity == "high" and ("process" in f.function or "pid" in json.dumps(f.detail)):
                finding_detail = {"finding_id": fid, "process_detail": f.detail}
                findings.append({"type": "isolation_suggestion", "detail": finding_detail, "severity": "high", "confidence": f.confidence})
                logger.info("Isolation suggestion for finding %s: %s", fid, f.detail)
        except Exception:
            logger.exception("Failed to process finding %s for isolation suggestion.", fid)
            continue
    logger.info("Isolation suggestion task completed with %d suggestions.", len(findings))
    return {"function": "isolate_suspected_processes", "findings": findings}

def miner_remediation() -> Dict[str, Any]:
    logger.info("Starting miner remediation suggestion task.")
    findings = []
    cron_paths = ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", os.path.expanduser("~/.crontab")]
    for path in cron_paths:
        if os.path.exists(path):
            finding_detail = {"path": path}
            findings.append({"type": "persistence_location", "detail": finding_detail, "severity": "medium", "confidence": 0.8})
            logger.info("Potential miner persistence location found: %s", path)
    logger.info("Miner remediation task completed with %d suggestions.", len(findings))
    return {"function": "miner_remediation", "findings": findings}

# ----------------------------
# Register tasks (with optional min_interval tuning)
# ----------------------------
TASK_MANAGER.register(Task(name="log_analysis", func=analyze_system_logs_task, schedule_seconds=3600, min_interval=300))
TASK_MANAGER.register(Task(name="security_check", func=perform_security_check_task, schedule_seconds=1800, min_interval=300))
TASK_MANAGER.register(Task(name="miner_analysis", func=miner_analysis_task, schedule_seconds=900, min_interval=300))
TASK_MANAGER.register(Task(name="isolate_suspected_processes", func=isolate_suspected_processes, schedule_seconds=None, min_interval=300))
TASK_MANAGER.register(Task(name="miner_remediation", func=miner_remediation, schedule_seconds=None, min_interval=600))

# ----------------------------
# Tools manifest (for LLM/agents)
# ----------------------------
TOOLS_MANIFEST = {
    "tools": [
        {
            "name": "log_analysis",
            "description": "Analyze system/application logs for anomalies (non-destructive).",
            "parameters": {"log_paths": {"type": "array", "items": {"type": "string"}}, "time_range_hours": {"type": "integer"}, "keywords": {"type": "array", "items": {"type": "string"}}},
            "returns": {"type": "object"},
            "safe": True,
            "auth_required": False,
            "when_to_call": "Call when suspicious logins, command injections, or persistence changes are suspected"
        },
        {
            "name": "security_check",
            "description": "Quick surface-level security check: listen ports, suspicious processes (non-destructive).",
            "parameters": {"check_vuln": {"type": "boolean"}, "check_malicious_proc": {"type": "boolean"}},
            "returns": {"type": "object"},
            "safe": True,
            "auth_required": False,
            "when_to_call": "Call for quick triage or suspected compromise"
        },
        {
            "name": "traceability_analysis",
            "description": "Correlate findings and IOCs to produce associates and attack-chain hints (non-destructive).",
            "parameters": {"iocs": {"type": "array"}, "log_analysis_result": {"type": "object"}, "security_check_result": {"type": "object"}},
            "returns": {"type": "object"},
            "safe": True,
            "auth_required": False,
            "when_to_call": "Call when there are findings to trace and correlate"
        },
        {
            "name": "baseline_check",
            "description": "System baseline compliance checks (file perms, services, network; non-destructive).",
            "parameters": {"baseline_config": {"type": "object"}},
            "returns": {"type": "object"},
            "safe": True,
            "auth_required": True,
            "when_to_call": "Call for compliance audits or configuration investigations"
        },
        {
            "name": "miner_analysis",
            "description": "Dedicated miner detection: CPU/GPU/persistence analysis (non-destructive).",
            "parameters": {"cpu_threshold": {"type": "number"}, "gpu_check": {"type": "boolean"}},
            "returns": {"type": "object"},
            "safe": True,
            "auth_required": False,
            "when_to_call": "Call when high CPU/GPU usage or miner pool domains observed"
        }
    ]
}

# ----------------------------
# MCP server setup (safe wrappers + restart runner) - MCP logs preserved
# ----------------------------
_mcp_thread: Optional[threading.Thread] = None
_mcp_instance = None
_mcp_stop_event = threading.Event()

def _wrap_tool(func):
    """
    Return wrapper that normalizes kwargs, runs func, and catches exceptions to avoid
    propagating them to FastMCP runtime.
    Logs MCP tool calls.
    """
    def wrapper(**kwargs):
        logger.info("MCP tool '%s' called with parameters: %s", getattr(func, "__name__", "unknown"), kwargs)
        try:
            actual = normalize_to_kwargs(kwargs)
            result = func(**actual)
            if not isinstance(result, dict):
                logger.debug("MCP tool '%s' returned non-dict result: %s", getattr(func, "__name__", "unknown"), type(result))
                return {"function": getattr(func, "__name__", "tool"), "result": result, "findings": []}
            logger.info("MCP tool '%s' completed successfully, returned %d findings.", getattr(func, "__name__", "unknown"), len(result.get("findings", [])))
            return result
        except Exception as exc:
            logger.exception("MCP tool '%s' raised an exception: %s", getattr(func, "__name__", "tool"), exc)
            tb = traceback.format_exc()
            return {"function": getattr(func, "__name__", "tool"), "error": str(exc), "traceback": tb, "findings": []}
    return wrapper

def setup_mcp_server(host: str = "127.0.0.1", port: int = 8000):
    """
    Create and register MCP tools safely. Tools are wrapped to avoid unhandled exceptions.
    Returns mcp instance or None if FastMCP not available/failed.
    Logs MCP server setup status.
    """
    global _mcp_instance
    if FastMCP is None:
        logger.info("FastMCP not available; skipping MCP server startup.")
        return None
    try:
        logger.info("Setting up MCP server on %s:%d", host, port)
        mcp = FastMCP(host=host, port=port, name="multi-security-mcp")
        # register wrapped tools - these will now log via the wrapper
        mcp.tool()(_wrap_tool(analyze_system_logs_task))
        mcp.tool()(_wrap_tool(perform_security_check_task))
        mcp.tool()(_wrap_tool(lambda **kw: perform_traceability_analysis_wrapper(list(TASK_MANAGER.findings.values()), custom_iocs=kw.get("iocs"))))
        mcp.tool()(_wrap_tool(perform_baseline_check_wrapper))
        mcp.tool()(_wrap_tool(miner_analysis_task))
        _mcp_instance = mcp
        logger.info("Safe MCP tools registered and server ready.")
        return mcp
    except Exception:
        logger.exception("Failed to setup MCP server")
        return None

def _mcp_runner_with_restarts(host: str, port: int, max_retries: int = 10):
    """
    Runner loop for FastMCP.run() with bounded retries and exponential backoff.
    Use _mcp_stop_event to request shutdown.
    Logs MCP runner status and errors.
    """
    global _mcp_instance
    retry = 0
    base_backoff = 0.5
    logger.info("MCP runner thread started.")
    while not _mcp_stop_event.is_set():
        try:
            mcp = setup_mcp_server(host, port)
            if mcp is None:
                logger.info("No MCP instance created; will not attempt to run MCP.")
                return
            logger.info("Starting FastMCP.run() loop.")
            mcp.run()
            logger.info("FastMCP.run() exited normally (likely due to stop event).")
            break # Exit loop if run() returns normally
        except Exception:
            logger.exception("FastMCP.run() crashed or raised an exception")
            retry += 1
            if retry > max_retries:
                logger.error("FastMCP crashed too many times (>%d); stopping restart attempts", max_retries)
                break
            sleep_time = min(60, base_backoff * (2 ** (retry - 1)))
            logger.info("Restarting MCP in %.1fs (retry %d/%d)", sleep_time, retry, max_retries)
            end = time.time() + sleep_time
            while time.time() < end and not _mcp_stop_event.is_set():
                time.sleep(0.2)
    logger.info("MCP runner loop exiting.")

def run_mcp_in_thread(host="127.0.0.1", port=8000):
    """
    Start MCP runner thread (idempotent).
    Logs thread start/stop.
    """
    global _mcp_thread, _mcp_stop_event
    if FastMCP is None:
        logger.info("FastMCP not installed; skipping MCP server startup.")
        return None
    if _mcp_thread and _mcp_thread.is_alive():
        logger.debug("MCP thread already running")
        return _mcp_thread
    _mcp_stop_event.clear()
    t = threading.Thread(target=_mcp_runner_with_restarts, args=(host, port), daemon=True)
    _mcp_thread = t
    t.start()
    logger.info("MCP runner thread started on %s:%d", host, port)
    return t

def stop_mcp_thread(timeout: float = 1.0):
    """
    Stop MCP thread if running. Attempts to call mcp.stop() if supported.
    Logs thread stop status.
    """
    global _mcp_thread, _mcp_instance, _mcp_stop_event
    logger.info("Requesting MCP thread to stop...")
    _mcp_stop_event.set()
    try:
        if _mcp_instance is not None:
            try:
                if hasattr(_mcp_instance, "stop"):
                    logger.info("Calling mcp.stop()...")
                    _mcp_instance.stop()
            except Exception:
                logger.exception("Failed to call _mcp_instance.stop()")
        if _mcp_thread:
            logger.info("Waiting for MCP thread to finish (timeout: %.1fs)...", timeout)
            _mcp_thread.join(timeout=timeout)
            if _mcp_thread.is_alive():
                logger.warning("MCP thread did not finish within timeout.")
            else:
                logger.info("MCP thread finished successfully.")
        # Ensure MCP logs are flushed to file
        logging.shutdown()
    except Exception:
        logger.exception("Error while stopping mcp thread")
    finally:
        _mcp_thread = None
        _mcp_instance = None

# ----------------------------
# Traceability & Baseline wrappers
# ----------------------------
def perform_traceability_analysis_wrapper(findings: List[Finding], custom_iocs: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
    logger.info("Starting traceability analysis on %d findings.", len(findings))
    associated = {"ips": set(), "domains": set(), "processes": set(), "files": set(), "wallets": set(), "pools": set()}
    for f in findings:
        try:
            detail = f.detail if isinstance(f, Finding) else (f.get("detail") or {})
            s = json.dumps(detail)
            for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", s):
                associated["ips"].add(ip)
            pn = detail.get("process_name") if isinstance(detail, dict) else None
            if pn:
                associated["processes"].add(pn)
            w = re.search(r"-u\s+([A-Za-z0-9]{30,})", s)
            if w:
                associated["wallets"].add(w.group(1))
        except Exception:
            logger.exception("Failed to extract IOCs from finding: %s", f.id)
            continue
    if custom_iocs:
        for i in custom_iocs:
            t = i.get("type"); v = i.get("value")
            if t == "ip": associated["ips"].add(v)
            if t == "process": associated["processes"].add(v)
    result = {"function": "traceability_analysis", "associated_iocs": {k: sorted(list(v)) for k, v in associated.items()}, "attack_chain": []}
    logger.info("Traceability analysis completed. Associated IOCs: %s", result["associated_iocs"])
    return result

def perform_baseline_check_wrapper(**kwargs):
    logger.info("Starting baseline check.")
    findings = []
    baseline = kwargs.get("baseline_config") or SECURITY_BASELINE
    caps = get_capabilities()

    # --- User management ---
    um = baseline.get("user_management", {})
    if um.get("no_empty_password", True):
        logger.debug("Checking for accounts with empty passwords...")
        try:
            with open("/etc/shadow", "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) > 1 and parts[1] in ("", "!!", "*"):
                        user = parts[0]
                        finding_detail = {"user": user}
                        findings.append({"type": "empty_password_account", "detail": finding_detail, "severity": "high", "confidence": 0.95})
                        logger.warning("Account with empty password found: %s", user)
        except PermissionError:
            logger.warning("No permission to read /etc/shadow (requires root).")
        except Exception as e:
            logger.exception("Failed to check /etc/shadow: %s", e)

    # --- File permissions ---
    fp = baseline.get("file_permissions", {})
    logger.debug("Checking file permissions: %s", fp)
    for filepath, expected_mode in fp.items():
        if not os.path.exists(filepath):
            logger.debug("File does not exist for permission check: %s", filepath)
            continue
        try:
            actual_stat = os.stat(filepath)
            actual_mode = actual_stat.st_mode & 0o777
            if actual_mode != expected_mode:
                finding_detail = {"file": filepath, "expected_mode": oct(expected_mode), "actual_mode": oct(actual_mode)}
                findings.append({"type": "file_permission_violation", "detail": finding_detail, "severity": "medium", "confidence": 0.85})
                logger.warning("File permission violation: %s, expected %s, got %s", filepath, oct(expected_mode), oct(actual_mode))
        except Exception as e:
            logger.exception("Permission check failed for %s: %s", filepath, e)

    # --- Service management ---
    sm = baseline.get("service_management", {})
    if caps.has_systemctl:
        logger.debug("Checking services (systemctl available)...")
        for svc in sm.get("forbidden_services", []):
            rc, _, _ = execute_command_safe(["systemctl", "is-active", "--quiet", svc])
            if rc == 0:
                finding_detail = {"service": svc}
                findings.append({"type": "forbidden_service_running", "detail": finding_detail, "severity": "medium", "confidence": 0.8})
                logger.warning("Forbidden service is running: %s", svc)
        for svc in sm.get("required_services", []):
            rc, _, _ = execute_command_safe(["systemctl", "is-active", "--quiet", svc])
            if rc != 0:
                finding_detail = {"service": svc}
                findings.append({"type": "required_service_missing", "detail": finding_detail, "severity": "medium", "confidence": 0.8})
                logger.warning("Required service is not running: %s", svc)
    else:
        logger.debug("Systemctl not available, skipping service checks.")

    # --- Network sysctl checks ---
    ns = baseline.get("network_security", {})
    logger.debug("Checking network sysctls...")
    try:
        sysctl_out = subprocess.check_output(["sysctl", "-a"], stderr=subprocess.DEVNULL, text=True)
        sysctl_lines = sysctl_out.strip().split("\n")
        sysctl_map = {}
        for line in sysctl_lines:
            if "=" in line:
                k, v = line.split("=", 1)
                sysctl_map[k.strip()] = v.strip()
        if ns.get("allow_icmp_echo") is False:
            val = sysctl_map.get("net.ipv4.icmp_echo_ignore_all", "0")
            if val != "1":
                finding_detail = {"current_value": val}
                findings.append({"type": "icmp_echo_not_disabled", "detail": finding_detail, "severity": "low", "confidence": 0.7})
                logger.warning("ICMP echo is not disabled (net.ipv4.icmp_echo_ignore_all = %s)", val)
        if ns.get("tcp_syncookies") is True:
            val = sysctl_map.get("net.ipv4.tcp_syncookies", "0")
            if val != "1":
                finding_detail = {"current_value": val}
                findings.append({"type": "tcp_syncookies_disabled", "detail": finding_detail, "severity": "medium", "confidence": 0.8})
                logger.warning("TCP SYN cookies are disabled (net.ipv4.tcp_syncookies = %s)", val)
    except Exception:
        logger.exception("sysctl check failed or not available")

    logger.info("Baseline check completed with %d findings.", len(findings))
    return {"function": "baseline_check", "findings": findings}

# ----------------------------
# Web UI and API (aiohttp) - With Authentication
# ----------------------------

# Authentication middleware
async def auth_middleware(app, handler):
    async def middleware_handler(request):
        # Allow access to the tools manifest without auth, as it's often used for discovery
        if request.path == '/api/tools_manifest':
            logger.debug("Accessing tools manifest without auth: %s", request.remote)
            return await handler(request)

        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Basic '):
            logger.warning("Unauthorized access attempt to %s from %s", request.path, request.remote)
            return web.Response(status=401, text="Unauthorized", headers={'WWW-Authenticate': 'Basic realm="Restricted"'})

        try:
            # Decode Basic Auth header
            provided_user, provided_pass = BasicAuth.decode(auth_header).login, BasicAuth.decode(auth_header).password
        except Exception:
            logger.warning("Invalid Authorization header format from %s", request.remote)
            return web.Response(status=401, text="Unauthorized", headers={'WWW-Authenticate': 'Basic realm="Restricted"'})

        # Compare with stored credentials
        if provided_user != AUTH_USER or provided_pass != AUTH_PASS:
            logger.warning("Authentication failed for user '%s' from %s", provided_user, request.remote)
            return web.Response(status=401, text="Unauthorized", headers={'WWW-Authenticate': 'Basic realm="Restricted"'})

        # Authentication successful, proceed
        logger.debug("Successful authentication for user '%s' accessing %s from %s", provided_user, request.path, request.remote)
        return await handler(request)
    return middleware_handler

async def sse_handler(request):
    if web is None:
        raise RuntimeError("aiohttp not available")
    logger.info("SSE stream requested from %s", request.remote)
    resp = web.StreamResponse(status=200, reason='OK', headers={'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive'})
    await resp.prepare(request)
    q = asyncio.Queue()
    TASK_MANAGER.subscribers.add(q)
    try:
        while True:
            event = await q.get()
            data = json.dumps(event)
            try:
                await resp.write(f"data: {data}\n\n".encode("utf-8"))
            except ConnectionResetError:
                logger.info("SSE stream to %s closed due to connection reset.", request.remote)
                break
    except asyncio.CancelledError:
        logger.info("SSE stream to %s was cancelled.", request.remote)
    finally:
        TASK_MANAGER.subscribers.discard(q)
        logger.debug("SSE subscriber removed for %s", request.remote)
    return resp

async def api_findings(request):
    logger.info("API request for findings from %s", request.remote)
    items = [asdict(f) for f in TASK_MANAGER.findings.values()]
    return web.json_response({"findings": items, "metrics": TASK_MANAGER.metrics})

async def api_tasks(request):
    logger.info("API request for tasks from %s", request.remote)
    tasks = {}
    for name, t in TASK_MANAGER.tasks.items():
        tasks[name] = {"status": t.status, "last_run": t.last_run, "schedule_seconds": t.schedule_seconds, "min_interval": t.min_interval, "inflight": (name in TASK_MANAGER._inflight), "last_scheduled_ts": TASK_MANAGER._last_scheduled.get(name)}
    return web.json_response({"tasks": tasks})

async def api_tools_manifest(request):
    # This endpoint is now allowed without auth
    logger.info("API request for tools manifest from %s", request.remote)
    return web.json_response(TOOLS_MANIFEST)

async def api_log_file(request):
    """API endpoint to stream the log file content"""
    logger.info("API request for log file from %s", request.remote)
    
    # Check if log file exists
    if not os.path.exists("mcp.log"):
        return web.Response(status=404, text="Log file not found")
    
    try:
        with open("mcp.log", "r", encoding="utf-8") as f:
            content = f.read()
        return web.Response(text=content, content_type='text/plain')
    except Exception as e:
        logger.error("Error reading log file: %s", e)
        return web.Response(status=500, text=f"Error reading log file: {str(e)}")

async def dashboard(request):
    logger.info("Dashboard requested from %s", request.remote)
    findings = [asdict(f) for f in TASK_MANAGER.findings.values()]
    counts = {"total": len(findings), "high": sum(1 for f in findings if f["severity"] == "high")}
    html = f"""
    <html><head><title>Security MCP Dashboard</title></head>
    <body>
      <h1>Security MCP Dashboard</h1>
      <p>Metrics: tasks_ran={TASK_MANAGER.metrics.get('tasks_ran')} findings={TASK_MANAGER.metrics.get('findings_count')}</p>
      <p>Findings total: {counts['total']}, high severity: {counts['high']}</p>
      <h2>Recent Findings</h2><ul>
    """
    for f in sorted(findings, key=lambda x: x["timestamp"], reverse=True)[:50]:
        html += f"<li>[{f['severity']}] {f['function']} - {json.dumps(f['detail'])}</li>"
    html += """
      </ul>
      <p>Live events: <a href='/events'>Stream</a></p>
      <p>View full logs: <a href='/api/log'>Log File</a></p>
      <p>API endpoints: <a href='/api/findings'>Findings</a>, <a href='/api/tasks'>Tasks</a>, <a href='/api/tools_manifest'>Tools Manifest</a></p>
    </body></html>
    """
    return web.Response(text=html, content_type='text/html')

def create_web_runner(host="0.0.0.0", port=8080):
    if web is None:
        logger.warning("aiohttp not installed; web UI disabled.")
        return None
    app = web.Application(middlewares=[auth_middleware])
    app.add_routes([
        web.get("/", dashboard),
        web.get("/api/findings", api_findings),
        web.get("/api/tasks", api_tasks),
        web.get("/api/tools_manifest", api_tools_manifest),
        web.get("/api/log", api_log_file),  # New endpoint for log file
        web.get("/events", sse_handler)
    ])
    runner = web.AppRunner(app)
    return runner, host, port

# ----------------------------
# Entrypoint orchestration & graceful shutdown
# ----------------------------
async def main_async(host="127.0.0.1", mcp_port=8000, web_port=8080, ioc_file: Optional[str] = None, auth_user: str = "admin", auth_pass: str = "securepassword", log_level: str = "INFO"):
    global AUTH_USER, AUTH_PASS, AUTH_CREDENTIALS

    # Set credentials
    AUTH_USER = auth_user
    AUTH_PASS = auth_pass
    AUTH_CREDENTIALS = (auth_user, auth_pass)

    # Set log level
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {log_level}')
    logger.setLevel(numeric_level)
    logger.info(f"Log level set to {log_level.upper()}")

    logger.info("Starting Multi-Function Security MCP with Auth and Logging. Host=%s, MCP Port=%d, Web Port=%d", host, mcp_port, web_port)

    # load custom iocs
    if ioc_file and os.path.exists(ioc_file):
        try:
            with open(ioc_file, "r", encoding="utf-8") as f:
                custom = yaml.safe_load(f) or {}
            for k, v in custom.items():
                if hasattr(IOCS, k) and isinstance(getattr(IOCS, k), list) and isinstance(v, list):
                    getattr(IOCS, k).extend(v)
            logger.info("Loaded custom IOCs from %s", ioc_file)
        except Exception:
            logger.exception("Failed to load custom IOCs from %s", ioc_file)

    # detect capabilities lazily and cache
    global CAPS
    CAPS = get_capabilities()

    # start MCP server if available (safe runner with restarts)
    run_mcp_in_thread(host=host, port=mcp_port)

    # start periodic scheduler
    sched_task = asyncio.create_task(TASK_MANAGER.periodic_scheduler())

    # start web UI if aiohttp available
    runner_info = create_web_runner(host=host, port=web_port)
    site = None
    runner = None
    if runner_info:
        runner, vh, vp = runner_info
        await runner.setup()
        try:
            site = web.TCPSite(runner, host=vh, port=vp)
            await site.start()
            logger.info("Web UI running at http://%s:%d", vh, vp)
        except Exception:
            logger.exception("Failed to start web UI on %s:%d", vh, vp)
            site = None
    else:
        logger.info("Web UI disabled due to missing aiohttp.")

    # handle graceful shutdown signals
    stop_event = asyncio.Event()

    def _term_handler():
        logger.info("Termination signal received.")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(s, _term_handler)
        except Exception as e:
            logger.warning("Could not add signal handler for %s: %s", s, e)

    # run until signaled
    logger.info("Main loop started, waiting for shutdown signal...")
    await stop_event.wait()
    logger.info("Shutdown sequence starting...")

    # attempt tidy shutdown
    if site and runner:
        try:
            logger.info("Shutting down web runner...")
            await runner.cleanup()
            logger.info("Web runner shutdown complete.")
        except Exception:
            logger.exception("Error cleaning up web runner")
    logger.info("Shutting down task manager...")
    await TASK_MANAGER.shutdown()
    logger.info("Stopping MCP thread...")
    stop_mcp_thread()
    try:
        logger.info("Cancelling periodic scheduler task...")
        sched_task.cancel()
        await asyncio.wait_for(sched_task, timeout=2)
        logger.info("Periodic scheduler task cancelled.")
    except Exception:
        logger.exception("Error cancelling or waiting for scheduler task")
    logger.info("Shutdown complete. Goodbye.")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Multi-Function Security MCP (improved with auth, logging, and preserved MCP logs)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--mcp-port", type=int, default=8000)
    parser.add_argument("--web-port", type=int, default=8080)
    parser.add_argument("--ioc-file", default="custom_iocs.yaml")
    parser.add_argument("--auth-user", default="admin", help="Username for web API and UI")
    parser.add_argument("--auth-pass", default="securepassword", help="Password for web API and UI")
    parser.add_argument("--log-level", default="INFO", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help="Set the logging level")
    args = parser.parse_args()

    try:
        asyncio.run(main_async(host=args.host, mcp_port=args.mcp_port, web_port=args.web_port, ioc_file=args.ioc_file, auth_user=args.auth_user, auth_pass=args.auth_pass, log_level=args.log_level))
    except KeyboardInterrupt:
        logger.info("Shutdown requested via KeyboardInterrupt.")
    except Exception:
        logger.exception("Fatal error in main()")

if __name__ == "__main__":
    main()



