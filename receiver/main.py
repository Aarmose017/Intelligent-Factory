import hashlib
import hmac
import os
import pathlib
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from engine.log import now, write
from engine.policy import DEFAULT_PATH, load_policy, load_settings
from engine.respond import Responder
from engine.schema import Alert

RULES = load_policy()
SETTINGS = load_settings()
# Which policy made the decisions: logged at startup and shown on /health, so a silent edit to policy.yaml shows up.
POLICY_SHA256 = hashlib.sha256(pathlib.Path(DEFAULT_PATH).read_bytes()).hexdigest()
# Shared secret Team B sends in the X-Alert-Key header. Read from the environment, never stored in the repo.
# shortcut: when ALERT_KEY is not set, any sender is accepted (fine on one machine), set it before a shared network.
KEY = os.environ.get("ALERT_KEY") or None
# No line attached yet, so tier 2 and 3 are decided and logged but not carried out. Correlation, suppression
# and the rate limit all apply, on a monotonic clock in seconds (one tick is one second, still a proposal).
RESPONDER = Responder(RULES, SETTINGS)
# alert_ids already accepted, oldest first, so a captured alert cannot be sent again.
# shortcut: kept in memory and capped at MAX_SEEN, so ids are forgotten on restart; move to SQLite with incidents.
SEEN = {}
MAX_SEEN = 10_000
# FastAPI runs sync handlers on a thread pool, and the incident list and SEEN are shared state.
_lock = threading.Lock()


@asynccontextmanager
async def lifespan(app):
    write({}, None, event="startup", policy_sha256=POLICY_SHA256, rules_loaded=len(RULES),
          sender_key_required=KEY is not None)
    yield


app = FastAPI(title="Factory response layer", lifespan=lifespan)


def _reject(request, alert, status, reason, **extra):
    write(alert, None, request.state.received_at, event="rejected", reason=reason, **extra)
    return JSONResponse({"detail": reason}, status_code=status)


@app.middleware("http")
async def stamp_arrival(request: Request, call_next):
    # Stamped when the request reaches the server, before the body is read and
    # before FastAPI queues the handler on its thread pool. Stamping inside the
    # handler would hide that queue time and make our latency look smaller.
    request.state.received_at = now()
    request.state.received_clock = time.perf_counter()
    # The key is checked before the body is even parsed, so an unknown sender learns nothing about our schema.
    if KEY and request.url.path == "/alert" and not hmac.compare_digest(
            request.headers.get("x-alert-key", "").encode(), KEY.encode()):
        return _reject(request, {}, 401, "missing or wrong sender key")
    return await call_next(request)


@app.exception_handler(RequestValidationError)
async def log_rejected(request: Request, exc):
    # A body we refuse still gets a log line, otherwise bad input leaves no trace. It keeps whatever alert_id and
    # class the body had and names the failing fields, so Team B can tell which alert broke the contract and why.
    fields = sorted({".".join(map(str, e["loc"][1:])) or "body" for e in exc.errors()})
    write(exc.body if isinstance(exc.body, dict) else {}, None, request.state.received_at, event="rejected",
          reason="request body failed validation", fields=fields)
    return await request_validation_exception_handler(request, exc)


@app.post("/alert")
def receive(alert: Alert, request: Request):
    alert = alert.model_dump()
    max_age = SETTINGS.get("max_alert_age_s")
    if max_age is not None:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(alert["emitted_at"])).total_seconds()
        if age > max_age:
            return _reject(request, alert, 422, "alert is stale", age_s=round(age, 1))
    with _lock:
        if alert["alert_id"] in SEEN:
            return _reject(request, alert, 409, "duplicate alert_id")
        SEEN[alert["alert_id"]] = None
        if len(SEEN) > MAX_SEEN:
            del SEEN[next(iter(SEEN))]
        inc = RESPONDER.handle(alert, request.state.received_clock,
                               request.state.received_at, request.state.received_clock)
    if inc["tier"] is None:
        return {"decision": "no_rule_matched", "incident_id": inc["id"]}
    return {"decision": "matched", "tier": inc["tier"], "rule": inc["technique"], "incident_id": inc["id"]}


@app.get("/health")
def health():
    return {"status": "ok", "rules_loaded": len(RULES), "policy_sha256": POLICY_SHA256,
            "sender_key_required": KEY is not None}
