import threading
import time

from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError

from engine.log import now, write
from engine.policy import load_policy, load_settings
from engine.respond import Responder
from engine.schema import Alert

app = FastAPI(title="Factory response layer")
RULES = load_policy()
# No line attached yet, so tier 2 and 3 are decided and logged but not carried out. Correlation, suppression
# and the rate limit all apply, on a monotonic clock in seconds (one tick is one second, still a proposal).
RESPONDER = Responder(RULES, load_settings())
# FastAPI runs sync handlers on a thread pool, and the incident list is shared state.
_lock = threading.Lock()


@app.middleware("http")
async def stamp_arrival(request: Request, call_next):
    # Stamped when the request reaches the server, before the body is read and
    # before FastAPI queues the handler on its thread pool. Stamping inside the
    # handler would hide that queue time and make our latency look smaller.
    request.state.received_at = now()
    request.state.received_clock = time.perf_counter()
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
    with _lock:
        inc = RESPONDER.handle(alert.model_dump(), request.state.received_clock,
                               request.state.received_at, request.state.received_clock)
    if inc["tier"] is None:
        return {"decision": "no_rule_matched", "incident_id": inc["id"]}
    return {"decision": "matched", "tier": inc["tier"], "rule": inc["technique"], "incident_id": inc["id"]}


@app.get("/health")
def health():
    return {"status": "ok", "rules_loaded": len(RULES)}
