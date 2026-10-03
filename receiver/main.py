import time

from fastapi import FastAPI, Request

from engine.log import now, write
from engine.policy import load_policy, pick_tier

app = FastAPI(title="Factory response layer")
RULES = load_policy()


@app.middleware("http")
async def stamp_arrival(request: Request, call_next):
    # Stamped when the request reaches the server, before the body is read and
    # before FastAPI queues the handler on its thread pool. Stamping inside the
    # handler would hide that queue time and make our latency look smaller.
    request.state.received_at = now()
    request.state.received_clock = time.perf_counter()
    return await call_next(request)


@app.post("/alert")
def receive(alert: dict, request: Request):
    rule = pick_tier(alert, RULES)
    decision_ms = (time.perf_counter() - request.state.received_clock) * 1000
    write(alert, rule, request.state.received_at, decision_ms)
    if rule is None:
        return {"decision": "no_rule_matched"}
    return {"decision": "matched", "tier": rule["tier"], "rule": rule["technique"]}


@app.get("/health")
def health():
    return {"status": "ok", "rules_loaded": len(RULES)}
