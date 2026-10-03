from fastapi import FastAPI

from engine.log import now, write
from engine.policy import load_policy, pick_tier

app = FastAPI(title="Factory response layer")
RULES = load_policy()


@app.post("/alert")
def receive(alert: dict):
    # Taken first, before any of our own work, so it marks where our latency starts.
    received_at = now()
    rule = pick_tier(alert, RULES)
    write(alert, rule, received_at)
    if rule is None:
        return {"decision": "no_rule_matched"}
    return {"decision": "matched", "tier": rule["tier"], "rule": rule["technique"]}


@app.get("/health")
def health():
    return {"status": "ok", "rules_loaded": len(RULES)}
