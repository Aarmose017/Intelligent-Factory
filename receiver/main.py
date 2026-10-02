from fastapi import FastAPI

from engine.log import write
from engine.policy import load_policy, pick_tier

app = FastAPI(title="Factory response layer")
RULES = load_policy()


@app.post("/alert")
def receive(alert: dict):
    rule = pick_tier(alert, RULES)
    write(alert, rule)
    if rule is None:
        return {"decision": "no_rule_matched"}
    return {"decision": "matched", "tier": rule["tier"], "rule": rule["technique"]}


@app.get("/health")
def health():
    return {"status": "ok", "rules_loaded": len(RULES)}
