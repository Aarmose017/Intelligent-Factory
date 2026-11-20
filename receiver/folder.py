"""Offline replay: a folder of alert files through the same contract and Responder as the live receiver.

    python -m receiver.folder <folder>      (writes logs/folder.jsonl, never the live receiver's log)

Lets Team B hand us alerts without a network: one alert per .json file. Alerts are taken in emitted_at order
and correlation runs on those times, so the same folder always gives the same decisions. A file that is not
valid JSON or breaks the schema is logged as rejected, with the file name, and the rest still run.
"""
import json
import pathlib
import sys
from datetime import datetime

from pydantic import ValidationError

from engine import log
from engine.policy import load_policy, load_settings
from engine.respond import Responder
from engine.schema import Alert


def replay(folder):
    responder, alerts, rejected = Responder(load_policy(), load_settings()), [], 0
    for path in sorted(pathlib.Path(folder).glob("*.json")):
        body = None
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
            alert = Alert.model_validate(body).model_dump()
        except (OSError, ValueError) as e:  # bad JSON, bad encoding and ValidationError are all ValueError
            fields = sorted({".".join(map(str, err["loc"])) or "body" for err in e.errors()}) \
                if isinstance(e, ValidationError) else []
            log.write(body if isinstance(body, dict) else {}, None, log.now(), event="rejected",
                      reason="alert failed validation" if fields else f"could not read: {e}", fields=fields,
                      file=path.name)
            rejected += 1
            continue
        alerts.append((datetime.fromisoformat(alert["emitted_at"]).timestamp(), path.name, alert))
    for when, name, alert in sorted(alerts, key=lambda a: a[:2]):
        responder.handle(alert, when, log.now())
    return responder, len(alerts), rejected


if __name__ == "__main__":
    if len(sys.argv) != 2 or not pathlib.Path(sys.argv[1]).is_dir():
        sys.exit("usage: python -m receiver.folder <folder of alert .json files>")
    log.LOG = log.LOG.parent / "folder.jsonl"
    responder, accepted, rejected = replay(sys.argv[1])
    for i in responder.incidents.all:
        print(f"incident {i['id']} {i['incident_class']} on {i['subsystem']}: {i['technique']} tier {i['tier']}, "
              f"{i['alerts']} alerts, actions {i['actions']}")
    print(f"{accepted} alerts accepted, {rejected} rejected | log: {log.LOG}")
