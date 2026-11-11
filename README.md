# Factory response layer

Team A, Intelligent Factory capstone. Takes an alert from Team B's detector,
decides an action tier from policy, and logs the decision.

## Setup

    python -m venv .venv
    .venv\Scripts\Activate.ps1      # Windows PowerShell
    source .venv/bin/activate       # Mac / Linux / Git Bash
    pip install -r requirements.txt

## Run

    uvicorn receiver.main:app --reload

In a second terminal:

    python stub/send_alert.py

Whole loop in the simulation (inject, detect, decide, act, recover), same seed gives the same result:

    python -m sim.scenario skip_step      # or drift, or none

It writes logs/scenario.jsonl and the ground-truth logs/labels.jsonl, never the live receiver's log.

Watchdog for a running receiver (fail-open: alerts the operator, never stops the line):

    python -m receiver.watchdog

## Test

    pytest -q

## Layout

    schema/     alert schema and sample, shared with Team B
    policy/     policy table as config, read at startup
    engine/     matching, tiers, logging, incidents, the responder
    receiver/   FastAPI endpoint, watchdog
    stub/       fake alert sender
    actions/    isolate, safe state, return to normal
    sim/        shared line, attacks with labels, stand-in detector, scenario runner
    tests/
    docs/       definitions, threat analysis, environment notes
    logs/       JSON Lines output, not committed
