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

## Test

    pytest -q

## Layout

    schema/     alert schema and sample, shared with Team B
    policy/     policy table as config, read at startup
    engine/     matching, tiers, logging
    receiver/   FastAPI endpoint
    stub/       fake alert sender
    actions/    response actions (Sprint 3)
    tests/
    docs/       definitions, threat analysis, environment notes
    logs/       JSON Lines output, not committed
