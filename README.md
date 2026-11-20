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

The receiver checks every alert against the schema in `engine/schema.py` (the fields of
`schema/sample_alert.json`). A bad alert gets a 422 and a `rejected` log line naming the fields. Good alerts go
through the same responder as the simulation: correlation, suppression and the rate limit. No line is attached
to the live receiver yet, so tier 2 and 3 are decided and logged but not carried out.

Offline replay of a folder of alert files, one alert per `.json` file, in `emitted_at` order:

    python -m receiver.folder path\to\alerts   # writes logs/folder.jsonl

Whole loop in the simulation (inject, detect, decide, act, recover), same seed gives the same result:

    python -m sim.scenario skip_step      # or drift, or none

It writes logs/scenario.jsonl and the ground-truth logs/labels.jsonl, never the live receiver's log.

Sprint 4 measurements, every attack on fixed seeds with our layer on and off:

    python -m sim.replay                  # writes logs/replay/results.json

Watchdog for a running receiver (fail-open: alerts the operator, never stops the line):

    python -m receiver.watchdog

## Test

    pytest -q

## Layout

    schema/     alert schema and sample, shared with Team B
    policy/     policy table as config, read at startup
    engine/     alert schema check, matching, tiers, logging, incidents, the responder
    receiver/   FastAPI endpoint, folder replay, watchdog
    stub/       fake alert sender
    actions/    isolate, safe state, return to normal
    sim/        shared line, attacks with labels, stand-in detector, scenario runner
    tests/
    docs/       definitions, threat analysis, environment notes
    logs/       JSON Lines output, not committed
