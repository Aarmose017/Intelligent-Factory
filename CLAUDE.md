# Project context for Claude Code

## What this is

Team A's slice of an FIU Capstone 2 project called "Intelligent factory: detecting
the attack, then answering it". Two teams, one simulated production line.

Team B detects attacks from process telemetry and emits an alert.
Team A (us) injects the attacks and owns everything after the alert arrives:
correlate, decide an action, execute it, log it, bring the line to a safe state.

The alert schema is the only contract between the two teams.

## Team

Aykhan Mammadli, team lead. Measurement and assurance, plus governance.
Joshua Aranzazu. Detection contract and policy.
Aaron Jeloni Moseley. Response engineering.
Juan Carlos Perez Ojea. Threat stimulus and environment. Inactive since October;
his area (sim/, attacks, labels, environment notes) is now Aykhan's.

Product Owner: Mohammed Al Duniawi, PhD student under Dr. Ruimin Sun, FIU.
Course instructor: Prof. Masoud Sadjadi.

## Stack, already decided

Python 3.14 throughout (CI and local runs), because FactorySimPy is a SimPy library and our attack
injection has to run inside it. A second language would only add an integration
boundary.

- Alerts: JSON over HTTP, FastAPI receiver. Offline replay reads JSON from a folder.
- Policy: YAML, read at startup. Never hardcode policy in Python.
- Incidents: SQLite planned. For now they are kept in memory, and every state change
  is in the JSONL log.
- Logs: JSON Lines, one object per line, append only.
- Tests: pytest, GitHub Actions on push.
- No rules engine. Plain Python matching is enough for roughly fifty rules.

## Design decisions that are settled

1. Threat analysis is written as the policy table itself, so the ATT&CK for ICS
   mapping and the engine config are one artifact.
2. The operator is modelled as a configurable delay, not a person clicking, so
   replays stay deterministic and our decision latency stays separable.
3. We build against a stub alert emitter first. Nothing in our slice waits on Team B.
4. We own the labeled attack set, so Team B's precision and recall are measured
   against our labels.
5. When two policy rules match one alert, the higher tier wins.

## Action tiers

0 log only, no confirmation, no cost
1 alert operator, no confirmation
2 isolate subsystem, no confirmation, partial production loss
3 degrade to safe mode, operator confirmation required, full production stop

## Scope exclusions, agreed with the Product Owner

- No network-layer response. No firewall rules, segmentation or host isolation.
  The attack shows up in process behaviour, so the response belongs at the control layer.
- No detection of attacks that leave no process signature.
- No automatic execution of tier 3. Safe mode and full shutdown need confirmation.
- No multi-line or plant-wide coordination. One line only.
- No forensics or attribution.
- No real industrial data or hardware. Everything stays in FactorySimPy.
- No network traffic analysis. Process telemetry only.

## Open questions, now answered

- Can FactorySimPy be written to? Yes. Plain attributes, changed mid-run, so actions
  call the simulation directly (docs/environment-notes.md).
- Is there a safe state in the model? Not as a library concept. Ours is: the Source
  stops and the line drains. Built and tested, still needs the Product Owner's sign-off.
- Does anything represent physical harm? No. The proxy is good and bad items at the
  Sink, still needs the Product Owner's sign-off.
- What is the cycle time? Not fixed. On Team B's line an item enters every 0.8 time
  units. Proposal: one time unit is one second.

## Build order

1. Threat analysis as the policy table
2. Stub emitter
3. Listener, structured log, alert action
4. Isolate action
5. Correlation window, one incident yields one decision (built so an incident can
   move up a tier; that needs Joshua's agreement)
6. Incident record with open, contained, resolved states
7. Safe mode and confirmation path
8. Return to normal with a precondition check
9. Rate limit and watchdog
10. Live integration with Team B
11. Replay harness and paired measurement

Sprints 1 and 2 cover steps 1 to 3. Stretch work starts only after step 11 produces numbers.

## Measurements we have to produce

- Time to decision, median and worst case, per action type
- Time to safe state, assumed operator delay included
- Recovery success rate, per incident class
- Process impact avoided, same injection with the layer on and off
- Cost of wrong responses, stoppages and downtime from alerts that were not attacks
- Policy coverage, techniques with an action against those without

Replays run on fixed seeds and a fixed operator delay. Numbers that shift between
runs cannot be defended.

## Working conventions

- Policy lives in config, never in code.
- The log ships with every action, not after. Measurements read from it.
- One owner per area. Do not commit inside someone else's paths without asking.
- Branch and open a PR. No commits straight to main.

## Writing style for any document in this repo

Plain, direct, no em dashes. No symmetrical paragraph structures or polished
transitions. Student-natural prose for anything submitted for the course.
