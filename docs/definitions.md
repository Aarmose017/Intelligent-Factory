# Shared definitions

Owner: Joshua. First draft by Aykhan, for Joshua to review. One or two lines each.

These have to match the code, the alert schema (`schema/sample_alert.json`), the
policy file, the threat analysis and the environment notes. If one of those
changes, change the definition here in the same pull request. Items marked
**Proposal** are not agreed yet.

## The six terms on the card

**Alert.** One JSON message from Team B's detector saying a process signal left
its expected band. It has an `alert_id`, an `incident_class`, a `confidence`
between 0 and 1 and an `affected_subsystem`, in the format of
`schema/sample_alert.json`.

**Incident.** What our layer treats as one problem on the line. It can be built
from many alerts and gets one record. An alert joins it if it has the same class
and subsystem and the incident is unresolved, or was resolved less than one
correlation window ago. A later alert only causes another action if it asks for a
higher tier. **Proposal:** CLAUDE.md says one decision per incident, and moving up
a tier needs Joshua's agreement.

**Action tier.** How disruptive our response is, picked by the policy rule that
matches the incident. 0 log only, 1 alert the operator, 2 isolate the subsystem,
3 safe state with operator confirmation. When two rules match, the higher tier
wins. Tier 3 never runs without confirmation.

**Contained.** The action for the incident has run, its effect shows up in the
telemetry, and the deviation is not spreading to other subsystems. A logged
action is not enough on its own, because some changes to the simulation do not
take effect (environment notes, traps 1 to 3). **Proposal:** only tier 2 and 3
can contain an incident, since tier 0 and 1 do not touch the line.

**Resolved.** The line is back to normal operation, the precondition check before
return to normal has passed (build step 8), and the incident is closed. The
precondition is that the settings stayed at their normal values for a whole
correlation window, so the line never restarts while an attacker is still active.

**Safe state.** **Proposal**, to agree with Mohammed: the Source stops generating,
every item already on the line reaches the Sink, and every machine is idle.
Nothing enters and nothing is left in progress. This is built and tested
(`actions/line.py`). It is what tier 3 drives the line to. Check it with
counts, Sink received equal to Source generated, not with the Source's `state`,
which still reads `GENERATING_STATE` after it has been stopped.

## Other terms we use

**Incident class.** The kind of deviation Team B reports, for example
`sensor_drift` or `sequence_violation`. It describes what the process did, not
who caused it. The policy matches on this field.

**Technique.** An ATT&CK for ICS technique ID, for example T0836, from
`docs/threat-analysis.md`. It describes the cause we injected. Team B cannot see
it, so it is used in our labels and in policy coverage, not in alerts.

**Subsystem.** One node on the line, named by its FactorySimPy `id`. The alert's
`affected_subsystem` has to use the same id the simulation uses, or our action
cannot find the node.

**Isolate.** The tier 2 action. Stop one subsystem so that items no longer flow
through it. We claim every worker slot of the machine, so it finishes what it holds
and takes nothing new, and releasing them restarts it. During safe state isolate
does nothing, because the line is already stopping. On a straight line this stops everything: the buffer
before it fills, the Source blocks and the Sink gets nothing. It only means
partial production loss, as CLAUDE.md assumes, if the line has a parallel branch
that keeps running.

**Incident states.** Open, contained, resolved, in that order. An incident is
open from the moment we create it until it is contained, or resolved directly if
it needed no action.

**Decision.** The tier the policy picks for one incident, written as one line in
`logs/response.jsonl` when the decision is made. No rule matching is also logged,
with an empty rule and tier. What that case should mean is still a team decision.

**Normal operation.** The line behaving like a baseline run, meaning the same
configuration and seed with no injection. Every signal stays inside the band seen
in the baseline.

**Operator delay.** A fixed, configurable wait between asking for tier 3 and
getting the confirmation. It stands in for a person, so replays give the same
result every time.

**Wrong response.** An action of tier 1 or higher that does not match an attack
in our labeled set: no attack was running, the incident class is wrong, or it came
outside the attack plus one correlation window. Its stoppage and downtime count
toward the cost of wrong responses.

**Time unit.** **Proposal**, to agree with Mohammed: one simulation tick is one
second. On our line (Team B's) an item enters every 0.8 s and takes 1.1 s on one
of 4 workers, about 75 items a minute.

## Timestamps

All four are in every log line and are UTC, ISO 8601.

| Field | Set by | Meaning |
|---|---|---|
| `observed_at` | Team B | when the detector saw the deviation |
| `emitted_at` | Team B | when the detector sent the alert |
| `received_at` | us | when the request reached our receiver |
| `logged_at` | us | when the decision was written |

`decision_ms` is our own time from receipt to decision, measured on a monotonic
clock. On the live receiver, time to decision is measured from `received_at`. In
the replay harness (`docs/sprint4-results.md`) every time is measured from the
attack's start in its ground-truth label instead, so it includes detection. Time
to safe state runs until the line is drained, operator delay included.
