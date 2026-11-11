# Sprint 4 results

Owner: Aykhan. Produced by `python -m sim.replay` on 2026-11-08. Every number below comes from that run and can be
reproduced exactly with the same command.

**Provisional.** The time unit (1 simulation tick = 1 second) and the harm proxy (good and bad items at the Sink) are
not yet agreed with the Product Owner. Any number in seconds or items can change if he picks something else.

## How we measured

- The line is the one in Team B's test.py: Source, BUF1, MACHINE1 (4 workers, 1.1 s per item), BUF2, Sink.
- Two attacks, each with a ground-truth label: T0836 drift (MACHINE1 slows down for 40 s) and T0889 skip-a-step
  (items go round MACHINE1 for 20 s).
- Alerts come from our stand-in detector, since Team B does not have a detector yet.
- 10 seeds per case. The seed decides when the attack starts, somewhere between 15 and 45 s, so each run hits a
  different point in the line's cycle. Each run lasts 200 s.
- Every case runs twice, once with our layer acting on the line and once with it off. With it off, decisions are
  still logged but nothing is done to the line.
- Two operator delays, 5 s and 30 s. A real operator confirming a full stop probably takes 30 s or more, so 5 s is
  the optimistic case.

Times are median / worst over the 10 seeds, in seconds from the moment the attack started.

## Results

| Measure | Drift, 5 s delay | Drift, 30 s delay | Skip-a-step, 5 s delay | Skip-a-step, 30 s delay |
|---|---|---|---|---|
| Time to first alert | 0.9 / 1.3 | 0.9 / 1.3 | 2.3 / 3.0 | 2.3 / 3.0 |
| Time to decision | alert operator 0.9 / 1.3, isolate 6.0 / 6.7 | same | safe state 2.3 / 3.0 | same |
| Time to safe state | no tier 3 | no tier 3 | 10.3 / 11.0 | 35.3 / 36.0 |
| Time to resolve | 52.3 / 53.3 | 47.3 / 48.3 | 25.3 / 26.0 | 75.3 / 76.0 |
| Recovery success | 100% | 100% | 100% | 100% |
| Wrong responses | 0 | 0 | 0 | 0 |
| Duplicate actions | 0 | 0 | 0 | 0 |
| Bad items, layer on vs off | 0 vs 0 | 0 vs 0 | 4.7 vs 12 | 11.6 vs 12 |
| Good items, layer on vs off | 192 vs 230 | 199 vs 230 | 220.5 vs 235 | 182.2 vs 235 |

Clean runs with no attack: 0 alerts and 0 actions over 10 seeds and both delays. Good items 247 in every clean run.

Policy coverage: 2 of the 18 techniques in the threat analysis have a policy action (T0836 and T0889). The other 16
have none yet.

## What the numbers say

Detection and decision are fast. Once an alert arrives our layer decides in the same instant, so time to decision
is really the stand-in detector's speed. The one exception is drift, where isolation comes about 5 s after the
first alert. That is on purpose: confidence starts low, the first decision is only an operator alert, and the
incident moves up to isolation once confidence passes 0.8.

Safe state helps only if the operator is quick. With a 5 s delay it cut bad product from 12 items to 4.7, at a cost
of about 15 good items. With a 30 s delay it prevented almost nothing, because the skip-a-step attack lasts only
20 s and the line stopped after the damage was already done. It still cost about 53 good items. So for short
attacks, tier 3 with operator confirmation is too slow. This is a policy question for Joshua and the Product Owner.

For drift, our response costs more than it saves if you only count items. The attack slows the machine but makes
no bad product, while isolation stops the machine completely, so the line makes 31 to 38 fewer good items with our
layer on. This is the main reason the harm proxy needs agreeing. If a slow machine also wears out or produces
off-spec parts, the picture changes, but nothing in FactorySimPy models that.

Recovery always worked and never restarted the line while the attacker was still active. Resolve times are long
because recovery checks that the settings stay at their normal values for a full 10 s window. Those checks run
on a fixed cycle that starts when the incident is contained, so the incident resolves 7 to 12 s after the attack
ends, depending on how the cycle lines up. That is also why drift happens to resolve sooner with the 30 s delay.

No wrong responses and no duplicate actions in any run.

## Limits

- Everything runs in the simulation with our own attacks and our own stand-in detector. Team B's detector is not
  part of these numbers.
- Only two techniques are tested, so the coverage number is low and the results say nothing about the other 16.
- The line has one machine and one path. The only variation between seeds is when the attack starts.
- Our layer's own processing time is instant in the simulation. Real decision time is only measured on the live
  receiver (`decision_ms`, 1 to 2 ms on a laptop).
- Good and bad items are a proxy. They do not capture wear, damage or safety, because the simulation has none.

## How to reproduce

    python -m sim.replay

This writes `logs/replay/results.json` and one log per run in `logs/replay/`. The tests in
`tests/test_replay.py` check that the same seeds give the same numbers.
