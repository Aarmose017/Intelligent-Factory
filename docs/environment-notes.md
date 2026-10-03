# What FactorySimPy lets us read and change

Owner: Aykhan, taken over from Juan Carlos on 2026-10-03. Findings verified by running the library, not by reading docs alone. First run on Linux with Python 3.12, then re-run on Windows 11 with Python 3.14 (see section 6).

Version tested: factorysimpy 0.1.0b3, from PyPI, with simpy 4.1.2.

    pip install factorysimpy

The GitHub install also works but PyPI is simpler:

    pip install git+https://github.com/FactorySimPy/FactorySimPy.git

## What it is

A component library on top of SimPy. You build a line out of nodes joined by edges, then run a discrete-event clock over it.

Nodes: `Source`, `Machine`, `Sink`, `Combiner`, `Splitter`, under `factorysimpy.nodes`.
Edges: `Buffer`, `ContinuousConveyor`, `SlottedConveyor`, `Fleet`, under `factorysimpy.edges`.

Minimal line that runs:

```python
import simpy
from factorysimpy.nodes.source import Source
from factorysimpy.nodes.machine import Machine
from factorysimpy.nodes.sink import Sink
from factorysimpy.edges.buffer import Buffer

env = simpy.Environment()
src = Source(env, id="src", inter_arrival_time=2)
m   = Machine(env, id="m1", processing_delay=3)
snk = Sink(env, id="sink")
b1  = Buffer(env, id="b1", capacity=5)
b2  = Buffer(env, id="b2", capacity=5)

b1.connect(src, m)
b2.connect(m, snk)

env.run(until=40)
```

The library prints a trace line for every event (`T=12.00: m1 is in PROCESSING_STATE` and so on). Useful for debugging, but it floods the console in long runs. Redirect stdout if you do not need it.

Constructor defaults worth knowing, read from the 0.1.0b3 signatures:

- `Buffer(env, id, capacity=1, delay=0, mode="FIFO")`. The parameter is `capacity`. The GitHub README calls it `store_capacity`, which is wrong for this version.
- `Machine(..., node_setup_time=0, work_capacity=1, processing_delay=0, blocking=True, in_edge_selection="FIRST_AVAILABLE", out_edge_selection="FIRST_AVAILABLE")`

## 1. What we can read

Yes, and more than enough for detection. Every node and edge carries a live `state` string and a `stats` dict that updates as the simulation runs.

**Machine**

- `state`: one of `SETUP_STATE`, `IDLE_STATE`, `PROCESSING_STATE`, `BLOCKED_STATE`
- `stats["num_item_processed"]`, `stats["num_item_discarded"]`
- `stats["total_time_spent_in_states"]`, a dict of seconds per state
- `stats["processing_delay"]`, the delay actually used for each item, in order
- `stats["in_edge_selection"]` and `stats["out_edge_selection"]`, which edge was chosen each time
- `stats["last_state_change_time"]`
- `item_in_process`, `num_workers`, `work_capacity`

**Source**

- `stats["num_item_generated"]`, `stats["num_item_discarded"]`
- `stats["total_time_spent_in_states"]`
- `state`: `SETUP_STATE`, `GENERATING_STATE`, `BLOCKED_STATE`

**Sink**

- `stats["num_item_received"]`, `stats["total_cycle_time"]`
- `stats["total_time_spent_in_states"]`, only `COLLECTING_STATE`

**Buffer**

- `stats["time_averaged_num_of_items_in_buffer"]`
- `stats["total_time_spent_in_states"]` over `IDLE_STATE`, `RELEASING_STATE`, `BLOCKED_STATE`. In our runs all three stayed at 0.0 and `last_state_change_time` stayed `None`, so the buffer does not seem to track its own states in this version. Do not build detection on these.
- `len(buffer.inbuiltstore.ready_items)` for the live count. Not `inbuiltstore.items`, which stayed empty for the whole run even while the library's own trace reported 4 items in the buffer. `ready_items` rose from 0 to 5 as the buffer filled. There is also `reserved_items`, which held 1 item once the machine started pulling, probably the item the machine has claimed. Unsure whether the true count is `ready_items` alone or `ready_items` plus `reserved_items`.
- `capacity`, `mode` (FIFO or LIFO), `delay`

Sample output from a 40-tick run of the line above (identical on Linux and Windows):

```
MACHINE state: PROCESSING_STATE
MACHINE stats: num_item_processed 12, processing_delay [3,3,3,...],
               total_time_spent_in_states {IDLE 2.0, PROCESSING 36.0, BLOCKED 0.0}
SINK stats:    num_item_received 12, total_cycle_time 102.0
SOURCE stats:  num_item_generated 18, BLOCKED_STATE 2.0
BUFFER b1:     time_averaged_num_of_items_in_buffer 2.76
```

That is the telemetry Team B detects on. Processing delay per item, buffer level, time blocked, and item counts are all there.

## 2. Can we change values from outside

Yes. Plain Python attributes, no setters, no guards. Confirmed by mutating a running simulation.

Writing `machine.processing_delay = 12` at T=20 changed the behaviour from that point. The recorded delay sequence came out `[3, 3, 3, 3, 3, 3, 12, 12, 12, 12]`, so the change took effect on the next item and the library kept running without complaint.

This matters for us in two ways.

**Injection is straightforward.** Our attacks run as SimPy processes alongside the line:

```python
def attack(env, machine):
    yield env.timeout(20)
    machine.processing_delay = 12   # the deviation
env.process(attack(env, m))
```

**Actions can act on the line directly.** Changing `processing_delay` or the Source `inter_arrival_time` changes what the line does. So the response layer does not need to be modelled as a command queue the simulation polls. The direct approach the design assumes is possible. But see the traps below, not every assignment does what it looks like.

`processing_delay` accepts an int, a float, a callable, or a generator, which gives us several ways to shape an attack.

**Trap 1, buffer capacity.** Setting `buffer.capacity` changes the attribute but not the underlying store. After `b1.capacity = 99` the store still reported capacity 5. Anything that needs the real limit has to go through `buffer.inbuiltstore`. Check the effect rather than trusting the assignment.

**Trap 2, machine state.** Setting `machine.state` does not change what the machine does. After forcing `m.state = "BLOCKED_STATE"` at T=10, the attribute still read `BLOCKED_STATE` at T=11.0, and by T=11.5 the machine had overwritten it on its next real state change. It processed 12 items by T=40, the same as with no change. So `state` cannot be used to stop or isolate a machine. It does give us a clean way to inject a spoofed report (T1692.002 in the threat analysis), since the telemetry lies while the process carries on normally.

**Trap 3, stopping is one way.** A very large value stops a node. With `processing_delay = 1e9` at T=20, the Sink got 6 items by T=60 against 19 with no change. With the Source `inter_arrival_time = 1e9` at T=20, the Source stopped at 10 items and the Sink received all 10, so the line drained. But setting the value back does not undo it. The node is already inside its long wait and does not see the new value. Restoring the normal value at T=30 still left the Sink at 6 (machine) and 10 (Source) by T=80, against 25 with no change. So this works for stopping and for safe state, but return to normal needs a different mechanism, for example interrupting the node's SimPy process. Not tested yet.

## 3. Cycle time

There is no fixed cycle time in the library. Time is whatever we configure, and `env.now` is a plain SimPy clock with no unit attached.

The two parameters that set the pace:

- `Source(inter_arrival_time=...)`, how often an item enters
- `Machine(processing_delay=...)`, how long one item takes

In the example above, items arrive every 2 and processing takes 3, so the machine is the bottleneck and the effective cycle is 3 time units per item.

**For the latency budget:** we choose the numbers, so we should pick them to look like a real line and then state the mapping. Proposal, to agree with Mohammed: one time unit equals one second, `processing_delay` 3, `inter_arrival_time` 2, giving a 3 second cycle. The latency target then becomes a fraction of 3 seconds.

## 4. What this settles

| Open question | Answer |
| --- | --- |
| Can we read process telemetry? | Yes. `state` and `stats` on every node and edge. Buffer state times are not tracked. |
| Can we write to the simulation? | Yes. Plain attributes, mutable mid-run. Check each one has a real effect (see traps). |
| Must actions be a command queue? | No. Direct changes work. |
| Is there a cycle time? | Not fixed. We set it through `inter_arrival_time` and `processing_delay`. |

## 5. Still open

**Safe state is not a library concept.** Nothing in FactorySimPy represents a safe state, so we define it ourselves. The obvious candidate is forcing the source to stop generating and letting the line drain. That now works in a test (trap 3, all 10 generated items reached the Sink), but it is still our design decision and needs writing down.

**Return to normal has no mechanism yet.** Stopping by a large delay cannot be undone by restoring the value (trap 3). Build step 8 needs a way to pause and resume a node. Interrupting its SimPy process is the first thing to try.

**Nothing represents physical harm.** There is no damage, wear, scrap or off-spec output in the model. Our "process impact avoided" measure therefore needs a proxy. Candidates: items discarded (`num_item_discarded` exists on Source and Machine), time spent in `BLOCKED_STATE`, throughput lost against a clean baseline, or items processed with an out-of-band delay. Throughput lost is probably the cleanest. Needs agreeing with Mohammed.

**Live buffer count.** Unsure whether it is `ready_items` alone or plus `reserved_items` (section 1).

## 6. Windows check

Re-ran every claim above on Windows 11, Python 3.14.7, factorysimpy 0.1.0b3, simpy 4.1.2, on 2026-10-03.

| Claim | Result on Windows |
| --- | --- |
| 40-tick sample numbers | Identical: 12 processed, IDLE 2.0, PROCESSING 36.0, Sink 12 and 102.0, Source 18 generated, buffer average 2.76 |
| `processing_delay` change at T=20 | Identical delay sequence |
| `buffer.capacity` trap | Same, attribute 99, store 5 |
| Live count via `inbuiltstore.items` | Did not hold, always 0. Corrected to `ready_items` in section 1 |
| Setting `machine.state` acts on the line | Did not hold. Only the reported value changes. Corrected, trap 2 |
| Stop with a large value, then restore | New finding, trap 3 |

Python 3.11 and 3.12 on Windows were not tested.
