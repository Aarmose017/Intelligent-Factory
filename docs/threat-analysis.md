# ATT&CK for ICS threat analysis

Owner: Aykhan. Target for Sprint 2 is eight in-scope techniques, not full coverage.

Format per technique:

### T#### Technique name
Tactic:
What it looks like on our line:
Observable in process data? yes / no / partly
In scope because:

---

## Notes before reading

IDs and tactics were checked against the MITRE ATT&CK for ICS site on 2026-10-01,
which is version 19 (May 2026). Version 19 changed some IDs that older papers and
slides still use. T0855 Unauthorized Command Message and T0856 Spoof Reporting
Message are now sub-techniques of T1692 Unauthorized Message. T0803 Block Command
Message and T0804 Block Reporting Message are now sub-techniques of T1691 Block
Operational Technology Message. T0833 Modify Control Logic is marked deprecated and
its page does not say what replaced it. If the product owner is working from an
older version of the matrix, that is why the numbers will not match.

FactorySimPy has no controllers, no network and no messages. It has nodes (Source,
Machine, Sink, plus Splitter and Combiner) connected by edges (Buffer, conveyors).
The parameters it exposes include `processing_delay` on Machine,
`inter_arrival_time` on Source and `store_capacity` on Buffer. Its docs say nothing
about machine failures or machine states. So every technique below is modelled by
its effect on the process, not by the mechanism a real attacker would use. Where a
technique attacks "messages", it means the telemetry stream Team B reads, which is
something we or Team B have to build on top of the simulation.

Things marked **Unsure** are open and should not be presented as settled.

The techniques are split into three groups. The core set is the eight we commit to
for Sprint 2. Each one is something we can inject or measure on our own line. The
extended set adds eight more. They are real and they apply to us, but most of them
are Impact techniques that describe the result of a core technique, or they depend
on something in the simulation we have not confirmed. The conditional set is two
techniques that only apply if the simulation turns out to model safety or physical
damage.

## Summary

| ID | Name | Tactic | Group | Observable |
|---|---|---|---|---|
| T0836 | Modify Parameter | Impair Process Control | core | yes |
| T1692 | Unauthorized Message | Evasion, Impair Process Control | core | yes (.001), partly (.002) |
| T1691 | Block Operational Technology Message | Inhibit Response Function | core | partly |
| T0806 | Brute Force I/O | Impair Process Control | core | yes |
| T0816 | Device Restart/Shutdown | Inhibit Response Function | core | yes |
| T0889 | Modify Program | Persistence | core | partly |
| T0831 | Manipulation of Control | Impact | core | yes |
| T0828 | Loss of Productivity and Revenue | Impact | core | yes |
| T0821 | Modify Controller Tasking | Execution | extended | partly |
| T0835 | Manipulate I/O Image | Inhibit Response Function | extended | yes |
| T0832 | Manipulation of View | Impact | extended | partly |
| T0815 | Denial of View | Impact | extended | yes |
| T0829 | Loss of View | Impact | extended | yes |
| T0813 | Denial of Control | Impact | extended | partly |
| T0827 | Loss of Control | Impact | extended | yes |
| T0826 | Loss of Availability | Impact | extended | yes |
| T0880 | Loss of Safety | Impact | conditional | only if modelled |
| T0879 | Damage to Property | Impact | conditional | only if modelled |

18 techniques in total. If the product owner asks for a coverage number, the honest
one for Sprint 2 is the eight core techniques.

---

## Core set

### T0836 Modify Parameter
Tactic: Impair Process Control

What it looks like on our line: A machine's `processing_delay` is changed mid run,
or the Source `inter_arrival_time`, or a Buffer `store_capacity`. A slower machine
shows up as cycle time leaving its normal band. Its upstream buffer fills and the
Sink count rate drops. A shrunk buffer causes blocking upstream earlier than it
should.

Observable in process data? yes

In scope because: These are exactly the knobs FactorySimPy exposes, so it is the
most direct attack we can inject and the clearest signature Team B can detect. The
sample alert in `schema/sample_alert.json` (cycle time 17.4 s against a 10 to 12 s
band) is really this technique.

**Unsure:** whether a parameter can be changed while the simulation is running, or
only set at construction. If only at construction we would have to wrap the
Machine or restart the run. Waiting on Juan Carlos's environment notes.

### T1692 Unauthorized Message
Tactic: Evasion, Impair Process Control

What it looks like on our line: Two sub-techniques that look very different in data,
so they are described separately.

T1692.001 Command Message. Someone tells a machine to stop, pause or start when it
should not. On our line that means a machine goes idle while its input buffer has
items and its output is not blocked. The input buffer fills and Sink throughput
drops.

T1692.002 Reporting Message. The line runs normally but the telemetry reports false
values, for example a buffer level or a part count. Or the opposite, a real problem
is hidden behind normal looking numbers.

Observable in process data? yes for .001, partly for .002. Spoofed reports can only
be caught when they contradict other signals, for example a reported buffer level
that does not match items in minus items out. If the attacker spoofs every related
signal consistently there is nothing to catch.

In scope because: .001 is a basic way to disrupt a discrete line and has a clear
signature. .002 matters for us on the response side, since acting on a spoofed
report means we isolate a subsystem that was fine, which is one of the wrong
response costs we have to measure.

**Unsure:** .001 and T0816 can look the same in process data. The difference may
only be duration and whether the machine loses work in progress. .002 needs a
telemetry layer between the simulation and Team B, which nobody has agreed to build
yet.

### T1691 Block Operational Technology Message
Tactic: Inhibit Response Function

What it looks like on our line: T1691.002 Reporting Message is the main case.
Telemetry from one machine stops arriving, or freezes at its last value while the
rest of the line keeps moving. T1691.001 Command Message would mean a command never
reaches the machine. Since the simulation has no commands, the only commands on our
line are our own response actions, for example an isolate that never takes effect.

Observable in process data? partly. A gap in samples is easy to see. A frozen value
is visible only if that signal normally varies.

In scope because: It is the plain version of hiding an attack, and the .001 case is
a direct test of our own layer. The watchdog in build step 9 is supposed to catch an
action that did not execute.

**Unsure:** same dependency on a telemetry layer as T1692.002.

### T0806 Brute Force I/O
Tactic: Impair Process Control

What it looks like on our line: A value is changed repeatedly instead of once. For
example `processing_delay` flipping between two values every few cycles, or a
machine being stopped and started over and over. Cycle time oscillates and buffer
levels swing instead of drifting.

Observable in process data? yes

In scope because: It gives Team B a different shape of signal from a single step
change (T0836), which is useful for checking that their detector handles more than
one pattern. It also tests our correlation window, since one attack produces a burst
of alerts that should become one incident.

### T0816 Device Restart/Shutdown
Tactic: Inhibit Response Function

What it looks like on our line: A machine drops out for a period and comes back.
Throughput at that machine goes to zero, upstream buffers fill, downstream starves.
A restart may also lose the item that was in the machine.

Observable in process data? yes

In scope because: Unplanned stoppage is the most common disruption on a real
discrete line and the easiest to tie to production loss. It is also the case where
a false positive is most likely, since machines stop for normal reasons too, so it
feeds the cost of wrong responses measurement.

**Unsure:** FactorySimPy does not document breakdowns or machine states, so we would
have to implement shutdown ourselves, probably by interrupting the machine's SimPy
process. Not confirmed this works.

### T0889 Modify Program
Tactic: Persistence

What it looks like on our line: The logic that decides how items flow is changed.
Items skip a machine, go to the wrong output edge, or steps happen out of order. In
FactorySimPy the closest thing to a program is routing, `in_edge_selection` and
`out_edge_selection`. This is what our `sequence_violation` incident class is meant
to cover.

Observable in process data? partly. Items arriving at the Sink without passing a
required machine would be visible if items carry a route history. Without that,
only knock on effects like unbalanced buffer levels show.

In scope because: Step order matters on a discrete line, and our policy already has
a rule for sequence violations, so it needs a technique behind it.

**Unsure:** this is the weakest mapping in the list. ATT&CK lists T0889 under
Persistence only, which does not describe the process effect. T0821 Modify
Controller Tasking (Execution) is the other candidate. T0833 Modify Control Logic
used to be the obvious fit but it is deprecated now. Worth asking the product owner
which one to use before we lock the policy table.

### T0831 Manipulation of Control
Tactic: Impact

What it looks like on our line: The physical process does something other than what
it was set up to do. Different cycle times, different routing, different output.
This is the result of T0836, T1692.001 and T0806, not a separate injection.

Observable in process data? yes

In scope because: Our response layer acts on effects, not on how the attacker got
in. Having the Impact technique in the table lets us state which effect each
response is meant to stop.

**Unsure:** whether an Impact technique should have its own row in the policy table
or just be listed as the outcome of the techniques above. Leaning towards the
second.

### T0828 Loss of Productivity and Revenue
Tactic: Impact

What it looks like on our line: Fewer items reach the Sink than the baseline run for
the same time period. Every attack above ends here if nothing responds.

Observable in process data? yes. Sink count against the baseline is the simplest
number the simulation produces.

In scope because: It is the measurement behind "process impact avoided". The same
injection with the response layer on and off should show a difference in Sink
count, and that difference is the number we report. Our own tier 2 and tier 3
actions also cause this, which is why wrong responses have a cost.

**Unsure:** same question as T0831 about whether it gets its own policy row.

---

## Extended set

### T0821 Modify Controller Tasking
Tactic: Execution

What it looks like on our line: The timing of the work changes rather than one
value. A machine runs its task more or less often than it should, or one machine
gets priority over another for a shared input. In FactorySimPy the closest knob is
`in_edge_selection`, which decides which input edge a machine pulls from. The
signature is a periodic pattern in cycle time, or one branch of the line starving
while another is fed.

Observable in process data? partly. A regular pattern is visible if Team B looks
at timing over a window and not just single values.

In scope because: It is the other candidate for `sequence_violation`, next to
T0889. T0889 changes what the logic does, T0821 changes when it runs.

**Unsure:** in FactorySimPy both "program" and "tasking" come down to how a node
behaves, so we may not be able to inject T0821 and T0889 in ways that look
different. We should only count both if Juan Carlos can.

### T0835 Manipulate I/O Image
Tactic: Inhibit Response Function

What it looks like on our line: The machine acts on false inputs while the
telemetry stays truthful. For example a machine is told its output buffer is full
and stops sending items, while the reported buffer level shows space. The
signature is a machine blocked while the next buffer has room.

Observable in process data? yes, as long as both the machine state and the buffer
level are in the telemetry.

In scope because: It is the mirror of T1692.002. There the view is false and the
process is fine. Here the process is wrong and the view is correct. Having both
in the labeled set helps check whether Team B can tell them apart, and the right
response is different. Isolating the machine makes sense here, but not for a
spoofed report.

**Unsure:** FactorySimPy has no PLC and no I/O image. We would fake it by changing
what a machine sees about its neighbours. Nodes have a `blocking` parameter but
we have not checked whether this can be overridden mid run.

### T0832 Manipulation of View
Tactic: Impact

What it looks like on our line: Whoever reads the telemetry sees a false picture.
On our line that is Team B's detector, our response layer and the modelled
operator. This is the result of T1692.002.

Observable in process data? partly, for the same reasons as T1692.002.

In scope because: Our layer reads the view too. A manipulated view is what leads
us to take the wrong action, so it sits behind the cost of wrong responses
measurement.

**Unsure:** this overlaps with T1692.002 completely in our data. It is listed as the
Impact side of that technique, not as a separate injection.

### T0815 Denial of View
Tactic: Impact

What it looks like on our line: A temporary gap in telemetry from part or all of
the line. The line keeps running but nobody can see it for a while. This is the
result of T1691.002.

Observable in process data? yes. Missing samples are easy to see.

In scope because: The policy needs an answer for "we are blind for a while". Right
now there is no rule for it. Tier 1 (alert the operator) seems right for a short
gap.

### T0829 Loss of View
Tactic: Impact

What it looks like on our line: The same as T0815, but the telemetry does not come
back.

Observable in process data? yes, as a lasting absence of data.

In scope because: A long blind period is where the response should change. After
enough time without data, safe mode (tier 3, with operator confirmation) may be
the only defensible action, since we cannot see whether the line is being
damaged.

**Unsure:** how long a gap has to last to count as loss instead of denial. It
should be some number of cycle times, and the cycle time is still an open
question.

### T0813 Denial of Control
Tactic: Impact

What it looks like on our line: For a while, commands to the line do not take
effect. In our setup the only commands are our own response actions, so this
means an isolate or safe mode that is logged as sent but does not change anything
in the process.

Observable in process data? partly. It is only visible if we check the process
after our own action, not just log that we sent it.

In scope because: It tests our own layer directly. The watchdog (build step 9) and
the precondition check before return to normal (step 8) are there for this case.

### T0827 Loss of Control
Tactic: Impact

What it looks like on our line: The lasting version of T0813. Isolate and safe mode
both fail and the machine keeps running at the attacked settings, even after the
injection stops.

Observable in process data? yes. The deviation continues after our response.

In scope because: It is the failure case for time to safe state and recovery
success rate. If the line never reaches a safe state, the measurement has to
record that as a failure and not leave the run out.

### T0826 Loss of Availability
Tactic: Impact

What it looks like on our line: Part of the line, or all of it, produces nothing.
T0828 is about reduced output. This one is about zero output.

Observable in process data? yes. The Sink count stops.

In scope because: Our own tier 2 and tier 3 actions cause this on purpose. When we
measure the cost of wrong responses we need to separate downtime caused by the
attacker from downtime caused by us. Having the technique in the table makes that
split explicit.

**Unsure:** this overlaps a lot with T0828. They may end up as one row.

---

## Conditional set

These two depend on the open question of whether anything in the simulation
represents physical harm. They are written up now so they are ready if the answer
is yes.

### T0880 Loss of Safety
Tactic: Impact

What it looks like on our line: Only applies if the simulation has a safety
function, for example a machine that must stop when a value crosses a limit. The
attack would be the limit being crossed and the stop not happening.

Observable in process data? only if a safety function is modelled.

In scope because: It is the strongest reason for tier 3 to exist. It would also
give the paired on/off measurement a harm number, not just a throughput number.

**Unsure:** nothing like this is in the FactorySimPy docs. We may have to add it
ourselves, and then we need to be clear in the report that we added it.

### T0879 Damage to Property
Tactic: Impact

What it looks like on our line: Only applies if the simulation tracks wear or
damage, for example a machine that is damaged after running outside its band for
too long, or after rapid stop and start cycles from T0806.

Observable in process data? only if damage is modelled as a state.

In scope because: Without it, process impact avoided can only be measured as lost
throughput. With it we could also report damage avoided.

**Unsure:** same as T0880. Not in the FactorySimPy docs as far as we can tell.

---

## Considered and excluded

Most of these leave no process signature, which is exclusion two in our proposal.
Some also fall under the network layer exclusions.

- **Discovery and collection:** T0842 Network Sniffing, T0846 Remote System
  Discovery, T0888 Remote System Information Discovery, T0840 Network Connection
  Enumeration, T0801 Monitor Process State, T0861 Point & Tag Identification, T0802
  Automated Collection, T0882 Theft of Operational Information. Reading does not
  change the process.
- **Initial access and lateral movement:** T0865 Spearphishing Attachment, T0817
  Drive-by Compromise, T0819 Exploit Public-Facing Application, T0866 Exploitation
  of Remote Services, T0822 External Remote Services, T0847 Replication Through
  Removable Media, T0862 Supply Chain Compromise. These happen on IT hosts and
  networks, which the simulation does not have.
- **Accounts and credentials:** T0859 Valid Accounts, T0892 Change Credential, T1694
  Insecure Credentials. No accounts exist in the simulation.
- **Host level execution and evasion:** T0807 Command-Line Interface, T0853
  Scripting, T0871 Execution through API, T0874 Hooking, T0851 Rootkit, T0849
  Masquerading, T0872 Indicator Removal on Host, T0881 Service Stop. No hosts. Where
  one of these does affect the process, the effect shows up as one of the in-scope
  techniques.
- **Network layer:** T0814 Denial of Service, T1695 Block Communications, T0830
  Adversary-in-the-Middle. Out of scope by exclusion one and seven. Any process
  effect they have looks like T1691 or T1692 in our data.
- **Delivery mechanisms:** T0843 Program Download, T0845 Program Upload, T1693 Modify
  Firmware. How a change gets onto a device. The change itself is covered by T0889
  or T0836.
- **Alarms:** T0878 Alarm Suppression, T0838 Modify Alarm Settings. The simulation
  has no alarm system. In our setup the alarm is Team B's detector, and if that is
  suppressed no alert reaches us at all, so there is nothing for our layer to do.
- **No equivalent in FactorySimPy:** T0877 I/O Image (reading the I/O image, no
  process change), T0858 Change Operating Mode (no documented modes), T0809 Data
  Destruction (no data stores). **Unsure** on T0858. Its modes include Stop, which
  would look like T0816 on our line. If Juan Carlos finds machine modes, it should
  come back in.
- **T0837 Loss of Protection:** about protective functions like relays and
  breakers. Nothing like that is in the simulation, and if a safety function gets
  added, T0880 already covers it.

---

## How this maps to policy.yaml

The policy table matches on `incident_class`, which is what Team B emits. Team B
cannot tell which technique caused an alert, only what the process did. So the
mapping goes technique to the signature it leaves to the incident class. Right now
`policy.yaml` has two classes and uses made up names in the `technique` field
instead of ATT&CK IDs.

| Technique | Signature | Current class |
|---|---|---|
| T0836 | step change in cycle time, buffer level, arrival rate | `sensor_drift` (name does not really fit) |
| T1692.001 | machine idle with input waiting | none yet |
| T1692.002 | reported values that contradict each other | `sensor_drift` maybe |
| T1691.002 | missing or frozen telemetry | none yet |
| T0806 | oscillating cycle time or machine state | none yet |
| T0816 | machine throughput drops to zero for a period | none yet |
| T0889 | items out of order or skipping a step | `sequence_violation` |
| T0831, T0828 | outcomes, see above | n/a |
| T0821 | periodic timing pattern, one branch starved | `sequence_violation` maybe |
| T0835 | machine blocked while next buffer has room | none yet |
| T0832 | same as T1692.002 | same as T1692.002 |
| T0815 | short telemetry gap | none yet |
| T0829 | telemetry gone for longer than a threshold | none yet |
| T0813, T0827 | our action sent but the process does not change | none, our watchdog catches it, not Team B |
| T0826 | Sink count stops | none yet |
| T0880, T0879 | only if modelled | n/a |

Questions for Joshua and Team B:

1. `sensor_drift` is used for a cycle time change in the sample alert, but a cycle
   time change is a parameter change (T0836), not a drifting sensor. Should the
   classes be renamed to describe the signature, for example `cycle_time_deviation`?
2. Should the `technique` field in `policy.yaml` hold the ATT&CK ID so coverage can
   be counted straight from the file?
3. Who builds the telemetry layer that T1692.002 and T1691.002 attack?
4. Does Team B emit an alert when telemetry goes missing (T0815, T0829), or do we
   detect the gap ourselves? If nobody does, being blind never triggers a
   response.
