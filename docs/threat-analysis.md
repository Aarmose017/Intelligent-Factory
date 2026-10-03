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

---

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
- **No equivalent in FactorySimPy:** T0835 Manipulate I/O Image and T0877 I/O Image
  (no PLC I/O image), T0858 Change Operating Mode (no documented modes), T0809 Data
  Destruction (no data stores). **Unsure** on T0858. If Juan Carlos finds machine
  modes, it should come back in.
- **Overlapping Impact techniques:** T0826 Loss of Availability, T0827 Loss of
  Control, T0813 Denial of Control, T0815 Denial of View, T0829 Loss of View, T0832
  Manipulation of View. Real, but in our data they look the same as T0831, T0828 or
  T1691.002. Kept out to avoid counting the same signal twice.
- **Pending, not excluded yet:** T0879 Damage to Property, T0880 Loss of Safety,
  T0837 Loss of Protection. These depend on the open question of whether anything in
  the simulation represents physical harm or a safety system. If it does, T0880
  should probably be in scope, because our paired on/off measurement depends on it.

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

Questions for Joshua and Team B:

1. `sensor_drift` is used for a cycle time change in the sample alert, but a cycle
   time change is a parameter change (T0836), not a drifting sensor. Should the
   classes be renamed to describe the signature, for example `cycle_time_deviation`?
2. Should the `technique` field in `policy.yaml` hold the ATT&CK ID so coverage can
   be counted straight from the file?
3. Who builds the telemetry layer that T1692.002 and T1691.002 attack?
