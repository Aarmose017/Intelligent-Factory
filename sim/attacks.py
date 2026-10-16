"""Attacks we inject. Each one maps to an ATT&CK for ICS technique and records its ground-truth label.

Label format (to be agreed with Team B): technique, incident_class, subsystem, start, end, all times in
simulation seconds. Team B's precision and recall are measured against these.
"""


def label(labels, technique, incident_class, subsystem, start, end):
    labels.append({"label_id": len(labels) + 1, "technique": technique, "incident_class": incident_class,
                   "subsystem": subsystem, "start": start, "end": end})


def drift(env, labels, machine, start, end, step=0.3, every=5):
    """T0836 Modify Parameter. processing_delay creeps up until it leaves its band.
    The attacker stops at `end` but does not put the value back, so recovery has to."""
    yield env.timeout(start)
    label(labels, "T0836", "sensor_drift", machine.id, start, end)
    while env.now < end:
        machine.processing_delay += step
        yield env.timeout(every)


def skip_step(env, labels, before, after, machine_id, start, end):
    """T0889 Modify Program. Items are moved straight from the buffer before the machine to the one after it,
    so they reach the Sink without being processed."""
    yield env.timeout(start)
    label(labels, "T0889", "sequence_violation", machine_id, start, end)
    while env.now < end:
        # Queue for the next item alongside the machine, which otherwise takes every item the moment it is ready.
        got = before.reserve_get()
        yield got | env.timeout(end - env.now)
        if not got.triggered:
            got.resourcename.reserve_get_cancel(got)  # attack over, do not hold a place in the queue
            break
        item = before.get(got)
        put = after.reserve_put()
        yield put
        after.put(put, item)
