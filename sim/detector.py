"""Stand-in for Team B's detector. Their repo has no detector yet (checked 2026-10-16), so this samples the
line and emits alerts in the shared schema. Replace it with their alerts once they exist."""

BAND = (0.9, 1.3)  # MACHINE1 processing_delay is 1.1 at baseline


def alert(n, now, incident_class, confidence, subsystem, signal, expected_band, actual):
    return {"schema_version": "1.0", "alert_id": f"sim-{n}", "emitted_at": now, "observed_at": now,
            "incident_class": incident_class, "confidence": round(confidence, 2), "affected_subsystem": subsystem,
            "observed_deviation": {"signal": signal, "expected_band": expected_band, "actual": actual}}


def detector(env, nodes, emit, period=1.0):
    machine, sink = nodes["MACHINE1"], nodes["SINK"]
    n = skipped_before = 0
    while True:
        yield env.timeout(period)
        delays = machine.stats["processing_delay"]
        if delays and not BAND[0] <= delays[-1] <= BAND[1]:
            n += 1
            mid = sum(BAND) / 2
            emit(alert(n, env.now, "sensor_drift", min(0.99, 0.5 + abs(delays[-1] - mid) / mid), machine.id,
                       "processing_delay", list(BAND), delays[-1]))
        # Every item the Sink receives should have been through the machine first. Alert on new skips only,
        # the running total never goes back down once the attack stops.
        skipped = sink.stats["num_item_received"] - machine.stats["num_item_processed"]
        if skipped > skipped_before:
            n += 1
            emit(alert(n, env.now, "sequence_violation", 0.9, machine.id,
                       "items_skipping_machine", [0, 0], skipped - skipped_before))
        skipped_before = max(skipped, skipped_before)
