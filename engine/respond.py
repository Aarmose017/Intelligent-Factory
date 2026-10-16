"""Alert in, at most one action per tier per incident out. Shared by the simulation now and by the live receiver
once Team B sends alerts. With no line to act on, actions are logged as decided but not carried out."""
from engine import log
from engine.incidents import Incidents, move
from engine.policy import pick_tier

ACTIONS = {None: "no_rule", 0: "log_only", 1: "alert_operator", 2: "isolate", 3: "safe_state"}


class Responder:
    def __init__(self, rules, settings, env=None, control=None):
        self.rules, self.s, self.env, self.control = rules, settings, env, control
        self.incidents = Incidents(settings["correlation_window"])
        self.disruptive = []  # times of tier 2 and 3 actions, for the rate limit

    def handle(self, alert, now):
        inc, new = self.incidents.correlate(alert, now)
        rule = pick_tier(alert, self.rules)
        tier, why = (rule["tier"] if rule else None), None
        if tier is not None and tier >= 2:
            limit = self.s["rate_limit"]
            if self.control and tier == 2 and inc["subsystem"] not in self.control.machines:
                tier, why = 1, "unknown_subsystem"  # the alert names something we cannot isolate
            elif len([t for t in self.disruptive if now - t < limit["per_seconds"]]) >= limit["max_actions"]:
                tier, why = 1, "rate_limited"
        # Suppression: an incident only gets another action when an alert asks for a higher tier than it has.
        if not new and (tier is None or tier <= (-1 if inc["tier"] is None else inc["tier"])):
            log.write(alert, rule, now, event="suppressed", reason=why, incident_id=inc["id"], tier=tier, t=now)
            return inc
        if tier is not None and tier >= 2:
            self.disruptive.append(now)
        inc["tier"], inc["technique"] = tier, rule["technique"] if rule else None
        inc["actions"].append(ACTIONS[tier])
        log.write(alert, rule, now, event="decision", action=ACTIONS[tier], reason=why, escalated=not new,
                  incident_id=inc["id"], tier=tier, t=now)
        if self.control and tier in (2, 3):
            self.env.process(self._isolate(inc) if tier == 2 else self._safe_state(inc))
        return inc

    def _isolate(self, inc):
        yield self.control.isolate(inc["subsystem"])
        if inc["tier"] == 2:  # not escalated while the machine was finishing its items
            self._contain(inc)
            yield from self._recover(inc, 2)

    def _safe_state(self, inc):
        yield self.env.timeout(self.s["operator_delay"])  # tier 3 waits for the operator to confirm
        self._event(inc, "operator_confirmed")
        self.control.safe_state()
        while not self.control.drained():
            yield self.env.timeout(self.s["check_period"])
        self._contain(inc)
        yield from self._recover(inc, 3)

    def _recover(self, inc, tier):
        yield self.env.timeout(self.s["operator_delay"])  # the operator looks at the cause before any restart
        while inc["tier"] == tier:
            self.control.restore_baseline()
            yield self.env.timeout(self.s["correlation_window"])
            if inc["tier"] != tier:
                return  # escalated meanwhile, the newer action owns recovery now
            # Precondition: settings stayed at baseline for a whole correlation window. An attacker still
            # active would have changed them again. One slower than that gets through and shows up again as
            # a new incident after the window.
            if self.control.at_baseline():
                # The line restarts with the last incident that needed it stopped, not before.
                if not any(i is not inc and i["state"] != "resolved" and (i["tier"] or 0) >= 2
                           for i in self.incidents.all):
                    self.control.resume()
                move(inc, "resolved", self.env.now)
                self._event(inc, "resolved")
                return
            self._event(inc, "precondition_failed")

    def _contain(self, inc):
        if inc["state"] == "open":
            move(inc, "contained", self.env.now)
        self._event(inc, "contained")

    def _event(self, inc, event):
        log.write({}, {"technique": inc["technique"], "tier": inc["tier"]}, event=event, incident_id=inc["id"],
                  incident_class=inc["incident_class"], affected_subsystem=inc["subsystem"], t=self.env.now)
