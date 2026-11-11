"""What our layer can do to the line, and how to undo it. Return to normal needs every action to be reversible,
which rules out the obvious ways: writing machine.state changes nothing, and a huge delay cannot be taken back
(docs/environment-notes.md, traps 2 and 3)."""
from factorysimpy.nodes.machine import Machine
from factorysimpy.nodes.sink import Sink
from factorysimpy.nodes.source import Source


class LineControl:
    def __init__(self, env, nodes):
        self.env = env
        self.machines = {k: n for k, n in nodes.items() if isinstance(n, Machine)}
        self.sources = {k: n for k, n in nodes.items() if isinstance(n, Source)}
        self.sinks = [n for n in nodes.values() if isinstance(n, Sink)]
        self.baseline = {**{k: m.processing_delay for k, m in self.machines.items()},
                         **{k: s.inter_arrival_time for k, s in self.sources.items()}}
        self.held = {}
        self.stopped_at = None

    def isolate(self, machine_id):
        """Tier 2. Claim every worker slot, so the machine finishes what it holds and takes nothing new.
        Returns an event that fires once it has stopped."""
        if self.stopped_at is not None:
            return self.env.timeout(0)  # safe state already stops the line, and holding a machine blocks its drain
        if machine_id not in self.held:
            worker = self.machines[machine_id].worker_thread
            self.held[machine_id] = [worker.request() for _ in range(worker.capacity)]
        return self.env.all_of(self.held[machine_id])

    def safe_state(self):
        """Tier 3. Stop new items and let everything already on the line reach the Sink. Lifts any isolation,
        otherwise items waiting at an isolated machine would never drain."""
        for s in self.sources.values():
            s.inter_arrival_time = float("inf")
        self.stopped_at = self.env.now
        self._release()

    def drained(self):
        """True once every generated item has reached a Sink or been discarded."""
        # One item can still be on its way out of the Source when it is stopped.
        if self.env.now - self.stopped_at < max(self.baseline[k] for k in self.sources):
            return False
        generated = sum(s.stats["num_item_generated"] for s in self.sources.values())
        done = (sum(s.stats["num_item_received"] for s in self.sinks)
                + sum(n.stats["num_item_discarded"] for n in [*self.sources.values(), *self.machines.values()]))
        return generated == done

    def _settings(self, sources):
        current = {k: m.processing_delay for k, m in self.machines.items()}
        return {**current, **{k: s.inter_arrival_time for k, s in self.sources.items()}} if sources else current

    def restore_baseline(self):
        # While in safe state the stopped Source is ours, so it is not touched here. Resetting it is what let
        # one incident's recovery restart the line under another incident's safe state.
        for k, m in self.machines.items():
            m.processing_delay = self.baseline[k]
        if self.stopped_at is None:
            for k, s in self.sources.items():
                s.inter_arrival_time = self.baseline[k]

    def at_baseline(self):
        """Return-to-normal precondition: every setting we can see is back where it started. Our own stop of
        the Source does not count as a change."""
        sources = self.stopped_at is None
        return self._settings(sources) == {k: self.baseline[k] for k in self._settings(sources)}

    def resume(self):
        """Undo isolate and safe state."""
        self._release()
        if self.stopped_at is not None:
            # shortcut: the stopped Source loop sleeps forever, so a fresh one takes over. Item names restart
            # at 1, which only matters if anything starts keying on item ids.
            for k, s in self.sources.items():
                s.inter_arrival_time = self.baseline[k]
                self.env.process(s.behaviour())
            self.stopped_at = None

    def _release(self):
        for machine_id, requests in self.held.items():
            for r in requests:
                r.cancel()  # a request still queued has to be withdrawn, release() alone leaves it waiting
                self.machines[machine_id].worker_thread.release(r)
        self.held.clear()
