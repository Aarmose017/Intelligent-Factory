"""The shared line. Same nodes and numbers as Team B's test.py, so node ids in their alerts match ours."""
import contextlib
import io
import random

import simpy
from factorysimpy.edges.buffer import Buffer
from factorysimpy.nodes.machine import Machine
from factorysimpy.nodes.sink import Sink
from factorysimpy.nodes.source import Source


def quiet():
    """FactorySimPy prints a line for every event. Wrap building and running in this to keep output readable."""
    return contextlib.redirect_stdout(io.StringIO())


def build(seed=0):
    # RANDOM edge selection draws from the global random module, so the seed makes replays repeat exactly.
    random.seed(seed)
    env = simpy.Environment()
    with quiet():
        nodes = {
            "SRC": Source(env, id="SRC", flow_item_type="item", inter_arrival_time=0.8,
                          blocking=False, out_edge_selection="RANDOM"),
            "MACHINE1": Machine(env, id="MACHINE1", work_capacity=4, processing_delay=1.1, blocking=False,
                                in_edge_selection="RANDOM", out_edge_selection="RANDOM"),
            "SINK": Sink(env, id="SINK"),
            "BUF1": Buffer(env, id="BUF1", capacity=4, delay=0.5, mode="FIFO"),
            "BUF2": Buffer(env, id="BUF2", capacity=4, delay=0.5, mode="FIFO"),
        }
        nodes["BUF1"].connect(nodes["SRC"], nodes["MACHINE1"])
        nodes["BUF2"].connect(nodes["MACHINE1"], nodes["SINK"])
    return env, nodes
