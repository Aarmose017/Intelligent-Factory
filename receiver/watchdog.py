"""Watchdog for the response layer, checked from outside its process.

Fail-open: if the response layer goes down, the line keeps running without protection. We never stop the line
just because our own software died, since that would turn killing our process into a way to stop production.
Instead the watchdog raises an operator alert when the heartbeat stops, and another when it comes back.

Limit: on Windows a refused local connection is retried for about 2 seconds before failing, so an outage shorter
than that can go unseen. Measured 2026-10-18; a 6 second outage gave exactly one down and one up alert.

    python -m receiver.watchdog [health_url] [period_seconds]
"""
import sys
import time

import httpx

from engine import log


def alive(url):
    try:
        return httpx.get(url, timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


def watch(url="http://127.0.0.1:8000/health", period=5.0, checks=None):
    """Log only changes, so a long outage is one alert, not one per check. `checks` limits the loop for tests."""
    up = True
    while checks is None or checks > 0:
        if alive(url) != up:
            up = not up
            log.write({}, None, event="watchdog", action="alert_operator",
                      status="response_layer_up" if up else "response_layer_down", url=url)
            print("response layer", "back up" if up else "DOWN, line running unprotected (fail-open)", flush=True)
        if checks is not None:
            checks -= 1
        time.sleep(period)


if __name__ == "__main__":
    watch(*sys.argv[1:2], *map(float, sys.argv[2:3]))
