"""Container health probe (stdlib only; no shell or curl in the image).

* ``NEXUSFLOW_HEALTHCHECK=http`` (default): HTTP roles probe ``/health/live``
  on localhost (port ``NEXUSFLOW_HEALTHCHECK_PORT``, default 8000).
* ``NEXUSFLOW_HEALTHCHECK=heartbeat``: workers and beat are healthy while the
  heartbeat file (``NEXUSFLOW_HEARTBEAT_PATH``) is younger than
  ``NEXUSFLOW_HEARTBEAT_MAX_AGE`` seconds (default 90). The consumer touches
  it from its event loop while connected to the broker, beat on every tick,
  so a hung loop or a lost broker makes the container unhealthy.
"""

import os
import sys
import time
import urllib.request
from pathlib import Path

MODE = os.environ.get("NEXUSFLOW_HEALTHCHECK", "http")
PORT = os.environ.get("NEXUSFLOW_HEALTHCHECK_PORT", "8000")
HEARTBEAT_PATH = os.environ.get("NEXUSFLOW_HEARTBEAT_PATH", "/tmp/nexusflow-heartbeat")  # noqa: S108  # nosec B108 - a private tmpfs
HEARTBEAT_MAX_AGE = float(os.environ.get("NEXUSFLOW_HEARTBEAT_MAX_AGE", "90"))


def heartbeat_is_fresh(path: str, max_age: float, now: float | None = None) -> bool:
    try:
        modified = Path(path).stat().st_mtime
    except OSError:
        return False  # not written yet (still starting) or not writable
    return (now if now is not None else time.time()) - modified <= max_age


def http_is_live(port: str) -> bool:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/health/live", headers={"Host": "localhost"}
    )
    try:
        # Fixed loopback URL - never user input.
        with urllib.request.urlopen(request, timeout=4) as response:  # noqa: S310  # nosec B310
            return bool(response.status == 200)
    except OSError:
        return False


def main() -> int:
    if MODE == "heartbeat":
        return 0 if heartbeat_is_fresh(HEARTBEAT_PATH, HEARTBEAT_MAX_AGE) else 1
    return 0 if http_is_live(PORT) else 1


if __name__ == "__main__":
    sys.exit(main())
