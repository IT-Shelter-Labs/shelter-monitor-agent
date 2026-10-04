"""Periodic jobs: one lightweight daemon thread per job."""

from __future__ import annotations

import logging
import random
import threading
from typing import Callable

log = logging.getLogger(__name__)


class PeriodicTask:
    def __init__(self, name: str, interval: float, fn: Callable[[], None], initial_delay: float | None = None):
        self.name = name
        self.interval = interval
        self._fn = fn
        # Small jitter so all jobs don't wake up at the same moment.
        self._initial_delay = initial_delay if initial_delay is not None else random.uniform(1, 5)
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._run_lock = threading.Lock()
        self._thread = threading.Thread(target=self._loop, name=f"task-{name}", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def join(self, timeout: float | None = None) -> None:
        self._thread.join(timeout)

    def run_once(self) -> None:
        """Run the job in the caller's thread (serialised with the scheduled runs)."""
        with self._run_lock:
            try:
                self._fn()
            except Exception:
                log.exception("task %s failed", self.name)

    def trigger(self) -> None:
        """Ask the background thread to run the job as soon as possible."""
        self._wake.set()

    def _loop(self) -> None:
        if self._stop.wait(self._initial_delay):
            return
        while not self._stop.is_set():
            self.run_once()
            self._wake.wait(self.interval)
            self._wake.clear()
