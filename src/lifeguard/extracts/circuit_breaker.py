"""Circuit breaker utility for outbound calls."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class CircuitOpenError(Exception):
    """Raised when a circuit breaker refuses new calls."""


class CircuitBreaker:
    """Simple circuit breaker with half-open support."""

    STATE_CLOSED = "closed"
    STATE_OPEN = "open"
    STATE_HALF_OPEN = "half_open"

    def __init__(
        self,
        failure_threshold: int = 5,
        success_threshold: int = 3,
        reset_timeout: float = 60.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.failure_threshold = int(failure_threshold)
        self.success_threshold = int(success_threshold)
        self.reset_timeout = float(reset_timeout)
        self._clock = clock
        self._lock = threading.Lock()
        self.state = self.STATE_CLOSED
        self.failures = 0
        self.successes = 0
        self.last_failure_time: Optional[float] = None

    def call(self, func: Callable[[], Any]) -> Any:
        """Execute ``func`` with circuit protection."""
        with self._lock:
            if self.state == self.STATE_OPEN:
                if self._should_attempt_reset():
                    self.state = self.STATE_HALF_OPEN
                    logger.info("Circuit breaker entering half-open state")
                else:
                    raise CircuitOpenError(
                        f"Circuit breaker open, retry after {self.reset_timeout}s"
                    )

        # Execute func outside lock to avoid holding lock during input or output.
        try:
            result = func()
            with self._lock:
                self._on_success()
            return result
        except Exception:
            with self._lock:
                self._on_failure()
            raise

    def _should_attempt_reset(self) -> bool:
        if self.last_failure_time is None:
            return True
        return self._clock() - self.last_failure_time >= self.reset_timeout

    def _on_success(self) -> None:
        if self.state == self.STATE_CLOSED:
            self.failures = 0
            self.successes = 0
            return

        self.successes += 1
        if self.state == self.STATE_HALF_OPEN and self.successes >= self.success_threshold:
            self.state = self.STATE_CLOSED
            self.failures = 0
            self.successes = 0
            logger.info("Circuit breaker closed")

    def _on_failure(self) -> None:
        self.failures += 1
        self.last_failure_time = self._clock()
        if self.state == self.STATE_HALF_OPEN:
            self.state = self.STATE_OPEN
            logger.warning("Circuit breaker opened after failure")
        elif self.failures >= self.failure_threshold:
            self.state = self.STATE_OPEN
            logger.warning(
                "Circuit breaker opened after %s consecutive failures", self.failures
            )

