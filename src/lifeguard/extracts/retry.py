"""Reusable retry utilities with exponential backoff."""

from __future__ import annotations

import logging
import random
import time
from typing import Any, Callable, Optional, Tuple, Type

logger = logging.getLogger(__name__)


DEFAULT_RETRYABLE_EXCEPTIONS: Tuple[Type[BaseException], ...] = (
    TimeoutError,
    ConnectionError,
    OSError,
)


class RetryConfig:
    """Configuration for retry behavior."""

    def __init__(
        self,
        max_retries: int = 3,
        initial_backoff: float = 1.0,
        max_backoff: float = 60.0,
        backoff_multiplier: float = 2.0,
        jitter: float = 0.1,
        retryable_exceptions: Optional[Tuple[Type[BaseException], ...]] = None,
    ) -> None:
        self.max_retries = int(max_retries)
        self.initial_backoff = float(initial_backoff)
        self.max_backoff = float(max_backoff)
        self.backoff_multiplier = float(backoff_multiplier)
        self.jitter = float(jitter)
        self.retryable_exceptions = retryable_exceptions or DEFAULT_RETRYABLE_EXCEPTIONS
        self._rng = random.Random()

    def get_backoff_delay(self, attempt: int) -> float:
        delay = min(
            self.initial_backoff * (self.backoff_multiplier**attempt),
            self.max_backoff,
        )
        jitter_factor = self._rng.uniform(1.0 - self.jitter, 1.0 + self.jitter)
        return delay * jitter_factor

    def is_retryable(self, error: BaseException) -> bool:
        return isinstance(error, self.retryable_exceptions)


def retry_with_backoff(
    func: Callable[[], Any],
    config: Optional[RetryConfig] = None,
    on_retry: Optional[Callable[[int, BaseException, float], None]] = None,
) -> Any:
    config = config or RetryConfig()
    last_error: Optional[BaseException] = None

    for attempt in range(config.max_retries + 1):
        try:
            return func()
        except Exception as exc:
            last_error = exc
            is_last_attempt = attempt >= config.max_retries
            if is_last_attempt or not config.is_retryable(exc):
                raise

            delay = config.get_backoff_delay(attempt)
            if on_retry:
                on_retry(attempt, exc, delay)
            else:
                logger.warning(
                    "Retry %s/%s after error: %s. Waiting %.1fs...",
                    attempt + 1,
                    config.max_retries,
                    str(exc)[:100],
                    delay,
                )
            time.sleep(delay)

    if last_error is not None:
        raise last_error
    raise RuntimeError("Unexpected retry loop exit")


def with_retry(
    max_retries: int = 3,
    initial_backoff: float = 1.0,
    max_backoff: float = 60.0,
    retryable_exceptions: Optional[Tuple[Type[BaseException], ...]] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    config = RetryConfig(
        max_retries=max_retries,
        initial_backoff=initial_backoff,
        max_backoff=max_backoff,
        retryable_exceptions=retryable_exceptions,
    )

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return retry_with_backoff(lambda: func(*args, **kwargs), config=config)

        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper

    return decorator

