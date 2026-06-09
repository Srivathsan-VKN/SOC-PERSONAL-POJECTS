"""
Logging configuration — structured JSON logs via structlog.

Why structured logs:
- Every log line is a JSON object → easy to grep, filter, and ship to a SIEM
- Standard practice in modern Python apps
- Recruiters reading the code see professional-grade observability
"""
import logging
import sys
import structlog


def configure_logging(level: str = "INFO") -> None:
    """Call once at app startup."""
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.BoundLogger:
    """Get a structured logger for a module."""
    return structlog.get_logger(name)