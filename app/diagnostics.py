import json
import logging
import os
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

LOG_DIR = Path(os.getenv("DIAGNOSTIC_LOG_DIR", "/app/data/logs"))
LOG_FILE = LOG_DIR / "application.log"

_SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9._~+\-/=]+"),
    re.compile(r"(?i)(x-auth-token\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"(?i)(password\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"(?i)(secret(?:_key)?\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"(?i)(refreshToken\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"(?i)(token\s*[:=]\s*)[^\s,;]+"),
]


def redact(value: Any) -> str:
    text = str(value)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(r"\1[REDACTED]", text)
    return text


def configure_logging() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("migration")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not any(isinstance(h, RotatingFileHandler) for h in logger.handlers):
        handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=5 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)sZ %(levelname)s %(name)s %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
        )
        logger.addHandler(handler)
    return logger


logger = configure_logging()


def log_info(event: str, **fields):
    safe = {k: redact(v) for k, v in fields.items()}
    logger.info("%s %s", event, json.dumps(safe, default=str, sort_keys=True))


def log_warning(event: str, **fields):
    safe = {k: redact(v) for k, v in fields.items()}
    logger.warning("%s %s", event, json.dumps(safe, default=str, sort_keys=True))


def log_error(event: str, **fields):
    safe = {k: redact(v) for k, v in fields.items()}
    logger.error("%s %s", event, json.dumps(safe, default=str, sort_keys=True))


def tail_log(max_bytes: int = 2 * 1024 * 1024) -> str:
    if not LOG_FILE.exists():
        return ""
    size = LOG_FILE.stat().st_size
    with LOG_FILE.open("rb") as f:
        if size > max_bytes:
            f.seek(size - max_bytes)
            f.readline()
        data = f.read()
    return redact(data.decode("utf-8", errors="replace"))
