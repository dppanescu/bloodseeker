from __future__ import annotations
import logging, os, sys, pathlib

# Try modern import name first, then the legacy one; fallback to plain formatter
try:
    from pythonjsonlogger import jsonlogger as _jsonlogger
except Exception:
    try:
        from python_json_logger import jsonlogger as _jsonlogger  # legacy
    except Exception:
        _jsonlogger = None

LOG_DIRS = [pathlib.Path('/var/log/brandmon'), pathlib.Path.cwd()]
LOG_FILE = 'brandmon.log'

def configure_logger(name: str = 'brandmon', level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers.clear()
    logger.propagate = False

    fmt = (_jsonlogger.JsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s")
           if _jsonlogger else
           logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))

    # Console
    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(level)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    # File with fallback
    for d in LOG_DIRS:
        try:
            d.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(d / LOG_FILE)
            fh.setLevel(level)
            fh.setFormatter(fmt)
            logger.addHandler(fh)
            break
        except Exception:
            continue

    return logger
