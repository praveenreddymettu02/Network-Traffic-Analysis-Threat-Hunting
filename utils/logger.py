import os
import sys
import logging
from logging.handlers import RotatingFileHandler
from config import Config

# Ensure logs directory exists
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

_configured_loggers = {}


def setup_logger(name=__name__, level=None):
    """Set up a logger with console and rotating file output.

    Each unique logger name gets its own configuration once.
    Capture/detection/alert loggers write to separate files.
    """
    if name in _configured_loggers:
        return _configured_loggers[name]

    if level is None:
        level = Config.LOG_LEVEL

    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Clear existing handlers to avoid duplicates
    if logger.handlers:
        logger.handlers.clear()

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # Determine log file based on component name
    if 'capture' in name.lower():
        log_file = os.path.join(LOG_DIR, 'capture.log')
    elif 'alert' in name.lower() or 'detection' in name.lower():
        log_file = os.path.join(LOG_DIR, 'detection.log')
    else:
        log_file = os.path.join(LOG_DIR, 'app.log')

    # Rotating file handler: 5MB max, 3 backups
    try:
        fh = RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding='utf-8'
        )
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    except Exception:
        pass  # Continue without file logging if directory is read-only

    _configured_loggers[name] = logger
    return logger
