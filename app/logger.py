"""
Logging Configuration
Sets up structured logging to both console and a rotating log file.
Logs are saved to logs/soar.log and rotate at 5MB (keeps last 3 files).
"""

import logging
import logging.handlers
from pathlib import Path

LOGS_DIR = Path(__file__).parent.parent / "logs"
LOG_FILE = LOGS_DIR / "soar.log"

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(level: str = "INFO") -> None:
    """
    Configures logging for the entire SOAR engine.
    - Console handler: output for development
    - File handler: rotating log file for audit trail
    """
    LOGS_DIR.mkdir(exist_ok=True)

    log_level = getattr(logging, level.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    root_logger.addHandler(console_handler)

    # Rotating file handler - rotates at 5MB, keeps last 3 files
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8"
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    root_logger.addHandler(file_handler)

    logging.getLogger("soar.main").info(
        f"[LOGGER] Logging initialized. File: {LOG_FILE}"
    )