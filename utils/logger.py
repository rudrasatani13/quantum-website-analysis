"""
Logging utilities for QS-AI-IDS
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Any, Dict

class SystemLogger:
    """System logger with security event tracking"""

    def __init__(self, name: str = "qsaiids.system", log_file: str = None):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)

        # Avoid duplicate handlers
        if not self.logger.handlers:
            # Console handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)

            # File handler
            if log_file:
                log_path = Path(log_file)
                log_path.parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.FileHandler(log_file)
                file_handler.setLevel(logging.DEBUG)

                # Formatter
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)

            # Formatter for console
            console_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)

    def info(self, message: str):
        """Log info message"""
        self.logger.info(message)

    def warning(self, message: str):
        """Log warning message"""
        self.logger.warning(message)

    def error(self, message: str):
        """Log error message"""
        self.logger.error(message)

    def debug(self, message: str):
        """Log debug message"""
        self.logger.debug(message)

    def security_event(self, event_type: str, severity: float, details: Dict[str, Any]):
        """Log security event"""
        timestamp = datetime.now().isoformat()

        security_msg = f"SECURITY_EVENT: {event_type} | Severity: {severity:.2f} | Time: {timestamp}"

        if severity >= 0.8:
            self.logger.critical(security_msg)
        elif severity >= 0.6:
            self.logger.error(security_msg)
        elif severity >= 0.4:
            self.logger.warning(security_msg)
        else:
            self.logger.info(security_msg)

        # Log details
        self.logger.debug(f"Security event details: {details}")
