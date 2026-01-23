"""
Logging configuration for the vulnerability scanner.

Provides structured logging with configurable verbosity levels.
Supports console output with color-coded severity levels.
"""

import logging
import sys
from typing import Optional


class ColoredFormatter(logging.Formatter):
    """Custom formatter with color codes for different log levels."""
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record):
        """Format log record with color based on severity."""
        log_color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{log_color}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logger(name: str, verbose: bool = False) -> logging.Logger:
    """
    Configure and return a logger instance.
    
    Args:
        name: Logger name (typically __name__ from calling module)
        verbose: If True, set log level to DEBUG; otherwise INFO
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Prevent duplicate handlers if logger already configured
    if logger.handlers:
        return logger
    
    # Set log level based on verbosity
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    
    # Create formatter
    formatter = ColoredFormatter(
        fmt='[%(asctime)s] %(levelname)s [%(name)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(formatter)
    
    # Add handler to logger
    logger.addHandler(console_handler)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get an existing logger by name.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)
