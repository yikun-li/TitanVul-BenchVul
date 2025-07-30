"""
Logging utilities for the Vulnerability Pipeline.

This module provides centralized logging configuration and utilities
for consistent logging across all pipeline components.
"""

import logging
import os
from typing import Optional


def setup_logger(
        name: str,
        level: int = logging.INFO,
        log_file: Optional[str] = "vulnerability_generation.log",
        console_output: bool = True
) -> logging.Logger:
    """
    Set up a logger with consistent formatting and output options.
    
    Args:
        name: Name of the logger (typically __name__)
        level: Logging level (e.g., logging.INFO, logging.DEBUG)
        log_file: Path to log file (None to disable file logging)
        console_output: Whether to output to console
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    # Avoid adding multiple handlers if logger already exists
    if logger.handlers:
        return logger

    logger.setLevel(level)

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Add file handler if log_file is specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    # Add console handler if requested
    if console_output:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get an existing logger or create a new one with default settings.
    
    Args:
        name: Name of the logger
        
    Returns:
        Logger instance
    """
    logger = logging.getLogger(name)

    # If logger doesn't have handlers, set it up with defaults
    if not logger.handlers:
        return setup_logger(name)

    return logger


class LoggerMixin:
    """
    Mixin class that provides logging capabilities to any class.
    
    Usage:
        class MyClass(LoggerMixin):
            def some_method(self):
                self.logger.info("This is a log message")
    """

    @property
    def logger(self) -> logging.Logger:
        """Get logger for the current class."""
        if not hasattr(self, '_logger'):
            self._logger = get_logger(self.__class__.__name__)
        return self._logger


def log_function_call(func):
    """
    Decorator to log function calls with arguments and execution time.
    
    Usage:
        @log_function_call
        def my_function(arg1, arg2):
            pass
    """
    import functools
    import time

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)

        # Log function entry
        logger.debug(f"Calling {func.__name__} with args={args}, kwargs={kwargs}")

        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time
            logger.debug(f"{func.__name__} completed in {execution_time:.2f}s")
            return result
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"{func.__name__} failed after {execution_time:.2f}s: {str(e)}")
            raise

    return wrapper


def log_api_call(provider: str, model: str, role: str):
    """
    Decorator specifically for logging API calls.
    
    Args:
        provider: API provider name (e.g., 'openai', 'anthropic')
        model: Model name
        role: Role or agent name making the call
    """

    def decorator(func):
        import functools

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            logger = get_logger(func.__module__)

            logger.info(f"Calling {role} using {provider} {model}...")

            try:
                result = func(*args, **kwargs)
                logger.info(f"{role} has responded.")
                return result
            except Exception as e:
                logger.error(f"Error calling {role} via {provider}: {str(e)}")
                raise

        return wrapper

    return decorator
