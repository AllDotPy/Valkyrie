"""
Logging system for Valkyrie
"""

import os
import logging
import sys
import threading
from typing import Optional


####
##      VALKYRIE SHARED LOGGER CLASS
#####
class SharedLogger:
    """Valkyrie Shared Logger."""
    
    _logger: Optional[logging.Logger] = None
    _lock = threading.Lock()
    debug_mode = os.getenv('VALKYRIE_DEBUG','0') == '1'
    
    @classmethod
    def get_logger(cls, name: str = "Valkyrie") -> logging.Logger:
        """Gets the static logger (initialized only once)"""

        if cls._logger is None:
            with cls._lock:
                if cls._logger is None:
                    cls._initialize_logger(name)
        return cls._logger
    
    @property
    @classmethod
    def logger(self) -> logging.Logger:
        return self.get_logger()
    
    @classmethod
    def _initialize_logger(cls, name: str,debug: bool = False):
        """One-time logger configuration"""

        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG if debug else logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        cls._logger = logger
    
    def debug(self, message: str):
        """Log a debug message"""
        if self.debug_mode:
            self.logger.debug(message)
    
    def info(self, message: str):
        """Log an info level message"""
        if self.debug_mode:
            self.logger.info(message)
    
    def warning(self, message: str):
        """Log a warnning level mesage"""
        if self.debug_mode:
            self.logger.warning(message)
    
    def error(self, message: str,* args, **kwargs):
        """Log an error level message"""
        if self.debug_mode:
            self.logger.error(message)
    
    def critical(self, message: str):
        """Log a critical level message"""
        if self.debug_mode:
            self.logger.critical(message)
