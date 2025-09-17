"""
Custom exceptions hierarchy for Valkyrie.
"""

from __future__ import annotations
import logging
from typing import Optional

from valkyrie.utilss import get_logger

# Configure a logger
logger = get_logger('Valkyrie')


####
##      BASE VALKYRIE EXCEPTION CLASS
#####
class ValkyrieException(Exception):
    """
    Base exception for all Valkyrie-specific errors.
    Automatically logs itself when raised to avoid stopping execution.
    """

    def __init__(
        self, 
        message: str, 
        *, 
        context: Optional[dict] = None
    ) -> None:

        self.message = message
        self.context = context or {}

        # Log the error immediately when raised
        self._log_error()

    def _log_error(self) -> None:
        """Log the error in a structured way instead of stopping execution."""

        if self.context:
            logger.error(
                f"{self.__class__.__name__}: {self.message} | Context: {self.context}"
            )
        else:
            logger.error(f"{self.__class__.__name__}: {self.message}")

    def __str__(self) -> str:
        return f"{self.__class__.__name__}: {self.message}"


####
##      RULE LOAD EXCEPTION CLASS
#####
class RuleError(ValkyrieException):
    """Base exception for rule-related errors."""
    pass

####
##      RULE LOAD EXCEPTION CLASS
#####
class RuleLoadError(RuleError):
    """Raised when a rule fails to load (syntax error, invalid schema, etc.)."""
    pass


####
##      RULE NOT FOUND EXCEPTION CLASS
#####
class RuleNotFoundError(RuleError):
    """Raised when a requested rule is not found."""
    pass


####
##      RULE VALIDATION EXCEPTION CLASS
#####
class RuleValidationError(RuleError):
    """Raised when a rule fails validation."""
    pass


####
##      SCAN EXECUTION EXCEPTION CLASS
#####
class ScanExecutionError(ValkyrieException):
    """Raised when a rule fails during its scan execution."""
    pass


####
##      INTEGRATION ERROR EXCEPTION CLASS
#####
class IntegrationError(ValkyrieException):
    """Raised when a CI/CD integration fails (GitHub, GitLab, etc.)."""
    pass


####
##      CONFIGURATION EXCEPTION CLASS
#####
class ConfigurationError(ValkyrieException):
    """Raised when the valkyrie.yaml configuration is invalid or missing fields."""
    pass


####
##      REPOSITORY ERROR EXCEPTION CLASS
#####
class RepositoryError(ValkyrieException):
    """Raised when rules cannot be fetched from a repository (local/remote)."""
    pass
