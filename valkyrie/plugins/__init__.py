"""
"""
from pathlib import Path
from typing import List

from valkyrie.core.types import (
    RuleMetadata, SecurityFinding, ScanRule
)


####
##      BASE CLASS FOR SECURITY RULE IMPLEMENTATION
#####
class BaseSecurityRule(ScanRule):
    """Base implementation for security rules"""
    
    def __init__(self, metadata: RuleMetadata):
        self._metadata = metadata
    
    @property
    def metadata(self) -> RuleMetadata:
        return self._metadata
    
    def is_applicable(self, file_path: Path) -> bool:
        """Default implementation - override in subclasses"""
        return True
    
    async def scan(self, file_path: Path, content: str) -> List[SecurityFinding]:
        """Override in subclasses"""
        return []
