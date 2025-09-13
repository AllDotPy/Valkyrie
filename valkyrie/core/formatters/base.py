from abc import ABC, abstractmethod

from valkyrie.core.types import ScanResult

####
##      SCAN RESULT FORMATTERS BASE CLASS
#####
class ResultFormatter(ABC):
    """Abstract base class for result formatting"""
    
    @abstractmethod
    def format(self, result: ScanResult) -> str:
        """Format scan result to string"""
        pass