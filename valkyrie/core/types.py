from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Protocol
from datetime import datetime


####
##      SECURITY LEVEL ENUM
#####
class SeverityLevel(Enum):
    """Security finding severity levels"""

    CRITICAL = "critical"
    HIGH = "high" 
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


####
##      SECURITY FINDING CATEGORIES ENUM
#####
class FindingCategory(Enum):
    """Categories of security findings"""

    SECRETS = "secrets"
    DEPENDENCIES = "dependencies"
    IAM_CONFIG = "iam_config"
    CODE_QUALITY = "code_quality"
    INFRASTRUCTURE = "infrastructure"
    CUSTOM = "custom"


####
##      SECURITY SCAN STATUS ENUM
#####
class ScanStatus(Enum):
    """Status of scan execution"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


#### DATA MODELS

####
##      FILE LOCATION REPRESENTATION MODEL
#####
@dataclass(frozen=True)
class FileLocation:
    """Represents a location within a file"""

    file_path: Path
    line_number: int
    column_start: int = 0
    column_end: int = 0
    
    def __str__(self) -> str:
        return f"{self.file_path}:{self.line_number}"


####
##      SECURITY SCAN ISSUE
#####
@dataclass(frozen=True)
class SecurityFinding:
    """Represents a security issue found during scanning"""

    id: str
    title: str
    description: str
    severity: SeverityLevel
    category: FindingCategory
    location: FileLocation
    rule_id: str
    confidence: float = 1.0  # 0.0 to 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    remediation_advice: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for serialization"""

        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "location": {
                "file_path": str(self.location.file_path),
                "line_number": self.location.line_number,
                "column_start": self.location.column_start,
                "column_end": self.location.column_end,
            },
            "rule_id": self.rule_id,
            "confidence": self.confidence,
            "metadata": self.metadata,
            "remediation_advice": self.remediation_advice,
        }


####
##      SECURITY SCAN RESULT
#####
@dataclass
class ScanResult:
    """Complete result of a security scan"""

    scan_id: str
    status: ScanStatus
    findings: List[SecurityFinding] = field(default_factory=list)
    scan_duration: Optional[float] = None
    timestamp: datetime = field(default_factory=datetime.now)
    scanned_files: Set[Path] = field(default_factory=set)
    errors: List[str] = field(default_factory=list)
    
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SeverityLevel.CRITICAL)
    
    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SeverityLevel.HIGH)
    
    @property
    def has_blocking_issues(self) -> bool:
        """Check if scan has critical or high severity issues"""
        return self.critical_count > 0 or self.high_count > 0


####
##      RULE METADATA MODEL
#####
@dataclass(frozen=True)
class RuleMetadata:
    """Metadata for a security rule"""

    id: str
    name: str
    description: str
    category: FindingCategory
    severity: SeverityLevel
    author: str
    version: str = "1.0.0"
    tags: Set[str] = field(default_factory=set)
    enabled: bool = True


####
##      SECURITY SCAN RULE PROTOCOL
#####
class ScanRule(Protocol):
    """Protocol defining the interface for security rules"""
    
    @property
    def metadata(self) -> RuleMetadata:
        """Rule metadata"""
        ...
    
    async def scan(self, file_path: Path, content: str) -> List[SecurityFinding]:
        """
        Scan file content and return security findings
        
        Args:
            file_path: Path to the file being scanned
            content: File content as string
            
        Returns:
            List of security findings
        """
        ...
    
    def is_applicable(self, file_path: Path) -> bool:
        """
        Check if this rule should be applied to the given file
        
        Args:
            file_path: Path to check
            
        Returns:
            True if rule is applicable, False otherwise
        """
        ...


####    PLUGIN SYSTEM 

####
##     SCANNER PLUGINS BASE CLASS
#####
class ScannerPlugin(ABC):
    """Abstract base class for scanner plugins"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name"""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version"""
        pass
    
    @abstractmethod
    async def initialize(self, config: Dict[str, Any]) -> None:
        """Initialize the plugin with configuration"""
        pass
    
    @abstractmethod
    async def get_rules(self) -> List[ScanRule]:
        """Return list of rules provided by this plugin"""
        pass
    
    @abstractmethod
    async def cleanup(self) -> None:
        """Cleanup plugin resources"""
        pass


####    RULE REPOSITORY

####
##      SECURITY SCAN RULE REPOSITORY
#####
class RuleRepository(ABC):
    """Abstract interface for rule storage and retrieval"""
    
    @abstractmethod
    async def load_rules(self) -> List[ScanRule]:
        """Load all available rules"""
        pass
    
    @abstractmethod
    async def get_rule(self, rule_id: str) -> Optional[ScanRule]:
        """Get specific rule by ID"""
        pass
    
    @abstractmethod
    async def add_rule(self, rule: ScanRule) -> None:
        """Add a new rule"""
        pass
    
    @abstractmethod
    async def update_rule(self, rule: ScanRule) -> None:
        """Update existing rule"""
        pass
