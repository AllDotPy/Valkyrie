"""
Vlakyrie Engine configuration module.
"""

from enum import Enum
from typing import (
    List, Set, Optional, Dict, Any,
    Type, TypeVar,
)
from pathlib import Path

from pydantic import BaseModel, Field

from valkyrie.core.types import SeverityLevel

#### GENERIC TYPES
T = TypeVar('T', bound='BaseConfigModel')

####
##     LOG LEVELs
#####
class LogLevel(str, Enum):
    """Log Levels"""

    DEBUG = 'debug'
    INFO = 'info'
    WARNING = 'warning'
    ERROR = 'error'
    CRITICAL = 'critical'


####
##      LOG FORMAT CHOICES
#####
class LogFormat(str, Enum):
    """Log Format choices."""

    PLAIN = 'plain'
    JSON = 'json'


####
##      LOGGING CONFIG MODEL CLASS
#####
class LoggingConfig(BaseModel):
    """Logging Configuration Model"""

    enabled: bool = False
    level: LogLevel = LogLevel.INFO
    file: Optional[str] = None
    console: bool = True
    max_size: int = 10  # MB
    backups: int = 5
    compress: bool = True
    format: LogFormat = LogFormat.PLAIN
    rotate: bool = True


####
##      BASE CONFIGURATION CLASS
#####
class BaseConfigModel(BaseModel):
    """Base class of all configuration models."""

    class Config:
        extra = 'forbid'  # Undefined fields are not allowed
        validate_all = True
        use_enum_values = True

    def to_json(self) -> Dict[str, Any]:
        """
        Converts model fields into a dictionary.
        """

        return self.model_dump()
    
    def to_json_string(self) -> str:
        """
        Converts model fields into a JSON string.
        """
        return self.model_dump_json()
    
    @classmethod
    def from_json(cls: Type[T], json_dict: Dict[str, Any]) -> T:
        """
        Loads model from a dictionary.
        """
        cls.model_rebuild()
        return cls.model_validate(json_dict)
    
    @classmethod
    def from_json_string(cls: Type[T], json_str: str) -> T:
        """
        Loads model from a JSON string.
        """
        cls.model_rebuild()
        return cls.model_validate_json(json_str)


####
##      SCANNER PLUGIN CONFIG MODEL CLASS
#####
class PluginConfig(BaseConfigModel):
    """Scanner Plugin Configuration"""

    enabled: Optional[bool] = True
    config: Dict[str,Any] = Field(
        default_factory = Dict
    )


####
##      SCANNER CONFIG MODEL CLASS
#####
class OutputConfig(BaseConfigModel):
    """Scan Output Configuration"""

    format: str = 'sarif'
    """Default output format, json, sarif, html"""

    file: Optional[str] = None
    """Output file (optional)"""

    verbose: Optional[bool] = False
    """Verbose logging"""

    include_success: Optional[bool] = False
    """Include successful scans in output"""


####
##      RULE REPOSITORY CONFIG MODEL CLASS
#####
class RuleRepositoryConfig(BaseConfigModel):
    """Remote rule repository Configuration"""

    type: str = 'github'
    url: str = 'AllDotPt/valkyrie-community-rules'
    branch: str = 'main'
    token_env: str = 'GITHUB_TOKEN'


####
##      RULE CATEGORIES CONFIG MODEL CLASS
#####
class RuleCategoriesConfig(BaseConfigModel):
    """Rule Categories Configuration"""

    secrets: bool =  True
    dependencies: bool =  True
    iam_config: bool =  True
    code_quality: bool =  True
    infrastructure: bool =  True


####
##      RULE CONFIG MODEL CLASS
#####
class RulesConfig(BaseConfigModel):
    """Remote rule repository Configuration"""

    repository: Optional[RuleRepositoryConfig]
    """Remote rule repository (GitHub, GitLab, etc.)"""

    local_rules_dir: str = "./rules"
    """Local rules directory"""

    include_rules: List[str] = Field(
        default_factory = lambda: []
    )
    """Rule filters (empty = all rules enabled)"""

    exclude_rules: List[str]
    """Disabled rules"""

    categories: Optional[RuleCategoriesConfig] = Field(
        default_factory = lambda: RuleCategoriesConfig()
    )
    """Custom rule categories to enable/disable"""


####
##      SCANNER CONFIG MODEL CLASS
#####
class ScanConfig(BaseConfigModel):
    """Configuration for scanner execution"""

    target_path: Path
    """Target directory to scan (relative to config file)"""

    include_patterns: List[str] = Field(
        default_factory=lambda: ["**/*"]
    )
    """File inclusion patterns (glob patterns)"""

    exclude_patterns: List[str] = Field(
        default_factory=lambda: [
            "**/.git/**", "**/.vscode/**",
            "**/node_modules/**", "**/__pycache__/**"
        ]
    )
    """File exclusion patterns"""

    max_file_size: int = 10 * 1024 * 1024  # 10MB
    """Maximum file size to scan (in bytes, default to 10MB)."""

    parallel_workers: int = 4
    """Number of parallel scanning workers"""

    rule_filters: Set[str] = Field(default_factory=set)  # Rule IDs to include
    """Specific rules to include"""

    severity_threshold: SeverityLevel = SeverityLevel.LOW
    """Minimum severity level to report"""

    diff_only: bool = False
    """Scan only changed files in CI (if supported)"""

    fail_on_findings: bool = True
    """Whether to fail the build on security findings"""


####
##      VALKYRIE CONFIG MODEL CLASS
#####
class ValkyrieConfig(BaseConfigModel):
    """Valkyrie Configuration"""

    scanner: ScanConfig
    """Scanner engine configuration."""

    rules: Optional[RulesConfig] 
    """Rule repositories"""

    plugins: List[PluginConfig]
    """Scanner Plugins to use."""

    output: OutputConfig = Field(
        default_factory = lambda: OutputConfig()
    )
    """Scan Result Outout format"""

    ci_integration: List
    """A list of ci integration (github action, gitlab ci, etc)"""
