from typing import List, Optional
from dataclasses import dataclass, field
from valkyrie.core.types import (
    SeverityLevel
)


####
##      VULNERABILITY MODEL
#####
@dataclass
class VulnerabilityInfo:
    """Information about a vulnerability"""
    
    cve_id: str
    severity: SeverityLevel
    description: str
    affected_versions: List[str]
    fixed_versions: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


####
##      DEPENDENCY MODEL
#####
@dataclass
class Dependency:
    """Project dependency rpresentation model"""

    name: str
    version: Optional[str] = None
    dev: bool = False
    source: Optional[str] = None 
    
    def __str__(self):
        version_str = f"@{self.version}" if self.version else ""
        dev_str = " (dev)" if self.dev else ""
        return f"{self.name}{version_str}{dev_str}"


####    DEPENDENCIES
DEPS_FIES = {
    # Node.js
    'package.json', 'package-lock.json', 'yarn.lock',

    # Python
    'requirements.txt', 'Pipfile', 'Pipfile.lock', 'poetry.lock',

    # Java
    'pom.xml', 'gradle.build',

    # Rust
    'Cargo.toml', 'Cargo.lock',

    # Go
    'go.mod', 'go.sum',

    # PHP
    'composer.json', 'composer.lock'
}
