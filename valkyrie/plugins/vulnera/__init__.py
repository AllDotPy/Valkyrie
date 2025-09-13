import hashlib
from pathlib import Path
from typing import Dict, List, Any

from valkyrie.plugins import BaseSecurityRule
from valkyrie.core.types import (
    ScanRule, ScannerPlugin, RuleMetadata, SecurityFinding, 
    FileLocation, SeverityLevel, FindingCategory,
)

from .conf import VulnerabilityInfo
from .parser import parse_dependencies, is_supported


####
##      VULNERABILITY RULE
#####
class DependencyVulnerabilityRule(BaseSecurityRule):
    """Rule for detecting vulnerable dependencies"""
    
    def __init__(
        self, 
        vulnerability_db: Dict[str, List[VulnerabilityInfo]]
    ):
        metadata = RuleMetadata(
            id = "deps-001",
            name = "Dependency Vulnerability Scanner",
            description = "Scans dependencies for known vulnerabilities",
            category = FindingCategory.DEPENDENCIES,
            severity = SeverityLevel.HIGH,
            author = "Valkyrie Core Team",
            tags = {"dependencies", "vulnerabilities", "sbom"}
        )
        super().__init__(metadata)
        self.vulnerability_db = vulnerability_db
    
    def is_applicable(self, file_path: Path) -> bool:
        """Check if file is a supported dependency manifest"""

        return is_supported(file_path)
    
    async def scan(
        self, 
        file_path: Path, 
        content: str
    ) -> List[SecurityFinding]:
        """Scan dependency file for vulnerabilities."""

        findings = []
        
        try:
            dependencies = await self._parse_dependencies(file_path)
            
            for dep_name, version in dependencies.items():
                if dep_name in self.vulnerability_db:
                    vulnerabilities = self.vulnerability_db[dep_name]
                    
                    for vuln in vulnerabilities:
                        if self._is_version_affected(version, vuln.affected_versions):

                            # Then add it to findings
                            finding = SecurityFinding(
                                id = hashlib.md5(f"{file_path}:{dep_name}:{vuln.cve_id}".encode()).hexdigest(),
                                title = f"Vulnerable dependency: {dep_name}",
                                description = f"Dependency {dep_name}@{version} has vulnerability {vuln.cve_id}: {vuln.description}",
                                severity = vuln.severity,
                                category = self.metadata.category,
                                location = FileLocation(file_path=file_path, line_number=1),
                                rule_id = self.metadata.id,
                                confidence = 0.9,
                                metadata = {
                                    "dependency": dep_name,
                                    "version": version,
                                    "cve_id": vuln.cve_id,
                                    "fixed_versions": vuln.fixed_versions,
                                    "references": vuln.references
                                },
                                remediation_advice = (
                                    f"Update {dep_name} to version "
                                    f"{', '.join(vuln.fixed_versions) if vuln.fixed_versions else 'latest'}"
                                )
                            )
                            findings.append(finding)
        
        except Exception as e:
            # Log parsing error but don't fail the scan
            self.logger.warning(
                f'Error scanning file {file_path}: {e}'
            )
        
        return findings
    
    async def _parse_dependencies(self, file_path: Path) -> Dict[str, str]:
        """Parse dependencies from file content"""

        dependencies = {}
        
        # Parse the dependency file
        for dep in parse_dependencies(file_path=file_path):
            dependencies[dep.name] = dep.version
        
        return dependencies
    
    def _is_version_affected(
        self, 
        version: str, 
        affected_versions: List[str]
    ) -> bool:
        """Check if version is affected by vulnerability"""
        # Simplified version comparison for now
        # I'll use a proper semver library in next push
        return version in affected_versions


####
##      VULNERABILITY PLUGIN
#####
class DependenciesPlugin(ScannerPlugin):
    """Plugin for dependency vulnerability scanning"""
    
    def __init__(self):
        self.vulnerability_db: Dict[str, List[VulnerabilityInfo]] = {}
    
    @property
    def name(self) -> str:
        return "vulnera"
    
    @property
    def version(self) -> str:
        return "0.1.0"
    
    async def initialize(self, config: Dict[str, Any]) -> None:
        """Initialize plugin and load vulnerability database"""
        await self._load_vulnerability_db()
    
    async def _load_vulnerability_db(self) -> None:
        """Load vulnerability database from external sources"""
        
        # Normally we need to call an external service 
        # Or load a local vulnerabilities dbm
        # but i'm usinng a mock database and
        # i'll fix that in next push
        self.vulnerability_db = {
            "lodash": [
                VulnerabilityInfo(
                    cve_id="CVE-2021-23337",
                    severity=SeverityLevel.HIGH,
                    description="Prototype pollution in lodash",
                    affected_versions=["4.17.20"],
                    fixed_versions=["4.17.21"],
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"]
                )
            ],
            "requests": [
                VulnerabilityInfo(
                    cve_id="CVE-2023-32681",
                    severity=SeverityLevel.MEDIUM,
                    description="Certificate verification bypass in requests",
                    affected_versions=["2.30.0", "2.29.0"],
                    fixed_versions=["2.31.0"],
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2023-32681"]
                )
            ]
        }
    
    async def get_rules(self) -> List[ScanRule]:
        """Return dependency scanning rules"""
        return [DependencyVulnerabilityRule(self.vulnerability_db)]
    
    async def cleanup(self) -> None:
        """Cleanup plugin resources"""
        pass
