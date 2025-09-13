import hashlib
from pathlib import Path
from typing import Dict, List, Any

from valkyrie.plugins import BaseSecurityRule
from valkyrie.core.types import (
    ScanRule, ScannerPlugin, RuleMetadata, SecurityFinding, 
    FileLocation, SeverityLevel, FindingCategory,
)

from .conf import RISKY_PATTERNS


####
##      IAM CONFIGURATION RULE
#####
class IAMConfigurationRule(BaseSecurityRule):
    """Rule for detecting risky IAM configurations"""
    
    def __init__(self):
        metadata = RuleMetadata(
            id = "iam-001",
            name = "IAM Configuration Scanner",
            description = "Detects overly permissive IAM policies and configurations",
            category = FindingCategory.IAM_CONFIG,
            severity = SeverityLevel.HIGH,
            author = "Valkyrie Core Team",
            tags = {"iam", "aws", "gcp", "azure", "permissions"}
        )
        super().__init__(metadata)
        
        # Define risky patterns
        self.risky_patterns = RISKY_PATTERNS
    
    def is_applicable(self, file_path: Path) -> bool:
        """Check if file contains IAM configurations"""

        iam_files = {
            '.json', '.yaml', '.yml', '.tf', '.hcl'
        }
        
        if file_path.suffix.lower() not in iam_files:
            return False
        
        # Check filename patterns
        iam_patterns = [
            'policy', 'iam', 'role', 'permission', 'access',
            'cloudformation', 'terraform', 'main.tf'
        ]
        
        filename_lower = file_path.name.lower()
        return any(
            pattern in filename_lower 
            for pattern in iam_patterns
        )
    
    async def scan(
        self, 
        file_path: Path, 
        content: str
    ) -> List[SecurityFinding]:
        """Scan IAM configuration files"""

        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern_info in self.risky_patterns:
                matches = pattern_info.pattern.finditer(line)
                
                for match in matches:
                    finding = SecurityFinding(
                        id = hashlib.md5(f"{file_path}:{line_num}:{pattern_info.name}".encode()).hexdigest(),
                        title = f"Risky IAM Configuration: {pattern_info.name}",
                        description = pattern_info.description,
                        severity = pattern_info.severity,
                        category = self.metadata.category,
                        location = FileLocation(
                            file_path = file_path,
                            line_number = line_num,
                            column_start = match.start(),
                            column_end = match.end()
                        ),
                        rule_id = self.metadata.id,
                        confidence = 0.8,
                        metadata={
                            "pattern_name": pattern_info["name"],
                            "line_content": line.strip(),
                            "cloud_provider": self._detect_cloud_provider(content)
                        },
                        remediation_advice = (
                            "Apply principle of least privilege. "
                            "Specify exact resources and actions needed."
                        )
                    )
                    findings.append(finding)
        
        return findings
    
    def _detect_cloud_provider(self, content: str) -> str:
        """Detect cloud provider from content"""

        content_lower = content.lower()
        
        if 'amazonaws.com' in content_lower or 'aws:' in content_lower:
            return "AWS"
        elif 'googleapis.com' in content_lower or 'gcp' in content_lower:
            return "GCP"
        elif 'azure' in content_lower or 'microsoft.com' in content_lower:
            return "Azure"
        else:
            return "Unknown"


####
##      IAM CONFIGURATION PLUGIN
#####
class IAMPlugin(ScannerPlugin):
    """Plugin for IAM configuration scanning"""
    
    @property
    def name(self) -> str:
        return "iam-scanner"
    
    @property
    def version(self) -> str:
        return "0.1.0"
    
    async def initialize(self, config: Dict[str, Any]) -> None:
        """Initialize IAM plugin"""
        pass
    
    async def get_rules(self) -> List[ScanRule]:
        """Return IAM scanning rules"""
        return [IAMConfigurationRule()]
    
    async def cleanup(self) -> None:
        """Cleanup plugin resources"""
        pass
