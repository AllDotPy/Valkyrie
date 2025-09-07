"""
"""
import re
import hashlib
from typing import (
    Set, List, Pattern, Dict, Any
)
from pathlib import Path
from dataclasses import dataclass, field

from valkyrie.plugins import BaseSecurityRule
from valkyrie.core.types import (
    RuleMetadata, FindingCategory, SeverityLevel,
    SecurityFinding, ScanRule, ScannerPlugin,
    FileLocation
)


####
##      SECRET PATTERN MODEL
#####
@dataclass
class SecretPattern:
    """Pattern definition for secret detection"""

    name: str
    pattern: Pattern[str]
    entropy_threshold: float = 0.0
    keywords: Set[str] = field(default_factory=set)
    file_extensions: Set[str] = field(default_factory=set)


####
##      SECRET DETECTION RULE
#####
class SecretsDetectionRule(BaseSecurityRule):
    """Rule for detecting secrets and credentials"""
    
    def __init__(self):
        metadata = RuleMetadata(
            id = "secrets-001",
            name = "Generic Secrets Detection",
            description = "Detects API keys, tokens, passwords, and other secrets",
            category = FindingCategory.SECRETS,
            severity = SeverityLevel.CRITICAL,
            author = "Valkyrie Core Team",
            tags = {"secrets", "credentials", "api-keys"}
        )
        super().__init__(metadata)
        
        # Define secret patterns
        self.patterns = [
            SecretPattern(
                name = "AWS Access Key",
                pattern = re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE),
                keywords = {"aws", "amazon", "access", "key"}
            ),
            SecretPattern(
                name = "Generic API Key",
                pattern = re.compile(r'(?i)(api[_-]?key|apikey|secret[_-]?key|secretkey)\s*[:=]\s*["\']?([a-z0-9]{20,})', re.IGNORECASE),
                entropy_threshold = 3.5
            ),
            SecretPattern(
                name = "JWT Token",
                pattern = re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'),
                keywords = {"jwt", "token", "bearer"}
            ),
            SecretPattern(
                name = "GitHub Token",
                pattern = re.compile(r'gh[pousr]_[A-Za-z0-9_]{36}'),
                keywords = {"github", "token"}
            ),
            SecretPattern(
                name = "Private Key",
                pattern = re.compile(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----'),
                keywords = {"private", "key", "rsa", "ssh"}
            ),
            SecretPattern(
                name = "Database Connection String",
                pattern = re.compile(r'(mongodb|mysql|postgres|redis)://[^\s]+', re.IGNORECASE),
                keywords = {"database", "connection", "string"}
            )
        ]
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""

        if not text:
            return 0
        
        # Get character frequencies
        frequencies = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        length = len(text)
        for freq in frequencies.values():
            probability = freq / length
            entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def is_applicable(self, file_path: Path) -> bool:
        """Check if file should be scanned for secrets"""
        # Skip binary files and common non-text files
        skip_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', 
            '.pdf', '.zip', '.tar', '.gz', 
            '.exe', '.dll', '.so', '.dmg'
        }
        if file_path.suffix.lower() in skip_extensions:
            return False
        
        return True
    
    async def scan(self, file_path: Path, content: str) -> List[SecurityFinding]:
        """Scan for secrets in file content"""

        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments and obvious false positives
            line_lower = line.lower().strip()
            if (line_lower.startswith('#') or 
                line_lower.startswith('//') or 
                'example' in line_lower or 
                'placeholder' in line_lower or 
                'your_api_key_here' in line_lower):
                continue
            
            for pattern in self.patterns:
                matches = pattern.pattern.finditer(line)
                
                for match in matches:
                    matched_text = match.group()
                    
                    # Check entropy if threshold is set
                    if pattern.entropy_threshold > 0:
                        entropy = self._calculate_entropy(matched_text)
                        if entropy < pattern.entropy_threshold:
                            continue
                    
                    # Calculate confidence based on context
                    confidence = self._calculate_confidence(line, pattern)
                    
                    finding = SecurityFinding(
                        id = hashlib.md5(f"{file_path}:{line_num}:{matched_text}".encode()).hexdigest(),
                        title = f"Potential {pattern.name} detected",
                        description = f"Found pattern matching {pattern.name} in {file_path}",
                        severity = self.metadata.severity,
                        category = self.metadata.category,
                        location =FileLocation(
                            file_path = file_path,
                            line_number = line_num,
                            column_start = match.start(),
                            column_end = match.end()
                        ),
                        rule_id = self.metadata.id,
                        confidence = confidence,
                        metadata = {
                            "pattern_name": pattern.name,
                            "matched_text": matched_text[:50] + "..." if len(matched_text) > 50 else matched_text,
                            "line_content": line.strip()
                        },
                        remediation_advice = (
                            f"Remove or secure the {pattern.name}. "
                            "Consider using environment variables or secure vault services."
                        )
                    )
                    findings.append(finding)
        
        return findings
    
    def _calculate_confidence(self, line: str, pattern: SecretPattern) -> float:
        """Calculate confidence score for a potential secret"""

        confidence = 0.5  # Base confidence
        
        # Increase confidence if keywords are present
        line_lower = line.lower()
        for keyword in pattern.keywords:
            if keyword in line_lower:
                confidence += 0.1
        
        # Decrease confidence for test files
        if any(
            test_indicator in line_lower 
            for test_indicator in ['test', 'example', 'demo', 'fake']
        ):
            confidence -= 0.3
        
        return max(0.0, min(1.0, confidence))


####
##      SECRETS PLUGIN
#####
class SecretsPlugin(ScannerPlugin):
    """Plugin for secrets detection"""
    
    @property
    def name(self) -> str:
        return "secrets-detector"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    async def initialize(self, config: Dict[str, Any]) -> None:
        """Initialize secrets plugin"""
        pass
    
    async def get_rules(self) -> List[ScanRule]:
        """Return secrets detection rules"""
        return [SecretsDetectionRule()]
    
    async def cleanup(self) -> None:
        """Cleanup plugin resources"""
        pass