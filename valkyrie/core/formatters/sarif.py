"""
Valkyrie - SARIF Scan result Foormatter
"""

import json
from typing import List, Dict, Any
from valkyrie.core.types import (
    ScanResult, ScanStatus, SecurityFinding,
    SeverityLevel
)
from .base import ResultFormatter


####
##      SARIF SCAN RESUT FORMATTER
#####
class SARIFFormatter(ResultFormatter):
    """SARIF (Static Analysis Results Interchange Format) formatter"""
    
    def format(self, result: ScanResult) -> str:
        """Format results as SARIF JSON"""

        sarif_report = {
            "version": "2.1.0",
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Valkyrie",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/valkyrie-scanner/valkyrie",
                            "rules": self._generate_rules(result.findings)
                        }
                    },
                    "results": self._generate_results(result.findings),
                    "invocations": [
                        {
                            "executionSuccessful": result.status == ScanStatus.COMPLETED,
                            "startTimeUtc": result.timestamp.isoformat() + "Z",
                            "endTimeUtc": result.timestamp.isoformat() + "Z"
                        }
                    ]
                }
            ]
        }
        
        return json.dumps(sarif_report, indent=2)
    
    def _generate_rules(
        self, 
        findings: List[SecurityFinding]
    ) -> List[Dict[str, Any]]:
        """Generate SARIF rules from findings"""

        rules = {}
        
        for finding in findings:
            if finding.rule_id not in rules:
                rules[finding.rule_id] = {
                    "id": finding.rule_id,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "help": {
                        "text": finding.remediation_advice or "Review and fix the security issue"
                    },
                    "properties": {
                        "security-severity": self._severity_to_score(finding.severity)
                    }
                }
        
        return list(rules.values())
    
    def _generate_results(
        self, 
        findings: List[SecurityFinding]
    ) -> List[Dict[str, Any]]:
        """Generate SARIF results from findings"""

        results = []
        
        for finding in findings:
            result = {
                "ruleId": finding.rule_id,
                "message": {"text": finding.description},
                "level": self._severity_to_level(finding.severity),
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(finding.location.file_path)
                            },
                            "region": {
                                "startLine": finding.location.line_number,
                                "startColumn": finding.location.column_start,
                                "endColumn": finding.location.column_end
                            }
                        }
                    }
                ]
            }
            results.append(result)
        
        return results
    
    def _severity_to_level(self, severity: SeverityLevel) -> str:
        """Convert severity to SARIF level"""

        mapping = {
            SeverityLevel.CRITICAL: "error",
            SeverityLevel.HIGH: "error",
            SeverityLevel.MEDIUM: "warning",
            SeverityLevel.LOW: "note",
            SeverityLevel.INFO: "note"
        }
        return mapping.get(severity, "note")
    
    def _severity_to_score(self, severity: SeverityLevel) -> str:
        """Convert severity to security score"""
        
        mapping = {
            SeverityLevel.CRITICAL: "9.0",
            SeverityLevel.HIGH: "7.0",
            SeverityLevel.MEDIUM: "5.0",
            SeverityLevel.LOW: "3.0",
            SeverityLevel.INFO: "1.0"
        }
        return mapping.get(severity, "1.0")
