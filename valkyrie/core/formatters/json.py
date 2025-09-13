"""
Valkyrie - HTML Scan Result Formatter
"""

import json
from valkyrie.core.types import (
    ScanResult,
)

from .base import ResultFormatter


####
##      HTML SCAN RESUT FORMATTER
#####
class JSONFormatter(ResultFormatter):
    """JSON result formatter"""
    
    def format(self, result: ScanResult) -> str:
        return json.dumps({
            "scan_id": result.scan_id,
            "status": result.status.value,
            "timestamp": result.timestamp.isoformat(),
            "scan_duration": result.scan_duration,
            "summary": {
                "total_findings": len(result.findings),
                "critical": result.critical_count,
                "high": result.high_count,
                "has_blocking_issues": result.has_blocking_issues
            },
            "findings": [finding.to_dict() for finding in result.findings],
            "scanned_files": [str(path) for path in result.scanned_files],
            "errors": result.errors
        }, indent=2)