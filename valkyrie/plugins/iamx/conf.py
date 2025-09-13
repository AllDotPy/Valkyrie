import re
from dataclasses import dataclass
from typing import (
    List, Pattern, Optional
)

from valkyrie.core.types import SeverityLevel


####
##      SECRET PATTERN MODEL
#####
@dataclass
class RiskyPattern:
    """Pattern definition for secret detection"""

    name: str
    pattern: Pattern[str]
    description: Optional[str] = None
    severity: SeverityLevel = SeverityLevel.MEDIUM


#### 
RISKY_PATTERNS: List[RiskyPattern] = [
    ## AMAZON WEB SERVICES (AWS)
    RiskyPattern(
        **{
            "name": "AWS Wildcard Resource",
            "pattern": re.compile(r'"Resource"\s*:\s*"\*"', re.IGNORECASE),
            "description": "Policy allows access to all resources",
            "severity": SeverityLevel.CRITICAL
        },
    ),
    RiskyPattern(
        **{
            "name": "AWS Admin Access",
            "pattern": re.compile(r'"Action"\s*:\s*"\*"', re.IGNORECASE),
            "description": "Policy grants all actions (admin access)",
            "severity": SeverityLevel.CRITICAL
        },
    ),

    ## GOOGLE CLOUD (GCP)
    RiskyPattern(
        **{
            "name": "GCP All Scopes",
            "pattern": re.compile(r'https://www\.googleapis\.com/auth/cloud-platform', re.IGNORECASE),
            "description": "Grants access to all Google Cloud Platform services",
            "severity": SeverityLevel.HIGH
        },
    ),
    
    ## MICROSOFT AZURE
    RiskyPattern(
        **{
            "name": "Azure Contributor Role",
            "pattern": re.compile(r'"roleDefinitionId".*"b24988ac-6180-42a0-ab88-20f7382dd24c"', re.IGNORECASE),
            "description": "Grants broad contributor access to Azure resources",
            "severity": SeverityLevel.MEDIUM
        }
    )
]
