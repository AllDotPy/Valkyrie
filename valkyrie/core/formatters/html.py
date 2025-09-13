"""
Valkyrie - HTML Scan Result Formatter
"""

from valkyrie.core.types import (
    SeverityLevel, ScanResult, ScanStatus
)

from .base import ResultFormatter


####
##      HTML SCAN RESUT FORMATTER
#####
class HTMLFormatter(ResultFormatter):
    """HTML report formatter"""
    
    def format(self, result: ScanResult) -> str:
        """Format results as HTML report"""

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Valkyrie Security Scan Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }}
        .content {{ padding: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .metric {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #667eea; }}
        .critical {{ border-left-color: #dc3545; }}
        .high {{ border-left-color: #fd7e14; }}
        .medium {{ border-left-color: #ffc107; }}
        .low {{ border-left-color: #28a745; }}
        .finding {{ border: 1px solid #dee2e6; border-radius: 8px; margin-bottom: 15px; }}
        .finding-header {{ padding: 15px; background: #f8f9fa; border-bottom: 1px solid #dee2e6; }}
        .finding-body {{ padding: 15px; }}
        .severity-badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; text-transform: uppercase; }}
        .severity-critical {{ background: #dc3545; color: white; }}
        .severity-high {{ background: #fd7e14; color: white; }}
        .severity-medium {{ background: #ffc107; color: black; }}
        .severity-low {{ background: #28a745; color: white; }}
        .severity-info {{ background: #17a2b8; color: white; }}
        .file-location {{ font-family: monospace; background: #f8f9fa; padding: 4px 8px; border-radius: 4px; }}
        .no-findings {{ text-align: center; padding: 60px; color: #6c757d; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Valkyrie Security Scan Report</h1>
            <p>Scan completed on {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Duration: {result.scan_duration:.2f}s | Files scanned: {len(result.scanned_files)}</p>
        </div>
        
        <div class="content">
            {self._generate_summary_html(result)}
            {self._generate_findings_html(result)}
        </div>
    </div>
</body>
</html>
        """
        return html
    
    def _generate_summary_html(self, result: ScanResult) -> str:
        """Generate summary section HTML"""

        if result.status == ScanStatus.FAILED:
            return '<div class="summary"><div class="metric critical"><h3>❌ Scan Failed</h3><p>Check logs for details</p></div></div>'
        
        return f"""
        <div class="summary">
            <div class="metric">
                <h3>{len(result.findings)}</h3>
                <p>Total Issues</p>
            </div>
            <div class="metric critical">
                <h3>{result.critical_count}</h3>
                <p>Critical</p>
            </div>
            <div class="metric high">
                <h3>{result.high_count}</h3>
                <p>High</p>
            </div>
            <div class="metric medium">
                <h3>{sum(1 for f in result.findings if f.severity == SeverityLevel.MEDIUM)}</h3>
                <p>Medium</p>
            </div>
            <div class="metric low">
                <h3>{sum(1 for f in result.findings if f.severity == SeverityLevel.LOW)}</h3>
                <p>Low</p>
            </div>
        </div>
        """
    
    def _generate_findings_html(self, result: ScanResult) -> str:
        """Generate findings section HTML"""

        if not result.findings:
            return '<div class="no-findings"><h2>✅ No security issues found!</h2><p>All scanned files are secure.</p></div>'
        
        html = "<h2>Security Findings</h2>"
        
        # Sort findings by severity
        sorted_findings = sorted(result.findings, key=lambda f: [
            SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, 
            SeverityLevel.LOW, SeverityLevel.INFO
        ].index(f.severity))
        
        for finding in sorted_findings:
            severity_class = f"severity-{finding.severity.value}"
            html += f"""
            <div class="finding">
                <div class="finding-header">
                    <span class="severity-badge {severity_class}">{finding.severity.value}</span>
                    <strong>{finding.title}</strong>
                    <div style="float: right;">
                        <span class="file-location">{finding.location.file_path}:{finding.location.line_number}</span>
                    </div>
                </div>
                <div class="finding-body">
                    <p>{finding.description}</p>
                    {f'<p><strong>Remediation:</strong> {finding.remediation_advice}</p>' if finding.remediation_advice else ''}
                    <p><strong>Rule ID:</strong> {finding.rule_id} | <strong>Confidence:</strong> {finding.confidence:.1%}</p>
                </div>
            </div>
            """
        
        return html
