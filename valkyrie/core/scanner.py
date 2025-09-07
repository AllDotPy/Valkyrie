"""
Valkyrie Security Scanner - Core Architecture
"""

from pathlib import Path
from typing import Dict, List, Optional
import asyncio
import logging
from datetime import datetime


from valkyrie.core.types import (
    RuleRepository, ScannerPlugin, ScanRule,
    ScanConfig, SecurityFinding, ScanResult,
    ScanStatus
)


####
##      VALKYRIE SCANNER ENGINE
#####
class ValkyrieScanner:
    """
    Main scanner engine that orchestrates security scanning
    """
    
    def __init__(
        self,
        rule_repository: RuleRepository,
        logger: Optional[logging.Logger] = None
    ):
        self.rule_repository = rule_repository
        self.logger = logger or logging.getLogger(__name__)
        self.plugins: Dict[str, ScannerPlugin] = {}
        self._rules_cache: Optional[List[ScanRule]] = None
    
    async def register_plugin(self, plugin: ScannerPlugin) -> None:
        """Register a scanner plugin"""

        # Initialize the plugin
        await plugin.initialize({})

        # Then add it to the scanner registry
        self.plugins[plugin.name] = plugin
        self._rules_cache = None  # Invalidate cache
        self.logger.info(f"Registered plugin: {plugin.name} v{plugin.version}")
    
    async def unregister_plugin(self, plugin_name: str) -> None:
        """Unregister a scanner plugin"""

        if plugin_name in self.plugins:
            # Then perform cleanup before deleting it
            await self.plugins[plugin_name].cleanup()

            del self.plugins[plugin_name]
            self._rules_cache = None  # Invalidate cache
            self.logger.info(f"Unregistered plugin: {plugin_name}")
    
    async def _load_all_rules(self) -> List[ScanRule]:
        """Load rules from repository and plugins"""
        
        if self._rules_cache is not None:
            return self._rules_cache
        
        # Load from repository
        rules = await self.rule_repository.load_rules()
        
        # Load from plugins
        for plugin in self.plugins.values():
            plugin_rules = await plugin.get_rules()
            rules.extend(plugin_rules)
        
        self._rules_cache = rules
        return rules
    
    def _get_scannable_files(self, config: ScanConfig) -> List[Path]:
        """Get list of files to scan based on configuration"""

        files = []
        
        for pattern in config.include_patterns:
            for file_path in config.target_path.glob(pattern):
                if not file_path.is_file():
                    continue
                
                # Check file size
                if file_path.stat().st_size > config.max_file_size:
                    self.logger.warning(f"Skipping large file: {file_path}")
                    continue
                
                # Check exclude patterns
                should_exclude = any(
                    file_path.match(exclude_pattern) 
                    for exclude_pattern in config.exclude_patterns
                )
                
                if not should_exclude:
                    files.append(file_path)
        
        return files
    
    async def _scan_file(
        self,
        file_path: Path,
        rules: List[ScanRule],
        config: ScanConfig
    ) -> List[SecurityFinding]:
        """Scan a single file with applicable rules"""
        findings = []
        
        try:
            # Read file content
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Apply applicable rules
            for rule in rules:
                # Ignore disabled rules
                if not rule.metadata.enabled:
                    continue
                
                # Rule is not in rule filters
                if config.rule_filters and rule.metadata.id not in config.rule_filters:
                    continue
                
                # Rule does'nt have the least severity
                if rule.metadata.severity.value < config.severity_threshold.value:
                    continue
                
                if rule.is_applicable(file_path):
                    try:
                        rule_findings = await rule.scan(file_path, content)
                        findings.extend(rule_findings)
                    except Exception as e:
                        self.logger.error(f"Rule {rule.metadata.id} failed on {file_path}: {e}")
        
        except Exception as e:
            self.logger.error(f"Failed to scan file {file_path}: {e}")
        
        return findings
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """
        Execute security scan based on configuration
        
        Args:
            config: Scan configuration
            
        Returns:
            Complete scan results
        """
        
        scan_id = f"scan_{datetime.now().isoformat()}"
        start_time = datetime.now()
        
        self.logger.info(f"Starting security scan: {scan_id}")
        
        try:
            # Load all rules
            rules = await self._load_all_rules()
            self.logger.info(f"Loaded {len(rules)} security rules")
            
            # Get files to scan
            files_to_scan = self._get_scannable_files(config)
            self.logger.info(f"Scanning {len(files_to_scan)} files")
            
            # Create scan tasks
            semaphore = asyncio.Semaphore(config.parallel_workers)
            
            async def scan_with_semaphore(file_path: Path) -> List[SecurityFinding]:
                async with semaphore:
                    return await self._scan_file(file_path, rules, config)
            
            # Execute scans concurrently
            scan_tasks = [scan_with_semaphore(file_path) for file_path in files_to_scan]
            results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            
            # Collect findings and errors
            all_findings = []
            errors = []
            
            for result in results:
                if isinstance(result, Exception):
                    errors.append(str(result))
                else:
                    all_findings.extend(result)
            
            # Calculate duration
            scan_duration = (datetime.now() - start_time).total_seconds()
            
            scan_result = ScanResult(
                scan_id=scan_id,
                status=ScanStatus.COMPLETED,
                findings=all_findings,
                scan_duration=scan_duration,
                scanned_files=set(files_to_scan),
                errors=errors
            )
            
            self.logger.info(
                f"Scan completed: {len(all_findings)} findings, "
                f"{scan_result.critical_count} critical, "
                f"{scan_result.high_count} high severity"
            )
            
            return scan_result
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            return ScanResult(
                scan_id=scan_id,
                status=ScanStatus.FAILED,
                errors=[str(e)],
                scan_duration=(datetime.now() - start_time).total_seconds()
            )
