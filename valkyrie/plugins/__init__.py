"""
Valkyrie - Plugin module.
"""
from pathlib import Path
from typing import List, Set, Dict, Any, Optional
import logging

from valkyrie.core.types import (
    RuleMetadata, SecurityFinding, ScanRule,
    ScannerPlugin
)


####
##      BASE CLASS FOR SECURITY RULE IMPLEMENTATION
#####
class BaseSecurityRule(ScanRule):
    """Base implementation for security rules"""
    
    def __init__(
        self, 
        metadata: RuleMetadata,
        logger: Optional[logging.Logger] = None
    ):
        self._metadata = metadata
        self.logger = logger or logging.getLogger(__name__)
    
    @property
    def metadata(self) -> RuleMetadata:
        return self._metadata
    
    def is_applicable(self, file_path: Path) -> bool:
        """Default implementation - override in subclasses"""
        return True
    
    async def scan(
        self, 
        file_path: Path, 
        content: str
    ) -> List[SecurityFinding]:
        """Override in subclasses"""
        
        return []


####
##      PLUGUN MANAGER CLASS
#####
class PluginManager:
    """Manages scanner plugins and their lifecycle"""
    
    def __init__(
        self,
        logger: Optional[logging.Logger] = None
    ):
        self.plugins: Dict[str, ScannerPlugin] = {}
        self.enabled_plugins: Set[str] = set()
        self.logger = logger or logging.getLogger(__name__)
    
    async def register_plugin(
        self, 
        plugin: ScannerPlugin, 
        config: Dict[str, Any] = None
    ) -> None:
        """Register and initialize a plugin"""
        
        await plugin.initialize(config or {})
        self.plugins[plugin.name] = plugin
        self.enabled_plugins.add(plugin.name)
    
    async def unregister_plugin(self, plugin_name: str) -> None:
        """Unregister a plugin"""

        if plugin_name in self.plugins:
            await self.plugins[plugin_name].cleanup()
            del self.plugins[plugin_name]
            self.enabled_plugins.discard(plugin_name)
    
    def enable_plugin(self, plugin_name: str) -> None:
        """Enable a registered plugin"""

        if plugin_name in self.plugins:
            self.enabled_plugins.add(plugin_name)
    
    def disable_plugin(self, plugin_name: str) -> None:
        """Disable a plugin"""
        self.enabled_plugins.discard(plugin_name)
    
    async def get_all_rules(self) -> List[ScanRule]:
        """Get rules from all enabled plugins"""
        
        all_rules = []
        
        for plugin_name in self.enabled_plugins:
            if plugin_name in self.plugins:
                plugin_rules = await self.plugins[plugin_name].get_rules()
                all_rules.extend(plugin_rules)
        
        return all_rules
    
    async def cleanup_all(self) -> None:
        """Cleanup all plugins"""
        for plugin in self.plugins.values():
            await plugin.cleanup()
        
        self.plugins.clear()
        self.enabled_plugins.clear()
