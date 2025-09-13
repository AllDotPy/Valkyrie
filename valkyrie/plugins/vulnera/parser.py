"""
Valkyrie vulnera plugin dependency parser module.
"""

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Union, Type
import toml

from .conf import Dependency


####
##      DEPENDENCY PARSER ERROR CLASS
#####
class DependencyParserError(Exception):
    """Exception raised when an error occurs in dependency file parsing."""
    pass


####
##      BASE DEPENDENCY PARSER
#####
class BaseDependencyParser:
    """Base calss for all dependenccy parsers."""
    
    def __init__(self, file_path: Union[str, Path]):
        self.file_path = Path(file_path)

        if not self.file_path.exists():
            raise FileNotFoundError(
                f"The {self.file_path} file doesn't exist."
            )
        
    @property
    def dep_file(self) -> str:
        raise NotImplementedError(
            "'dep_file' property must be implemented in all subclasses."
        )
    
    def parse(self) -> List[Dependency]:
        """Parse a dependency file and return a deps list"""

        raise NotImplementedError(
            "Parse method must be implemented in all subclasses."
        )
    
    def _read_file(self) -> str:
        """Read and returns a dependency file content."""

        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                return f.read()
            
        except UnicodeDecodeError:
            # Fallback for files with different encoding
            with open(self.file_path, 'r', encoding='latin-1') as f:
                return f.read()
            

####
##      MAIN DEPENDENCY PARSER
#####
class DependencyParser:
    """Main dependency parser"""
    
    _PARSERS: Dict[str,Type[BaseDependencyParser]] = {}

    @classmethod
    def register(cls, name: Optional[str] = None) -> None: # type: ignore
        """Register a new Parser class."""

        def wrapper(adapter: Type[BaseDependencyParser]):
            """Wrapper"""

            nonlocal name
            name = name or adapter.dep_file
            name = name.upper()
            if name not in cls._PARSERS.keys():
                cls._registry[name] = adapter
                
            return adapter

        return wrapper
    
    @classmethod
    def get(cls, name: str) -> Type[BaseDependencyParser]: # type: ignore
        """Get a Parser class by its name."""

        if name not in cls._registry:
            raise DependencyParserError(
                f"Invalid Parser name: '{name}' not found."
                )
        
        return cls._PARSERS[name]
    
    @classmethod
    def all(cls) -> List[Type[BaseDependencyParser]]: # type: ignore
        """Get all registered Parsers classes."""
        return list(cls._PARSERS.values())

    @classmethod
    def clear(cls) -> None:
        """Clear the registry."""
        cls._PARSERS.clear()

    @classmethod
    def get_supported_files(cls) -> List[str]:
        """List all registered Parsers names."""
        return list(cls._PARSERS.keys())
    
    @classmethod
    def parse(cls, file_path: Union[str, Path]) -> List[Dependency]:
        """
        Parse a dependency file and return a dependencies list
        
        Args:
            file_path: path to the dependency file
            
        Returns:
            List of dependencies
            
        Raises:
            DependencyParserError: if file format is not supported
            FileNotFoundError: if hthe file doesn't exist        
        """

        file_path = Path(file_path)
        filename = file_path.name
        
        if filename not in cls._PARSERS:
            raise DependencyParserError(
                f"Usupported file format: {filename}. "
                f"Supported format are: {', '.join(cls._PARSERS.keys())}"
            )
        
        parser_class = cls.get(filename)
        parser = parser_class(file_path)
        
        try:
            return parser.parse()
        except Exception as e:
            raise DependencyParserError(
                f"Error when parsing {filename}: {str(e)}"
            ) from e
    
    @classmethod
    def is_supported(cls, file_path: Union[str, Path]) -> bool:
        """check if a file is supported."""

        filename = Path(file_path).name
        return filename in cls._PARSERS
    

####
##      "Package.json" PARSER
#####
DependencyParser.register()
class PackageJsonParser(BaseDependencyParser):
    """Parser for package.json (Node.js)"""

    @property
    def dep_file(self):
        return "package.json"
    
    def parse(self) -> List[Dependency]:
        content = self._read_file()
        data = json.loads(content)
        
        dependencies = []
        
        # Production
        if 'dependencies' in data:
            for name, version in data['dependencies'].items():
                dependencies.append(Dependency(name, version, dev=False))
        
        # Developement
        if 'devDependencies' in data:
            for name, version in data['devDependencies'].items():
                dependencies.append(Dependency(name, version, dev=True))
        
        return dependencies
    

####
##      "package-lock.json" PARSER
#####
DependencyParser.register()
class PackageLockParser(BaseDependencyParser):
    """Parser for package-lock.json (Node.js)"""

    @property
    def dep_file(self):
        return "package-lock.json"
    
    def parse(self) -> List[Dependency]:
        content = self._read_file()
        data = json.loads(content)
        
        dependencies = []
        
        # Format npm v7+
        if 'packages' in data:
            for path, info in data['packages'].items():
                if path == "":  # Skip root package
                    continue

                name = path.replace('node_modules/', '')
                version = info.get('version')
                is_dev = info.get('dev', False)
                dependencies.append(Dependency(name, version, dev=is_dev))

        # Format npm v6
        elif 'dependencies' in data:
            for name, info in data['dependencies'].items():
                version = info.get('version')
                is_dev = info.get('dev', False)
                dependencies.append(Dependency(name, version, dev=is_dev))
        
        return dependencies
    

####
##      "yarn.lock" PARSER
#####
DependencyParser.register()
class YarnLockParser(BaseDependencyParser):
    """Parser for yarn.lock (Node.js)"""

    @property
    def dep_file(self):
        return "yarn.lock"
    
    def parse(self) -> List[Dependency]:
        content = self._read_file()
        dependencies = []
        
        # yarn.lock entries matching pattern
        pattern = r'^([^#\s][^:]*?):\s*\n(?:\s+.*\n)*?\s+version\s+"([^"]+)"'
        matches = re.findall(pattern, content, re.MULTILINE)
        
        seen = set()
        for name_pattern, version in matches:
            # Extract package name (before @)
            name = re.split(r'@(?=\d)', name_pattern.split(',')[0].strip())[0].strip('"')
            if name not in seen:
                dependencies.append(Dependency(name, version))
                seen.add(name)
        
        return dependencies
    

####
##      "requirements.txt" PARSER
#####
DependencyParser.register()
class RequirementsTxtParser(BaseDependencyParser):
    """Parser for requirements.txt (Python)"""

    @property
    def dep_file(self):
        return "requirements.txt"
    
    def parse(self) -> List[Dependency]:
        content = self._read_file()
        dependencies = []
        
        for line in content.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Skip pip options like -r, -e, etc.
            if line.startswith('-'):
                continue
            
            # matching name==version, nane>=version, etc.
            match = re.match(r'^([a-zA-Z0-9_.-]+)([><=!]*)(.*?)(?:\s*#.*)?$', line)
            if match:
                name = match.group(1)
                operator = match.group(2)
                version = match.group(3).strip() if match.group(3) else None
                version_str = f"{operator}{version}" if version else None
                dependencies.append(Dependency(name, version_str))
        
        return dependencies
    

####
##      "Pipfile" PARSER
#####
DependencyParser.register()
class PipfileParser(BaseDependencyParser):
    """Parser for Pipfile (Python)"""

    @property
    def dep_file(self):
        return "Pipfile"
    
    def parse(self) -> List[Dependency]:
        content = self._read_file()
        data = toml.loads(content)
        
        dependencies = []
        
        # Production
        if 'packages' in data:
            for name, version_info in data['packages'].items():
                version = (
                    version_info 
                    if isinstance(version_info, str) 
                    else version_info.get('version', '*')
                )
                dependencies.append(Dependency(name, version, dev=False))
        
        # Developement
        if 'dev-packages' in data:
            for name, version_info in data['dev-packages'].items():
                version = (
                    version_info 
                    if isinstance(version_info, str) 
                    else version_info.get('version', '*')
                )
                dependencies.append(Dependency(name, version, dev=True))
        
        return dependencies


####
##      "Pipfile.lock" PARSER
#####
DependencyParser.register()
class PipfileLockParser(BaseDependencyParser):
    """Parser for Pipfile.lock (Python)"""

    @property
    def dep_file(self):
        return "Pipfile.lock"
    
    def parse(self) -> List[Dependency]:
        content = self._read_file()
        data = json.loads(content)
        
        dependencies = []
        
        # Production
        if 'default' in data:
            for name, info in data['default'].items():
                version = info.get('version', '').replace('==', '')
                dependencies.append(Dependency(name, version, dev=False))
        
        # Developement
        if 'develop' in data:
            for name, info in data['develop'].items():
                version = info.get('version', '').replace('==', '')
                dependencies.append(Dependency(name, version, dev=True))
        
        return dependencies
    

####
##      "poetry.lock" PARSER
#####
DependencyParser.register()
class PoetryLockParser(BaseDependencyParser):
    """Parser for poetry.lock (Python)"""

    @property
    def dep_file(self):
        return "poetry.lock"
    
    def parse(self) -> List[Dependency]:
        content = self._read_file()
        data = toml.loads(content)
        
        dependencies = []
        
        if 'package' in data:
            for package in data['package']:
                name = package.get('name')
                version = package.get('version')
                category = package.get('category', 'main')
                is_dev = category == 'dev'
                dependencies.append(Dependency(name, version, dev=is_dev))
        
        return dependencies
    

####
##      "pom.xml" PARSER
#####
DependencyParser.register()
class PomXmlParser(BaseDependencyParser):
    """Parser for pom.xml (Java/Maven)"""

    @property
    def dep_file(self):
        return "pom.xml"
    
    def parse(self) -> List[Dependency]:
        content = self._read_file()
        root = ET.fromstring(content)
        
        # Maven namespaces
        namespaces = {'maven': 'http://maven.apache.org/POM/4.0.0'}
        if root.tag.startswith('{'):
            ns = root.tag.split('}')[0] + '}'
            namespaces['maven'] = ns[1:-1]
        
        dependencies = []
        
        # Find all dependencies
        for dep in root.findall('.//maven:dependency', namespaces) or root.findall('.//dependency'):
            group_id = dep.find('maven:groupId', namespaces) or dep.find('groupId')
            artifact_id = dep.find('maven:artifactId', namespaces) or dep.find('artifactId')
            version = dep.find('maven:version', namespaces) or dep.find('version')
            scope = dep.find('maven:scope', namespaces) or dep.find('scope')
            
            if group_id is not None and artifact_id is not None:
                name = f"{group_id.text}:{artifact_id.text}"
                version_str = version.text if version is not None else None
                is_dev = scope is not None and scope.text in ['test', 'provided']
                dependencies.append(Dependency(name, version_str, dev=is_dev))
        
        return dependencies
    

####
##      "build.gradle" PARSER
#####
DependencyParser.register()
class GradleBuildParser(BaseDependencyParser):
    """Parser for build.gradle (Java/Gradle)"""

    @property
    def dep_file(self):
        return "build.gradle"
    
    def parse(self) -> List[Dependency]:
        content = self._read_file()
        dependencies = []
        
        # Gradle deppendenciees matching pattern
        patterns = [
            r"(?:implementation|compile|api|testImplementation|testCompile)\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]",
            r"(?:implementation|compile|api|testImplementation|testCompile)\s+group:\s*['\"]([^'\"]+)['\"],\s*name:\s*['\"]([^'\"]+)['\"],\s*version:\s*['\"]([^'\"]+)['\"]"
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if len(match) == 3:
                    group_id, artifact_id, version = match
                    name = f"{group_id}:{artifact_id}"
                    dependencies.append(Dependency(name, version))
        
        return dependencies
    

####
##      "Cargo.toml" PARSER
#####
DependencyParser.register()
class CargoTomlParser(BaseDependencyParser):
    """Parser for Cargo.toml (Rust)"""

    @property
    def dep_file(self):
        return "Cargo.toml"
    
    def parse(self) -> List[Dependency]:
        content = self._read_file()
        data = toml.loads(content)
        
        dependencies = []
        
        # Production
        if 'dependencies' in data:
            for name, version_info in data['dependencies'].items():
                version = version_info if isinstance(version_info, str) else version_info.get('version')
                dependencies.append(Dependency(name, version, dev=False))
        
        # Developpement
        if 'dev-dependencies' in data:
            for name, version_info in data['dev-dependencies'].items():
                version = version_info if isinstance(version_info, str) else version_info.get('version')
                dependencies.append(Dependency(name, version, dev=True))
        
        return dependencies
    

####
##      "Cargo.lock" PARSER
#####
DependencyParser.register()
class CargoLockParser(BaseDependencyParser):
    """Parser for Cargo.lock (Rust)"""

    @property
    def dep_file(self):
        return "Cargo.lock"
    
    def parse(self) -> List[Dependency]:
        content = self._read_file()
        data = toml.loads(content)
        
        dependencies = []
        
        if 'package' in data:
            for package in data['package']:
                name = package.get('name')
                version = package.get('version')
                dependencies.append(Dependency(name, version))
        
        return dependencies
    

####
##      "go.mod" PARSER
#####
DependencyParser.register()
class GoModParser(BaseDependencyParser):
    """Parser for go.mod (Go)"""

    @property
    def dep_file(self):
        return "go.mod"
    
    def parse(self) -> List[Dependency]:
        content = self._read_file()
        dependencies = []
        
        # Required matching pattern
        in_require = False
        for line in content.split('\n'):
            line = line.strip()
            
            if line.startswith('require ('):
                in_require = True
                continue
            elif line == ')' and in_require:
                in_require = False
                continue
            
            if in_require or line.startswith('require '):
                # Clean the line
                line = line.replace('require ', '').strip()
                if not line or line == '(':
                    continue
                
                # Match module version
                parts = line.split()
                if len(parts) >= 2:
                    module = parts[0]
                    version = parts[1]
                    dependencies.append(Dependency(module, version))
        
        return dependencies
    

####
##      "composer.json" PARSER
#####
DependencyParser.register()
class ComposerJsonParser(BaseDependencyParser):
    """Parser for composer.json (PHP)"""

    @property
    def dep_file(self):
        return "composer.json"
    
    def parse(self) -> List[Dependency]:
        content = self._read_file()
        data = json.loads(content)
        
        dependencies = []
        
        # Production
        if 'require' in data:
            for name, version in data['require'].items():
                if name != 'php':  # Exclude PHP version
                    dependencies.append(Dependency(name, version, dev=False))
        
        # Developement
        if 'require-dev' in data:
            for name, version in data['require-dev'].items():
                dependencies.append(Dependency(name, version, dev=True))
        
        return dependencies
    

####
##      "composer.lock" PARSER
#####
DependencyParser.register()
class ComposerLockParser(BaseDependencyParser):
    """Parser for composer.lock (PHP)"""

    @property
    def dep_file(self):
        return "composer.lock "
    
    def parse(self) -> List[Dependency]:
        content = self._read_file()
        data = json.loads(content)
        
        dependencies = []
        
        # Production
        if 'packages' in data:
            for package in data['packages']:
                name = package.get('name')
                version = package.get('version')
                dependencies.append(Dependency(name, version, dev=False))
        
        # Developement
        if 'packages-dev' in data:
            for package in data['packages-dev']:
                name = package.get('name')
                version = package.get('version')
                dependencies.append(Dependency(name, version, dev=True))
        
        return dependencies


####    DEPENDENCY PARSER UTILITY FFUNCTION
def parse_dependencies(file_path: Union[str, Path]) -> List[Dependency]:
    """
    Utillity funnction for dependency files parsing
    
    Args:
        file_path: depenedency file path
        
    Returns:
        Dependency List
    """
    return DependencyParser.parse(file_path)

###     IS DEP FILE SUPPORTED
def is_supported(file_path: Union[str,Path]) -> bool:
    """
    Check if the file is a supported dependency manifest
    
    Args:
        file_path: depenedency file path
        
    Returns:
        True if file is upported else False
    """
    return DependencyParser.is_supported(file_path)
