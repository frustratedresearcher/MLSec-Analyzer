"""Base class for test case generators."""

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class GeneratedTestCase:
    """Represents a generated malicious test case."""
    filename: str
    filepath: str
    vulnerability_type: str
    target_parser: str
    cve_id: Optional[str]
    description: str
    severity: str  # critical, high, medium, low


class BaseTestCaseGenerator(ABC):
    """Base class for all test case generators.
    
    Test case generators create malicious model files that contain
    exploit payloads targeting specific parser vulnerabilities.
    """
    
    @abstractmethod
    def get_format_name(self) -> str:
        """Get the format name this generator handles."""
        pass
    
    @abstractmethod
    def get_format_extensions(self) -> List[str]:
        """Get file extensions for this format."""
        pass
    
    @abstractmethod
    def get_vulnerability_types(self) -> List[str]:
        """Get list of vulnerability types this generator can create."""
        pass
    
    @abstractmethod
    def generate_all(self, output_dir: str) -> List[GeneratedTestCase]:
        """Generate all test cases for this format.
        
        Args:
            output_dir: Directory to write generated files
            
        Returns:
            List of generated test case metadata
        """
        pass
    
    @abstractmethod
    def generate_specific(self, vuln_type: str, output_dir: str) -> Optional[GeneratedTestCase]:
        """Generate a specific vulnerability test case.
        
        Args:
            vuln_type: Type of vulnerability to generate
            output_dir: Directory to write generated file
            
        Returns:
            Generated test case metadata, or None if vuln_type not supported
        """
        pass
    
    def _ensure_output_dir(self, output_dir: str) -> str:
        """Ensure output directory exists."""
        os.makedirs(output_dir, exist_ok=True)
        return output_dir
    
    def _create_testcase(
        self,
        filename: str,
        filepath: str,
        vuln_type: str,
        target_parser: str,
        cve_id: Optional[str],
        description: str,
        severity: str = "critical",
    ) -> GeneratedTestCase:
        """Create a test case metadata object."""
        return GeneratedTestCase(
            filename=filename,
            filepath=filepath,
            vulnerability_type=vuln_type,
            target_parser=target_parser,
            cve_id=cve_id,
            description=description,
            severity=severity,
        )
