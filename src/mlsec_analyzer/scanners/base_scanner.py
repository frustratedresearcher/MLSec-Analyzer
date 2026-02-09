"""Base scanner interface and vulnerability data structures."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class SeverityLevel(Enum):
    """Severity levels for vulnerabilities."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class Severity:
    """Severity information for a vulnerability."""
    
    level: str
    cvss_score: float
    cvss_vector: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "level": self.level,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
        }
    
    @classmethod
    def critical(cls, cvss_score: float = 9.8, cvss_vector: str = "") -> "Severity":
        """Create a critical severity."""
        return cls(
            level="Critical",
            cvss_score=cvss_score,
            cvss_vector=cvss_vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
    
    @classmethod
    def high(cls, cvss_score: float = 7.5, cvss_vector: str = "") -> "Severity":
        """Create a high severity."""
        return cls(
            level="High",
            cvss_score=cvss_score,
            cvss_vector=cvss_vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        )
    
    @classmethod
    def medium(cls, cvss_score: float = 5.5, cvss_vector: str = "") -> "Severity":
        """Create a medium severity."""
        return cls(
            level="Medium",
            cvss_score=cvss_score,
            cvss_vector=cvss_vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        )
    
    @classmethod
    def low(cls, cvss_score: float = 3.0, cvss_vector: str = "") -> "Severity":
        """Create a low severity."""
        return cls(
            level="Low",
            cvss_score=cvss_score,
            cvss_vector=cvss_vector or "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        )


@dataclass
class Vulnerability:
    """Represents a detected vulnerability."""
    
    id: str
    scanner: str
    vulnerability_type: str
    severity: Severity
    description: str
    location: Dict[str, Any]
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    references: List[str] = field(default_factory=list)
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "scanner": self.scanner,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity.to_dict(),
            "description": self.description,
            "location": self.location,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "references": self.references,
            "cwe_id": self.cwe_id,
            "cve_id": self.cve_id,
        }


@dataclass
class ScanResult:
    """Result of a scanner run."""
    
    scanner_name: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_vulnerability(self, vuln: Vulnerability):
        """Add a vulnerability to the result."""
        self.vulnerabilities.append(vuln)
    
    def add_error(self, error: str):
        """Add an error to the result."""
        self.errors.append(error)
    
    def add_warning(self, warning: str):
        """Add a warning to the result."""
        self.warnings.append(warning)


class BaseScanner(ABC):
    """Abstract base class for all vulnerability scanners."""
    
    # Class-level vulnerability counter for ID generation
    _vuln_counter: int = 0
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the scanner.
        
        Args:
            config: Scanner-specific configuration.
        """
        self.config = config
        self.enabled = config.get("enabled", True)
    
    @abstractmethod
    def scan(self, model_path: str, global_config: Dict[str, Any]) -> ScanResult:
        """Scan a model file for vulnerabilities.
        
        Args:
            model_path: Path to the model file.
            global_config: Global configuration dictionary.
            
        Returns:
            ScanResult containing any found vulnerabilities.
        """
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """Get the scanner name.
        
        Returns:
            Human-readable scanner name.
        """
        pass
    
    @abstractmethod
    def get_supported_formats(self) -> List[str]:
        """Get list of supported file formats.
        
        Returns:
            List of file extensions (e.g., ['.pkl', '.pth']).
        """
        pass
    
    def get_description(self) -> str:
        """Get a description of what this scanner detects.
        
        Returns:
            Scanner description.
        """
        return "No description available."
    
    def _generate_vuln_id(self) -> str:
        """Generate a unique vulnerability ID.
        
        Returns:
            Unique vulnerability ID.
        """
        BaseScanner._vuln_counter += 1
        return f"VULN-{BaseScanner._vuln_counter:04d}"
    
    def _create_vulnerability(
        self,
        vulnerability_type: str,
        severity: Severity,
        description: str,
        location: Dict[str, Any],
        evidence: Optional[Dict[str, Any]] = None,
        recommendation: str = "",
        references: Optional[List[str]] = None,
        cwe_id: Optional[str] = None,
        cve_id: Optional[str] = None,
    ) -> Vulnerability:
        """Helper to create a vulnerability.
        
        Args:
            vulnerability_type: Type of vulnerability.
            severity: Severity information.
            description: Description of the vulnerability.
            location: Location information.
            evidence: Evidence dictionary.
            recommendation: Remediation recommendation.
            references: Reference URLs.
            cwe_id: CWE identifier.
            cve_id: CVE identifier.
            
        Returns:
            Vulnerability instance.
        """
        return Vulnerability(
            id=self._generate_vuln_id(),
            scanner=self.get_name(),
            vulnerability_type=vulnerability_type,
            severity=severity,
            description=description,
            location=location,
            evidence=evidence or {},
            recommendation=recommendation,
            references=references or [],
            cwe_id=cwe_id,
            cve_id=cve_id,
        )
