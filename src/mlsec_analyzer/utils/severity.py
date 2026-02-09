"""CVSS scoring and severity level calculation."""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Tuple


class SeverityLevel(Enum):
    """Severity level enumeration."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class CVSSVector:
    """CVSS v3.1 vector components."""
    
    # Base Score Metrics
    attack_vector: str = "N"  # N=Network, A=Adjacent, L=Local, P=Physical
    attack_complexity: str = "L"  # L=Low, H=High
    privileges_required: str = "N"  # N=None, L=Low, H=High
    user_interaction: str = "N"  # N=None, R=Required
    scope: str = "U"  # U=Unchanged, C=Changed
    
    # Impact Metrics
    confidentiality_impact: str = "N"  # N=None, L=Low, H=High
    integrity_impact: str = "N"  # N=None, L=Low, H=High
    availability_impact: str = "N"  # N=None, L=Low, H=High
    
    def to_string(self) -> str:
        """Convert to CVSS vector string format.
        
        Returns:
            CVSS vector string (e.g., 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').
        """
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/"
            f"PR:{self.privileges_required}/UI:{self.user_interaction}/S:{self.scope}/"
            f"C:{self.confidentiality_impact}/I:{self.integrity_impact}/A:{self.availability_impact}"
        )
    
    @classmethod
    def from_string(cls, vector_string: str) -> "CVSSVector":
        """Parse a CVSS vector string.
        
        Args:
            vector_string: CVSS vector string.
            
        Returns:
            CVSSVector instance.
        """
        vector = cls()
        
        # Remove prefix
        if vector_string.startswith("CVSS:3.1/"):
            vector_string = vector_string[9:]
        elif vector_string.startswith("CVSS:3.0/"):
            vector_string = vector_string[9:]
        
        # Parse components
        for component in vector_string.split("/"):
            if ":" not in component:
                continue
            key, value = component.split(":", 1)
            
            if key == "AV":
                vector.attack_vector = value
            elif key == "AC":
                vector.attack_complexity = value
            elif key == "PR":
                vector.privileges_required = value
            elif key == "UI":
                vector.user_interaction = value
            elif key == "S":
                vector.scope = value
            elif key == "C":
                vector.confidentiality_impact = value
            elif key == "I":
                vector.integrity_impact = value
            elif key == "A":
                vector.availability_impact = value
        
        return vector


class SeverityCalculator:
    """Calculator for CVSS scores and severity levels."""
    
    # CVSS v3.1 metric weights
    AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    AC_WEIGHTS = {"L": 0.77, "H": 0.44}
    PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
    UI_WEIGHTS = {"N": 0.85, "R": 0.62}
    IMPACT_WEIGHTS = {"N": 0, "L": 0.22, "H": 0.56}
    
    @classmethod
    def calculate_cvss_score(cls, vector: CVSSVector) -> float:
        """Calculate CVSS base score from vector.
        
        Args:
            vector: CVSS vector components.
            
        Returns:
            CVSS base score (0.0 - 10.0).
        """
        # Get weights
        av = cls.AV_WEIGHTS.get(vector.attack_vector, 0.85)
        ac = cls.AC_WEIGHTS.get(vector.attack_complexity, 0.77)
        
        if vector.scope == "C":
            pr = cls.PR_WEIGHTS_CHANGED.get(vector.privileges_required, 0.85)
        else:
            pr = cls.PR_WEIGHTS_UNCHANGED.get(vector.privileges_required, 0.85)
        
        ui = cls.UI_WEIGHTS.get(vector.user_interaction, 0.85)
        
        c = cls.IMPACT_WEIGHTS.get(vector.confidentiality_impact, 0)
        i = cls.IMPACT_WEIGHTS.get(vector.integrity_impact, 0)
        a = cls.IMPACT_WEIGHTS.get(vector.availability_impact, 0)
        
        # Calculate exploitability
        exploitability = 8.22 * av * ac * pr * ui
        
        # Calculate impact
        isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
        
        if vector.scope == "U":
            impact = 6.42 * isc_base
        else:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * pow(isc_base - 0.02, 15)
        
        # Calculate base score
        if impact <= 0:
            return 0.0
        
        if vector.scope == "U":
            base_score = min(impact + exploitability, 10)
        else:
            base_score = min(1.08 * (impact + exploitability), 10)
        
        # Round up to one decimal place
        return round(base_score * 10) / 10
    
    @classmethod
    def score_to_level(cls, score: float) -> SeverityLevel:
        """Convert CVSS score to severity level.
        
        Args:
            score: CVSS score (0.0 - 10.0).
            
        Returns:
            Corresponding severity level.
        """
        if score >= 9.0:
            return SeverityLevel.CRITICAL
        elif score >= 7.0:
            return SeverityLevel.HIGH
        elif score >= 4.0:
            return SeverityLevel.MEDIUM
        elif score > 0.0:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO
    
    @classmethod
    def level_to_score_range(cls, level: SeverityLevel) -> Tuple[float, float]:
        """Get the CVSS score range for a severity level.
        
        Args:
            level: Severity level.
            
        Returns:
            Tuple of (min_score, max_score).
        """
        ranges = {
            SeverityLevel.CRITICAL: (9.0, 10.0),
            SeverityLevel.HIGH: (7.0, 8.9),
            SeverityLevel.MEDIUM: (4.0, 6.9),
            SeverityLevel.LOW: (0.1, 3.9),
            SeverityLevel.INFO: (0.0, 0.0),
        }
        return ranges.get(level, (0.0, 10.0))
    
    @classmethod
    def calculate_severity(
        cls,
        vector: Optional[CVSSVector] = None,
        vector_string: Optional[str] = None,
    ) -> Tuple[float, SeverityLevel, str]:
        """Calculate severity from CVSS vector.
        
        Args:
            vector: CVSSVector instance.
            vector_string: CVSS vector string (alternative to vector).
            
        Returns:
            Tuple of (score, level, vector_string).
        """
        if vector_string and not vector:
            vector = CVSSVector.from_string(vector_string)
        
        if not vector:
            vector = CVSSVector()
        
        score = cls.calculate_cvss_score(vector)
        level = cls.score_to_level(score)
        
        return score, level, vector.to_string()


# Predefined severity configurations for common vulnerability types
SEVERITY_PRESETS: Dict[str, CVSSVector] = {
    "rce_network": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality_impact="H",
        integrity_impact="H",
        availability_impact="H",
    ),
    "rce_local": CVSSVector(
        attack_vector="L",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="R",
        scope="U",
        confidentiality_impact="H",
        integrity_impact="H",
        availability_impact="H",
    ),
    "file_write": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="R",
        scope="U",
        confidentiality_impact="N",
        integrity_impact="H",
        availability_impact="H",
    ),
    "information_disclosure": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality_impact="H",
        integrity_impact="N",
        availability_impact="N",
    ),
    "ssrf": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="C",
        confidentiality_impact="L",
        integrity_impact="L",
        availability_impact="N",
    ),
    "dos": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality_impact="N",
        integrity_impact="N",
        availability_impact="H",
    ),
}
