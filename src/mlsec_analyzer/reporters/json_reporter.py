"""JSON report generator for scan results."""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..analyzer import AnalysisResult


class JSONReporter:
    """Generates JSON reports from scan results."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the JSON reporter.
        
        Args:
            config: Reporter configuration.
        """
        self.config = config or {}
        self.include_evidence = self.config.get("include_evidence", True)
        self.include_recommendations = self.config.get("include_recommendations", True)
        self.include_references = self.config.get("include_references", True)
    
    def generate(self, results: AnalysisResult) -> Dict[str, Any]:
        """Generate a JSON report from analysis results.
        
        Args:
            results: Analysis results to report.
            
        Returns:
            Dictionary suitable for JSON serialization.
        """
        report = {
            "scan_metadata": self._format_metadata(results.scan_metadata),
            "summary": results.summary,
            "vulnerabilities": self._format_vulnerabilities(results.vulnerabilities),
        }
        
        if results.errors:
            report["errors"] = results.errors
        
        if hasattr(results, 'warnings') and results.warnings:
            report["warnings"] = results.warnings
        
        if hasattr(results, 'scanner_metadata') and results.scanner_metadata:
            report["scanner_metadata"] = results.scanner_metadata
        
        return report
    
    def _format_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Format scan metadata."""
        formatted = {
            "tool_name": "ML Model Security Analyzer",
            "tool_version": metadata.get("tool_version", "1.0.0"),
            "scan_timestamp": metadata.get("scan_timestamp", datetime.utcnow().isoformat() + "Z"),
            "target": metadata.get("target", ""),
            "target_format": metadata.get("target_format", "unknown"),
            "scanners_executed": metadata.get("scanners_executed", []),
        }
        
        return formatted
    
    def _format_vulnerabilities(self, vulnerabilities: List[Any]) -> List[Dict[str, Any]]:
        """Format vulnerability list."""
        formatted = []
        
        for vuln in vulnerabilities:
            vuln_dict = vuln.to_dict() if hasattr(vuln, "to_dict") else dict(vuln)
            
            # Optionally filter fields
            if not self.include_evidence and "evidence" in vuln_dict:
                vuln_dict["evidence"] = {"redacted": True}
            
            if not self.include_recommendations and "recommendation" in vuln_dict:
                del vuln_dict["recommendation"]
            
            if not self.include_references and "references" in vuln_dict:
                del vuln_dict["references"]
            
            formatted.append(vuln_dict)
        
        return formatted
    
    def to_string(self, results: AnalysisResult, indent: int = 2) -> str:
        """Generate JSON string from analysis results.
        
        Args:
            results: Analysis results to report.
            indent: JSON indentation level.
            
        Returns:
            JSON string.
        """
        report = self.generate(results)
        return json.dumps(report, indent=indent, default=str)
    
    def save(self, results: AnalysisResult, output_path: str, indent: int = 2):
        """Save JSON report to file.
        
        Args:
            results: Analysis results to report.
            output_path: Path to save the report.
            indent: JSON indentation level.
        """
        report = self.generate(results)
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=indent, default=str)
