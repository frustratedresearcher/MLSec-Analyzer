"""Tests for the JSON and SARIF reporters."""

import json
import os
import tempfile
from datetime import datetime

import pytest

from mlsec_analyzer.analyzer import AnalysisResult
from mlsec_analyzer.reporters.json_reporter import JSONReporter
from mlsec_analyzer.reporters.sarif_reporter import SARIFReporter
from mlsec_analyzer.scanners.base_scanner import Severity, Vulnerability


class TestJSONReporter:
    """Test cases for JSONReporter."""
    
    @pytest.fixture
    def reporter(self):
        """Create a reporter instance."""
        return JSONReporter()
    
    @pytest.fixture
    def sample_vulnerability(self):
        """Create a sample vulnerability."""
        return Vulnerability(
            id="VULN-0001",
            scanner="test_scanner",
            vulnerability_type="Test Vulnerability",
            severity=Severity.high(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
            description="This is a test vulnerability",
            location={"file": "test.pkl", "offset": 100},
            evidence={"pattern": "os.system"},
            recommendation="Fix this issue",
            references=["https://example.com"],
            cwe_id="CWE-502",
        )
    
    @pytest.fixture
    def sample_result(self, sample_vulnerability):
        """Create a sample analysis result."""
        return AnalysisResult(
            scan_metadata={
                "tool_version": "1.0.0",
                "scan_timestamp": "2026-02-04T10:00:00Z",
                "target": "test.pkl",
                "target_format": "pickle",
                "scanners_executed": ["test_scanner"],
            },
            vulnerabilities=[sample_vulnerability],
            summary={
                "total_vulnerabilities": 1,
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
            },
        )
    
    def test_generate_report(self, reporter, sample_result):
        """Test generating a JSON report."""
        report = reporter.generate(sample_result)
        
        assert "scan_metadata" in report
        assert "summary" in report
        assert "vulnerabilities" in report
        assert len(report["vulnerabilities"]) == 1
    
    def test_report_metadata(self, reporter, sample_result):
        """Test report metadata."""
        report = reporter.generate(sample_result)
        
        metadata = report["scan_metadata"]
        assert metadata["tool_name"] == "ML Model Security Analyzer"
        assert metadata["tool_version"] == "1.0.0"
        assert metadata["target"] == "test.pkl"
    
    def test_report_summary(self, reporter, sample_result):
        """Test report summary."""
        report = reporter.generate(sample_result)
        
        summary = report["summary"]
        assert summary["total_vulnerabilities"] == 1
        assert summary["high"] == 1
    
    def test_vulnerability_details(self, reporter, sample_result):
        """Test vulnerability details in report."""
        report = reporter.generate(sample_result)
        
        vuln = report["vulnerabilities"][0]
        assert vuln["id"] == "VULN-0001"
        assert vuln["vulnerability_type"] == "Test Vulnerability"
        assert vuln["severity"]["level"] == "High"
    
    def test_to_string(self, reporter, sample_result):
        """Test JSON string generation."""
        json_str = reporter.to_string(sample_result)
        
        # Should be valid JSON
        parsed = json.loads(json_str)
        assert "vulnerabilities" in parsed
    
    def test_save_report(self, reporter, sample_result):
        """Test saving report to file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = os.path.join(temp_dir, "report.json")
            reporter.save(sample_result, output_path)
            
            assert os.path.exists(output_path)
            
            with open(output_path) as f:
                loaded = json.load(f)
            
            assert loaded["summary"]["total_vulnerabilities"] == 1


class TestSARIFReporter:
    """Test cases for SARIFReporter."""
    
    @pytest.fixture
    def reporter(self):
        """Create a reporter instance."""
        return SARIFReporter()
    
    @pytest.fixture
    def sample_vulnerability(self):
        """Create a sample vulnerability."""
        return Vulnerability(
            id="VULN-0001",
            scanner="pickle_scanner",
            vulnerability_type="Pickle Deserialization",
            severity=Severity.critical(9.8),
            description="Malicious pickle detected",
            location={"file": "model.pkl"},
            evidence={},
            recommendation="Use SafeTensors instead",
            references=[],
            cwe_id="CWE-502",
        )
    
    @pytest.fixture
    def sample_result(self, sample_vulnerability):
        """Create a sample analysis result."""
        return AnalysisResult(
            scan_metadata={
                "tool_version": "1.0.0",
                "scan_timestamp": datetime.utcnow().isoformat() + "Z",
                "target": "model.pkl",
                "target_format": "pickle",
                "scanners_executed": ["pickle_scanner"],
            },
            vulnerabilities=[sample_vulnerability],
            summary={"total_vulnerabilities": 1, "critical": 1, "high": 0, "medium": 0, "low": 0},
        )
    
    def test_generate_sarif(self, reporter, sample_result):
        """Test SARIF report generation."""
        sarif = reporter.generate(sample_result)
        
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1
    
    def test_sarif_tool_info(self, reporter, sample_result):
        """Test SARIF tool information."""
        sarif = reporter.generate(sample_result)
        
        tool = sarif["runs"][0]["tool"]["driver"]
        assert tool["name"] == "ML Model Security Analyzer"
        assert "rules" in tool
    
    def test_sarif_results(self, reporter, sample_result):
        """Test SARIF results."""
        sarif = reporter.generate(sample_result)
        
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        
        result = results[0]
        assert "ruleId" in result
        assert result["level"] == "error"  # Critical maps to error
    
    def test_sarif_rule_mapping(self, reporter):
        """Test rule ID mapping."""
        vuln = Vulnerability(
            id="TEST",
            scanner="test",
            vulnerability_type="Pickle Deserialization Vulnerability",
            severity=Severity.critical(),
            description="test",
            location={"file": "test"},
        )
        
        rule_id = reporter._get_rule_id(vuln)
        assert rule_id == "MLSEC001"
    
    def test_sarif_severity_mapping(self, reporter):
        """Test severity to level mapping."""
        assert reporter._severity_to_level("Critical") == "error"
        assert reporter._severity_to_level("High") == "error"
        assert reporter._severity_to_level("Medium") == "warning"
        assert reporter._severity_to_level("Low") == "note"
    
    def test_save_sarif(self, reporter, sample_result):
        """Test saving SARIF to file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = os.path.join(temp_dir, "report.sarif")
            reporter.save(sample_result, output_path)
            
            assert os.path.exists(output_path)
            
            with open(output_path) as f:
                loaded = json.load(f)
            
            assert loaded["version"] == "2.1.0"
