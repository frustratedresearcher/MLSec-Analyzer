"""Tests for the Zip Slip scanner."""

import os
import tempfile
import zipfile

import pytest

from mlsec_analyzer.scanners.zip_slip_scanner import ZipSlipScanner


class TestZipSlipScanner:
    """Test cases for ZipSlipScanner."""
    
    @pytest.fixture
    def scanner(self):
        """Create a scanner instance."""
        return ZipSlipScanner({})
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory."""
        with tempfile.TemporaryDirectory() as td:
            yield td
    
    def test_get_name(self, scanner):
        """Test scanner name."""
        assert scanner.get_name() == "Zip Slip Scanner"
    
    def test_get_supported_formats(self, scanner):
        """Test supported formats."""
        formats = scanner.get_supported_formats()
        assert ".zip" in formats
        assert ".npz" in formats
        assert ".keras" in formats
    
    def test_scan_safe_archive(self, scanner, temp_dir):
        """Test scanning a safe archive."""
        zip_path = os.path.join(temp_dir, "safe.zip")
        
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("file1.txt", "content1")
            zf.writestr("subdir/file2.txt", "content2")
        
        result = scanner.scan(zip_path, {})
        
        # Safe archive should have no vulnerabilities
        zip_slip_vulns = [
            v for v in result.vulnerabilities 
            if "slip" in v.vulnerability_type.lower() or "traversal" in v.vulnerability_type.lower()
        ]
        assert len(zip_slip_vulns) == 0
    
    def test_detect_path_traversal(self, scanner, temp_dir):
        """Test detection of path traversal entries."""
        zip_path = os.path.join(temp_dir, "malicious.zip")
        
        # Create a ZIP with path traversal
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("safe.txt", "safe content")
            # Add a malicious entry manually
            info = zipfile.ZipInfo("../../../etc/passwd")
            zf.writestr(info, "malicious content")
        
        result = scanner.scan(zip_path, {})
        
        # Should detect path traversal
        assert len(result.vulnerabilities) > 0
        
        # Check for high severity
        high_or_critical = [
            v for v in result.vulnerabilities 
            if v.severity.level in ["High", "Critical"]
        ]
        assert len(high_or_critical) > 0
    
    def test_detect_absolute_path(self, scanner, temp_dir):
        """Test detection of absolute paths."""
        zip_path = os.path.join(temp_dir, "absolute.zip")
        
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("safe.txt", "safe")
            info = zipfile.ZipInfo("/etc/passwd")
            zf.writestr(info, "absolute path entry")
        
        result = scanner.scan(zip_path, {})
        
        # Should detect absolute path
        vulns = [v for v in result.vulnerabilities if "absolute" in v.vulnerability_type.lower()]
        assert len(vulns) > 0
    
    def test_find_traversal_entries(self, scanner):
        """Test the traversal entry detection method."""
        entries = [
            "safe/file.txt",
            "../../../etc/passwd",
            "subdir/../file.txt",
            "normal.txt",
        ]
        
        dangerous = scanner._find_traversal_entries(entries)
        
        assert "../../../etc/passwd" in dangerous
        # Note: "subdir/../file.txt" depends on implementation
    
    def test_scan_file_not_found(self, scanner):
        """Test scanning non-existent file."""
        result = scanner.scan("/nonexistent/archive.zip", {})
        assert len(result.errors) > 0
    
    def test_scan_invalid_zip(self, scanner, temp_dir):
        """Test scanning invalid ZIP file."""
        invalid_path = os.path.join(temp_dir, "invalid.zip")
        with open(invalid_path, "wb") as f:
            f.write(b"not a zip file")
        
        result = scanner.scan(invalid_path, {})
        # Should handle gracefully
        assert result is not None


class TestZipSlipScannerNpz:
    """Test cases for NPZ format scanning."""
    
    @pytest.fixture
    def scanner(self):
        return ZipSlipScanner({})
    
    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as td:
            yield td
    
    def test_scan_safe_npz(self, scanner, temp_dir):
        """Test scanning a safe NPZ file."""
        import numpy as np
        
        npz_path = os.path.join(temp_dir, "safe.npz")
        
        # Create a safe NPZ file
        np.savez(npz_path, arr1=np.array([1, 2, 3]), arr2=np.array([4, 5, 6]))
        
        result = scanner.scan(npz_path, {})
        
        # Should have no path traversal vulnerabilities
        traversal_vulns = [
            v for v in result.vulnerabilities 
            if "traversal" in v.vulnerability_type.lower()
        ]
        assert len(traversal_vulns) == 0
