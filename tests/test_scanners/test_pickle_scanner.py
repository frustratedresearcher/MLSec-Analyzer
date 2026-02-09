"""Tests for the pickle deserialization scanner."""

import io
import os
import pickle
import pickletools
import tempfile
import zipfile
from unittest.mock import patch

import pytest

from mlsec_analyzer.scanners.pickle_scanner import PickleScanner


class TestPickleScanner:
    """Test cases for PickleScanner."""
    
    @pytest.fixture
    def scanner(self):
        """Create a scanner instance."""
        return PickleScanner({})
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory."""
        with tempfile.TemporaryDirectory() as td:
            yield td
    
    def test_get_name(self, scanner):
        """Test scanner name."""
        assert scanner.get_name() == "Pickle Deserialization Scanner"
    
    def test_get_supported_formats(self, scanner):
        """Test supported formats."""
        formats = scanner.get_supported_formats()
        assert ".pkl" in formats
        assert ".pickle" in formats
        assert ".pth" in formats
    
    def test_scan_benign_pickle(self, scanner, temp_dir):
        """Test scanning a benign pickle file."""
        # Create a benign pickle
        data = {"hello": "world", "numbers": [1, 2, 3]}
        pickle_path = os.path.join(temp_dir, "benign.pkl")
        
        with open(pickle_path, "wb") as f:
            pickle.dump(data, f)
        
        result = scanner.scan(pickle_path, {})
        
        # Benign pickle should have no or low severity vulnerabilities
        critical_vulns = [v for v in result.vulnerabilities if v.severity.level == "Critical"]
        assert len(critical_vulns) == 0
    
    def test_scan_file_not_found(self, scanner):
        """Test scanning non-existent file."""
        result = scanner.scan("/nonexistent/path.pkl", {})
        assert len(result.errors) > 0
    
    def test_dangerous_opcodes_detection(self, scanner):
        """Test that REDUCE opcode is detected."""
        # The REDUCE opcode is present in any pickle with a callable
        # Check that the scanner correctly identifies dangerous patterns
        dangerous_opcodes = scanner.DANGEROUS_OPCODES
        assert "REDUCE" in dangerous_opcodes
        assert "GLOBAL" in dangerous_opcodes
        assert "STACK_GLOBAL" in dangerous_opcodes
    
    def test_dangerous_imports_list(self, scanner):
        """Test that common dangerous imports are tracked."""
        dangerous = scanner.HIGHLY_DANGEROUS_IMPORTS
        
        assert ("os", "system") in dangerous
        assert ("subprocess", "Popen") in dangerous
        assert ("builtins", "eval") in dangerous
    
    def test_scan_pytorch_format(self, scanner, temp_dir):
        """Test scanning PyTorch-style ZIP files."""
        # Create a mock PyTorch file (ZIP with pickle inside)
        pth_path = os.path.join(temp_dir, "model.pth")
        
        # Create a simple data structure
        data = {"weight": [1.0, 2.0, 3.0]}
        pickle_data = pickle.dumps(data)
        
        with zipfile.ZipFile(pth_path, "w") as zf:
            zf.writestr("data.pkl", pickle_data)
        
        result = scanner.scan(pth_path, {})
        
        # Should parse without errors
        assert len(result.errors) == 0


class TestPickleScannerMalicious:
    """Test cases for detecting malicious pickles."""
    
    @pytest.fixture
    def scanner(self):
        return PickleScanner({})
    
    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as td:
            yield td
    
    def test_detect_os_system_import(self, scanner, temp_dir):
        """Test detection of os.system import in pickle."""
        # Create a pickle that would import os.system
        # We need to create this manually since pickle.dumps with a real
        # malicious class would require unsafe code
        
        # This is the structure of a malicious pickle
        malicious_pickle = (
            b'\x80\x04\x95\x1e\x00\x00\x00\x00\x00\x00\x00\x8c\x02os\x94\x8c\x06system\x94\x93\x94'
            b'\x8c\x06whoami\x94\x85\x94R\x94.'
        )
        
        pickle_path = os.path.join(temp_dir, "malicious.pkl")
        with open(pickle_path, "wb") as f:
            f.write(malicious_pickle)
        
        result = scanner.scan(pickle_path, {})
        
        # Should detect the dangerous import
        assert len(result.vulnerabilities) > 0
        
        # Check for critical severity
        critical = [v for v in result.vulnerabilities if v.severity.level == "Critical"]
        assert len(critical) > 0
    
    def test_extract_opcodes(self, scanner, temp_dir):
        """Test opcode extraction."""
        data = {"test": 123}
        pickle_data = pickle.dumps(data)
        
        opcodes = scanner._extract_opcodes(pickle_data)
        
        # Should have extracted some opcodes
        assert len(opcodes) > 0
        
        # Common opcodes should be present
        opcode_names = [name for name, _ in opcodes]
        assert "PROTO" in opcode_names or "FRAME" in opcode_names


class TestPickleScannerEdgeCases:
    """Edge case tests for PickleScanner."""
    
    @pytest.fixture
    def scanner(self):
        return PickleScanner({})
    
    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as td:
            yield td
    
    def test_empty_file(self, scanner, temp_dir):
        """Test scanning an empty file."""
        empty_path = os.path.join(temp_dir, "empty.pkl")
        with open(empty_path, "wb") as f:
            pass  # Create empty file
        
        result = scanner.scan(empty_path, {})
        # Should handle empty file gracefully
        assert result is not None
    
    def test_invalid_pickle(self, scanner, temp_dir):
        """Test scanning an invalid pickle file."""
        invalid_path = os.path.join(temp_dir, "invalid.pkl")
        with open(invalid_path, "wb") as f:
            f.write(b"not a pickle file")
        
        result = scanner.scan(invalid_path, {})
        # Should handle invalid pickle gracefully
        assert result is not None
    
    def test_corrupted_zip_pth(self, scanner, temp_dir):
        """Test scanning a corrupted .pth file."""
        pth_path = os.path.join(temp_dir, "corrupted.pth")
        with open(pth_path, "wb") as f:
            f.write(b"not a zip file")
        
        result = scanner.scan(pth_path, {})
        # Should fall back to pickle scanning
        assert result is not None
