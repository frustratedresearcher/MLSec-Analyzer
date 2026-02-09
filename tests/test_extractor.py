"""Tests for the model extractor."""

import os
import tarfile
import tempfile
import zipfile

import pytest

from mlsec_analyzer.extractor import ModelExtractor


class TestModelExtractor:
    """Test cases for ModelExtractor."""
    
    @pytest.fixture
    def extractor(self):
        """Create an extractor instance."""
        return ModelExtractor({})
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory."""
        with tempfile.TemporaryDirectory() as td:
            yield td
    
    def test_is_archive_zip(self, extractor, temp_dir):
        """Test archive detection for ZIP files."""
        zip_path = os.path.join(temp_dir, "test.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("test.txt", "content")
        
        assert extractor.is_archive(zip_path)
    
    def test_is_archive_npz(self, extractor, temp_dir):
        """Test archive detection for NPZ files."""
        # NPZ is a ZIP-based format
        npz_path = os.path.join(temp_dir, "test.npz")
        with zipfile.ZipFile(npz_path, "w") as zf:
            zf.writestr("arr_0.npy", b"test")
        
        assert extractor.is_archive(npz_path)
    
    def test_is_not_archive(self, extractor, temp_dir):
        """Test that regular files are not detected as archives."""
        txt_path = os.path.join(temp_dir, "test.txt")
        with open(txt_path, "w") as f:
            f.write("not an archive")
        
        assert not extractor.is_archive(txt_path)
    
    def test_extract_zip_safe(self, extractor, temp_dir):
        """Test safe ZIP extraction."""
        zip_path = os.path.join(temp_dir, "safe.zip")
        extract_dir = os.path.join(temp_dir, "extracted")
        
        # Create a safe ZIP
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("file1.txt", "content1")
            zf.writestr("subdir/file2.txt", "content2")
        
        extracted = extractor.extract_archive(zip_path, extract_dir)
        
        # Should extract files
        assert len(extracted) == 2
        assert os.path.exists(os.path.join(extract_dir, "file1.txt"))
        assert os.path.exists(os.path.join(extract_dir, "subdir", "file2.txt"))
    
    def test_extract_zip_blocks_traversal(self, extractor, temp_dir):
        """Test that ZIP extraction blocks path traversal."""
        zip_path = os.path.join(temp_dir, "malicious.zip")
        extract_dir = os.path.join(temp_dir, "extracted")
        
        # Create a ZIP with path traversal
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("safe.txt", "safe")
            info = zipfile.ZipInfo("../../../etc/passwd")
            zf.writestr(info, "malicious")
        
        extracted = extractor.extract_archive(zip_path, extract_dir)
        
        # Should only extract safe file
        assert len(extracted) == 1
        assert not os.path.exists(os.path.join(temp_dir, "..", "etc", "passwd"))
    
    def test_extract_tar_safe(self, extractor, temp_dir):
        """Test safe TAR extraction."""
        tar_path = os.path.join(temp_dir, "safe.tar")
        extract_dir = os.path.join(temp_dir, "extracted")
        
        # Create a safe TAR
        with tarfile.open(tar_path, "w") as tf:
            # Add a file
            import io
            content = b"test content"
            info = tarfile.TarInfo(name="test.txt")
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
        
        extracted = extractor.extract_archive(tar_path, extract_dir)
        
        assert len(extracted) == 1
    
    def test_unsupported_archive_format(self, extractor, temp_dir):
        """Test handling of unsupported archive format."""
        unsupported_path = os.path.join(temp_dir, "test.unknown")
        with open(unsupported_path, "wb") as f:
            f.write(b"not an archive")
        
        with pytest.raises(ValueError):
            extractor.extract_archive(unsupported_path, temp_dir)


class TestModelExtractorConfig:
    """Test configuration options for ModelExtractor."""
    
    def test_max_file_size_config(self):
        """Test max file size configuration."""
        config = {
            "extraction": {
                "max_file_size_mb": 100
            }
        }
        extractor = ModelExtractor(config)
        
        assert extractor.max_file_size == 100 * 1024 * 1024
    
    def test_timeout_config(self):
        """Test timeout configuration."""
        config = {
            "extraction": {
                "timeout_seconds": 60
            }
        }
        extractor = ModelExtractor(config)
        
        assert extractor.timeout == 60
    
    def test_default_config(self):
        """Test default configuration values."""
        extractor = ModelExtractor({})
        
        assert extractor.max_file_size == 500 * 1024 * 1024  # 500MB default
        assert extractor.timeout == 300  # 300s default
