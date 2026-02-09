"""File utilities for the security analyzer."""

import os
import struct
from typing import Any, Dict, List, Optional, Tuple


class FileUtils:
    """Utility class for file operations."""
    
    # Magic bytes for various file formats
    MAGIC_BYTES = {
        b"\x80\x04\x95": "pickle",  # Protocol 4 pickle
        b"\x80\x03": "pickle",  # Protocol 3 pickle
        b"\x80\x02": "pickle",  # Protocol 2 pickle
        b"PK\x03\x04": "zip",  # ZIP archive
        b"\x1f\x8b\x08": "gzip",  # GZIP
        b"BZh": "bzip2",  # BZIP2
        b"\x89HDF\r\n\x1a\n": "hdf5",  # HDF5
        b"\x89PNG\r\n\x1a\n": "png",  # PNG image
        b"\xff\xd8\xff": "jpeg",  # JPEG image
        b"GIF87a": "gif",  # GIF87a
        b"GIF89a": "gif",  # GIF89a
        b"GGUF": "gguf",  # GGUF format
        b"GGML": "ggml",  # GGML format (legacy)
    }
    
    # Numpy array magic
    NUMPY_MAGIC = b"\x93NUMPY"
    
    @classmethod
    def get_file_magic(cls, file_path: str, num_bytes: int = 16) -> bytes:
        """Read the magic bytes from a file.
        
        Args:
            file_path: Path to the file.
            num_bytes: Number of bytes to read.
            
        Returns:
            First num_bytes of the file.
        """
        with open(file_path, "rb") as f:
            return f.read(num_bytes)
    
    @classmethod
    def detect_format_by_magic(cls, file_path: str) -> Optional[str]:
        """Detect file format by magic bytes.
        
        Args:
            file_path: Path to the file.
            
        Returns:
            Detected format name or None.
        """
        try:
            magic = cls.get_file_magic(file_path)
        except (IOError, OSError):
            return None
        
        # Check for numpy format
        if magic[:6] == cls.NUMPY_MAGIC:
            return "numpy"
        
        # Check known magic bytes
        for pattern, format_name in cls.MAGIC_BYTES.items():
            if magic.startswith(pattern):
                return format_name
        
        return None
    
    @classmethod
    def get_file_size(cls, file_path: str) -> int:
        """Get file size in bytes.
        
        Args:
            file_path: Path to the file.
            
        Returns:
            File size in bytes.
        """
        return os.path.getsize(file_path)
    
    @classmethod
    def is_binary_file(cls, file_path: str, sample_size: int = 8192) -> bool:
        """Check if a file is binary.
        
        Args:
            file_path: Path to the file.
            sample_size: Number of bytes to sample.
            
        Returns:
            True if the file appears to be binary.
        """
        try:
            with open(file_path, "rb") as f:
                sample = f.read(sample_size)
            
            # Check for null bytes
            if b"\x00" in sample:
                return True
            
            # Check for high ratio of non-printable characters
            text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})
            non_text = sum(1 for byte in sample if byte not in text_chars)
            
            return non_text / len(sample) > 0.30 if sample else False
            
        except (IOError, OSError):
            return True
    
    @classmethod
    def read_file_chunk(
        cls,
        file_path: str,
        offset: int = 0,
        size: int = 4096,
    ) -> bytes:
        """Read a chunk of bytes from a file.
        
        Args:
            file_path: Path to the file.
            offset: Byte offset to start reading.
            size: Number of bytes to read.
            
        Returns:
            Bytes read from the file.
        """
        with open(file_path, "rb") as f:
            f.seek(offset)
            return f.read(size)
    
    @classmethod
    def find_patterns(
        cls,
        file_path: str,
        patterns: List[bytes],
        max_offset: int = -1,
    ) -> List[Tuple[bytes, int]]:
        """Find byte patterns in a file.
        
        Args:
            file_path: Path to the file.
            patterns: List of byte patterns to search for.
            max_offset: Maximum offset to search (-1 for entire file).
            
        Returns:
            List of (pattern, offset) tuples for found patterns.
        """
        results = []
        
        with open(file_path, "rb") as f:
            content = f.read(max_offset) if max_offset > 0 else f.read()
        
        for pattern in patterns:
            offset = 0
            while True:
                pos = content.find(pattern, offset)
                if pos == -1:
                    break
                results.append((pattern, pos))
                offset = pos + 1
        
        return results
    
    @classmethod
    def safe_read_string(
        cls,
        data: bytes,
        offset: int = 0,
        max_length: int = 1000,
        encoding: str = "utf-8",
    ) -> Tuple[str, int]:
        """Safely read a null-terminated string from bytes.
        
        Args:
            data: Byte data to read from.
            offset: Starting offset.
            max_length: Maximum string length.
            encoding: String encoding.
            
        Returns:
            Tuple of (decoded string, bytes consumed).
        """
        end = offset
        while end < len(data) and end - offset < max_length:
            if data[end] == 0:
                break
            end += 1
        
        try:
            string = data[offset:end].decode(encoding)
        except UnicodeDecodeError:
            string = data[offset:end].decode(encoding, errors="replace")
        
        return string, end - offset + 1  # +1 for null terminator
    
    @classmethod
    def get_file_hash(cls, file_path: str, algorithm: str = "sha256") -> str:
        """Calculate hash of a file.
        
        Args:
            file_path: Path to the file.
            algorithm: Hash algorithm (sha256, sha1, md5).
            
        Returns:
            Hex-encoded hash string.
        """
        import hashlib
        
        hasher = hashlib.new(algorithm)
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        
        return hasher.hexdigest()
