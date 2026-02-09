"""Model format detection and handling."""

import os
from dataclasses import dataclass
from typing import Dict, List, Optional

from .file_utils import FileUtils


@dataclass
class ModelFormat:
    """Information about a model format."""
    
    name: str
    extension: str
    description: str
    framework: Optional[str] = None
    is_archive: bool = False
    can_execute_code: bool = False
    
    def __str__(self) -> str:
        return self.name


class ModelFormatDetector:
    """Detector for ML model file formats."""
    
    # Format definitions
    FORMATS: Dict[str, ModelFormat] = {
        ".pkl": ModelFormat(
            name="pickle",
            extension=".pkl",
            description="Python Pickle serialization",
            framework="Python",
            can_execute_code=True,
        ),
        ".pickle": ModelFormat(
            name="pickle",
            extension=".pickle",
            description="Python Pickle serialization",
            framework="Python",
            can_execute_code=True,
        ),
        ".pth": ModelFormat(
            name="pytorch",
            extension=".pth",
            description="PyTorch model checkpoint",
            framework="PyTorch",
            is_archive=True,
            can_execute_code=True,
        ),
        ".pt": ModelFormat(
            name="pytorch",
            extension=".pt",
            description="PyTorch model checkpoint",
            framework="PyTorch",
            is_archive=True,
            can_execute_code=True,
        ),
        ".bin": ModelFormat(
            name="binary",
            extension=".bin",
            description="Binary model file",
            framework="Various",
            can_execute_code=True,
        ),
        ".h5": ModelFormat(
            name="hdf5",
            extension=".h5",
            description="HDF5/Keras model",
            framework="Keras/TensorFlow",
            can_execute_code=True,
        ),
        ".hdf5": ModelFormat(
            name="hdf5",
            extension=".hdf5",
            description="HDF5/Keras model",
            framework="Keras/TensorFlow",
            can_execute_code=True,
        ),
        ".keras": ModelFormat(
            name="keras",
            extension=".keras",
            description="Keras v3 model",
            framework="Keras",
            is_archive=True,
            can_execute_code=True,
        ),
        ".pb": ModelFormat(
            name="protobuf",
            extension=".pb",
            description="TensorFlow Protobuf",
            framework="TensorFlow",
            can_execute_code=True,
        ),
        ".tflite": ModelFormat(
            name="tflite",
            extension=".tflite",
            description="TensorFlow Lite model",
            framework="TensorFlow",
            can_execute_code=False,
        ),
        ".onnx": ModelFormat(
            name="onnx",
            extension=".onnx",
            description="ONNX model",
            framework="ONNX",
            can_execute_code=False,
        ),
        ".gguf": ModelFormat(
            name="gguf",
            extension=".gguf",
            description="GGUF quantized model",
            framework="llama.cpp",
            can_execute_code=False,
        ),
        ".ggml": ModelFormat(
            name="ggml",
            extension=".ggml",
            description="GGML quantized model (legacy)",
            framework="llama.cpp",
            can_execute_code=False,
        ),
        ".safetensors": ModelFormat(
            name="safetensors",
            extension=".safetensors",
            description="SafeTensors format",
            framework="HuggingFace",
            can_execute_code=False,
        ),
        ".npy": ModelFormat(
            name="numpy",
            extension=".npy",
            description="NumPy array",
            framework="NumPy",
            can_execute_code=False,
        ),
        ".npz": ModelFormat(
            name="numpy_archive",
            extension=".npz",
            description="NumPy compressed archive",
            framework="NumPy",
            is_archive=True,
            can_execute_code=False,
        ),
        ".joblib": ModelFormat(
            name="joblib",
            extension=".joblib",
            description="Joblib serialization",
            framework="scikit-learn",
            can_execute_code=True,
        ),
        ".model": ModelFormat(
            name="generic_model",
            extension=".model",
            description="Generic model file",
            framework="Various",
            can_execute_code=True,
        ),
        ".whl": ModelFormat(
            name="wheel",
            extension=".whl",
            description="Python wheel package",
            framework="Python",
            is_archive=True,
            can_execute_code=True,
        ),
    }
    
    def __init__(self):
        """Initialize the format detector."""
        self.file_utils = FileUtils()
    
    def detect(self, file_path: str) -> str:
        """Detect the format of a model file.
        
        Args:
            file_path: Path to the file.
            
        Returns:
            Format name string.
        """
        if not os.path.exists(file_path):
            return "unknown"
        
        if os.path.isdir(file_path):
            return self._detect_directory_format(file_path)
        
        # Check by extension first
        ext = os.path.splitext(file_path)[1].lower()
        
        # Handle compound extensions
        if file_path.lower().endswith(".tar.gz"):
            return "tar_gzip"
        if file_path.lower().endswith(".tar.bz2"):
            return "tar_bzip2"
        
        if ext in self.FORMATS:
            format_info = self.FORMATS[ext]
            
            # Verify with magic bytes for some formats
            magic_format = self.file_utils.detect_format_by_magic(file_path)
            
            if magic_format:
                # Special handling for PyTorch/Keras that use ZIP
                if magic_format == "zip" and ext in [".pth", ".pt", ".keras"]:
                    return format_info.name
                
                # Special handling for HDF5
                if magic_format == "hdf5" and ext in [".h5", ".hdf5"]:
                    return format_info.name
                
                # If magic bytes detected, use that
                return magic_format
            
            return format_info.name
        
        # Fall back to magic byte detection
        magic_format = self.file_utils.detect_format_by_magic(file_path)
        if magic_format:
            return magic_format
        
        return "unknown"
    
    def _detect_directory_format(self, dir_path: str) -> str:
        """Detect the format of a model directory.
        
        Args:
            dir_path: Path to the directory.
            
        Returns:
            Format name string.
        """
        # Check for TensorFlow SavedModel
        if os.path.exists(os.path.join(dir_path, "saved_model.pb")):
            return "tensorflow_saved_model"
        
        # Check for HuggingFace model
        config_files = ["config.json", "pytorch_model.bin", "model.safetensors"]
        if any(os.path.exists(os.path.join(dir_path, f)) for f in config_files):
            return "huggingface_model"
        
        return "directory"
    
    def get_format_info(self, format_name: str) -> Optional[ModelFormat]:
        """Get information about a format.
        
        Args:
            format_name: Format name.
            
        Returns:
            ModelFormat instance or None.
        """
        for fmt in self.FORMATS.values():
            if fmt.name == format_name:
                return fmt
        return None
    
    def get_supported_formats(self) -> List[ModelFormat]:
        """Get list of all supported formats.
        
        Returns:
            List of ModelFormat instances.
        """
        # Return unique formats
        seen = set()
        result = []
        for fmt in self.FORMATS.values():
            if fmt.name not in seen:
                seen.add(fmt.name)
                result.append(fmt)
        return result
    
    def get_all_extensions(self) -> List[str]:
        """Get all supported file extensions.
        
        Returns:
            List of file extensions.
        """
        return list(self.FORMATS.keys())
    
    def can_execute_code(self, file_path: str) -> bool:
        """Check if a model format can execute arbitrary code.
        
        Args:
            file_path: Path to the file.
            
        Returns:
            True if the format can execute code.
        """
        format_name = self.detect(file_path)
        
        for fmt in self.FORMATS.values():
            if fmt.name == format_name:
                return fmt.can_execute_code
        
        # Unknown formats are potentially dangerous
        return True
