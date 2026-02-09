"""Neural backdoor detection scanner."""

import os
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from .base_scanner import BaseScanner, ScanResult, Severity, Vulnerability


class BackdoorScanner(BaseScanner):
    """Scanner for neural backdoor/trojan detection.
    
    Performs lightweight statistical analysis on model weights to detect
    potential backdoors or trojans. Full detection requires training data,
    so this is a heuristic-based approach.
    """
    
    def get_name(self) -> str:
        return "Neural Backdoor Scanner"
    
    def get_supported_formats(self) -> List[str]:
        return [".pth", ".pt", ".h5", ".hdf5", ".keras", ".onnx", ".safetensors"]
    
    def get_description(self) -> str:
        return "Detects potential neural backdoors through weight analysis"
    
    def scan(self, model_path: str, global_config: Dict[str, Any]) -> ScanResult:
        """Scan a model for potential backdoors."""
        result = ScanResult(scanner_name=self.get_name())
        
        if not os.path.exists(model_path):
            result.add_error(f"File not found: {model_path}")
            return result
        
        ext = os.path.splitext(model_path)[1].lower()
        
        try:
            if ext in [".pth", ".pt"]:
                weights = self._load_pytorch_weights(model_path)
            elif ext in [".h5", ".hdf5", ".keras"]:
                weights = self._load_keras_weights(model_path)
            elif ext == ".safetensors":
                weights = self._load_safetensors_weights(model_path)
            elif ext == ".onnx":
                weights = self._load_onnx_weights(model_path)
            else:
                result.add_warning(f"Unsupported format for weight analysis: {ext}")
                return result
            
            if not weights:
                result.add_warning("Could not extract weights for analysis")
                return result
            
            # Perform backdoor detection analysis
            self._analyze_weights(weights, model_path, result)
            
        except Exception as e:
            result.add_warning(f"Weight analysis failed: {e}")
        
        return result
    
    def _load_pytorch_weights(self, model_path: str) -> Dict[str, np.ndarray]:
        """Load weights from PyTorch model without executing pickle."""
        weights = {}
        
        try:
            import zipfile
            import io
            
            if not zipfile.is_zipfile(model_path):
                return weights
            
            with zipfile.ZipFile(model_path, "r") as zf:
                # Look for tensor data files
                for name in zf.namelist():
                    if "data" in name or name.endswith(".npy"):
                        try:
                            data = zf.read(name)
                            # Try to interpret as numpy
                            arr = np.frombuffer(data[:min(len(data), 1024*1024)], dtype=np.float32)
                            if len(arr) > 0:
                                weights[name] = arr
                        except Exception:
                            continue
        except Exception:
            pass
        
        return weights
    
    def _load_keras_weights(self, model_path: str) -> Dict[str, np.ndarray]:
        """Load weights from Keras/HDF5 model."""
        weights = {}
        
        try:
            import h5py
        except ImportError:
            return weights
        
        try:
            with h5py.File(model_path, "r") as f:
                self._extract_h5_weights(f, weights)
        except Exception:
            pass
        
        return weights
    
    def _extract_h5_weights(self, group, weights: Dict, path: str = ""):
        """Recursively extract weights from HDF5."""
        for key in group.keys():
            item = group[key]
            current_path = f"{path}/{key}" if path else key
            
            if hasattr(item, "shape") and len(item.shape) > 0:
                # This is a dataset (tensor)
                try:
                    data = item[:]
                    if data.dtype in [np.float32, np.float64, np.float16]:
                        # Limit size for performance
                        if data.size < 10_000_000:
                            weights[current_path] = data.astype(np.float32).flatten()
                except Exception:
                    pass
            
            if hasattr(item, "keys"):
                self._extract_h5_weights(item, weights, current_path)
    
    def _load_safetensors_weights(self, model_path: str) -> Dict[str, np.ndarray]:
        """Load weights from SafeTensors format."""
        weights = {}
        
        try:
            import struct
            import json
            
            with open(model_path, "rb") as f:
                # Read header size
                header_size = struct.unpack("<Q", f.read(8))[0]
                
                # Read header
                header = json.loads(f.read(header_size).decode("utf-8"))
                
                # Read tensor data
                for name, info in header.items():
                    if name == "__metadata__":
                        continue
                    
                    dtype = info.get("dtype", "F32")
                    offsets = info.get("data_offsets", [0, 0])
                    
                    if dtype in ["F32", "F16", "BF16"]:
                        start, end = offsets
                        size = end - start
                        
                        if size < 10_000_000 * 4:  # Limit for performance
                            f.seek(8 + header_size + start)
                            data = f.read(size)
                            
                            if dtype == "F32":
                                arr = np.frombuffer(data, dtype=np.float32)
                            elif dtype == "F16":
                                arr = np.frombuffer(data, dtype=np.float16).astype(np.float32)
                            else:
                                continue
                            
                            weights[name] = arr
                            
        except Exception:
            pass
        
        return weights
    
    def _load_onnx_weights(self, model_path: str) -> Dict[str, np.ndarray]:
        """Load weights from ONNX model."""
        weights = {}
        
        try:
            import onnx
            from onnx import numpy_helper
            
            model = onnx.load(model_path)
            
            for initializer in model.graph.initializer:
                try:
                    arr = numpy_helper.to_array(initializer)
                    if arr.dtype in [np.float32, np.float64, np.float16]:
                        if arr.size < 10_000_000:
                            weights[initializer.name] = arr.astype(np.float32).flatten()
                except Exception:
                    continue
                    
        except ImportError:
            pass
        except Exception:
            pass
        
        return weights
    
    def _analyze_weights(
        self,
        weights: Dict[str, np.ndarray],
        model_path: str,
        result: ScanResult
    ):
        """Analyze weights for backdoor indicators."""
        if not weights:
            return
        
        anomalies = []
        
        # Get config thresholds
        outlier_threshold = self.config.get("outlier_threshold", 3.0)
        entropy_threshold = self.config.get("entropy_threshold", 0.5)
        
        # Analyze each weight tensor
        for name, arr in weights.items():
            if len(arr) < 100:
                continue
            
            # Check for outlier weights
            outlier_info = self._check_outliers(arr, outlier_threshold)
            if outlier_info:
                anomalies.append({
                    "type": "outlier_weights",
                    "layer": name,
                    **outlier_info,
                })
            
            # Check for unusual weight patterns
            pattern_info = self._check_unusual_patterns(arr)
            if pattern_info:
                anomalies.append({
                    "type": "unusual_pattern",
                    "layer": name,
                    **pattern_info,
                })
            
            # Check for low entropy (could indicate trigger patterns)
            entropy_info = self._check_entropy(arr, entropy_threshold)
            if entropy_info:
                anomalies.append({
                    "type": "low_entropy",
                    "layer": name,
                    **entropy_info,
                })
        
        # Report findings
        if anomalies:
            # Group by type
            outlier_count = sum(1 for a in anomalies if a["type"] == "outlier_weights")
            pattern_count = sum(1 for a in anomalies if a["type"] == "unusual_pattern")
            entropy_count = sum(1 for a in anomalies if a["type"] == "low_entropy")
            
            # Determine overall severity
            total_anomalies = len(anomalies)
            
            if total_anomalies >= 5 or (outlier_count >= 3 and pattern_count >= 1):
                severity = Severity.high(7.5)
                description = (
                    f"Model shows multiple signs of potential backdoor: "
                    f"{outlier_count} layers with outlier weights, "
                    f"{pattern_count} unusual patterns, "
                    f"{entropy_count} low-entropy regions. "
                    f"This warrants thorough investigation."
                )
            elif total_anomalies >= 2:
                severity = Severity.medium(5.5)
                description = (
                    f"Model shows some anomalous weight patterns that could indicate "
                    f"a backdoor. Found {total_anomalies} suspicious layers."
                )
            else:
                severity = Severity.low(3.5)
                description = (
                    f"Model has minor weight anomalies. This may be normal but "
                    f"should be verified."
                )
            
            vuln = self._create_vulnerability(
                vulnerability_type="Neural Backdoor - Weight Anomalies",
                severity=severity,
                description=description,
                location={"file": model_path},
                evidence={
                    "total_anomalies": total_anomalies,
                    "outlier_layers": outlier_count,
                    "unusual_patterns": pattern_count,
                    "low_entropy_regions": entropy_count,
                    "sample_anomalies": anomalies[:5],
                },
                recommendation=(
                    "Perform thorough testing with trigger detection methods. "
                    "Consider using tools like Neural Cleanse or ABS for verification."
                ),
                references=[
                    "https://arxiv.org/abs/2109.02836",
                    "https://arxiv.org/abs/2204.06974",
                ],
                cwe_id="CWE-506",
            )
            result.add_vulnerability(vuln)
    
    def _check_outliers(
        self,
        arr: np.ndarray,
        threshold: float
    ) -> Optional[Dict]:
        """Check for outlier weights using z-score."""
        try:
            mean = np.mean(arr)
            std = np.std(arr)
            
            if std < 1e-10:
                return None
            
            z_scores = np.abs((arr - mean) / std)
            outliers = np.sum(z_scores > threshold)
            outlier_ratio = outliers / len(arr)
            
            # Significant if more than 1% of weights are extreme outliers
            if outlier_ratio > 0.01:
                return {
                    "outlier_count": int(outliers),
                    "outlier_ratio": float(outlier_ratio),
                    "max_zscore": float(np.max(z_scores)),
                }
                
        except Exception:
            pass
        
        return None
    
    def _check_unusual_patterns(self, arr: np.ndarray) -> Optional[Dict]:
        """Check for unusual repetitive patterns in weights."""
        try:
            # Check for exact duplicate values (unusual in trained models)
            unique = np.unique(arr)
            uniqueness_ratio = len(unique) / len(arr)
            
            if uniqueness_ratio < 0.5 and len(arr) > 1000:
                return {
                    "uniqueness_ratio": float(uniqueness_ratio),
                    "unique_values": len(unique),
                    "total_values": len(arr),
                }
            
            # Check for suspiciously regular patterns
            diffs = np.diff(arr)
            if len(diffs) > 100:
                diff_std = np.std(diffs)
                if diff_std < 1e-6:  # Almost constant differences
                    return {
                        "pattern": "constant_increment",
                        "diff_std": float(diff_std),
                    }
                    
        except Exception:
            pass
        
        return None
    
    def _check_entropy(
        self,
        arr: np.ndarray,
        threshold: float
    ) -> Optional[Dict]:
        """Check for low entropy regions (potential trigger patterns)."""
        try:
            # Discretize values for entropy calculation
            min_val, max_val = np.min(arr), np.max(arr)
            
            if max_val - min_val < 1e-10:
                return {"entropy": 0.0, "issue": "constant_values"}
            
            # Create histogram
            bins = min(100, len(arr) // 10)
            hist, _ = np.histogram(arr, bins=bins)
            hist = hist / np.sum(hist)  # Normalize
            
            # Calculate entropy
            hist = hist[hist > 0]  # Remove zeros
            entropy = -np.sum(hist * np.log2(hist))
            max_entropy = np.log2(bins)
            normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0
            
            if normalized_entropy < threshold:
                return {
                    "entropy": float(normalized_entropy),
                    "max_entropy": float(max_entropy),
                    "issue": "low_entropy",
                }
                
        except Exception:
            pass
        
        return None
