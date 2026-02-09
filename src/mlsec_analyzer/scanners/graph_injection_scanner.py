"""TensorFlow computational graph injection scanner."""

import os
import struct
from typing import Any, Dict, List, Optional, Set

from .base_scanner import BaseScanner, ScanResult, Severity, Vulnerability


class GraphInjectionScanner(BaseScanner):
    """Scanner for TensorFlow computational graph injection vulnerabilities.
    
    Detects malicious operations injected into TensorFlow graphs that can
    execute system calls, file operations, or network requests.
    """
    
    # Operations that can execute Python code
    PYTHON_EXEC_OPS = {
        "PyFunc",
        "PyFuncStateless",
        "EagerPyFunc",
    }
    
    # Operations that can perform file I/O
    FILE_IO_OPS = {
        "ReadFile",
        "WriteFile",
        "MatchingFiles",
        "ShardedFilename",
        "TFRecordReader",
        "TFRecordWriter",
        "WholeFileReader",
        "TextLineReader",
        "FixedLengthRecordReader",
        "IdentityReader",
        "ReaderRead",
        "ReaderReadUpTo",
        "ReaderNumRecordsProduced",
        "ReaderNumWorkUnitsCompleted",
        "ReaderSerializeState",
        "ReaderRestoreState",
        "ReaderReset",
        "Save",
        "SaveSlices",
        "SaveV2",
        "Restore",
        "RestoreSlice",
        "RestoreV2",
    }
    
    # Operations that can perform network operations
    NETWORK_OPS = {
        "SendTPUEmbeddingGradients",
        "RecvTPUEmbeddingActivations",
        "CollectiveGather",
        "CollectiveBcastSend",
        "CollectiveBcastRecv",
        "CollectiveReduce",
    }
    
    # Other suspicious operations
    SUSPICIOUS_OPS = {
        "Assert",  # Can be used for information disclosure
        "Print",   # Can leak information
        "PrintV2",
        "StringFormat",
        "Timestamp",
        "SleepOp",
    }
    
    def get_name(self) -> str:
        return "Graph Injection Scanner"
    
    def get_supported_formats(self) -> List[str]:
        return [".pb", ".pbtxt", "tensorflow_saved_model"]
    
    def get_description(self) -> str:
        return "Detects malicious operations in TensorFlow computational graphs"
    
    def scan(self, model_path: str, global_config: Dict[str, Any]) -> ScanResult:
        """Scan a TensorFlow model for graph injection vulnerabilities."""
        result = ScanResult(scanner_name=self.get_name())
        
        if not os.path.exists(model_path):
            result.add_error(f"Path not found: {model_path}")
            return result
        
        if os.path.isdir(model_path):
            return self._scan_saved_model(model_path, result)
        else:
            return self._scan_pb_file(model_path, result)
    
    def _scan_saved_model(self, dir_path: str, result: ScanResult) -> ScanResult:
        """Scan a TensorFlow SavedModel directory."""
        # Look for saved_model.pb
        pb_path = os.path.join(dir_path, "saved_model.pb")
        
        if os.path.exists(pb_path):
            self._scan_pb_file(pb_path, result)
        
        # Also check for graph.pb in variables/
        graph_path = os.path.join(dir_path, "variables", "variables.index")
        if os.path.exists(graph_path):
            result.add_warning("SavedModel has variables that were not fully analyzed")
        
        return result
    
    def _scan_pb_file(self, file_path: str, result: ScanResult) -> ScanResult:
        """Scan a protobuf file for dangerous operations."""
        try:
            # Try to parse with TensorFlow
            operations = self._extract_operations_tensorflow(file_path)
        except Exception:
            # Fall back to raw protobuf parsing
            operations = self._extract_operations_raw(file_path)
        
        if not operations:
            result.add_warning("No operations found in graph")
            return result
        
        # Check for Python execution ops
        python_ops = [op for op in operations if op in self.PYTHON_EXEC_OPS]
        if python_ops:
            vuln = self._create_vulnerability(
                vulnerability_type="Graph Injection - Python Execution",
                severity=Severity.critical(9.1),
                description=(
                    f"TensorFlow graph contains operations that execute arbitrary Python code: "
                    f"{', '.join(python_ops)}"
                ),
                location={"file": file_path},
                evidence={
                    "python_exec_ops": python_ops,
                    "total_ops": len(operations),
                },
                recommendation=(
                    "Run untrusted TensorFlow models in a sandbox (e.g., nsjail). "
                    "Review the model source and remove PyFunc operations if not needed."
                ),
                references=[
                    "https://www.computer.org/csdl/proceedings-article/sp/2025/223600a012/21B7Q4kpO7e",
                    "https://github.com/tensorflow/tensorflow/security/policy",
                ],
                cwe_id="CWE-94",
            )
            result.add_vulnerability(vuln)
        
        # Check for file I/O ops
        file_ops = [op for op in operations if op in self.FILE_IO_OPS]
        if file_ops:
            vuln = self._create_vulnerability(
                vulnerability_type="Graph Injection - File I/O Operations",
                severity=Severity.high(7.5),
                description=(
                    f"TensorFlow graph contains file I/O operations that could read/write "
                    f"arbitrary files: {', '.join(set(file_ops))}"
                ),
                location={"file": file_path},
                evidence={
                    "file_io_ops": list(set(file_ops)),
                    "count": len(file_ops),
                },
                recommendation=(
                    "Verify the model's intended file operations. "
                    "Run in a sandboxed environment with restricted filesystem access."
                ),
                references=[],
                cwe_id="CWE-22",
            )
            result.add_vulnerability(vuln)
        
        # Check for network ops
        network_ops = [op for op in operations if op in self.NETWORK_OPS]
        if network_ops:
            vuln = self._create_vulnerability(
                vulnerability_type="Graph Injection - Network Operations",
                severity=Severity.medium(6.0),
                description=(
                    f"TensorFlow graph contains network operations: {', '.join(set(network_ops))}"
                ),
                location={"file": file_path},
                evidence={
                    "network_ops": list(set(network_ops)),
                },
                recommendation=(
                    "Verify if network operations are expected. "
                    "Run in an isolated network environment."
                ),
                references=[],
                cwe_id="CWE-918",
            )
            result.add_vulnerability(vuln)
        
        # Check for suspicious ops
        sus_ops = [op for op in operations if op in self.SUSPICIOUS_OPS]
        if sus_ops:
            vuln = self._create_vulnerability(
                vulnerability_type="Graph Injection - Suspicious Operations",
                severity=Severity.low(3.5),
                description=(
                    f"TensorFlow graph contains suspicious operations that may leak "
                    f"information: {', '.join(set(sus_ops))}"
                ),
                location={"file": file_path},
                evidence={
                    "suspicious_ops": list(set(sus_ops)),
                },
                recommendation=(
                    "Review the purpose of these operations."
                ),
                references=[],
                cwe_id="CWE-200",
            )
            result.add_vulnerability(vuln)
        
        return result
    
    def _extract_operations_tensorflow(self, file_path: str) -> List[str]:
        """Extract operations using TensorFlow."""
        try:
            # Try TensorFlow 2.x
            import tensorflow as tf
            
            # Load the graph
            graph_def = tf.compat.v1.GraphDef()
            with open(file_path, "rb") as f:
                graph_def.ParseFromString(f.read())
            
            # Extract operation names
            return [node.op for node in graph_def.node]
            
        except ImportError:
            raise
        except Exception as e:
            raise RuntimeError(f"Failed to parse with TensorFlow: {e}")
    
    def _extract_operations_raw(self, file_path: str) -> List[str]:
        """Extract operations by raw protobuf parsing (fallback)."""
        operations = []
        
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            
            # Simple heuristic: look for known operation strings
            all_ops = (
                self.PYTHON_EXEC_OPS |
                self.FILE_IO_OPS |
                self.NETWORK_OPS |
                self.SUSPICIOUS_OPS
            )
            
            for op in all_ops:
                op_bytes = op.encode("utf-8")
                if op_bytes in data:
                    operations.append(op)
            
        except Exception:
            pass
        
        return operations
