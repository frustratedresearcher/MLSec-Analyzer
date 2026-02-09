"""Fickling integration utilities for safe pickle handling.

Provides wrappers around Fickling (https://github.com/trailofbits/fickling)
for safe pickle analysis and loading.

Note: Some Fickling features may not work on newer Python versions (3.14+)
due to stdlib_list compatibility. The basic decompilation still works.
"""

from typing import Any, Dict, List, Optional, Tuple

# Try to import fickling components
FICKLING_AVAILABLE = False
FICKLING_ANALYSIS_AVAILABLE = False
FICKLING_PYTORCH_AVAILABLE = False

try:
    import fickling
    from fickling.fickle import Pickled
    FICKLING_AVAILABLE = True
    
    # Analysis module may fail on Python 3.14+ due to stdlib_list
    try:
        from fickling.analysis import check_safety, Severity as FicklingSeverity
        FICKLING_ANALYSIS_AVAILABLE = True
    except Exception:
        pass
except ImportError:
    pass

try:
    from fickling.pytorch import PyTorchModelWrapper
    FICKLING_PYTORCH_AVAILABLE = True
except ImportError:
    pass


def is_fickling_available() -> bool:
    """Check if Fickling is available."""
    return FICKLING_AVAILABLE


def is_fickling_pytorch_available() -> bool:
    """Check if Fickling's PyTorch module is available."""
    return FICKLING_PYTORCH_AVAILABLE


def activate_safe_ml_environment(also_allow: Optional[List[str]] = None):
    """Activate Fickling's safe ML environment hooks.
    
    This hooks the pickle module to verify imports against an allowlist
    of safe ML library imports.
    
    Args:
        also_allow: Additional imports to allow (be careful with this!)
    """
    if not FICKLING_AVAILABLE:
        raise ImportError("Fickling is not installed. Install with: pip install fickling")
    
    if also_allow:
        fickling.hook.activate_safe_ml_environment(also_allow=also_allow)
    else:
        fickling.hook.activate_safe_ml_environment()


def deactivate_safe_ml_environment():
    """Deactivate Fickling's safe ML environment hooks."""
    if not FICKLING_AVAILABLE:
        return
    fickling.hook.deactivate_safe_ml_environment()


def check_pickle_safety(file_path: str) -> Dict[str, Any]:
    """Check if a pickle file is safe to load.
    
    Args:
        file_path: Path to the pickle file.
        
    Returns:
        Dictionary with safety analysis results.
    """
    if not FICKLING_AVAILABLE:
        return {
            "available": False,
            "error": "Fickling is not installed",
        }
    
    try:
        # Try Fickling's built-in safety check
        if FICKLING_ANALYSIS_AVAILABLE:
            is_safe = fickling.is_likely_safe(file_path)
            return {
                "available": True,
                "is_likely_safe": is_safe,
                "file_path": file_path,
            }
        else:
            # Fall back to AST analysis
            import io
            with open(file_path, "rb") as f:
                fickled = Pickled.load(f)
            
            # Check for dangerous patterns in the AST
            import ast
            dangerous = _find_dangerous_in_ast(fickled.ast)
            
            return {
                "available": True,
                "is_likely_safe": len(dangerous) == 0,
                "dangerous_patterns": dangerous,
                "file_path": file_path,
                "note": "Using AST analysis (full analysis unavailable)",
            }
    except Exception as e:
        return {
            "available": True,
            "error": str(e),
            "file_path": file_path,
        }


def _find_dangerous_in_ast(pickle_ast) -> List[str]:
    """Find dangerous patterns in a Fickling-decompiled AST."""
    import ast
    
    dangerous = []
    dangerous_modules = {"os", "nt", "posix", "subprocess", "sys", "builtins", 
                         "pty", "socket", "pickle", "marshal", "ctypes"}
    dangerous_funcs = {"system", "popen", "exec", "eval", "compile", "spawn", 
                       "__import__", "Popen", "call", "check_call", "check_output"}
    
    class DangerousFinder(ast.NodeVisitor):
        def visit_ImportFrom(self, node):
            if node.module in dangerous_modules:
                dangerous.append(f"import from {node.module}")
            self.generic_visit(node)
            
        def visit_Call(self, node):
            try:
                if isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        if node.func.value.id in dangerous_modules:
                            dangerous.append(f"{node.func.value.id}.{node.func.attr}")
                elif isinstance(node.func, ast.Name):
                    if node.func.id in dangerous_funcs:
                        dangerous.append(node.func.id)
            except Exception:
                pass
            self.generic_visit(node)
    
    try:
        DangerousFinder().visit(pickle_ast)
    except Exception:
        pass
    
    return dangerous


def analyze_pickle_file(file_path: str) -> Dict[str, Any]:
    """Perform detailed analysis of a pickle file using Fickling.
    
    Args:
        file_path: Path to the pickle file.
        
    Returns:
        Dictionary with detailed analysis results.
    """
    if not FICKLING_AVAILABLE:
        return {
            "available": False,
            "error": "Fickling is not installed",
        }
    
    try:
        with open(file_path, "rb") as f:
            fickled = Pickled.load(f)
        
        # Try to get AST dump
        import ast
        ast_dump = None
        try:
            ast_dump = ast.dump(fickled.ast, indent=2)
        except Exception:
            pass
        
        # Try full safety analysis if available
        if FICKLING_ANALYSIS_AVAILABLE:
            try:
                safety_result = check_safety(fickled)
                return {
                    "available": True,
                    "severity": safety_result.severity.name if hasattr(safety_result.severity, 'name') else str(safety_result.severity),
                    "message": safety_result.message,
                    "is_likely_safe": safety_result.severity in [FicklingSeverity.LIKELY_SAFE, FicklingSeverity.UNKNOWN],
                    "ast": ast_dump,
                    "file_path": file_path,
                }
            except Exception:
                pass
        
        # Fall back to AST analysis
        dangerous = _find_dangerous_in_ast(fickled.ast)
        
        return {
            "available": True,
            "is_likely_safe": len(dangerous) == 0,
            "dangerous_patterns": dangerous,
            "ast": ast_dump,
            "file_path": file_path,
            "note": "Using AST analysis" if not FICKLING_ANALYSIS_AVAILABLE else None,
        }
    except Exception as e:
        return {
            "available": True,
            "error": str(e),
            "file_path": file_path,
        }


def analyze_pytorch_file(file_path: str) -> Dict[str, Any]:
    """Analyze a PyTorch file for format and polyglot characteristics.
    
    Args:
        file_path: Path to the PyTorch file.
        
    Returns:
        Dictionary with PyTorch format analysis.
    """
    if not FICKLING_PYTORCH_AVAILABLE:
        return {
            "available": False,
            "error": "Fickling PyTorch module is not available. Install with: pip install fickling[torch]",
        }
    
    try:
        wrapper = PyTorchModelWrapper(file_path)
        
        return {
            "available": True,
            "formats": wrapper.formats,
            "likely_format": getattr(wrapper, 'likely_format', wrapper.formats[0] if wrapper.formats else None),
            "is_polyglot": len(wrapper.formats) > 1,
            "file_path": file_path,
        }
    except Exception as e:
        return {
            "available": True,
            "error": str(e),
            "file_path": file_path,
        }


def safe_load_pickle(file_path: str) -> Any:
    """Safely load a pickle file using Fickling's safety checks.
    
    Args:
        file_path: Path to the pickle file.
        
    Returns:
        The unpickled object.
        
    Raises:
        fickling.UnsafeFileError: If the file is detected as unsafe.
        ImportError: If Fickling is not installed.
    """
    if not FICKLING_AVAILABLE:
        raise ImportError("Fickling is not installed. Install with: pip install fickling")
    
    return fickling.load(file_path)


def trace_pickle_execution(file_path: str) -> List[str]:
    """Trace pickle execution without actually executing any code.
    
    Args:
        file_path: Path to the pickle file.
        
    Returns:
        List of trace lines.
    """
    if not FICKLING_AVAILABLE:
        return ["Error: Fickling is not installed"]
    
    try:
        with open(file_path, "rb") as f:
            fickled = Pickled.load(f)
        
        # Get the operations
        trace = []
        for i, op in enumerate(fickled.operations):
            trace.append(f"{i}: {op}")
        
        return trace
    except Exception as e:
        return [f"Error: {e}"]
