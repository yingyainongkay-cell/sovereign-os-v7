
import ast
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

class CentralizedDefense:
    _private_key = Ed25519PrivateKey.generate()

    @staticmethod
    def safe_ast_parse(code: str) -> list[str]:
        class FixVisitor(ast.NodeVisitor):
            def __init__(self): 
                self.violations = []
                self.forbidden_names = {"eval", "exec", "compile", "__import__", "open", "getattr", "globals"}
                self.forbidden_attrs = {"system", "popen", "run", "call", "loads", "CDLL"}

            def visit_Call(self, node):
                if isinstance(node.func, ast.Name) and node.func.id in self.forbidden_names:
                    self.violations.append(f"ILLEGAL_CALL: {node.func.id}() at line {node.lineno}")
                elif isinstance(node.func, ast.Attribute) and node.func.attr in self.forbidden_attrs:
                    self.violations.append(f"ILLEGAL_ATTR: .{node.func.attr}() at line {node.lineno}")
                self.generic_visit(node)

        try:
            tree = ast.parse(code)
            visitor = FixVisitor()
            visitor.visit(tree)
            return visitor.violations
        except SyntaxError as e:
            return [f"SYNTAX_ERROR: {e.msg} at line {e.lineno}"]

    @classmethod
    def generate_signature(cls, artifact_hash: str) -> str:
        """สร้าง Ed25519 Signature สำหรับ Artifact Hash"""
        signature = cls._private_key.sign(artifact_hash.encode('utf-8'))
        return signature.hex()
