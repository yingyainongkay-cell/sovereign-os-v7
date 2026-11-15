
import ast
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

class CentralizedDefense:
    # 1. โหลด Key จาก Environment Variable (Externalized)
    _raw_key = os.environ.get("SOVEREIGN_SIGNING_KEY", "0" * 32)
    _key_bytes = _raw_key.encode('utf-8').ljust(32, b'0')[:32]
    
    _keys = {
        "security": Ed25519PrivateKey.from_private_bytes(_key_bytes),
        "governance": Ed25519PrivateKey.from_private_bytes(_key_bytes[::-1]), # Mock 2nd key
    }

    @staticmethod
    def safe_ast_parse(code: str) -> list[str]:
        """เปลี่ยนเป็น Allowlist: ถ้าไม่ใช่ของที่อนุญาต ให้ Block ทันที"""
        ALLOWED_MODULES = {"math", "json", "re", "typing"}
        ALLOWED_BUILTINS = {"print", "range", "len", "int", "str", "float", "list", "dict", "sum", "min", "max"}
        
        class AllowlistVisitor(ast.NodeVisitor):
            def __init__(self): 
                self.violations = []

            def visit_Import(self, node):
                for n in node.names:
                    if n.name.split('.')[0] not in ALLOWED_MODULES:
                        self.violations.append(f"DISALLOWED_IMPORT: {n.name}")
            
            def visit_ImportFrom(self, node):
                if node.module and node.module.split('.')[0] not in ALLOWED_MODULES:
                    self.violations.append(f"DISALLOWED_IMPORT_FROM: {node.module}")

            def visit_Name(self, node):
                # ดักจับชื่อฟังก์ชันที่ห้ามใช้ (ดักทั้งแบบเรียกและไม่เรียก)
                FORBIDDEN = {"eval", "exec", "open", "getattr", "globals", "locals", "compile", "__import__"}
                if node.id in FORBIDDEN:
                    self.violations.append(f"FORBIDDEN_NAME: {node.id} at line {node.lineno}")

            def visit_Attribute(self, node):
                FORBIDDEN_ATTRS = {"system", "popen", "run", "call", "loads", "CDLL", "__class__", "__subclasses__", "__base__", "__bases__"}
                if node.attr in FORBIDDEN_ATTRS:
                    self.violations.append(f"FORBIDDEN_ATTR: .{node.attr} at line {node.lineno}")
                self.generic_visit(node)

        try:
            tree = ast.parse(code)
            visitor = AllowlistVisitor()
            visitor.visit(tree)
            # ตรวจสอบ Builtins ใน Call
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    if node.func.id not in ALLOWED_BUILTINS and node.func.id not in ["math", "json", "re"]:
                        visitor.violations.append(f"DISALLOWED_CALL: {node.func.id}()")
            return visitor.violations
        except SyntaxError as e:
            return [f"SYNTAX_ERROR: {e.msg} at line {e.lineno}"]

    @classmethod
    def generate_multi_sig(cls, artifact_hash: str, signers=None) -> dict:
        if signers is None: signers = ["security", "governance"]
        signatures = {}
        for signer in signers:
            if signer in cls._keys:
                sig = cls._keys[signer].sign(artifact_hash.encode('utf-8')).hex()
                signatures[signer] = sig
        return {"artifact_hash": artifact_hash, "signatures": signatures, "quorum": f"{len(signatures)}-of-3"}
