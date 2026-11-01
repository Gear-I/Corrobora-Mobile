"""Static guards for architecture rules (docs/ARCHITECTURE.md, Section 2).

These parse source files; they do not import or execute them.
"""

import ast
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "corrobora_mobile"
VERIFIER = Path(__file__).resolve().parents[2] / "tools" / "verify_package.py"


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


class ArchitectureGuardTests(unittest.TestCase):
    def test_source_tree_exists(self):
        self.assertTrue(SRC.is_dir(), SRC)

    def test_only_stdlib_or_project_imports(self):
        allowed_top = set(sys.stdlib_module_names) | {"corrobora_mobile"}
        for path in SRC.rglob("*.py"):
            for module in _imported_modules(path):
                with self.subTest(file=path.name, module=module):
                    self.assertIn(module.split(".")[0], allowed_top)

    def test_core_does_not_import_platforms(self):
        for path in (SRC / "core").rglob("*.py"):
            for module in _imported_modules(path):
                with self.subTest(file=path.name, module=module):
                    self.assertFalse(module.startswith("corrobora_mobile.platforms"))

    def test_verifier_uses_only_the_standard_library(self):
        # Section 5.7: verification must not depend on the code that wrote the package.
        for module in _imported_modules(VERIFIER):
            with self.subTest(module=module):
                self.assertIn(module.split(".")[0], set(sys.stdlib_module_names))
                self.assertFalse(module.startswith("corrobora_mobile"))


if __name__ == "__main__":
    unittest.main()
