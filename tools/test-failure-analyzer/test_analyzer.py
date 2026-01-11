#!/usr/bin/env python3
"""
Unit tests for analyzer.py.

This file used to be a standalone script that `sys.exit(1)`'d at import time,
which breaks `python -m unittest` discovery. We keep the original intent (basic
sanity checks), but express it as real unit tests.
"""

import unittest
import sys


class TestAnalyzerBasics(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Ensure local imports resolve to this directory.
        sys.path.insert(0, ".")

    def test_imports_and_basic_contract(self):
        try:
            import analyzer  # noqa: F401
            import schemas  # noqa: F401
        except ModuleNotFoundError as e:
            # analyzer imports `yaml` (PyYAML). Skip if not installed in the test env.
            if getattr(e, "name", "") in ("yaml", "PyYAML"):
                self.skipTest("PyYAML not installed; skipping analyzer import tests")
            raise

        import analyzer

        required_functions = ["parse_args", "main", "resolve_run_info", "load_config"]
        for func in required_functions:
            self.assertTrue(hasattr(analyzer, func), f"missing function: {func}")


if __name__ == "__main__":
    unittest.main()

