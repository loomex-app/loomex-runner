#!/usr/bin/env python3
"""Focused regression tests for the compatibility-export contract gate."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
EXPORTER = ROOT / "scripts" / "export-compatibility.py"
CATALOG = ROOT / "contracts" / "method-catalog.json"
ROUTES = ROOT / "contracts" / "backend-routes.json"
MANIFEST = ROOT / "contracts" / "compatibility-manifest.json"


class CompatibilityExportTests(unittest.TestCase):
    def run_export(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(EXPORTER), *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_checked_in_manifest_matches_deterministic_export(self) -> None:
        result = self.run_export("--check")
        self.assertEqual(result.returncode, 0, result.stderr)
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "manifest.json"
            result = self.run_export("--output", str(output))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_text(), MANIFEST.read_text())
            package_root = Path(temp) / "package"
            (package_root / "metadata").mkdir(parents=True)
            (package_root / "metadata" / "compatibility-manifest.json").write_text(MANIFEST.read_text())
            result = self.run_export("--check-package-root", str(package_root))
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_duplicate_capability_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            catalog = Path(temp) / "catalog.json"
            value = json.loads(CATALOG.read_text())
            value["capabilities"].append(value["capabilities"][0])
            catalog.write_text(json.dumps(value))
            result = self.run_export("--catalog", str(catalog), "--output", str(Path(temp) / "out.json"))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("contains duplicate values", result.stderr)

    def test_unclassified_catalog_method_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            routes = Path(temp) / "routes.json"
            value = json.loads(ROUTES.read_text())
            value["methodBindings"] = [
                binding for binding in value["methodBindings"] if binding["method"] != "runs.get"
            ]
            routes.write_text(json.dumps(value))
            result = self.run_export("--routes", str(routes), "--output", str(Path(temp) / "out.json"))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("catalog coverage mismatch", result.stderr)

    def test_unknown_method_classification_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            routes = Path(temp) / "routes.json"
            value = json.loads(ROUTES.read_text())
            value["methodBindings"][0]["classification"] = "unreviewed-proxy"
            routes.write_text(json.dumps(value))
            result = self.run_export("--routes", str(routes), "--output", str(Path(temp) / "out.json"))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unknown classification", result.stderr)

    def test_invalid_schema_structure_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            catalog = Path(temp) / "catalog.json"
            value = json.loads(CATALOG.read_text())
            value["methods"][0]["inputSchema"]["required"] = ["notDeclared"]
            catalog.write_text(json.dumps(value))
            result = self.run_export("--catalog", str(catalog), "--output", str(Path(temp) / "out.json"))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("references undeclared property", result.stderr)


if __name__ == "__main__":
    unittest.main()
