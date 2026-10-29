#!/usr/bin/env python3
"""Focused regression tests for the compatibility-export contract gate."""

from __future__ import annotations

import json
import importlib.util
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
    def test_shika_schema_syntax_and_policy_are_explicit(self) -> None:
        spec = importlib.util.spec_from_file_location("compatibility_export", EXPORTER)
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        catalog = json.loads(CATALOG.read_text())
        methods = [method for method in catalog["methods"] if method["name"].startswith("shika.v2.")]
        self.assertEqual(len(methods), 7)
        for method in methods:
            with self.subTest(method=method["name"]):
                before = json.dumps(method, sort_keys=True)
                module.validate_schema(method["inputSchema"], "input")
                module.validate_schema(method["outputSchema"], "output", output=True)
                self.assertEqual(json.dumps(method, sort_keys=True), before)
                self.assertIs(method["appOnly"], False)
                self.assertEqual(method["transportRetry"], "never_after_send")
                binding = next(item for item in json.loads(ROUTES.read_text())["methodBindings"]
                               if item["method"] == method["name"])
                self.assertEqual((binding["classification"], binding["routeIds"]), ("local-control", []))

    def test_schema_extensions_reject_malformed_or_input_composition(self) -> None:
        spec = importlib.util.spec_from_file_location("compatibility_export", EXPORTER)
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        invalid = [
            {"type": "string", "description": 7},
            {"anyOf": []},
            {"allOf": [{"if": {"properties": {"x": {"const": True}}}}, {"type": "object"}]},
            {"allOf": [{"if": {}, "then": {}}, {"type": "object"}]},
            {"allOf": [{"type": "object", "unknown": True}, {"type": "object"}]},
            {"allOf": [{"if": {"properties": {"x": {"const": True}}, "additionalProperties": False},
                        "then": {"properties": {"x": {"const": True}}}}, {"type": "object"}]},
            {"type": "object", "if": {"properties": {"x": {"const": True}}},
             "then": {"properties": {"x": {"const": True}}}},
        ]
        for schema in invalid:
            with self.subTest(schema=schema), self.assertRaises(module.ContractError):
                module.validate_schema(schema, "output", output=True)
        with self.assertRaises(module.ContractError):
            module.validate_schema({"anyOf": [{"type": "string"}, {"type": "null"}]}, "input")
        with self.assertRaises(module.ContractError):
            module.validate_schema({"type": "string", "description": False}, "input")
        module.validate_schema({"type": "string", "description": "annotation"}, "input")
        nested = {"type": "string"}
        for _ in range(66):
            nested = {"type": "array", "items": nested}
        with self.assertRaises(module.ContractError):
            module.validate_schema(nested, "output", output=True)

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

    def test_native_authoring_starts_are_optional_strict_backend_methods(self) -> None:
        catalog = json.loads(CATALOG.read_text())
        methods = {value["name"]: value for value in catalog["methods"]}
        self.assertIn("authoring.chat-native/v1", catalog["capabilities"])
        for name, inputs, core in [
            ("builder.start", {"prompt", "idempotencyKey"}, "workflow_builder"),
            ("editor.start", {"prompt", "idempotencyKey", "workflowId", "expectedVersion", "expectedDefinitionChecksum"}, "workflow_editor"),
        ]:
            method = methods[name]
            self.assertEqual(set(method["inputSchema"]["properties"]), inputs)
            self.assertEqual(set(method["inputSchema"]["required"]), inputs)
            self.assertFalse(method["inputSchema"]["additionalProperties"])
            self.assertEqual(method["transportRetry"], "never_after_send")
            output = method["outputSchema"]["oneOf"][0]
            self.assertEqual(output["properties"]["systemWorkflowKey"]["const"], core)
            self.assertEqual(output["properties"]["nextAction"]["const"], "run_get")
            self.assertNotIn("executionPolicy", output["properties"])
            self.assertIn(name, methods["workflow.operations.get"]["inputSchema"]["properties"]["operation"]["enum"])
        manifest = json.loads(MANIFEST.read_text())
        exported = {method["name"]: method for method in manifest["methods"]}
        for name in ["builder.start", "editor.start"]:
            self.assertEqual(exported[name]["classification"], "backend-proxy")
            self.assertEqual(exported[name]["routeIds"], [name])

    def test_startup_auth_observation_changes_only_optional_read_contract(self) -> None:
        catalog = json.loads(CATALOG.read_text())
        method = next(value for value in catalog["methods"] if value["name"] == "auth.status")
        self.assertEqual(method["inputSchema"]["properties"], {
            "observation": {"type": "string", "enum": ["startup"]},
        })
        self.assertEqual(method["inputSchema"]["required"], [])
        self.assertIn("auth:startup-observation/v1", catalog["capabilities"])
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "manifest.json"
            result = self.run_export("--output", str(output))
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads(output.read_text())
            exported = next(value for value in manifest["methods"] if value["name"] == "auth.status")
            self.assertFalse(exported["mutating"])
            self.assertEqual(exported["classification"], "local-control")
            self.assertEqual(exported["routeIds"], [])
            self.assertEqual(exported["outputSchemaDigest"],
                             "sha256:0f9489a5a6bdcf6d010751e2a5a8654a3b0279065430f317420fa9c750fcd205")
            # Former {} status remains accepted, but the manifest must record
            # the reviewed optional startup input instead of its old digest.
            self.assertNotEqual(exported["inputSchemaDigest"],
                                "sha256:d0157ce84790721854763c7480015e84f7cb0c7fde53afb21c3a42908805bf35")

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
