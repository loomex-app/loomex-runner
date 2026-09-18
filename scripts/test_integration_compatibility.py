#!/usr/bin/env python3
"""Regression coverage for the cross-component compatibility verifier."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / "scripts" / "run-integration-compatibility-gate.sh"
SPEC = importlib.util.spec_from_file_location("integration_compatibility", ROOT / "scripts" / "verify-integration-compatibility.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class IntegrationCompatibilityTests(unittest.TestCase):
    def components(self) -> tuple[dict, dict, dict, dict, dict]:
        runner_routes = {
            "schemaVersion": "loomex.runner.backend-routes/v1",
            "basePath": "/api/v1/runner-control/runner/",
            "routes": [{"id": "workflow.list", "method": "GET", "pathTemplate": "v1/workflows/", "source": "src/control.rs"}],
        }
        runner_catalog = {
            "protocol": "loomex.local-control/v2",
            "version": "test",
            "maxFrameBytes": 1024,
            "capabilities": ["method:workflows.list"],
            "methods": [{"name": "workflows.list"}],
        }
        runner_manifest = {
            "schemaVersion": "loomex.runner.compatibility-manifest/v1",
            "protocol": "loomex.local-control/v2",
            "catalogVersion": "0.3.0",
            "maxFrameBytes": 1024,
            "capabilities": ["method:workflows.list"],
            "methods": [{
                "name": "workflows.list",
                "classification": "backend-proxy",
                "routeIds": ["workflow.list"],
                "inputSchemaDigest": "sha256:input",
                "outputSchemaDigest": "sha256:output",
            }],
            "routes": [{"id": "workflow.list", "method": "GET", "pathTemplate": "v1/workflows/", "source": "src/control.rs"}],
            "generatedFrom": {
                "backendRoutes": {"digest": MODULE.digest(runner_routes)},
                "methodCatalog": {"digest": MODULE.digest(runner_catalog)},
            },
        }
        plugin = {
            "schemaVersion": "loomex.plugin-compatibility-components/v1",
            "tools": [{"name": "loomex_workflows_list", "rpcMethod": "workflows.list"}],
            "resources": [{"uri": "ui://loomex/browser.html"}],
            "requiredRunnerCapabilities": ["method:workflows.list"],
            "skills": [{"name": "loomex-browse"}],
            "hooks": [{"event": "SessionStart"}],
        }
        plugin["tools"][0]["runnerOutputSchemaSha256"] = MODULE.digest({"type": "object"}).removeprefix("sha256:")
        runner_catalog["methods"][0]["inputSchema"] = {"type": "object"}
        runner_catalog["methods"][0]["outputSchema"] = {"type": "object"}
        runner_catalog["methods"][0]["mutating"] = False
        runner_catalog["methods"][0]["appOnly"] = False
        runner_catalog["methods"][0]["idempotent"] = True
        runner_catalog["methods"][0]["transportRetry"] = "before_response_once"
        runner_catalog["capabilities"] = ["method:workflows.list"]
        runner_routes["classifications"] = ["backend-auth", "backend-proxy", "daemon-lifecycle", "local-control"]
        runner_routes["methodBindings"] = [{"method": "workflows.list", "classification": "backend-proxy", "routeIds": ["workflow.list"]}]
        runner_routes["daemonRouteIds"] = []
        runner_manifest = MODULE.runner_manifest_projection(runner_catalog, runner_routes)
        backend = {
            "schemaVersion": "loomex.backend.runner-routes/v1",
            "basePath": "/api/v1/runner-control/runner/",
            "routes": [{"path": "/api/v1/runner-control/runner/v1/workflows/", "methods": ["GET"]}],
        }
        plugin["recoveryContracts"] = {
            name: hashlib.sha256((ROOT / "contracts" / name).read_bytes()).hexdigest()
            for name in ("error-recovery.json", "mutation-recovery.json")
        }
        return runner_manifest, runner_routes, runner_catalog, plugin, backend

    def test_required_mode_rejects_missing_or_drifted_recovery_contracts(self) -> None:
        for name in (None, "error-recovery.json", "mutation-recovery.json"):
            with self.subTest(contract=name):
                manifest, routes, catalog, plugin, backend = self.components()
                plugin["source"] = {"headRevision": "a" * 40, "workingTree": "clean"}
                backend["source"] = {"headRevision": "b" * 40, "workingTree": "clean"}
                if name is None:
                    del plugin["recoveryContracts"]
                else:
                    plugin["recoveryContracts"][name] = "0" * 64
                with self.assertRaisesRegex(MODULE.CompatibilityError, "recovery contracts"):
                    MODULE.verify(runner_manifest=manifest, runner_routes=routes,
                                  runner_catalog=catalog, plugin=plugin, backend=backend,
                                  require_clean_identities=True)

    def test_matches_real_component_exports(self) -> None:
        runner_manifest, runner_routes, runner_catalog, plugin, backend = self.components()
        result = MODULE.verify(
            runner_manifest=runner_manifest,
            runner_routes=runner_routes,
            runner_catalog=runner_catalog,
            plugin=plugin,
            backend=backend,
        )
        self.assertEqual(result["schemaVersion"], "loomex/compatibility-manifest/v1")
        self.assertEqual(result["verification"]["backendRequiredRouteCount"], 1)

    def test_rejects_absent_backend_method(self) -> None:
        runner_manifest, runner_routes, runner_catalog, plugin, backend = self.components()
        mutated = copy.deepcopy(backend)
        mutated["routes"][0]["methods"] = []
        with self.assertRaisesRegex(MODULE.CompatibilityError, "backend does not register"):
            MODULE.verify(
                runner_manifest=runner_manifest,
                runner_routes=runner_routes,
                runner_catalog=runner_catalog,
                plugin=plugin,
                backend=mutated,
            )

    def test_rejects_plugin_method_outside_runner_catalog(self) -> None:
        runner_manifest, runner_routes, runner_catalog, plugin, backend = self.components()
        mutated = copy.deepcopy(plugin)
        mutated["tools"][0]["rpcMethod"] = "missing.method"
        with self.assertRaisesRegex(MODULE.CompatibilityError, "unavailable runner method"):
            MODULE.verify(
                runner_manifest=runner_manifest,
                runner_routes=runner_routes,
                runner_catalog=runner_catalog,
                plugin=mutated,
                backend=backend,
            )

    def test_rejects_a_runner_manifest_bound_to_a_different_route_descriptor(self) -> None:
        runner_manifest, runner_routes, runner_catalog, plugin, backend = self.components()
        mutated = copy.deepcopy(runner_routes)
        mutated["routes"] = []
        with self.assertRaisesRegex(MODULE.CompatibilityError, "routes must not be empty"):
            MODULE.verify(
                runner_manifest=runner_manifest,
                runner_routes=mutated,
                runner_catalog=runner_catalog,
                plugin=plugin,
                backend=backend,
            )

    def test_rejects_a_manifest_field_that_is_not_the_canonical_projection(self) -> None:
        runner_manifest, runner_routes, runner_catalog, plugin, backend = self.components()
        mutated = copy.deepcopy(runner_manifest)
        mutated["methods"][0]["transportRetry"] = "never_after_send"
        with self.assertRaisesRegex(MODULE.CompatibilityError, "not the canonical projection"):
            MODULE.verify(
                runner_manifest=mutated,
                runner_routes=runner_routes,
                runner_catalog=runner_catalog,
                plugin=plugin,
                backend=backend,
            )

    def test_rejects_empty_plugin_components(self) -> None:
        runner_manifest, runner_routes, runner_catalog, plugin, backend = self.components()
        mutated = copy.deepcopy(plugin)
        mutated["tools"] = []
        with self.assertRaisesRegex(MODULE.CompatibilityError, "omits required public components"):
            MODULE.verify(
                runner_manifest=runner_manifest,
                runner_routes=runner_routes,
                runner_catalog=runner_catalog,
                plugin=mutated,
                backend=backend,
            )

    def test_rejects_omitted_plugin_components(self) -> None:
        runner_manifest, runner_routes, runner_catalog, plugin, backend = self.components()
        mutated = copy.deepcopy(plugin)
        del mutated["hooks"]
        with self.assertRaisesRegex(MODULE.CompatibilityError, "plugin hooks must be an array"):
            MODULE.verify(
                runner_manifest=runner_manifest,
                runner_routes=runner_routes,
                runner_catalog=runner_catalog,
                plugin=mutated,
                backend=backend,
            )

    def test_rejects_empty_runner_contract_inputs(self) -> None:
        runner_manifest, runner_routes, runner_catalog, plugin, backend = self.components()
        mutated = copy.deepcopy(runner_catalog)
        mutated["methods"] = []
        runner_manifest["generatedFrom"]["methodCatalog"]["digest"] = MODULE.digest(mutated)
        with self.assertRaisesRegex(MODULE.CompatibilityError, "methods must not be empty"):
            MODULE.verify(
                runner_manifest=runner_manifest,
                runner_routes=runner_routes,
                runner_catalog=mutated,
                plugin=plugin,
                backend=backend,
            )

    def test_rejects_invalid_runner_manifest_structure(self) -> None:
        runner_manifest, runner_routes, runner_catalog, plugin, backend = self.components()
        mutated = copy.deepcopy(runner_manifest)
        del mutated["methods"][0]["classification"]
        with self.assertRaisesRegex(MODULE.CompatibilityError, "classification must be a non-empty string"):
            MODULE.verify(
                runner_manifest=mutated,
                runner_routes=runner_routes,
                runner_catalog=runner_catalog,
                plugin=plugin,
                backend=backend,
            )

    def test_required_mode_accepts_clean_immutable_component_identities(self) -> None:
        runner_manifest, runner_routes, runner_catalog, plugin, backend = self.components()
        revision = "a" * 40
        plugin["source"] = {"headRevision": revision, "workingTree": "clean"}
        backend["source"] = {"headRevision": "b" * 40, "workingTree": "clean"}
        result = MODULE.verify(
            runner_manifest=runner_manifest,
            runner_routes=runner_routes,
            runner_catalog=runner_catalog,
            plugin=plugin,
            backend=backend,
            require_clean_identities=True,
            expected_plugin_revision=revision,
            expected_backend_revision="b" * 40,
        )
        self.assertEqual(result["verification"]["sourceRevisions"], {
            "plugin": revision,
            "backend": "b" * 40,
        })

    def test_required_mode_rejects_missing_or_dirty_component_identities(self) -> None:
        runner_manifest, runner_routes, runner_catalog, plugin, backend = self.components()
        with self.assertRaisesRegex(MODULE.CompatibilityError, "missing source identity"):
            MODULE.verify(
                runner_manifest=runner_manifest,
                runner_routes=runner_routes,
                runner_catalog=runner_catalog,
                plugin=plugin,
                backend=backend,
                require_clean_identities=True,
            )
        plugin["source"] = {"headRevision": "a" * 40, "workingTree": "dirty"}
        backend["source"] = {"headRevision": "b" * 40, "workingTree": "clean"}
        with self.assertRaisesRegex(MODULE.CompatibilityError, "workingTree must be clean"):
            MODULE.verify(
                runner_manifest=runner_manifest,
                runner_routes=runner_routes,
                runner_catalog=runner_catalog,
                plugin=plugin,
                backend=backend,
                require_clean_identities=True,
            )

    def test_required_mode_rejects_unverifiable_component_identity(self) -> None:
        runner_manifest, runner_routes, runner_catalog, plugin, backend = self.components()
        plugin["source"] = {"headRevision": "HEAD", "workingTree": "clean"}
        backend["source"] = {"headRevision": "b" * 40, "workingTree": "clean"}
        with self.assertRaisesRegex(MODULE.CompatibilityError, "unverifiable source.headRevision"):
            MODULE.verify(
                runner_manifest=runner_manifest,
                runner_routes=runner_routes,
                runner_catalog=runner_catalog,
                plugin=plugin,
                backend=backend,
                require_clean_identities=True,
            )

    def test_required_mode_rejects_an_export_from_a_different_checkout(self) -> None:
        runner_manifest, runner_routes, runner_catalog, plugin, backend = self.components()
        plugin["source"] = {"headRevision": "a" * 40, "workingTree": "clean"}
        backend["source"] = {"headRevision": "b" * 40, "workingTree": "clean"}
        with self.assertRaisesRegex(MODULE.CompatibilityError, "does not match the supplied checkout revision"):
            MODULE.verify(
                runner_manifest=runner_manifest,
                runner_routes=runner_routes,
                runner_catalog=runner_catalog,
                plugin=plugin,
                backend=backend,
                require_clean_identities=True,
                expected_plugin_revision="c" * 40,
            )

    def test_gate_required_mode_rejects_missing_component_inputs(self) -> None:
        result = subprocess.run(
            [str(GATE), "--required"], cwd=ROOT, text=True, capture_output=True, check=False
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("--required mode requires plugin/backend", result.stderr)


if __name__ == "__main__":
    unittest.main()
