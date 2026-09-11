#!/usr/bin/env python3
"""Verify the Loomex plugin, runner, and backend compatibility components.

This is intentionally an integration gate rather than a source-discovery tool.
Each component first exports its own authoritative view.  The gate only compares
those stable, versioned documents, which makes a mismatch actionable without
making formatting or implementation details part of the protocol.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
RUNNER_MANIFEST = ROOT / "contracts" / "compatibility-manifest.json"
RUNNER_ROUTES = ROOT / "contracts" / "backend-routes.json"
RUNNER_CATALOG = ROOT / "contracts" / "method-catalog.json"
RUNNER_EXPORTER = ROOT / "scripts" / "export-compatibility.py"
SCHEMA_VERSION = "loomex/compatibility-manifest/v1"
RUNNER_SCHEMA_VERSION = "loomex.runner.compatibility-manifest/v1"
PLUGIN_SCHEMA_VERSION = "loomex.plugin-compatibility-components/v1"
BACKEND_SCHEMA_VERSION = "loomex.backend.runner-routes/v1"


class CompatibilityError(ValueError):
    """An intentional, user-actionable compatibility mismatch."""


def runner_manifest_projection(catalog: dict[str, Any], routes: dict[str, Any]) -> dict[str, Any]:
    """Build the manifest using the runner's one canonical projection function."""
    spec = importlib.util.spec_from_file_location("loomex_runner_compatibility_export", RUNNER_EXPORTER)
    if spec is None or spec.loader is None:
        raise CompatibilityError("runner compatibility exporter is unavailable")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        return module.build(catalog, routes)
    except Exception as exc:  # The exporter's own error type remains implementation-private.
        raise CompatibilityError(f"runner compatibility projection is invalid: {exc}") from exc


def canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CompatibilityError(f"cannot read {label} at {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CompatibilityError(f"{label} must be a JSON object")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise CompatibilityError(f"{label} must be a non-empty string")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise CompatibilityError(f"{label} must be an array")
    return value


def require_non_empty_unique_strings(value: Any, label: str) -> list[str]:
    values = require_list(value, label)
    if not values or any(not isinstance(item, str) or not item for item in values):
        raise CompatibilityError(f"{label} must contain non-empty strings")
    if len(set(values)) != len(values):
        raise CompatibilityError(f"{label} contains duplicate values")
    return values


def validate_runner_inputs(
    runner_manifest: dict[str, Any], runner_routes: dict[str, Any], runner_catalog: dict[str, Any]
) -> tuple[set[str], set[str]]:
    """Validate the exported runner inputs before comparing other components."""
    if runner_catalog.get("protocol") != "loomex.local-control/v2":
        raise CompatibilityError("runner method catalog has an invalid protocol")
    catalog_method_entries = require_list(runner_catalog.get("methods"), "runner method catalog.methods")
    if not catalog_method_entries:
        raise CompatibilityError("runner method catalog.methods must not be empty")
    catalog_methods: set[str] = set()
    for entry in catalog_method_entries:
        if not isinstance(entry, dict):
            raise CompatibilityError("runner method catalog method must be an object")
        name = require_string(entry.get("name"), "runner method catalog method.name")
        if name in catalog_methods:
            raise CompatibilityError("runner method catalog contains duplicate methods")
        catalog_methods.add(name)
    catalog_capabilities = set(require_non_empty_unique_strings(
        runner_catalog.get("capabilities"), "runner method catalog.capabilities"
    ))

    if runner_manifest.get("protocol") != runner_catalog["protocol"]:
        raise CompatibilityError("runner manifest protocol does not match the method catalog")
    require_string(runner_manifest.get("catalogVersion"), "runner manifest.catalogVersion")
    max_frame = runner_manifest.get("maxFrameBytes")
    if not isinstance(max_frame, int) or isinstance(max_frame, bool) or max_frame <= 0:
        raise CompatibilityError("runner manifest.maxFrameBytes must be a positive integer")
    runner_capabilities = set(require_non_empty_unique_strings(
        runner_manifest.get("capabilities"), "runner manifest.capabilities"
    ))
    if runner_capabilities != catalog_capabilities:
        raise CompatibilityError("runner manifest capabilities do not match the method catalog")
    manifest_method_entries = require_list(runner_manifest.get("methods"), "runner manifest.methods")
    if not manifest_method_entries:
        raise CompatibilityError("runner manifest.methods must not be empty")
    manifest_methods: set[str] = set()
    for entry in manifest_method_entries:
        if not isinstance(entry, dict):
            raise CompatibilityError("runner manifest method must be an object")
        name = require_string(entry.get("name"), "runner manifest method.name")
        if name in manifest_methods:
            raise CompatibilityError("runner manifest contains an invalid or duplicate method")
        classification = require_string(entry.get("classification"), f"runner method {name}.classification")
        if classification not in {"backend-auth", "backend-proxy", "daemon-lifecycle", "local-control"}:
            raise CompatibilityError(f"runner method {name} has an invalid classification")
        require_list(entry.get("routeIds"), f"runner method {name}.routeIds")
        require_string(entry.get("inputSchemaDigest"), f"runner method {name}.inputSchemaDigest")
        require_string(entry.get("outputSchemaDigest"), f"runner method {name}.outputSchemaDigest")
        manifest_methods.add(name)
    if manifest_methods != catalog_methods:
        raise CompatibilityError("runner manifest methods do not match the method catalog")

    route_entries = require_list(runner_routes.get("routes"), "runner route descriptor.routes")
    if not route_entries:
        raise CompatibilityError("runner route descriptor.routes must not be empty")
    route_ids: set[str] = set()
    for entry in route_entries:
        if not isinstance(entry, dict):
            raise CompatibilityError("runner route descriptor entry must be an object")
        route_id = require_string(entry.get("id"), "runner route.id")
        if route_id in route_ids:
            raise CompatibilityError("runner route descriptor contains duplicate route ids")
        route_ids.add(route_id)
        require_string(entry.get("method"), f"runner route {route_id}.method")
        require_string(entry.get("pathTemplate"), f"runner route {route_id}.pathTemplate")
    manifest_routes = require_list(runner_manifest.get("routes"), "runner manifest.routes")
    if not manifest_routes:
        raise CompatibilityError("runner manifest.routes must not be empty")
    manifest_route_ids = {
        require_string(entry.get("id"), "runner manifest route.id")
        for entry in manifest_routes
        if isinstance(entry, dict)
    }
    if len(manifest_route_ids) != len(manifest_routes) or manifest_route_ids != route_ids:
        raise CompatibilityError("runner manifest routes do not match the route descriptor")
    return manifest_methods, runner_capabilities


def normalized_backend_path(path: str, base_path: str) -> str:
    if not path.startswith(base_path):
        raise CompatibilityError(f"backend route is outside {base_path}: {path}")

    def placeholder(match: re.Match[str]) -> str:
        parts = match.group(1).split("_")
        return "{" + parts[0] + "".join(part.title() for part in parts[1:]) + "}"

    return re.sub(r"<(?:uuid|str):([a-z_]+)>", placeholder, path.removeprefix(base_path))


def verify(
    *,
    runner_manifest: dict[str, Any],
    runner_routes: dict[str, Any],
    runner_catalog: dict[str, Any],
    plugin: dict[str, Any],
    backend: dict[str, Any],
) -> dict[str, Any]:
    if runner_manifest.get("schemaVersion") != RUNNER_SCHEMA_VERSION:
        raise CompatibilityError("runner manifest uses an unsupported schema version")
    if runner_routes.get("schemaVersion") != "loomex.runner.backend-routes/v1":
        raise CompatibilityError("runner route descriptor uses an unsupported schema version")
    if plugin.get("schemaVersion") != PLUGIN_SCHEMA_VERSION:
        raise CompatibilityError("plugin component export uses an unsupported schema version")
    if backend.get("schemaVersion") != BACKEND_SCHEMA_VERSION:
        raise CompatibilityError("backend route export uses an unsupported schema version")

    runner_method_names, runner_capabilities = validate_runner_inputs(
        runner_manifest, runner_routes, runner_catalog
    )
    runner_methods_by_name = {
        entry["name"]: entry
        for entry in require_list(runner_manifest.get("methods"), "runner manifest.methods")
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    }

    generated_from = runner_manifest.get("generatedFrom")
    if not isinstance(generated_from, dict):
        raise CompatibilityError("runner manifest is missing generated-from digests")
    for field, component in (("backendRoutes", runner_routes), ("methodCatalog", runner_catalog)):
        evidence = generated_from.get(field)
        if not isinstance(evidence, dict) or evidence.get("digest") != digest(component):
            raise CompatibilityError(f"runner manifest does not match the supplied {field} component")
    if canonical(runner_manifest) != canonical(runner_manifest_projection(runner_catalog, runner_routes)):
        raise CompatibilityError("runner manifest is not the canonical projection of its supplied components")

    base_path = require_string(runner_routes.get("basePath"), "runner route descriptor.basePath")
    if backend.get("basePath") != base_path:
        raise CompatibilityError("runner and backend route exports have different base paths")

    tools = require_list(plugin.get("tools"), "plugin tools")
    resources = require_list(plugin.get("resources"), "plugin resources")
    skills = require_list(plugin.get("skills"), "plugin skills")
    hooks = require_list(plugin.get("hooks"), "plugin hooks")
    if not tools or not resources or not skills or not hooks:
        raise CompatibilityError("plugin component export omits required public components")
    plugin_methods: set[str] = set()
    for tool in tools:
        if not isinstance(tool, dict):
            raise CompatibilityError("plugin tool component must be an object")
        name = require_string(tool.get("name"), "plugin tool.name")
        rpc_method = require_string(tool.get("rpcMethod"), f"plugin tool {name}.rpcMethod")
        if rpc_method not in runner_method_names:
            raise CompatibilityError(f"plugin tool {name} references unavailable runner method {rpc_method}")
        runner_method = runner_methods_by_name[rpc_method]
        expected_output_digest = runner_method.get("outputSchemaDigest")
        if not isinstance(expected_output_digest, str) or not expected_output_digest.startswith("sha256:"):
            raise CompatibilityError(f"runner method {rpc_method} has an invalid output schema digest")
        if tool.get("runnerOutputSchemaSha256") != expected_output_digest.removeprefix("sha256:"):
            raise CompatibilityError(f"plugin tool {name} does not bind the runner output schema for {rpc_method}")
        plugin_methods.add(rpc_method)

    required_capabilities = set(require_non_empty_unique_strings(
        plugin.get("requiredRunnerCapabilities"), "plugin requiredRunnerCapabilities"
    ))
    missing_capabilities = sorted(required_capabilities - runner_capabilities)
    if missing_capabilities:
        raise CompatibilityError(f"plugin requires unavailable runner capabilities: {', '.join(missing_capabilities)}")

    route_entries = require_list(runner_routes.get("routes"), "runner route descriptor.routes")
    backend_entries = require_list(backend.get("routes"), "backend route export.routes")
    backend_pairs: set[tuple[str, str]] = set()
    for route in backend_entries:
        if not isinstance(route, dict):
            raise CompatibilityError("backend route entry must be an object")
        path = normalized_backend_path(require_string(route.get("path"), "backend route.path"), base_path)
        for method in require_list(route.get("methods"), f"backend route {path}.methods"):
            backend_pairs.add((path, require_string(method, f"backend route {path}.method")))

    required_pairs: set[tuple[str, str]] = set()
    for route in route_entries:
        if not isinstance(route, dict):
            raise CompatibilityError("runner route descriptor entry must be an object")
        route_id = require_string(route.get("id"), "runner route.id")
        pair = (
            require_string(route.get("pathTemplate"), f"runner route {route_id}.pathTemplate"),
            require_string(route.get("method"), f"runner route {route_id}.method"),
        )
        if pair in required_pairs:
            raise CompatibilityError(f"runner route descriptor duplicates {pair[1]} {pair[0]}")
        required_pairs.add(pair)
    missing_routes = sorted(required_pairs - backend_pairs)
    if missing_routes:
        formatted = ", ".join(f"{method} {path}" for path, method in missing_routes)
        raise CompatibilityError(f"backend does not register runner-required routes: {formatted}")

    return {
        "schemaVersion": SCHEMA_VERSION,
        "components": {
            "backend": {"digest": digest(backend), "schemaVersion": BACKEND_SCHEMA_VERSION},
            "plugin": {"digest": digest(plugin), "schemaVersion": PLUGIN_SCHEMA_VERSION},
            "runner": {"digest": digest(runner_manifest), "schemaVersion": RUNNER_SCHEMA_VERSION},
            "runnerRoutes": {"digest": digest(runner_routes), "schemaVersion": "loomex.runner.backend-routes/v1"},
        },
        "verification": {
            "backendRequiredRouteCount": len(required_pairs),
            "pluginMappedMethodCount": len(plugin_methods),
            "runnerMethodCount": len(runner_method_names),
        },
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin-components", required=True, type=Path)
    parser.add_argument("--backend-routes", required=True, type=Path)
    parser.add_argument("--runner-manifest", type=Path, default=RUNNER_MANIFEST)
    parser.add_argument("--runner-routes", type=Path, default=RUNNER_ROUTES)
    parser.add_argument("--runner-catalog", type=Path, default=RUNNER_CATALOG)
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        result = verify(
            runner_manifest=load_object(args.runner_manifest, "runner manifest"),
            runner_routes=load_object(args.runner_routes, "runner route descriptor"),
            runner_catalog=load_object(args.runner_catalog, "runner method catalog"),
            plugin=load_object(args.plugin_components, "plugin component export"),
            backend=load_object(args.backend_routes, "backend route export"),
        )
    except CompatibilityError as exc:
        print(f"compatibility verification failed: {exc}", file=sys.stderr)
        return 1
    artifact = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(artifact, encoding="utf-8")
    else:
        print(artifact, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
