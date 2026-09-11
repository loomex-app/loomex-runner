#!/usr/bin/env python3
"""Build and verify the runner's deterministic compatibility manifest.

The inputs are intentionally explicit contracts.  This script never scrapes Rust
or Django source: endpoint discovery by regex would make an incidental source
formatting change alter the public compatibility result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = ROOT / "contracts" / "method-catalog.json"
ROUTES_PATH = ROOT / "contracts" / "backend-routes.json"
OUTPUT_PATH = ROOT / "contracts" / "compatibility-manifest.json"
HTTP_METHODS = {"GET", "POST", "PUT", "DELETE"}
METHOD_CLASSES = {"backend-auth", "backend-proxy", "daemon-lifecycle", "local-control"}
PATH_TEMPLATE = re.compile(
    r"^v[12]/(?:[a-z0-9-]+|\{[a-z][A-Za-z0-9]*\})(?:/(?:[a-z0-9-]+|\{[a-z][A-Za-z0-9]*\}))*?/$"
)


class ContractError(ValueError):
    pass


def fail(message: str) -> None:
    raise ContractError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path}: root must be an object")
    return value


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def require_object(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{where}: expected object")
    return value


def require_string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{where}: expected non-empty string")
    return value


def require_string_list(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        fail(f"{where}: expected non-empty strings")
    if len(set(value)) != len(value):
        fail(f"{where}: contains duplicate values")
    return value


def validate_schema(value: Any, where: str) -> None:
    schema = require_object(value, where)
    allowed = {
        "type", "properties", "required", "additionalProperties", "items", "oneOf",
        "const", "enum", "format", "minLength", "maxLength", "minimum", "minItems",
        "uniqueItems",
    }
    unknown = set(schema) - allowed
    if unknown:
        fail(f"{where}: unsupported schema keywords: {', '.join(sorted(unknown))}")
    if not set(schema) & {"type", "const", "enum", "oneOf"}:
        fail(f"{where}: schema must declare type, const, enum, or oneOf")
    if "type" in schema:
        allowed_types = {"object", "array", "string", "integer", "number", "boolean", "null"}
        declared_types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not declared_types or any(item not in allowed_types for item in declared_types) or len(set(declared_types)) != len(declared_types):
            fail(f"{where}.type: unsupported JSON Schema type")
    if "properties" in schema:
        properties = require_object(schema["properties"], f"{where}.properties")
        for name, child in properties.items():
            if not isinstance(name, str) or not name:
                fail(f"{where}.properties: invalid property name")
            validate_schema(child, f"{where}.properties.{name}")
    if "required" in schema:
        required = require_string_list(schema["required"], f"{where}.required")
        if "properties" in schema and not set(required).issubset(schema["properties"]):
            fail(f"{where}.required: references undeclared property")
    if "items" in schema:
        validate_schema(schema["items"], f"{where}.items")
    if "oneOf" in schema:
        alternatives = schema["oneOf"]
        if not isinstance(alternatives, list) or len(alternatives) < 2:
            fail(f"{where}.oneOf: expected at least two schemas")
        for index, child in enumerate(alternatives):
            validate_schema(child, f"{where}.oneOf[{index}]")
    if "enum" in schema:
        values = schema["enum"]
        if not isinstance(values, list) or not values:
            fail(f"{where}.enum: expected non-empty array")
        if len({canonical(item) for item in values}) != len(values):
            fail(f"{where}.enum: contains duplicate values")
    if "additionalProperties" in schema and not isinstance(schema["additionalProperties"], bool):
        fail(f"{where}.additionalProperties: expected boolean")
    for key in ("minLength", "maxLength", "minimum", "minItems"):
        if key in schema and (not isinstance(schema[key], int) or isinstance(schema[key], bool) or schema[key] < 0):
            fail(f"{where}.{key}: expected non-negative integer")
    if "uniqueItems" in schema and not isinstance(schema["uniqueItems"], bool):
        fail(f"{where}.uniqueItems: expected boolean")
    if "format" in schema and not isinstance(schema["format"], str):
        fail(f"{where}.format: expected string")


def validate_catalog(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if catalog.get("protocol") != "loomex.local-control/v2":
        fail("method catalog: protocol must be loomex.local-control/v2")
    require_string(catalog.get("version"), "method catalog.version")
    if not isinstance(catalog.get("maxFrameBytes"), int) or catalog["maxFrameBytes"] <= 0:
        fail("method catalog.maxFrameBytes: expected positive integer")
    capabilities = require_string_list(catalog.get("capabilities"), "method catalog.capabilities")
    methods = catalog.get("methods")
    if not isinstance(methods, list) or not methods:
        fail("method catalog.methods: expected non-empty array")
    by_name: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(methods):
        method = require_object(value, f"method catalog.methods[{index}]")
        name = require_string(method.get("name"), f"method catalog.methods[{index}].name")
        if name in by_name:
            fail(f"method catalog.methods: duplicate method {name}")
        if not isinstance(method.get("mutating"), bool) or not isinstance(method.get("idempotent"), bool):
            fail(f"method catalog.methods[{index}]: mutating and idempotent must be booleans")
        if "transportRetry" in method and method["transportRetry"] not in {"before_response_once", "never_after_send"}:
            fail(f"method catalog.methods[{index}].transportRetry: unsupported retry classification")
        validate_schema(method.get("inputSchema"), f"method catalog.methods[{index}].inputSchema")
        validate_schema(method.get("outputSchema"), f"method catalog.methods[{index}].outputSchema")
        by_name[name] = method
    # Negotiation is mandatory before capability discovery, so it is intentionally
    # not itself advertised as a `method:` capability.
    capability_methods = set(by_name) - {"protocol.negotiate"}
    declared_method_capabilities = {capability.removeprefix("method:") for capability in capabilities if capability.startswith("method:")}
    if declared_method_capabilities != capability_methods:
        missing = sorted(capability_methods - declared_method_capabilities)
        extra = sorted(declared_method_capabilities - capability_methods)
        fail(f"method catalog.capabilities: method capabilities mismatch (missing={missing}, extra={extra})")
    return by_name


def validate_routes(routes: dict[str, Any], catalog_methods: set[str]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    if routes.get("schemaVersion") != "loomex.runner.backend-routes/v1":
        fail("backend routes: unsupported schemaVersion")
    if routes.get("basePath") != "/api/v1/runner-control/runner/":
        fail("backend routes: basePath does not match runner API base")
    classes = require_string_list(routes.get("classifications"), "backend routes.classifications")
    if set(classes) != METHOD_CLASSES:
        fail("backend routes.classifications: must declare the supported classification set exactly once")
    entries = routes.get("routes")
    if not isinstance(entries, list) or not entries:
        fail("backend routes.routes: expected non-empty array")
    by_id: dict[str, dict[str, Any]] = {}
    seen_endpoints: set[tuple[str, str]] = set()
    for index, value in enumerate(entries):
        entry = require_object(value, f"backend routes.routes[{index}]")
        identifier = require_string(entry.get("id"), f"backend routes.routes[{index}].id")
        if identifier in by_id:
            fail(f"backend routes.routes: duplicate id {identifier}")
        method = require_string(entry.get("method"), f"backend routes.routes[{index}].method")
        template = require_string(entry.get("pathTemplate"), f"backend routes.routes[{index}].pathTemplate")
        source = require_string(entry.get("source"), f"backend routes.routes[{index}].source")
        if method not in HTTP_METHODS:
            fail(f"backend routes.routes[{index}].method: unsupported HTTP method")
        if not PATH_TEMPLATE.fullmatch(template):
            fail(f"backend routes.routes[{index}].pathTemplate: invalid route template")
        if not re.fullmatch(r"src/[a-z_]+\.rs", source) or not (ROOT / source).is_file():
            fail(f"backend routes.routes[{index}].source: expected existing runner source file")
        endpoint = (method, template)
        if endpoint in seen_endpoints:
            fail(f"backend routes.routes: duplicate endpoint {method} {template}")
        seen_endpoints.add(endpoint)
        by_id[identifier] = entry
    bindings = routes.get("methodBindings")
    if not isinstance(bindings, list) or not bindings:
        fail("backend routes.methodBindings: expected non-empty array")
    by_method: dict[str, dict[str, Any]] = {}
    route_references: Counter[str] = Counter()
    for index, value in enumerate(bindings):
        binding = require_object(value, f"backend routes.methodBindings[{index}]")
        method = require_string(binding.get("method"), f"backend routes.methodBindings[{index}].method")
        classification = require_string(binding.get("classification"), f"backend routes.methodBindings[{index}].classification")
        raw_route_ids = binding.get("routeIds")
        if not isinstance(raw_route_ids, list):
            fail(f"backend routes.methodBindings[{index}].routeIds: expected array")
        route_ids = require_string_list(raw_route_ids, f"backend routes.methodBindings[{index}].routeIds") if raw_route_ids else []
        if method in by_method:
            fail(f"backend routes.methodBindings: duplicate method {method}")
        if method not in catalog_methods:
            fail(f"backend routes.methodBindings: unknown catalog method {method}")
        if classification not in METHOD_CLASSES:
            fail(f"backend routes.methodBindings[{index}].classification: unknown classification")
        if classification in {"backend-auth", "backend-proxy"} and not route_ids:
            fail(f"backend routes.methodBindings[{index}]: backend methods need a route")
        if classification in {"daemon-lifecycle", "local-control"} and route_ids:
            fail(f"backend routes.methodBindings[{index}]: local methods cannot declare backend routes")
        for route_id in route_ids:
            if route_id not in by_id:
                fail(f"backend routes.methodBindings[{index}]: unknown route {route_id}")
            route_references[route_id] += 1
        by_method[method] = {"classification": classification, "routeIds": route_ids}
    if set(by_method) != catalog_methods:
        fail(f"backend routes.methodBindings: catalog coverage mismatch (missing={sorted(catalog_methods-set(by_method))}, extra={sorted(set(by_method)-catalog_methods)})")
    daemon_ids = require_string_list(routes.get("daemonRouteIds"), "backend routes.daemonRouteIds")
    for route_id in daemon_ids:
        if route_id not in by_id:
            fail(f"backend routes.daemonRouteIds: unknown route {route_id}")
        route_references[route_id] += 1
    if set(route_references) != set(by_id):
        fail(f"backend routes: unclassified routes {sorted(set(by_id)-set(route_references))}")
    return by_id, by_method


def build(catalog: dict[str, Any], routes: dict[str, Any]) -> dict[str, Any]:
    methods = validate_catalog(catalog)
    route_entries, bindings = validate_routes(routes, set(methods))
    manifest_methods = []
    for name in sorted(methods):
        method = methods[name]
        binding = bindings[name]
        manifest_methods.append({
            "name": name,
            "mutating": method["mutating"],
            "idempotent": method["idempotent"],
            "classification": binding["classification"],
            "routeIds": sorted(binding["routeIds"]),
            "transportRetry": method.get("transportRetry", "before_response_once"),
            "inputSchemaDigest": digest(method["inputSchema"]),
            "outputSchemaDigest": digest(method["outputSchema"]),
        })
    manifest_routes = [
        {"id": identifier, "method": route["method"], "pathTemplate": route["pathTemplate"], "source": route["source"]}
        for identifier, route in sorted(route_entries.items())
    ]
    counts = Counter(method["classification"] for method in manifest_methods)
    return {
        "schemaVersion": "loomex.runner.compatibility-manifest/v1",
        "protocol": catalog["protocol"],
        "catalogVersion": catalog["version"],
        "maxFrameBytes": catalog["maxFrameBytes"],
        "generatedFrom": {
            "methodCatalog": {"path": "contracts/method-catalog.json", "digest": digest(catalog)},
            "backendRoutes": {"path": "contracts/backend-routes.json", "digest": digest(routes)},
        },
        "capabilities": sorted(catalog["capabilities"]),
        "methods": manifest_methods,
        "routes": manifest_routes,
        "summary": {
            "methodCount": len(manifest_methods),
            "capabilityCount": len(catalog["capabilities"]),
            "backendRouteCount": len(manifest_routes),
            "methodClassifications": dict(sorted(counts.items())),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=CATALOG_PATH)
    parser.add_argument("--routes", type=Path, default=ROUTES_PATH)
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH)
    parser.add_argument("--check", action="store_true", help="fail when output differs from the generated manifest")
    parser.add_argument(
        "--check-package-root",
        type=Path,
        help="fail when an extracted package does not retain this generated manifest",
    )
    args = parser.parse_args()
    try:
        rendered = json.dumps(build(load_json(args.catalog), load_json(args.routes)), sort_keys=True, indent=2) + "\n"
        if args.check:
            try:
                existing = args.output.read_text()
            except OSError as exc:
                fail(f"cannot read generated manifest {args.output}: {exc}")
            if existing != rendered:
                fail(f"generated manifest is stale: run {Path(__file__).name}")
        if args.check_package_root:
            packaged = args.check_package_root / "metadata" / "compatibility-manifest.json"
            try:
                existing = packaged.read_text()
            except OSError as exc:
                fail(f"cannot read packaged compatibility manifest {packaged}: {exc}")
            if existing != rendered:
                fail(f"packaged compatibility manifest is stale: {packaged}")
        else:
            if not args.check:
                args.output.write_text(rendered)
    except ContractError as exc:
        print(f"compatibility export failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
