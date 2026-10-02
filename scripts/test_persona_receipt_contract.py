#!/usr/bin/env python3
"""Validate fixed receipt fixtures against the bounded canonical schema subset."""
import json
import re
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def matches(value, schema):
    if "oneOf" in schema:
        return sum(matches(value, branch) for branch in schema["oneOf"]) == 1
    if "const" in schema and value != schema["const"]:
        return False
    if "enum" in schema and value not in schema["enum"]:
        return False
    kind = schema.get("type")
    if kind == "object":
        if not isinstance(value, dict):
            return False
        props = schema.get("properties", {})
        if not set(schema.get("required", [])).issubset(value):
            return False
        if schema.get("additionalProperties") is False and not set(value).issubset(props):
            return False
        return all(matches(child, props[key]) for key, child in value.items() if key in props)
    if kind == "string":
        if not isinstance(value, str):
            return False
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            return False
        if schema.get("format") == "uuid":
            try:
                uuid.UUID(value)
            except ValueError:
                return False
    if kind == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
        return False
    if "minimum" in schema and value < schema["minimum"]:
        return False
    return True


class PersonaReceiptContractTests(unittest.TestCase):
    def test_discriminated_receipt_and_spool_fixtures(self):
        catalog = json.loads((ROOT / "contracts/method-catalog.json").read_text())
        schema = next(method["outputSchema"] for method in catalog["methods"]
                      if method["name"] == "personas.operations.get")
        self.assertEqual(len(schema["oneOf"]), 4)
        for branch, status in zip(schema["oneOf"], ("not_found", "processing", "completed")):
            self.assertEqual(branch["properties"]["status"], {"const": status})
            self.assertFalse(branch["additionalProperties"])
            self.assertEqual(set(branch["required"]), set(branch["properties"]))
        fixtures = json.loads((ROOT / "tests/fixtures/persona-operation-receipt-v1.json").read_text())
        for value in fixtures["valid"]:
            self.assertTrue(matches(value, schema), value)
        for value in fixtures["invalid"]:
            self.assertFalse(matches(value, schema), value)


if __name__ == "__main__":
    unittest.main()
