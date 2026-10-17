#!/usr/bin/env python3
"""Validate real runner delivery projections against the canonical pinned schemas.

Run with a Python environment providing jsonschema (the backend venv does).
All runner state is temporary; no daemon, native host, or installed package is used.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT.parent / "plugin"
NAMES = ("presentation.delivery.get", "presentation.delivery.begin", "presentation.delivery.settle")


class ContinuationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        catalog = json.loads((ROOT / "contracts/method-catalog.json").read_text())
        cls.schemas = {m["name"]: m["outputSchema"] for m in catalog["methods"] if m["name"] in NAMES}
        cls.validators = {name: Draft202012Validator(schema, format_checker=FormatChecker()) for name, schema in cls.schemas.items()}
        with tempfile.TemporaryDirectory() as temp:
            fixture = Path(temp) / "projection.json"
            env = dict(os.environ, LOOMEX_DELIVERY_CONTRACT_FIXTURE=str(fixture))
            result = subprocess.run(["cargo", "test", "--test", "continuation_contract", "--", "--nocapture"], cwd=ROOT, env=env, capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
            cls.projections = json.loads(fixture.read_text())

    def test_actual_runner_projections_and_legacy_reads(self):
        for name, validator in self.validators.items():
            for projection in self.projections:
                with self.subTest(method=name, status=projection["status"], resolution=projection["resolution"]["state"]):
                    validator.validate(projection)
                    legacy = {k: v for k, v in projection.items() if k not in ("resolution", "continuationEligible")}
                    validator.validate(legacy)
                    self.assertNotIn("resolution", self.schemas[name]["oneOf"][0]["required"])
                    self.assertNotIn("continuationEligible", self.schemas[name]["oneOf"][0]["required"])

    def test_resolution_rejects_malformed_receipts(self):
        retired = self.projections[-1]
        mutations = [
            lambda p: p.update(resolution={"state":"retired_by_owner"}),
            lambda p: p["resolution"].update(receiptId="not-a-uuid"),
            lambda p: p["resolution"].update(idempotencyKey="not-a-uuid"),
            lambda p: p["resolution"].update(resolvedAt=-1),
            lambda p: p["resolution"].update(schemaVersion="wrong"),
            lambda p: p["resolution"].update(state="superseded_by_verified_successor"),
            lambda p: p["resolution"]["candidate"].update(recordDigest="invalid"),
            lambda p: p["resolution"]["candidate"].update(kind="follow_session"),
            lambda p: p["resolution"]["candidate"].update(installationId="unexpected"),
            lambda p: p["resolution"]["candidate"].update(generation=1),
            lambda p: p["resolution"]["candidate"]["backendObservation"].update(terminal="true"),
            lambda p: p["resolution"]["evidence"].update(reasonCode="unverified"),
            lambda p: p["resolution"]["evidence"].update(extra=True),
            lambda p: p.update(resolution={"state":"unresolved", "receiptId":"unexpected"}),
            lambda p: p.update(continuationEligible="false"),
        ]
        for name, validator in self.validators.items():
            for index, mutate in enumerate(mutations):
                with self.subTest(method=name, mutation=index):
                    invalid = copy.deepcopy(retired)
                    mutate(invalid)
                    self.assertFalse(validator.is_valid(invalid))
        # The second closed variant has its own required evidence contract.
        terminal = copy.deepcopy(retired)
        terminal["resolution"].update(state="verified_terminal", evidence={"runId":terminal["continuation"]["runId"], "observationDigest":"a"*64})
        for validator in self.validators.values():
            validator.validate(terminal)
            malformed = copy.deepcopy(terminal)
            malformed["resolution"]["evidence"]["observationDigest"] = "invalid"
            self.assertFalse(validator.is_valid(malformed))

    def test_export_and_pins_do_not_diverge(self):
        self.assertEqual(len(self.schemas), 3)
        self.assertTrue(all(schema == self.schemas[NAMES[0]] for schema in self.schemas.values()))
        pin = json.loads((PLUGIN / "contracts/contract-pin.json").read_text())
        self.assertEqual(pin["version"], "1.2.9")
        for filename in ("method-catalog.json", "compatibility-manifest.json"):
            self.assertEqual((ROOT / "contracts" / filename).read_bytes(), (PLUGIN / "contracts" / filename).read_bytes())
        for filename, expected in pin["files"].items():
            self.assertEqual(hashlib.sha256((PLUGIN / "contracts" / filename).read_bytes()).hexdigest(), expected)
            self.assertEqual(hashlib.sha256((ROOT / "contracts" / filename).read_bytes()).hexdigest(), pin["runnerContractSha256"][filename])
        result = subprocess.run(["python3", str(ROOT / "scripts/export-compatibility.py"), "--check"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
