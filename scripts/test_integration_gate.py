#!/usr/bin/env python3
"""Portable invocation coverage for the optional cross-component gate."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / "scripts" / "run-integration-compatibility-gate.sh"


class IntegrationGateTests(unittest.TestCase):
    def test_skips_without_artifacts_or_checkout_roots(self) -> None:
        result = subprocess.run([str(GATE)], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("skipped", result.stdout)

    def test_rejects_one_sided_artifact_configuration(self) -> None:
        result = subprocess.run(
            [str(GATE), "--plugin-components", "/tmp/not-a-component.json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
