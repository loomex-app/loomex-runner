#!/usr/bin/env python3
"""Contract checks for the production release's required integration gate."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


class ReleaseWorkflowContractTests(unittest.TestCase):
    def test_production_release_requires_immutable_component_inputs(self):
        text = WORKFLOW.read_text(encoding="utf-8")

        for name in ("plugin_repository", "plugin_ref", "backend_repository", "backend_ref"):
            match = re.search(rf"(?ms)^      {name}:$(.*?)(?=^      \w+:|\Z)", text)
            self.assertIsNotNone(match)
            section = match.group(1)
            self.assertIn("required: true", section)
            self.assertIn("type: string", section)

        self.assertIn("name: Required plugin/backend compatibility gate", text)
        self.assertIn("needs: compatibility", text)
        self.assertIn("--required", text)
        self.assertIn("--plugin-root component-inputs/plugin", text)
        self.assertIn("--backend-root component-inputs/backend", text)
        self.assertIn("LOOMEX_COMPONENT_READ_TOKEN", text)
        self.assertIn('test "${PLUGIN_REPOSITORY%%/*}" = "loomex-app"', text)
        self.assertIn('test "${BACKEND_REPOSITORY%%/*}" = "loomex-app"', text)

    def test_release_identity_checks_are_fail_closed(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', text)
        self.assertIn('git status --porcelain=v1 --untracked-files=all', text)
        self.assertIn('[[ "$PLUGIN_REF" =~ ^[0-9a-f]{40}$ ]]', text)
        self.assertIn('[[ "$BACKEND_REF" =~ ^[0-9a-f]{40}$ ]]', text)


if __name__ == "__main__":
    unittest.main()
