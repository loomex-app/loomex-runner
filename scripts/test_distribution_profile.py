#!/usr/bin/env python3
"""Development distribution remains optimized and development classified."""
from pathlib import Path
import tomllib
import unittest
import json
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent


class DistributionProfileTests(unittest.TestCase):
    def test_profile_preserves_development_guards(self):
        profile = tomllib.loads((ROOT / "Cargo.toml").read_text())["profile"]["distribution-dev"]
        self.assertEqual(profile, {
            "inherits": "dev", "opt-level": 2, "debug-assertions": True,
            "overflow-checks": True, "debug": 1, "incremental": False,
        })
        self.assertNotIn("panic", profile)

    def test_development_packages_matching_profile_outputs(self):
        script = (ROOT / "scripts/build-release.sh").read_text()
        development = script.split('unsigned development artifact requires a macOS arm64 host', 1)[1].split('fi\npayload=', 1)[0]
        self.assertIn("cargo build --locked --profile distribution-dev", development)
        self.assertIn('binary_root="$temporary/target/distribution-dev"', development)
        for binary in ("loomex", "loomex-runner", "loomex-lifecycle-bootstrap"):
            self.assertIn(f"--bin {binary}", development)
            self.assertIn(f'cp "$binary_root/{binary}"', script)
        self.assertIn("cargo build --locked --release --target aarch64-apple-darwin", script)
        self.assertIn("arguments+=(--unsigned-development)", script)

    def test_diagnostics_profile_uses_cargo_output_binding(self):
        script = (ROOT / "build.rs").read_text()
        self.assertIn('env::var("OUT_DIR")', script)
        self.assertIn('env::var("OPT_LEVEL")', script)
        self.assertNotIn('env::var("PROFILE")', script)

    def test_isolated_packaging_exercises_distribution_build(self):
        script = (ROOT / "scripts/test-packaging.sh").read_text()
        self.assertIn("cargo build --locked --profile distribution-dev", script)
        self.assertNotIn("target/debug/", script)
        self.assertIn("--development-api-origin http://127.0.0.1:9", script)

    def test_optional_metadata_is_backward_compatible_and_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bin").mkdir()
            (root / "metadata").mkdir()
            for binary in ("loomex", "loomex-runner", "loomex-lifecycle-bootstrap"):
                path = root / "bin" / binary
                path.write_text("fixture")
                path.chmod(0o755)
            original = {"project": "loomex-runner", "version": "0.4.0",
                        "platform": "darwin-arm64", "stateSchema": "app.loomex.runner.state/v1"}
            build = {"profile": "distribution-dev", "optimizationLevel": "2",
                     "debugAssertions": True, "classification": "development"}
            for candidate, accepted in ((None, True), (build, True), ("explicit_null", False),
                    ({**build, "debugAssertions": False}, False),
                    ({**build, "debugAssertions": 1}, False),
                    ({**build, "profile": "release"}, False),
                    ({**build, "optimizationLevel": "0"}, False),
                    ({**build, "classification": "production"}, False)):
                metadata = dict(original)
                if candidate is not None:
                    metadata["build"] = None if candidate == "explicit_null" else candidate
                (root / "metadata/project.json").write_text(json.dumps(metadata))
                result = subprocess.run([sys.executable, str(ROOT / "scripts/validate_package.py"),
                    str(root), "--expected-version", "0.4.0"], capture_output=True, text=True)
                # The intentionally absent compatibility file is the next validation:
                # reaching it proves legacy/additive project metadata was accepted.
                expected = "runner compatibility manifest missing" if accepted else "runner build metadata mismatch"
                self.assertIn(expected, result.stderr)


if __name__ == "__main__":
    unittest.main()
