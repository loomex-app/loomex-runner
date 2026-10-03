#!/usr/bin/env python3
"""Failure feedback tests use a fake compiler; no packages are built."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('feedback', ROOT / 'scripts/build-feedback.py')
feedback = importlib.util.module_from_spec(spec)
spec.loader.exec_module(feedback)


class BuildFeedbackTests(unittest.TestCase):
    def test_logs_redact_secret_assignments_and_build_paths(self):
        with mock.patch.dict(os.environ, {'HOME': '/private/home-fixture', 'LOOMEX_BUILD_TEMP': '/private/build-fixture', 'FIXTURE_TOKEN': 'sentinel-secret'}):
            clean = feedback.sanitize('Bearer value token=other sentinel-secret /private/home-fixture /private/build-fixture')
            for forbidden in ('value', 'other', 'sentinel-secret', '/private/home-fixture', '/private/build-fixture'):
                self.assertNotIn(forbidden, clean)

    def test_failure_records_streamed_output_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / 'target/debug/build/fixture/out/generated.rs'
            output.parent.mkdir(parents=True)
            output.write_bytes(b'fixture dependency output')
            subprocess.run([sys.executable, str(ROOT / 'scripts/build-feedback.py'), 'failure', str(root), '17'], check=True)
            record = json.loads((root / 'failure-evidence.json').read_text())
            self.assertEqual(record['exitCode'], 17)
            self.assertEqual(record['dependencyOutputs'][0]['sha256'], hashlib.sha256(output.read_bytes()).hexdigest())

    def test_builder_retains_failure_only_when_requested_and_does_not_skip_test_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / 'repo'
            scripts = repo / 'scripts'
            scripts.mkdir(parents=True)
            (repo / 'Cargo.toml').write_text('[package]\nversion = "1.2.3"\n')
            for name in ('build-release.sh', 'build-feedback.py'):
                shutil.copyfile(ROOT / 'scripts' / name, scripts / name)
            # Only the immutable-snapshot interface is stubbed. A failure at the
            # mandatory test gate proves the production builder stops there.
            (scripts / 'artifact.py').write_text('''import json, pathlib, shutil, sys
args=sys.argv
assert args[1] == "source-manifest"
snapshot=pathlib.Path(args[args.index("--snapshot")+1]); snapshot.mkdir()
(snapshot/"scripts").mkdir()
shutil.copyfile(pathlib.Path(__file__).parent/"build-feedback.py", snapshot/"scripts/build-feedback.py")
pathlib.Path(args[args.index("--output")+1]).write_text("{}")
''')
            commands = root / 'commands'
            commands.mkdir()
            cargo = commands / 'cargo'
            cargo.write_text('#!/bin/sh\nprintf "token=fixture-secret\\n"\nprintf "%s\\n" "$*" >> "$FIXTURE_CALLS"\nexit 17\n')
            cargo.chmod(0o700)
            environment = {**os.environ, 'PATH': str(commands) + os.pathsep + os.environ['PATH'], 'FIXTURE_CALLS': str(root / 'calls')}
            retained = root / 'retained'
            result = subprocess.run(['/bin/bash', str(scripts / 'build-release.sh'), '--unsigned-development', '--output', str(root / 'never-package'), '--retain-failure-workspace', str(retained)], env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 17, result.stderr)
            self.assertEqual((root / 'calls').read_text().strip(), 'test --locked')
            self.assertFalse((root / 'never-package').exists())
            self.assertTrue((retained / 'source-content-manifest.json').exists())
            self.assertIn('<redacted>', (retained / 'build.log').read_text())
            self.assertNotIn('fixture-secret', (retained / 'build.log').read_text())
            self.assertEqual(json.loads((retained / 'invocations.jsonl').read_text())['argv'], ['cargo', 'test', '--locked'])
            self.assertEqual(json.loads((retained / 'failure-evidence.json').read_text())['exitCode'], 17)
            self.assertEqual(retained.stat().st_mode & 0o777, 0o700)
            refused = subprocess.run(['/bin/bash', str(scripts / 'build-release.sh'), '--unsigned-development', '--retain-failure-workspace', str(retained)], env=environment, capture_output=True, text=True)
            self.assertEqual(refused.returncode, 1)
            self.assertEqual((root / 'calls').read_text().strip(), 'test --locked')
            result = subprocess.run(['/bin/bash', str(scripts / 'build-release.sh'), '--unsigned-development', '--output', str(root / 'never-package')], env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 17)
            self.assertNotIn('retained:', result.stderr)

    def test_fast_path_is_explicitly_separate_from_distribution_evidence(self):
        script = (ROOT / 'scripts/build-dev-fast.sh').read_text()
        self.assertIn('FAST LOCAL DEVELOPMENT', script)
        self.assertIn('cargo +1.88.0 build --locked', script)
        self.assertNotIn('build-release.sh', script)
        immutable = (ROOT / 'scripts/build-release.sh').read_text()
        for gate in ('source-manifest', 'verify-source', 'cargo test --locked', 'export-compatibility.py" --check', 'validate_package.py'):
            self.assertIn(gate, immutable)


if __name__ == '__main__':
    unittest.main()
