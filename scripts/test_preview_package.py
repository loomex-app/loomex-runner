#!/usr/bin/env python3
"""Cloud preview packaging is explicit, origin bound and revision controlled."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n'


class PreviewPackageTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        for name in ('bin', 'metadata', 'launchd'):
            (root / name).mkdir()
        for name in ('loomex', 'loomex-runner', 'loomex-lifecycle-bootstrap'):
            binary = root / 'bin' / name
            binary.write_text('fixture')
            binary.chmod(0o755)
        project = {'project': 'loomex-runner', 'version': '0.4.9', 'platform': 'darwin-arm64',
            'stateSchema': 'app.loomex.runner.state/v1', 'build': {'profile': 'distribution-dev',
            'optimizationLevel': '2', 'debugAssertions': True, 'classification': 'development'}}
        (root / 'metadata/project.json').write_text(canonical(project))
        shutil.copy(ROOT / 'contracts/compatibility-manifest.json', root / 'metadata')
        shutil.copy(ROOT / 'scripts/app.loomex.runner.template.plist', root / 'launchd')
        source = {'schema': 'app.loomex.source-content/v1', 'sourceRevision': 'a' * 40,
            'files': [{'path': 'Cargo.toml', 'type': 'file', 'tracked': True, 'mode': '100644',
                'size': 0, 'sha256': 'b' * 64}]}
        (root / 'metadata/source-content-manifest.json').write_text(canonical(source))
        preview = {'schema': 'app.loomex.runner.preview-origin/v1', 'apiOrigin': 'https://preview.example/',
            'sourceRevision': 'a' * 40, 'version': '0.4.9'}
        (root / 'metadata/preview-origin.json').write_text(canonical(preview))
        return root, project, source, preview

    def validate(self, root):
        return subprocess.run([sys.executable, str(ROOT / 'scripts/validate_package.py'),
            str(root), '--expected-version', '0.4.9'], capture_output=True, text=True)

    def test_matching_preview_and_legacy_development_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _, _, _ = self.fixture(directory)
            self.assertEqual(self.validate(root).returncode, 0)
            (root / 'metadata/preview-origin.json').unlink()
            self.assertEqual(self.validate(root).returncode, 0)

    def test_invalid_preview_origins_schema_and_release_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _, _, original = self.fixture(directory)
            cases = [('apiOrigin', value) for value in ('http://preview.example/', 'https://user:pass@preview.example/',
                'https://preview.example/path/', 'https://preview.example/?', 'https://preview.example/#',
                'https://preview.example', 'https://preview.example/\n', 'https://PREVIEW.example/', 'https://preview.example:443/')]
            cases += [('schema', 'wrong'), ('version', '9.9.9'), ('sourceRevision', 'not-a-revision'), ('extra', True)]
            for key, value in cases:
                with self.subTest(key=key, value=value):
                    (root / 'metadata/preview-origin.json').write_text(canonical({**original, key: value}))
                    self.assertNotEqual(self.validate(root).returncode, 0)

    def test_preview_rejects_production_metadata_and_untracked_or_missing_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root, project, source, _ = self.fixture(directory)
            del project['build']
            (root / 'metadata/project.json').write_text(canonical(project))
            self.assertIn('preview origin metadata mismatch', self.validate(root).stderr)
        for files in ([], [{'path': 'untracked', 'tracked': False, 'type': 'file', 'mode': '100644', 'size': 0, 'sha256': 'b' * 64}],
                [{'path': 'missing', 'tracked': True, 'type': 'missing'}]):
            with tempfile.TemporaryDirectory() as directory:
                root, _, source, _ = self.fixture(directory)
                (root / 'metadata/source-content-manifest.json').write_text(canonical({**source, 'files': files}))
                self.assertIn('preview requires revision-controlled source', self.validate(root).stderr)

    def test_preview_build_requires_https_before_any_build(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(['/bin/bash', str(ROOT / 'scripts/build-release.sh'), '--unsigned-cloud-preview',
                '--output', str(Path(directory) / 'output')], capture_output=True, text=True,
                env={**os.environ, 'LOOMEX_API_ORIGIN': 'http://preview.example', 'LOOMEX_WEB_APP_ORIGIN': 'https://app.example/'})
            self.assertIn('LOOMEX_API_ORIGIN must be a configured HTTPS origin', result.stderr)
            self.assertFalse((Path(directory) / 'output').exists())

    def test_release_builder_uses_clean_archived_source_and_retains_signing_gates(self):
        script = (ROOT / 'scripts/build-release.sh').read_text()
        self.assertEqual(script.count('"$mode" == "--production" || "$mode" == "--unsigned-cloud-preview"'), 2)
        self.assertIn('production and cloud preview releases require a clean source tree', script)
        self.assertIn('git -C "$repo" archive "$revision"', script)
        self.assertIn('LOOMEX_CODESIGN_IDENTITY:?production requires', script)
        self.assertIn('LOOMEX_NOTARY_PROFILE:?production requires', script)
        self.assertIn('LOOMEX_MANIFEST_SIGNING_KEY:?production requires', script)


if __name__ == '__main__':
    unittest.main()
