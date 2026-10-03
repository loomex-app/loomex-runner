#!/usr/bin/env python3
"""BUILD-PATH01: small compiler fixtures; no runner/package artifact build."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
BUILDER = (ROOT / 'scripts/build-release.sh').read_text()


def builder_flags(spelled_source):
    # Execute the actual owner's post-snapshot flag block, with existing flags
    # retained. HOME is read normally; no environment identity is replaced.
    section = BUILDER.split('feedback_tool="$build_root/scripts/build-feedback.py"\n', 1)[1].split('\n(cd "$build_root"', 1)[0]
    result = subprocess.run(['/bin/bash', '-c', 'set -euo pipefail\nbuild_root="$1"\n' + section + '\nprintf "%s\\0%s\\0%s" "$canonical_build_root" "$remap_flags" "$remap_cflags"', 'fixture', str(spelled_source)],
                            env={**os.environ, 'RUSTFLAGS': '--cfg=loomex_path_fixture', 'CFLAGS': '-DLOOMEX_PATH_FIXTURE=1'},
                            check=True, capture_output=True)
    canonical, rust, c = result.stdout.decode().split('\0')
    return Path(canonical), rust, shlex.split(c)


class BuildPathRemapTests(unittest.TestCase):
    def fixture(self, directory):
        physical = Path(directory).resolve()
        source = physical / 'actual/source'
        source.mkdir(parents=True)
        (physical / 'spelled').symlink_to(physical / 'actual', target_is_directory=True)
        spelled = physical / 'spelled/source'
        self.assertTrue(source != spelled)
        canonical, rustflags, cflags = builder_flags(spelled)
        self.assertTrue(canonical == source.resolve(), 'builder must use actual snapshot directory')
        self.assertTrue('--cfg=loomex_path_fixture' in rustflags)
        self.assertTrue('-DLOOMEX_PATH_FIXTURE=1' in cflags)
        return physical, source, spelled, rustflags, cflags

    def test_pinned_rust_reproduces_canonical_leak_and_remaps_only_exact_source(self):
        with tempfile.TemporaryDirectory() as directory:
            physical, source, spelled, fixed_flags, _ = self.fixture(directory)
            (source / 'src').mkdir()
            (source / 'Cargo.toml').write_text('[package]\nname="path_fixture"\nversion="0.0.0"\nedition="2024"\n')
            (source / 'src/location.rs').write_text('fn source_location() -> &' + "'static str { file!() }\n")
            unrelated = physical / 'outside.rs'
            unrelated.write_text('fn outside_location() -> &' + "'static str { file!() }\n")
            (source / 'src/main.rs').write_text('include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/location.rs"));\ninclude!(' + json.dumps(str(unrelated)) + ');\nfn main() { println!("{}\\n{}", source_location(), outside_location()); }\n')
            for label, flags in [('before', f'--remap-path-prefix={spelled}=/loomex/src'), ('after', fixed_flags)]:
                output_dir = physical / label
                result = subprocess.run(['cargo', '+1.88.0', 'build', '--offline'], cwd=spelled,
                    env={**os.environ, 'RUSTFLAGS': flags, 'CARGO_TARGET_DIR': str(output_dir)}, capture_output=True)
                self.assertTrue(result.returncode == 0, 'small pinned Rust fixture must compile')
                binary = output_dir / 'debug/path_fixture'
                output = subprocess.run([str(binary)], check=True, capture_output=True).stdout.decode().splitlines()
                content = binary.read_bytes()
                if label == 'before':
                    self.assertTrue(str(source) in output[0], 'old lexical-only remap must reproduce canonical source leak')
                    self.assertTrue(str(source).encode() in content, 'canonical source leak must exist in old binary bytes')
                else:
                    self.assertTrue(output[0] == '/loomex/src/src/location.rs')
                    self.assertTrue(str(source).encode() not in content, 'fixed binary must omit actual source prefix')
                    self.assertTrue(str(spelled).encode() not in content, 'fixed binary must omit lexical source prefix')
                    self.assertTrue(output[1] == str(unrelated), 'unrelated source locations must remain visible')

    def test_c_compiler_remaps_both_source_spellings(self):
        with tempfile.TemporaryDirectory() as directory:
            physical, source, spelled, _, flags = self.fixture(directory)
            location = source / 'location.c'
            location.write_text('#include <stdio.h>\nint main(void) { puts(__FILE__); }\n')
            for label, argument in [('canonical', location), ('lexical', spelled / 'location.c')]:
                binary = physical / label
                subprocess.run(['/usr/bin/cc', *flags, str(argument), '-o', str(binary)], check=True, capture_output=True)
                observed = subprocess.run([str(binary)], check=True, capture_output=True).stdout.decode().strip()
                self.assertTrue(observed == '/loomex/src/location.c')

    @unittest.skipUnless(sys.platform == 'darwin', 'native macOS /var path alias')
    def test_native_macos_var_alias_uses_physical_snapshot_root(self):
        with tempfile.TemporaryDirectory(dir='/var/tmp') as directory:
            real = Path(directory).resolve()
            self.assertTrue(str(real).startswith('/private/var/'), 'macOS fixture must exercise native temporary source spelling')
            lexical = Path(str(real).removeprefix('/private'))
            (lexical / 'source').mkdir()
            canonical, _, _ = builder_flags(lexical / 'source')
            self.assertTrue(canonical == real / 'source')

    def test_payload_gate_refuses_either_source_prefix_without_reporting_private_paths(self):
        marker = 'python3 - "$payload" "${HOME:?}" "$build_root" "$canonical_build_root" <<\'PY\'\n'
        guard = BUILDER.split(marker, 1)[1].split('\nPY', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            physical, source, spelled, _, _ = self.fixture(directory)
            payload = physical / 'payload'
            payload.mkdir()
            for leaked in [source, spelled]:
                (payload / 'fixture').write_text(str(leaked) + '/src/location.rs')
                result = subprocess.run([sys.executable, '-c', guard, str(payload), '/fixture/home', str(spelled), str(source)], capture_output=True)
                self.assertTrue(result.returncode != 0, 'source leakage must fail package gate')
                self.assertTrue(b'payload embeds build source path: fixture' in result.stderr)
                self.assertTrue(str(leaked).encode() not in result.stderr)
            (payload / 'fixture').write_text('/loomex/src/src/location.rs')
            result = subprocess.run([sys.executable, '-c', guard, str(payload), '/fixture/home', str(spelled), str(source)], capture_output=True)
            self.assertTrue(result.returncode == 0)


if __name__ == '__main__':
    unittest.main()
