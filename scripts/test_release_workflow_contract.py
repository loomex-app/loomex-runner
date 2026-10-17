#!/usr/bin/env python3
"""Contract checks for the production release's required integration gate."""

from pathlib import Path
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
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
        self.assertIn("--plugin-root ../component-inputs/plugin", text)
        self.assertIn("--backend-root ../component-inputs/backend", text)
        self.assertIn("LOOMEX_COMPONENT_READ_TOKEN", text)
        self.assertIn('test "${PLUGIN_REPOSITORY%%/*}" = "loomex-app"', text)
        self.assertIn('test "${BACKEND_REPOSITORY%%/*}" = "loomex-app"', text)

    def test_component_checkouts_are_outside_clean_runner_source(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("path: runner-source", text)
        self.assertIn("working-directory: runner-source", text)
        self.assertIn("path: component-inputs/plugin", text)
        self.assertIn("--plugin-root ../component-inputs/plugin", text)
        self.assertIn("--backend-root ../component-inputs/backend", text)

    def test_release_identity_checks_are_fail_closed(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', text)
        self.assertIn('git status --porcelain=v1 --untracked-files=all', text)
        self.assertIn('[[ "$PLUGIN_REF" =~ ^[0-9a-f]{40}$ ]]', text)
        self.assertIn('[[ "$BACKEND_REF" =~ ^[0-9a-f]{40}$ ]]', text)

    def test_public_development_candidate_requires_existing_approved_signer(self):
        text=(ROOT/'.github/workflows/preview-release.yml').read_text()
        self.assertIn('LOOMEX_DEVELOPMENT_CODESIGN_IDENTITY: ${{ vars.LOOMEX_DEVELOPMENT_CODESIGN_IDENTITY }}',text)
        self.assertIn('["approved_development_signer"](require_identity=True)',text)
        self.assertLess(text.index('name: Require the approved persistent development signer'),text.index('name: Build plugin'))
        self.assertNotIn('security import',text)
        self.assertNotIn('security create-keychain',text)
        self.assertIn('toolchain: 1.88.0',text)
        self.assertIn("python-version: '3.12'",text)

    def test_public_helper_build_remaps_actual_source_and_home_in_binary(self):
        workflow=(ROOT/'.github/workflows/preview-release.yml').read_text()
        step=workflow.split('      - name: Build one self-contained native installer\n',1)[1].split('      - name:',1)[0]
        block=textwrap.dedent(step.split('        run: |\n',1)[1])
        cargo=shutil.which('cargo')
        self.assertIsNotNone(cargo,'pinned Rust helper fixture requires Cargo')
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory(prefix='loomex-helper-remap-',dir=Path.home()) as home_directory:
            physical=Path(directory).resolve();source=physical/'actual/source';source.mkdir(parents=True)
            (physical/'spelled').symlink_to(physical/'actual',target_is_directory=True)
            spelled=physical/'spelled/source';crate=source/'scripts/distribution-installer'
            (crate/'src').mkdir(parents=True)
            (crate/'Cargo.toml').write_text('[package]\nname="loomex-install"\nversion="0.0.0"\nedition="2024"\n')
            (crate/'Cargo.lock').write_text('version = 4\n\n[[package]]\nname = "loomex-install"\nversion = "0.0.0"\n')
            (crate/'src/location.rs').write_text("fn source_location() -> &'static str { file!() }\n")
            home_source=Path(home_directory)/'home.rs'
            home_source.write_text("fn home_location() -> &'static str { file!() }\n")
            (crate/'src/main.rs').write_text('include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/location.rs"));\ninclude!('+json.dumps(str(home_source))+');\nfn main() { println!("{}\\n{}\\n{}", source_location(), home_location(), cfg!(helper_remap_fixture)); }\n')
            commands=physical/'commands';commands.mkdir();record=physical/'cargo-call.json'
            # Run the workflow's actual command and environment. The wrapper
            # adapts only its Darwin target to the host for this tiny fixture.
            wrapper='#!'+sys.executable+'\n'+textwrap.dedent("""
                import json,os,shutil,subprocess,sys
                from pathlib import Path
                args=sys.argv[1:]
                Path(os.environ['HELPER_CALL_RECORD']).write_text(json.dumps({'args':args,'rust':os.environ.get('RUSTFLAGS',''),'c':os.environ.get('CFLAGS','')}))
                manifest=args[args.index('--manifest-path')+1]
                subprocess.run([__ACTUAL_CARGO__,'+1.88.0','build','--offline','--locked','--release','--manifest-path',manifest],check=True)
                target=Path(os.environ['CARGO_TARGET_DIR'])
                shipped=target/args[args.index('--target')+1]/'release/loomex-install'
                shipped.parent.mkdir(parents=True,exist_ok=True)
                shutil.copy2(target/'release/loomex-install',shipped)
            """).replace('__ACTUAL_CARGO__',repr(cargo))
            (commands/'cargo').write_text(wrapper);(commands/'cargo').chmod(0o700)
            stage=physical/'stage';stage.mkdir()
            environment={**os.environ,'PATH':str(commands)+os.pathsep+os.environ['PATH'],'RUNNER_TEMP':str(stage),'HELPER_CALL_RECORD':str(record),'RUSTFLAGS':'--cfg=helper_remap_fixture','CFLAGS':'-DHELPER_REMAP_FIXTURE=1'}
            result=subprocess.run(['/bin/bash','-c','set -euo pipefail\ncd "$1"\n'+block,'fixture',str(spelled)],cwd=physical,env=environment,capture_output=True,text=True)
            self.assertTrue(result.returncode==0,'native helper workflow fixture must compile')
            binary=stage/'loomex-install-darwin-arm64'
            observed=subprocess.run([str(binary)],check=True,capture_output=True,text=True).stdout.splitlines()
            content=binary.read_bytes()
            self.assertTrue(observed[0]=='/loomex/src/scripts/distribution-installer/src/location.rs','helper must remap actual compiler source locations')
            self.assertTrue(observed[1]=='/loomex/home/'+home_source.relative_to(Path.home()).as_posix(),'helper must remap compiler HOME locations')
            self.assertEqual(observed[2],'true','helper must preserve existing Rust flags')
            for prefix in [source,spelled,Path.home()]:
                self.assertTrue(str(prefix).encode() not in content,'native helper bytes must omit private compiler path prefixes')
            call=json.loads(record.read_text())
            self.assertEqual(call['args'],['build','--locked','--release','--target','aarch64-apple-darwin','--manifest-path','scripts/distribution-installer/Cargo.toml'])
            rustflags=shlex.split(call['rust']);cflags=shlex.split(call['c']);self.assertIn('-DHELPER_REMAP_FIXTURE=1',cflags)
            for prefix,replacement in [(source,'/loomex/src'),(spelled,'/loomex/src'),(Path.home(),'/loomex/home')]:
                self.assertIn('--remap-path-prefix='+str(prefix)+'='+replacement,rustflags)
                self.assertIn('-ffile-prefix-map='+str(prefix)+'='+replacement,cflags)

    def test_public_signing_gate_does_not_ban_unsigned_isolated_builds(self):
        text=(ROOT/'scripts/build-release.sh').read_text()
        self.assertIn('building unsigned development artifact for isolated testing only',text)
        self.assertIn('"$mode" == "--unsigned-cloud-preview" || -n "$local_origin"',text)
        self.assertIn("['qualify_development_signing'](Path(sys.argv[2]))",text)


if __name__ == "__main__":
    unittest.main()
