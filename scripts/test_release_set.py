#!/usr/bin/env python3
"""Disposable transport/delegation tests. No real runner service, account or Codex mutation."""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('release_set',ROOT/'scripts/release-set.py');pack=importlib.util.module_from_spec(spec);spec.loader.exec_module(pack)

def put(path,value,mode=0o644):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(pack.canonical(value) if isinstance(value,(dict,list)) else value.encode() if isinstance(value,str) else value)
    path.chmod(mode)
    return path

def archive(root,out):pack.artifact.deterministic_tar(root,out,0)
def file_record(path,root):return {'path':path.relative_to(root).as_posix(),'size':path.stat().st_size,'sha256':pack.sha(path),'mode':path.stat().st_mode&0o777}

def fixture(root,installer,profile=None):
    assets=root/'assets';assets.mkdir()
    tag='preview-runner-v0.5.2-plugin-v0.16.2';origin='https://api.example.test/'
    components={};contracts={}
    for kind,version,revision,repo in [('runner','0.5.2','a'*40,'loomex-app/loomex-runner'),('plugin','0.16.2','b'*40,'loomex-app/loomex-codex-plugin')]:
        envelope=root/f'{kind}-envelope';payload=root/f'{kind}-payload';envelope.mkdir();payload.mkdir()
        provenance={'schema':'app.loomex.source-content/v1','sourceRevision':revision,'files':[{'path':'fixture','type':'file','tracked':True,'mode':'100644','size':1,'sha256':'c'*64}]}
        if kind=='runner':
            put(payload/'metadata/source-content-manifest.json',provenance)
            metadata = {'schema':'app.loomex.runner.local-development-origin/v1','apiOrigin':'http://127.0.0.1:28080/','webAppOrigin':None,'sourceRevision':revision,'version':version} if profile=='local-development' else {'schema':'app.loomex.runner.preview-origin/v1','apiOrigin':origin,'sourceRevision':revision,'version':version}
            put(payload/('metadata/local-development-origin.json' if profile=='local-development' else 'metadata/preview-origin.json'),metadata)
            contracts[kind]={'protocol':'loomex.local-control/v2','fixture':kind}
            put(payload/'metadata/compatibility-manifest.json',contracts[kind])
            source_name='metadata/source-content-manifest.json';source_root=payload
            put(envelope/'loomex-lifecycle-bootstrap',r'''#!/bin/bash
set -euo pipefail
mode="$1";shift
if [[ "$mode" == uninstall-work ]]; then
 echo "$*" >> "$FIXTURE_STATE/work.log"
 echo "$FIXTURE_WORK_RESULT"
 exit "${FIXTURE_WORK_EXIT:-0}"
fi
if [[ "$mode" == recover-uninstall ]]; then
 echo recover >> "$FIXTURE_STATE/recovery.log"
 if [[ "${FIXTURE_RECOVERY_RESULT:-}" != "" ]]; then echo "$FIXTURE_RECOVERY_RESULT";exit 1;fi
 if [[ "${FIXTURE_RECOVERY_PENDING:-}" == 1 ]]; then
  echo '{"schema":"app.loomex.runner.bootstrap-activation/v1","outcome":"pending","operationId":"fixture-recovery","reasonCode":"SERVICE_STOP_PENDING","nextAction":"resume_bootstrap_uninstall"}'
 else
  /bin/rm -f "$FIXTURE_STATE/old-journal"
  echo '{"schema":"app.loomex.runner.bootstrap-activation/v1","outcome":"completed","operationId":null,"reasonCode":"RECOVERY_COMPLETED","nextAction":"install_candidate"}'
 fi
 exit 0
fi
[[ "$mode" == preflight ]]
echo runner >> "$FIXTURE_STATE/preflights.log"
echo "$*" >> "$FIXTURE_STATE/runner-preflight-args.log"
if [[ "${FIXTURE_RUNNER_PREFLIGHT_JSON:-}" != "" ]]; then echo "$FIXTURE_RUNNER_PREFLIGHT_JSON";exit "${FIXTURE_RUNNER_PREFLIGHT_EXIT:-0}";fi
if [[ "${FIXTURE_RUNNER_PREFLIGHT_FAIL:-}" == 1 ]]; then echo 'SECRET runner detail' >&2; exit 40; fi
recovery=false; old=""
while (($#)); do case "$1" in --recovery-uninstall) recovery=true;shift;; --expected-old-journal-sha256) old="$2";shift 2;; *) shift;; esac;done
status=none; owner=bootstrap_uninstall
if [[ "${FIXTURE_NATIVE_PENDING:-}" == 1 ]]; then status=pending;owner=native;fi
if [[ -f "$FIXTURE_STATE/old-journal" ]]; then
 [[ "$recovery" == true && "$old" == "$(/bin/cat "$FIXTURE_STATE/old-journal")" ]] || exit 46
 status=pending
fi
echo '{"schema":"app.loomex.runner.install-preflight/v1","artifact":{"eligible":true},"activation":{"eligible":true},"recoveryEligibility":{"eligible":true,"readOnly":true},"recoveryOwnership":{"status":"'"$status"'","owner":"'"$owner"'"}}'
''',0o755)
            side=envelope/'loomex-lifecycle-bootstrap';bootstrap={'file':side.name,'sha256':pack.sha(side),'size':side.stat().st_size}
            put(envelope/'scripts/install.sh',r'''#!/bin/bash
set -euo pipefail
release="$1"; shift
echo "$*" >> "$FIXTURE_STATE/runner-args.log"
if [[ "${FIXTURE_ACTIVATION:-}" != "" ]]; then
  echo "${FIXTURE_ACTIVATION}"
  exit "${FIXTURE_ACTIVATION_EXIT:-0}"
fi
base=""
while (($#)); do case "$1" in --install-base) base="$2";shift 2;; --preview-api-origin|--development-api-origin) shift 2;; *) shift;; esac; done
[[ -n "$base" ]]
if [[ ! -f "$base/installed" ]]; then
  /bin/mkdir -p "$base/current/bin"
  echo runner >> "$FIXTURE_STATE/owners.log"
  echo "$release" > "$base/installed"
  /bin/cat > "$base/current/bin/loomex" <<'STATUS'
#!/bin/bash
if [[ "${FIXTURE_HEALTH_FAIL:-}" == 1 ]]; then echo 'SECRET runner health detail' >&2;exit 55;fi
echo '{"version":"0.5.2","protocol":"loomex.local-control/v2","draining":false,"updateDeferred":false}'
STATUS
  /bin/chmod 0755 "$base/current/bin/loomex"
fi
echo '{"schema":"app.loomex.runner.bootstrap-activation/v1","outcome":"completed","operationId":null,"reasonCode":"ACTIVATION_COMPLETED","nextAction":"none"}'
''',0o755)
        else:
            put(envelope/'source-content.json',provenance)
            source_name='source-content.json';source_root=envelope
            contracts[kind]={'schemaVersion':'loomex.plugin-compatibility-components/v1','fixture':kind}
            put(envelope/'plugin-components.json',contracts[kind])
            put(payload/'plugin/package.json',{'version':version})
            runtime=put(envelope/'lifecycle-runtime/node',r'''#!/bin/bash
set -euo pipefail
shift
[[ "$1" == preflight ]]; shift
base=""; release=""; expected=""
while (($#)); do case "$1" in --install-base) base="$2";shift 2;; --release) release="$2";shift 2;; --expected-release-path) expected="$2";shift 2;; *) shift;; esac; done
echo plugin >> "$FIXTURE_STATE/preflights.log"
if [[ "${FIXTURE_PLUGIN_PREFLIGHT_JSON:-}" != "" ]]; then echo "$FIXTURE_PLUGIN_PREFLIGHT_JSON";exit "${FIXTURE_PLUGIN_PREFLIGHT_EXIT:-0}";fi
if [[ "${FIXTURE_PLUGIN_PREFLIGHT_FAIL:-}" == 1 ]]; then echo 'SECRET plugin detail' >&2; exit 41; fi
restore=false
if [[ -f "$base/pending" ]]; then
 [[ "$(/bin/cat "$base/pending")" == "${expected:-$release}" ]] || exit 44
 [[ -z "$expected" ]] || restore=true
fi
echo '{"schema":"app.loomex.plugin.install-preflight/v1","artifact":{"eligible":true},"activation":{"eligible":true},"pendingRecovery":{"cacheRestoreRequired":'"$restore"'}}'
''',0o755);manager=put(envelope/'lifecycle.mjs','// compiled fixture owner\n')
            bootstrap={role:{'file':p.relative_to(envelope).as_posix(),'sha256':pack.sha(p),'size':p.stat().st_size,'mode':p.stat().st_mode&0o777} for role,p in [('runtime',runtime),('manager',manager)]}
            put(envelope/'scripts/install.sh',r'''#!/bin/bash
set -euo pipefail
release="$1"; shift
base=""
while (($#)); do case "$1" in --install-base) base="$2";shift 2;; *) shift;; esac; done
[[ -n "$base" ]]
/bin/mkdir -p "$base"
if [[ -f "$base/pending" ]]; then [[ "$(/bin/cat "$base/pending")" == "$release" ]] || exit 44; fi
if [[ "${FIXTURE_PLUGIN_FAIL:-}" == 1 ]]; then echo "$release" > "$base/pending";exit 42;fi
if [[ ! -f "$base/installed" ]]; then echo plugin >> "$FIXTURE_STATE/owners.log";echo "$release" > "$base/installed";fi
/bin/rm -f "$base/pending"
''',0o755)
        archive(payload,envelope/'payload.tar.gz')
        manifest={'schema':'app.loomex.release/v1','project':f'loomex-{kind}','version':version,'sourceRevision':revision,'platform':'darwin-arm64','developmentOnly':True,'payload':{'file':'payload.tar.gz','sha256':pack.sha(envelope/'payload.tar.gz'),'files':[file_record(p,payload) for p in sorted(payload.rglob('*')) if p.is_file()]},'sourceContent':{'file':source_name,'sha256':pack.sha(source_root/source_name)},'bootstrap':bootstrap}
        put(envelope/'manifest.json',manifest)
        outer=assets/f'{kind}.tar.gz';archive(envelope,outer)
        components[kind]={'version':version,'sourceRevision':revision,'repository':repo,'releaseTag':tag,'manifestSha256':pack.sha(envelope/'manifest.json'),'asset':pack.asset(outer,tag)}
    evidence={'schema':'app.loomex.release-qualification/v1','sourceRevisions':{'runner':'a'*40,'plugin':'b'*40,'backend':'d'*40},'compatibility':{'schemaVersion':'loomex/compatibility-manifest/v1','verification':{'sourceRevisions':{'plugin':'b'*40,'backend':'d'*40}},'components':{k:{'digest':pack.contract_digest(v)} for k,v in contracts.items()}}}
    put(assets/'compatibility.json',evidence)
    target=assets/'loomex-install-darwin-arm64';shutil.copy2(installer,target)
    manifest={'schema':'app.loomex.release-set/v2','releaseTag':tag,'platform':'darwin-arm64','developmentOnly':True,'protocolVersion':'loomex.local-control/v2','deployment':{'profile':'cloud-preview','apiOrigin':origin},'components':components,'evidence':{'asset':pack.asset(assets/'compatibility.json',tag),'backendSourceRevision':'d'*40,'passed':True},'installer':pack.asset(target,tag)}
    if profile:
        manifest['schema']='app.loomex.release-set/v2';manifest.pop('deployment');manifest['deployment']={'profile':profile,'apiOrigin':'http://127.0.0.1:28080/' if profile=='local-development' else origin,'webAppOrigin':None}
    put(assets/'release-set.json',manifest)
    return assets,manifest

class SchemaTests(unittest.TestCase):
    def test_artifact_module_import_is_side_effect_free_and_cli_preserved(self):
        imported=subprocess.run([sys.executable,"-c",f"import importlib.util; spec=importlib.util.spec_from_file_location(\"artifact\",{str(ROOT / 'scripts/artifact.py')!r}); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); assert m.canonical({{\"a\":1}})==b'{{\"a\":1}}\\n'"],capture_output=True,text=True)
        self.assertEqual(imported.returncode,0,imported.stderr)
        help_result=subprocess.run([sys.executable,str(ROOT/"scripts/artifact.py"),"--help"],capture_output=True,text=True)
        self.assertEqual(help_result.returncode,0,help_result.stderr)
        self.assertIn("source-manifest",help_result.stdout)

    def test_output_dangling_symlink_refused_before_writes(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); output=root/"output"; target=root/"must-not-be-created"; output.symlink_to(target)
            args=type("Args",(),{"output":str(output)})()
            with self.assertRaises(ValueError): pack.package(args)
            self.assertTrue(output.is_symlink()); self.assertFalse(target.exists())

    def test_reject_schema_pair_platform_url_and_digest(self):
        # Schema validation is independent of installer execution and works on any host.
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);installer=put(p/'installer','fixture',0o755);_,m=fixture(p,installer)
            self.assertEqual(pack.validate_manifest(m),m)
            for key,value in [('platform','linux-x64'),('developmentOnly',False),('releaseTag','latest'),('schema','v0')]:
                bad=copy.deepcopy(m);bad[key]=value
                with self.assertRaises(ValueError):pack.validate_manifest(bad)
            for value in ['file:///tmp/x','https://example.test/run','https://github.com/loomex-app/loomex-runner/releases/latest/download/runner.tar.gz']:
                bad=copy.deepcopy(m);bad['components']['runner']['asset']['url']=value
                with self.assertRaises(ValueError):pack.validate_manifest(bad)
    def test_current_names_keep_exact_pair_and_hash_bindings(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);assets,m=fixture(p,put(p/'installer','fixture',0o755))
            m['releaseTag']=m['releaseTag'].removeprefix('preview-')
            for c in m['components'].values():
                c['releaseTag']=m['releaseTag']
            for a in [m['installer'],m['evidence']['asset']]+[c['asset'] for c in m['components'].values()]:
                a['url']=f"https://github.com/{pack.REPOSITORY}/releases/download/{m['releaseTag']}/{a['file']}"
            pack.validate_manifest(m)
            self.assertEqual(pack.launcher_name(m),'install.sh')
            self.assertEqual(pack.unsigned_flag(m),'--allow-unsigned-development')
            digest='a'*64;script=pack.launcher_script(m,digest)
            self.assertIn(digest,script);self.assertNotIn('preview',script)
            self.assertNotIn('/latest/',script)
            self.assertEqual(subprocess.run(['/bin/bash','-n'],input=script,text=True).returncode,0)
            notes=pack.release_notes(m,digest)
            self.assertIn('/install.sh',notes);self.assertIn('curl --fail',notes)
            self.assertIn('notarized',notes);self.assertNotIn('Unsigned development preview',notes)
            self.assertNotIn('preview',pack.offline_instructions(m,digest))
            bad=copy.deepcopy(m);bad['components']['runner']['releaseTag']='runner-v9.9.9-plugin-v0.16.2'
            with self.assertRaises(ValueError):pack.validate_manifest(bad)

    def test_regular_release_notes_distinguish_unsigned_envelope_and_persistent_native_identity(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);_,manifest=fixture(root,put(root/'installer','fixture',0o755),'local-development')
            historical=pack.release_notes(manifest,'e'*64)
            self.assertTrue(historical.startswith('Unsigned development preview for macOS ARM64 only. Not Developer ID signed or notarized. Explicit opt-in required.'))
            manifest['releaseTag']='runner-v1.2.7-plugin-v1.2.3'
            manifest['components']['runner']['version']='1.2.7';manifest['components']['plugin']['version']='1.2.3'
            digest='f'*64;notes=pack.release_notes(manifest,digest)
            classification=notes.split('\n\n',1)[0]
            self.assertIn('release envelope is unsigned',classification)
            self.assertIn('all three runner executables',classification)
            self.assertIn('persistent self-signed development identity',classification)
            self.assertIn('not Apple Developer ID signatures',classification)
            self.assertIn('not notarized',classification)
            self.assertNotIn('preview',classification.lower())
            self.assertNotIn('unsigned development builds',notes)
            self.assertIn('Live recovery, Keychain access and installation on another Mac remain unverified.',notes)
            for line in [f'Release-set SHA256: {digest}',f'Runner 1.2.7: {"a"*40}',f'Plugin 1.2.3: {"b"*40}',f'Backend qualified source: {"d"*40}','Deployment profile: local-development','API origin: http://127.0.0.1:28080/']:
                self.assertIn(line,notes)
            self.assertIn('/releases/download/runner-v1.2.7-plugin-v1.2.3/install.sh',notes)
            self.assertNotIn('/releases/latest/',notes)
            self.assertNotIn('cross-release recovery',historical)
            for text in ['existing Inspect and Reconcile actions','settled maintenance generation','pinned to their original release','approve a fresh assessment','no takeover command','Native recovery acceptance remains a separate validation step']:
                self.assertIn(text,notes)
            self.assertEqual(notes,pack.release_notes(manifest,digest))

    def test_local_deployment_is_explicit_and_loopback_only(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);_,m=fixture(p,put(p/'installer','fixture',0o755),'local-development')
            self.assertEqual(pack.validate_manifest(m),m)
            local_subdomain=copy.deepcopy(m);local_subdomain['deployment']['apiOrigin']='http://api.loomex.localhost:28080/'
            self.assertEqual(pack.validate_manifest(local_subdomain),local_subdomain)
            for origin in ['https://api.example.test/','http://example.test/','http://127.0.0.1:28080/path','http://127.0.0.1:28080/?token=x','http://user@127.0.0.1:28080/','http://127.0.0.1:28080','http://127.0.0.1:28080/\n']:
                bad=copy.deepcopy(m);bad['deployment']['apiOrigin']=origin
                with self.subTest(origin=origin), self.assertRaises(ValueError):pack.validate_manifest(bad)
            bad=copy.deepcopy(m);bad['deployment']['profile']='other'
            with self.assertRaises(ValueError):pack.validate_manifest(bad)
            bad=copy.deepcopy(m);bad['deployment']['profile']='cloud-preview'
            with self.assertRaises(ValueError):pack.validate_manifest(bad)

    def test_deployment_metadata_rejects_other_profile_origin_source_and_web(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);_,m=fixture(p,put(p/'installer','fixture',0o755),'local-development')
            payload=p/'runner-payload';component=m['components']['runner'];deployment=m['deployment']
            pack.verify_deployment(payload,component,deployment)
            path=payload/'metadata/local-development-origin.json';original=pack.read(path)
            for key,value in [('apiOrigin','http://127.0.0.1:28081/'),('webAppOrigin','http://127.0.0.1:5173/'),('version','9.9.9'),('sourceRevision','e'*40),('schema','other')]:
                put(path,{**original,key:value})
                with self.subTest(key=key),self.assertRaises(ValueError):pack.verify_deployment(payload,component,deployment)
            put(path,original);put(payload/'metadata/preview-origin.json',{})
            with self.assertRaises(ValueError):pack.verify_deployment(payload,component,deployment)

    def test_workflow_order_layout_and_no_publication(self):
        text=(ROOT/'.github/workflows/preview-release.yml').read_text()
        self.assertLess(text.index('npm run build'),text.index('run-integration-compatibility-gate.sh'))
        self.assertIn('--required',text);self.assertIn('--plugin-root ../component-inputs/plugin',text)
        self.assertIn('path: runner-source',text);self.assertNotIn('gh release create',text)
        self.assertIn('--unsigned-cloud-preview',text)
    def test_generated_artifacts_excluded_from_source_inventory(self):
        for name in ['scripts/distribution-installer/target/debug/example','scripts/__pycache__/test.pyc']:
            status=subprocess.run(['git','-C',str(ROOT),'check-ignore',name],capture_output=True)
            self.assertEqual(status.returncode,0,name)
    def test_shell_wrapper_requires_preview_and_frozen_digest(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);assets,m=fixture(p,put(p/'installer','fixture',0o755))
            text=pack.launcher_script(m,pack.sha(assets/'release-set.json'))
            self.assertIn('--allow-unsigned-preview required',text);self.assertNotIn('/latest/',text)
            self.assertNotIn('eval ',text);self.assertIn(m['installer']['sha256'],text)

class PublicSigningQualificationTests(unittest.TestCase):
    fingerprint='a'*40
    def signing_fixture(self, root):
        requirements={name:f'identifier "app.loomex.runner.{name}" and certificate leaf = H"{self.fingerprint}"' for name in pack.NATIVE_BINARIES}
        for name in pack.NATIVE_BINARIES:put(root/'bin'/name,'fixture',0o755)
        put(root/'metadata/development-signing.json',{'schema':'app.loomex.runner.development-signing/v1','requirements':requirements})
        return requirements
    def signed_command(self, requirements, *, adhoc=None, bad_requirement=None):
        def command(args,**kwargs):
            name=Path(args[-1]).name
            if '-dr' in args:
                requirement=bad_requirement if name=='loomex-runner' and bad_requirement else requirements[name]
                return subprocess.CompletedProcess(args,0,'',f'designated => {requirement}\n')
            if '-dv' in args:return subprocess.CompletedProcess(args,0,'','Signature=adhoc\n' if name==adhoc else 'Authority=Approved Local Fixture\nTeamIdentifier=not set\n')
            return subprocess.CompletedProcess(args,0,'','')
        return command
    def test_all_three_require_exact_approved_stable_signer_and_actual_metadata(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);requirements=self.signing_fixture(root)
            with patch.object(pack.subprocess,'run',side_effect=self.signed_command(requirements)) as calls:
                result=pack.qualify_development_signing(root,approved_fingerprint=self.fingerprint)
                self.assertEqual(len(calls.call_args_list),9);self.assertEqual(result['binaries'],list(pack.NATIVE_BINARIES))
            for name in pack.NATIVE_BINARIES:
                with patch.object(pack.subprocess,'run',side_effect=self.signed_command(requirements,adhoc=name)):
                    with self.subTest(name=name),self.assertRaisesRegex(ValueError,'ad-hoc'):pack.qualify_development_signing(root,approved_fingerprint=self.fingerprint)
            with patch.object(pack.subprocess,'run',side_effect=self.signed_command(requirements)):
                with self.assertRaisesRegex(ValueError,'approved persistent'):pack.qualify_development_signing(root,approved_fingerprint='b'*40)
            with patch.object(pack.subprocess,'run',side_effect=self.signed_command(requirements,bad_requirement='cdhash H"abc"')):
                with self.assertRaisesRegex(ValueError,'metadata'):pack.qualify_development_signing(root,approved_fingerprint=self.fingerprint)
            (root/'metadata/development-signing.json').unlink()
            with self.assertRaises(ValueError):pack.qualify_development_signing(root,approved_fingerprint=self.fingerprint)
    def test_public_outer_bootstrap_must_equal_the_qualified_signed_payload(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);payload=root/'payload';envelope=root/'envelope'
            requirements=self.signing_fixture(payload)
            put(envelope/'loomex-lifecycle-bootstrap','different bootstrap',0o755)
            with patch.object(pack.subprocess,'run',side_effect=self.signed_command(requirements)):
                with self.assertRaisesRegex(ValueError,'bootstrap differs'):pack.qualify_development_signing(payload,approved_fingerprint=self.fingerprint,envelope=envelope)
                shutil.copy2(payload/'bin/loomex-lifecycle-bootstrap',envelope/'loomex-lifecycle-bootstrap')
                pack.qualify_development_signing(payload,approved_fingerprint=self.fingerprint,envelope=envelope)

    def test_missing_or_adhoc_approved_signer_fails_before_host_lookup(self):
        for identity in ['', '-']:
            with patch.dict(os.environ,{'LOOMEX_DEVELOPMENT_CODESIGN_IDENTITY':identity,'LOOMEX_DEVELOPMENT_CODESIGN_FINGERPRINT':''}),patch.object(pack.subprocess,'run') as run:
                with self.assertRaisesRegex(ValueError,'approved persistent'):pack.approved_development_signer()
                run.assert_not_called()
    def test_approved_existing_identity_resolves_without_mutation(self):
        output=f'  1) {self.fingerprint.upper()} "Approved Development"\n     1 valid identities found\n'
        with patch.dict(os.environ,{'LOOMEX_DEVELOPMENT_CODESIGN_IDENTITY':'Approved Development','LOOMEX_DEVELOPMENT_CODESIGN_KEYCHAIN':'','LOOMEX_DEVELOPMENT_CODESIGN_FINGERPRINT':''}),patch.object(pack.subprocess,'run',return_value=subprocess.CompletedProcess([],0,output,'')) as run:
            self.assertEqual(pack.approved_development_signer(),self.fingerprint)
            self.assertEqual(run.call_args.args[0],['/usr/bin/security','find-identity','-p','codesigning'])

    def test_approved_available_self_signed_identity_does_not_require_apple_trust(self):
        output=f'  1) {self.fingerprint.upper()} "Approved Development" (CSSMERR_TP_NOT_TRUSTED)\n     0 valid identities found\n'
        env={'LOOMEX_DEVELOPMENT_CODESIGN_IDENTITY':'Approved Development','LOOMEX_DEVELOPMENT_CODESIGN_KEYCHAIN':'','LOOMEX_DEVELOPMENT_CODESIGN_FINGERPRINT':self.fingerprint}
        with patch.dict(os.environ,env),patch.object(pack.subprocess,'run',return_value=subprocess.CompletedProcess([],0,output,'')) as run:
            self.assertEqual(pack.approved_development_signer(require_identity=True),self.fingerprint)
            self.assertNotIn('-v',run.call_args.args[0])
        with patch.dict(os.environ,{**env,'LOOMEX_DEVELOPMENT_CODESIGN_FINGERPRINT':'b'*40}),patch.object(pack.subprocess,'run',return_value=subprocess.CompletedProcess([],0,output,'')):
            with self.assertRaisesRegex(ValueError,'differs from the approved fingerprint'):pack.approved_development_signer(require_identity=True)

    def test_artifact_verification_uses_explicit_pin_without_private_identity_lookup(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);requirements=self.signing_fixture(root)
            env={'LOOMEX_DEVELOPMENT_CODESIGN_IDENTITY':'','LOOMEX_DEVELOPMENT_CODESIGN_FINGERPRINT':self.fingerprint.upper()}
            with patch.dict(os.environ,env),patch.object(pack.subprocess,'run',side_effect=self.signed_command(requirements)) as run:
                pack.qualify_development_signing(root)
                self.assertEqual(len(run.call_args_list),9)
                self.assertTrue(all(call.args[0][0]=='/usr/bin/codesign' for call in run.call_args_list))
            with patch.dict(os.environ,env),patch.object(pack.subprocess,'run') as run:
                with self.assertRaisesRegex(ValueError,'building requires'):pack.approved_development_signer(require_identity=True)
                run.assert_not_called()
        with patch.dict(os.environ,{'LOOMEX_DEVELOPMENT_CODESIGN_IDENTITY':self.fingerprint.upper(),'LOOMEX_DEVELOPMENT_CODESIGN_FINGERPRINT':''}),patch.object(pack.subprocess,'run') as run:
            self.assertEqual(pack.approved_development_signer(),self.fingerprint)
            run.assert_not_called()

@unittest.skipUnless(sys.platform=='darwin' and os.uname().machine=='arm64','native installation transport supports macOS ARM64')
class NativeWholeCallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        custom=os.environ.get('LOOMEX_DISTRIBUTION_TEST_INSTALLER')
        cls.installer=Path(custom) if custom else ROOT/'scripts/distribution-installer/target/debug/loomex-install'
        if not cls.installer.is_file():
            subprocess.run(['cargo','build','--locked','--manifest-path',str(ROOT/'scripts/distribution-installer/Cargo.toml')],check=True)
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()
        self.assets,self.manifest=fixture(self.root,self.installer)
        self.state=self.root/'state';self.state.mkdir();self.bin=self.root/'bin';self.bin.mkdir()
        self.runner=self.root/'runner-install';self.plugin=self.root/'plugin-install'
        self.env=dict(os.environ,HOME=str(self.root/'home'),PATH='/usr/bin:/bin',LOOMEX_ALLOW_UNSAFE_DEV_INSTALL='1',FIXTURE_STATE=str(self.state))
    def tearDown(self):self.temp.cleanup()
    def invoke(self,flags=(),optin=True):
        cmd=[str(self.assets/'loomex-install-darwin-arm64'),'--offline',str(self.assets),'--manifest-sha256',pack.sha(self.assets/'release-set.json'),'--cache-dir',str(self.root/'cache'),'--runner-install-base',str(self.runner),'--plugin-install-base',str(self.plugin)]
        if optin:cmd+=['--allow-unsigned-preview']
        return subprocess.run(cmd+list(flags),env=self.env,capture_output=True,text=True)
    def update_manifest(self):put(self.assets/'release-set.json',self.manifest)
    def assert_no_owner(self):self.assertFalse((self.state/'owners.log').exists())
    def fake_codex(self,collision=False,fail_add=False):
        listing={'marketplaces':[{'name':'loomex-private','root':str(self.root/'unrelated') if collision else str(self.plugin),'marketplaceSource':{'sourceType':'local','source':str(self.plugin)}}]}
        installed={'installed':[{'pluginId':'loomex@loomex-private','version':'0.16.2','installed':True,'enabled':True,'source':{'source':'local','path':str(self.plugin/'current/plugin')}}]}
        put(self.bin/'codex',f'''#!/bin/bash
set -euo pipefail
echo "$*" >> "$FIXTURE_STATE/codex.log"
case "$*" in
  "plugin marketplace list --json") echo '{json.dumps(listing)}';;
  "plugin add loomex@loomex-private --json") {'exit 43' if fail_add else "echo '{}'"};;
  "plugin list --marketplace loomex-private --json") echo '{json.dumps(installed)}';;
  *) exit 45;;
esac
''',0o755)
        self.env['PATH']=f'{self.bin}:/usr/bin:/bin'
    def local_fixture(self):
        shutil.rmtree(self.assets)
        for name in ['runner-envelope','runner-payload','plugin-envelope','plugin-payload']:shutil.rmtree(self.root/name)
        self.assets,self.manifest=fixture(self.root,self.installer,'local-development')
    def test_local_profile_calls_only_existing_development_owner_option(self):
        self.local_fixture();result=self.invoke(['--runner-only']);self.assertEqual(result.returncode,0,result.stderr)
        args=(self.state/'runner-args.log').read_text()
        self.assertIn('--development-api-origin http://127.0.0.1:28080/',args);self.assertNotIn('--preview-api-origin',args)
    def test_profile_and_origin_substitution_prevents_owner_invocation(self):
        self.local_fixture()
        for profile,origin in [('cloud-preview','https://api.example.test/'),('local-development','http://127.0.0.1:28081/')]:
            self.manifest['deployment'].update(profile=profile,apiOrigin=origin);self.update_manifest()
            result=self.invoke();self.assertNotEqual(result.returncode,0);self.assert_no_owner()
    def test_local_profile_still_requires_both_unsafe_optins(self):
        self.local_fixture();self.assertNotEqual(self.invoke(optin=False).returncode,0);self.assert_no_owner()
        self.env.pop('LOOMEX_ALLOW_UNSAFE_DEV_INSTALL');self.assertNotEqual(self.invoke().returncode,0);self.assert_no_owner()

    def test_missing_codex_durable_manual_guidance(self):
        result=self.invoke();self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn(str(self.plugin),result.stdout);self.assertIn('Codex CLI is unavailable',result.stdout)
        self.assertTrue((self.runner/'installed').is_file());self.assertTrue((self.plugin/'installed').is_file())
    def test_partial_failure_then_same_path_resume_keeps_runner(self):
        self.env['FIXTURE_PLUGIN_FAIL']='1';first=self.invoke();self.assertNotEqual(first.returncode,0)
        self.assertTrue((self.runner/'installed').is_file());original=(self.plugin/'pending').read_text()
        self.env.pop('FIXTURE_PLUGIN_FAIL');self.fake_codex();second=self.invoke();self.assertEqual(second.returncode,0,second.stderr)
        self.assertEqual((self.plugin/'installed').read_text(),original)
        self.assertEqual((self.state/'owners.log').read_text().splitlines(),['runner','plugin'])
        commands=(self.state/'codex.log').read_text();self.assertIn('plugin add loomex@loomex-private --json',commands)
    def test_preview_requires_both_optins(self):
        self.assertNotEqual(self.invoke(optin=False).returncode,0);self.assert_no_owner()
        self.env.pop('LOOMEX_ALLOW_UNSAFE_DEV_INSTALL');self.assertNotEqual(self.invoke().returncode,0);self.assert_no_owner()
    def test_all_assets_verified_before_runner_only(self):
        with (self.assets/'plugin.tar.gz').open('ab') as f:f.write(b'tamper')
        result=self.invoke(['--runner-only']);self.assertNotEqual(result.returncode,0);self.assert_no_owner()
    def test_schema_platform_and_pair_rejected(self):
        self.manifest['components']['plugin']['releaseTag']='latest';self.update_manifest()
        self.assertNotEqual(self.invoke().returncode,0);self.assert_no_owner()
        self.manifest['components']['plugin']['releaseTag']=self.manifest['releaseTag'];self.manifest['platform']='linux-x64';self.update_manifest()
        self.assertNotEqual(self.invoke().returncode,0);self.assert_no_owner()
    def test_symlink_archive_rejected_before_owner(self):
        archive_path=self.assets/'plugin.tar.gz'
        with tarfile.open(archive_path,'w:gz') as tar:
            info=tarfile.TarInfo('escape');info.type=tarfile.SYMTYPE;info.linkname='/etc/passwd';tar.addfile(info)
        self.manifest['components']['plugin']['asset']=pack.asset(archive_path,self.manifest['releaseTag']);self.update_manifest()
        self.assertNotEqual(self.invoke().returncode,0);self.assert_no_owner()
    def test_wrong_qualified_pair_rejected(self):
        e=pack.read(self.assets/'compatibility.json');e['sourceRevisions']['runner']='e'*40;put(self.assets/'compatibility.json',e)
        self.manifest['evidence']['asset']=pack.asset(self.assets/'compatibility.json',self.manifest['releaseTag']);self.update_manifest()
        self.assertNotEqual(self.invoke().returncode,0);self.assert_no_owner()
    def test_installer_own_hash_is_required_offline(self):
        self.manifest['installer']['sha256']='0'*64;self.update_manifest()
        self.assertNotEqual(self.invoke().returncode,0);self.assert_no_owner()
    def test_unrelated_marketplace_and_registration_failure(self):
        self.fake_codex(collision=True);result=self.invoke();self.assertNotEqual(result.returncode,0);self.assert_no_owner()
        self.fake_codex(fail_add=True);result=self.invoke();self.assertNotEqual(result.returncode,0,result.stdout)
        self.assertTrue((self.runner/'installed').is_file());self.assertTrue((self.plugin/'installed').is_file())
        self.assertIn('runner and plugin files remain installed',result.stderr)
    def test_keychain_transition_requires_explicit_passthrough(self):
        result=self.invoke(["--runner-only"]);self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn("--authorize-keychain-transition",(self.state/"runner-args.log").read_text())
        result=self.invoke(["--runner-only","--authorize-keychain-transition"]);self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn("--authorize-keychain-transition",(self.state/"runner-args.log").read_text())

    def test_interrupted_cache_staging_can_resume_before_owner(self):
        digest=pack.sha(self.assets/"release-set.json");cache=self.root/"cache"/digest
        incoming=cache/".incoming";incoming.mkdir(parents=True)
        put(incoming/"interrupted-file",b"partial verified-copy attempt")
        result=self.invoke(["--runner-only"]);self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((incoming/"interrupted-file").exists())
        self.assertTrue((self.runner/"installed").is_file())

    def test_verify_only_has_no_cache_or_owner_mutation(self):
        result=self.invoke(["--verify-only"]);self.assertEqual(result.returncode,0,result.stderr)
        self.assert_no_owner();self.assertFalse((self.root/"cache").exists())
        self.assertFalse((self.state/"preflights.log").exists())

    def test_colliding_install_bases_rejected_before_owners_or_persistent_changes(self):
        alias=self.root/'alias';alias.symlink_to(self.root,target_is_directory=True)
        for candidate in [self.runner, self.root/'missing/../runner-install', alias/'runner-install', self.runner/'versions/nested', self.runner/'current/nested']:
            for mode in [[],['--preflight-only']]:
                result=self.invoke(['--plugin-install-base',str(candidate)]+mode)
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(json.loads(result.stderr)['phase'],'namespace-preflight')
                self.assert_no_owner();self.assertFalse((self.state/'preflights.log').exists())
                self.assertFalse((self.root/'cache').exists());self.assertFalse(self.runner.exists());self.assertFalse(self.plugin.exists())
        for name in ['versions','.lifecycle-runtime','lifecycle.json']:
            result=self.invoke(['--runner-install-base',str(self.plugin/name/'nested')])
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(json.loads(result.stderr)['phase'],'namespace-preflight')
            self.assert_no_owner();self.assertFalse((self.state/'preflights.log').exists())
            self.assertFalse((self.root/'cache').exists());self.assertFalse(self.plugin.exists())
        self.env['LOOMEX_STATE_DIR']=str(self.root/'runner-state')
        result=self.invoke(['--plugin-install-base',str(self.root/'runner-state/nested')])
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(json.loads(result.stderr)['phase'],'namespace-preflight')
        self.assert_no_owner();self.assertFalse((self.state/'preflights.log').exists())
        self.assertFalse((self.root/'runner-state').exists());self.assertFalse((self.root/'cache').exists())

    def test_missing_case_and_unicode_aliases_rejected_before_owner_invocation(self):
        probe=self.root/'NamespaceCaseProbe';probe.mkdir()
        if not (self.root/'namespacecaseprobe').exists():self.skipTest('fixture volume is case sensitive')
        pairs=[(self.root/'future-runner',self.root/'FUTURE-RUNNER'),(self.root/'future-runner',self.root/'future-runner/Versions/nested'),(self.root/'café',self.root/'café')]
        for runner,plugin in pairs:
            result=self.invoke(['--runner-install-base',str(runner),'--plugin-install-base',str(plugin),'--preflight-only'])
            self.assertNotEqual(result.returncode,0,(runner,plugin,result.stdout))
            self.assertEqual(json.loads(result.stderr)['phase'],'namespace-preflight')
            self.assert_no_owner();self.assertFalse((self.state/'preflights.log').exists())
            self.assertFalse((self.root/'cache').exists());self.assertFalse(runner.exists());self.assertFalse(plugin.exists())

    def test_external_owner_file_and_bootstrap_lock_namespaces_rejected_read_only(self):
        agents=self.root/'launch-agents'
        self.env['LOOMEX_LAUNCH_AGENTS_DIR']=str(agents)
        plist=agents/'app.loomex.runner.plist'
        anchor=self.plugin.parent/f'.{self.plugin.name}.lifecycle.bootstrap.lock'
        for option,base in [('--plugin-install-base',plist),('--plugin-install-base',plist/'nested'),('--runner-install-base',anchor),('--runner-install-base',anchor/'nested')]:
            result=self.invoke([option,str(base),'--preflight-only'])
            self.assertNotEqual(result.returncode,0,(base,result.stdout))
            self.assertEqual(json.loads(result.stderr)['phase'],'namespace-preflight')
            self.assert_no_owner();self.assertFalse((self.state/'preflights.log').exists())
            self.assertFalse((self.root/'cache').exists());self.assertFalse(agents.exists());self.assertFalse(anchor.exists())

    def test_managed_launch_agent_cannot_enter_owned_subtrees_but_unrelated_child_is_allowed(self):
        for agents in [self.plugin/'current',self.plugin/'.lifecycle-runtime',self.runner/'versions/nested',self.plugin.parent/f'.{self.plugin.name}.lifecycle.bootstrap.lock',self.root/'runner-state']:
            self.env['LOOMEX_LAUNCH_AGENTS_DIR']=str(agents)
            self.env['LOOMEX_STATE_DIR']=str(self.root/'runner-state')
            result=self.invoke(['--preflight-only'])
            self.assertNotEqual(result.returncode,0,(agents,result.stdout))
            self.assertEqual(json.loads(result.stderr)['phase'],'namespace-preflight')
            self.assert_no_owner();self.assertFalse((self.state/'preflights.log').exists())
            self.assertFalse((self.root/'cache').exists());self.assertFalse(agents.exists())
        self.env['LOOMEX_LAUNCH_AGENTS_DIR']=str(self.plugin/'unrelated-agents')
        result=self.invoke(['--preflight-only']);self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(self.plugin.exists());self.assertFalse((self.root/'cache').exists())

    def test_preflight_only_invokes_both_owners_without_cache_or_install_mutation(self):
        result=self.invoke(['--preflight-only']);self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(json.loads(result.stdout)['installedEligibilityVerified'])
        self.assertEqual((self.state/'preflights.log').read_text().splitlines(),['runner','plugin'])
        self.assert_no_owner();self.assertFalse((self.root/'cache').exists())
        self.assertFalse(self.runner.exists());self.assertFalse(self.plugin.exists())

    def test_owner_preflight_failure_happens_before_cache_or_activation(self):
        for owner in ['RUNNER','PLUGIN']:
            self.env[f'FIXTURE_{owner}_PREFLIGHT_FAIL']='1'
            result=self.invoke();self.assertNotEqual(result.returncode,0)
            report=json.loads(result.stderr)
            self.assertEqual(report['phase'],owner.lower()+'-preflight')
            self.assertEqual(report['completion']['runner'],'not-attempted')
            self.assertNotIn('SECRET',result.stderr)
            self.assert_no_owner();self.assertFalse((self.root/'cache').exists())
            self.env.pop(f'FIXTURE_{owner}_PREFLIGHT_FAIL')

    def test_plugin_failure_reports_healthy_runner_and_unconfirmed_plugin(self):
        self.env['FIXTURE_PLUGIN_FAIL']='1';result=self.invoke()
        report=json.loads(result.stderr)
        self.assertEqual(report['phase'],'plugin-activation')
        self.assertEqual(report['completion']['runner'],'healthy')
        self.assertEqual(report['completion']['plugin'],'unconfirmed')
        self.assertEqual(report['completion']['hostRegistration'],'not-attempted')

    def test_runner_health_failure_blocks_plugin_and_reports_unconfirmed_activation(self):
        self.env['FIXTURE_HEALTH_FAIL']='1';result=self.invoke()
        self.assertNotEqual(result.returncode,0)
        report=json.loads(result.stderr)
        self.assertEqual(report['phase'],'runner-health')
        self.assertEqual(report['completion']['runner'],'unconfirmed')
        self.assertEqual(report['completion']['plugin'],'not-attempted')
        self.assertFalse(self.plugin.exists());self.assertNotIn('SECRET',result.stderr)

    def test_preflight_existing_pending_cache_reuses_exact_owner_release_path(self):
        self.env['FIXTURE_PLUGIN_FAIL']='1';self.assertNotEqual(self.invoke().returncode,0)
        pending=(self.plugin/'pending').read_bytes()
        cache=self.root/'cache';before={str(p.relative_to(cache)):(p.read_bytes(),p.stat().st_mtime_ns) for p in cache.rglob('*') if p.is_file()}
        self.env.pop('FIXTURE_PLUGIN_FAIL')
        result=self.invoke(['--preflight-only']);self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((self.plugin/'pending').read_bytes(),pending)
        self.assertEqual(before,{str(p.relative_to(cache)):(p.read_bytes(),p.stat().st_mtime_ns) for p in cache.rglob('*') if p.is_file()})

    def test_verified_native_pending_preserves_operation_and_skips_health_plugin(self):
        self.env['FIXTURE_ACTIVATION']=json.dumps({'schema':'app.loomex.runner.bootstrap-activation/v1','outcome':'pending','reasonCode':'ACTIVE_WORK_PENDING','operationId':'fixture-operation','nextAction':'resume_native_operation'})
        self.env['FIXTURE_HEALTH_FAIL']='1'
        result=self.invoke();self.assertEqual(result.returncode,3,result.stderr)
        report=json.loads(result.stdout);self.assertEqual(report['schema'],'app.loomex.paired-install-result/v4')
        self.assertEqual(report['outcome'],'pending');self.assertEqual(report['operationId'],'fixture-operation')
        self.assertEqual(report['nextAction'],'resume_native_operation');self.assertFalse(self.plugin.exists())
        self.assertEqual(report['completion']['plugin'],'not-attempted')

    def test_missing_pending_cache_restores_original_path_only_on_install(self):
        for missing in ['compatibility.json','plugin/manifest.json','plugin','ALL']:
            with self.subTest(missing=missing):
                self.env['FIXTURE_PLUGIN_FAIL']='1';self.assertNotEqual(self.invoke().returncode,0)
                original=(self.plugin/'pending').read_text();cache=Path(original.strip()).parent
                if missing=='ALL':shutil.rmtree(cache)
                elif (cache/missing).is_dir():shutil.rmtree(cache/missing)
                else:(cache/missing).unlink()
                self.env.pop('FIXTURE_PLUGIN_FAIL')
                before={str(p):p.read_bytes() for p in cache.rglob('*') if p.is_file()} if cache.exists() else {}
                result=self.invoke(['--preflight-only']);self.assertEqual(result.returncode,3,result.stderr)
                self.assertEqual(json.loads(result.stdout)['nextAction'],'cache_restore_required')
                self.assertEqual(before,{str(p):p.read_bytes() for p in cache.rglob('*') if p.is_file()} if cache.exists() else {})
                result=self.invoke();self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual((self.plugin/'installed').read_text(),original)
                (self.plugin/'installed').unlink()

    def test_native_prose_or_unconfirmed_json_never_claims_pending(self):
        for result in ['SECRET native pending prose',json.dumps({'schema':'app.loomex.runner.bootstrap-activation/v1','outcome':'unconfirmed','operationId':None,'reasonCode':'ACTIVATION_UNCONFIRMED','nextAction':'inspect_lifecycle_status'})]:
            self.env['FIXTURE_ACTIVATION']=result
            response=self.invoke();self.assertEqual(response.returncode,1)
            report=json.loads(response.stderr);self.assertEqual(report['outcome'],'unconfirmed')
            self.assertFalse(self.plugin.exists());self.assertNotIn('SECRET',response.stderr)

    def test_native_unresolved_work_preserves_blocked_and_skips_plugin(self):
        self.env['FIXTURE_ACTIVATION']=json.dumps({'schema':'app.loomex.runner.bootstrap-activation/v1','outcome':'blocked','operationId':'fixture-operation','reasonCode':'MANAGED_WORK_UNRESOLVED','nextAction':'reconcile_managed_work'})
        self.env['FIXTURE_ACTIVATION_EXIT']='1'
        self.env['FIXTURE_HEALTH_FAIL']='1'
        result=self.invoke();self.assertEqual(result.returncode,1)
        report=json.loads(result.stderr)
        self.assertEqual(report['outcome'],'blocked')
        self.assertEqual(report['reasonCode'],'MANAGED_WORK_UNRESOLVED')
        self.assertEqual(report['operationId'],'fixture-operation')
        self.assertEqual(report['nextAction'],'reconcile_managed_work')
        self.assertEqual(report['phase'],'runner-activation')
        self.assertEqual(report['completion']['plugin'],'not-attempted')
        self.assertFalse(self.plugin.exists());self.assert_no_owner()

    def test_incomplete_cache_rejects_lexical_aliases_before_native_dispatch(self):
        flags=self.maintenance_fixture()
        for suffix in ['missing/../new-cache','./new-cache','new-cache/','new-cache//nested']:
            alias=str(self.root)+'/'+suffix
            result=self.invoke(flags+['--cache-dir',alias]);self.assertEqual(result.returncode,1,result.stdout)
            report=json.loads(result.stderr);self.assertEqual(report['phase'],'cache-locator-preflight');self.assertIn('canonical absolute --cache-dir',report['message'])
            self.assertFalse((self.state/'work.log').exists());self.assertFalse((self.state/'preflights.log').exists())
            self.assertFalse((self.root/'new-cache').exists());self.assertFalse((self.root/'cache').exists());self.assertFalse((self.root/'missing').exists());self.assert_no_owner()

    def test_incomplete_cache_canonical_locator_matches_native_binding(self):
        flags=self.maintenance_fixture();base=self.root/'canonical-cache';release=base/pack.sha(self.assets/'release-set.json')/'runner'
        locator=hashlib.sha256(str(release).encode()).hexdigest()
        for name in ['FIXTURE_RUNNER_PREFLIGHT_JSON','FIXTURE_WORK_RESULT']:
            value=json.loads(self.env[name]);value['maintenanceReference'].update(releasePathSha256=locator,candidateReleasePathSha256=locator);self.env[name]=json.dumps(value)
        result=self.invoke(flags+['--cache-dir',str(base)]);self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['maintenanceReference']['candidateReleasePathSha256'],locator)
        args=(self.state/'runner-preflight-args.log').read_text().splitlines()[-1].split();self.assertEqual(args[args.index('--expected-release-path')+1],str(release))
        work=(self.state/'work.log').read_text().splitlines()[-1].split();self.assertEqual(work[0],str(release));self.assertTrue(release.is_dir());self.assert_no_owner()

    def test_cache_symlink_parent_alias_cannot_be_normalized_away(self):
        flags=self.maintenance_fixture();target=self.root/'target';target.mkdir();alias=self.root/'alias';alias.symlink_to(target,target_is_directory=True)
        for path in [str(alias)+'/../escaped-cache',str(alias)+'/cache']:
            result=self.invoke(flags+['--cache-dir',path]);self.assertEqual(result.returncode,1,result.stdout)
            self.assertEqual(json.loads(result.stderr)['phase'],'cache-locator-preflight');self.assertFalse((self.state/'work.log').exists());self.assertFalse((self.state/'preflights.log').exists())
            self.assertFalse((self.root/'escaped-cache').exists());self.assertFalse((target/'cache').exists());self.assertTrue(alias.is_symlink());self.assert_no_owner()

    def test_cache_symlink_or_unexpected_entries_are_preserved(self):
        self.env['FIXTURE_PLUGIN_FAIL']='1';self.assertEqual(self.invoke().returncode,1)
        cache=Path((self.plugin/'pending').read_text().strip()).parent
        self.env.pop('FIXTURE_PLUGIN_FAIL')
        for name,kind in [('unexpected-file','file'),('unexpected-dir','dir'),('unexpected-link','symlink')]:
            path=cache/name
            if kind=='file':path.write_text('keep')
            elif kind=='dir':path.mkdir()
            else:path.symlink_to(self.root/'absent')
            result=self.invoke();self.assertEqual(result.returncode,1)
            self.assertTrue(path.exists() or path.is_symlink());self.assertFalse((self.plugin/'installed').exists())
            if kind=='dir':path.rmdir()
            else:path.unlink()

    def recovery_flags(self):return ['--recover-uninstall','--expected-old-journal-sha256','a'*64]

    def test_recovery_requires_explicit_binding_and_ordinary_install_never_cleans(self):
        put(self.state/'old-journal','a'*64)
        for flags in [[],['--recover-uninstall'],['--expected-old-journal-sha256','a'*64],['--recover-uninstall','--expected-old-journal-sha256','b'*64]]:
            result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout)
            self.assertFalse((self.state/'recovery.log').exists());self.assertFalse((self.root/'cache').exists());self.assert_no_owner()

    def test_recovery_preflights_all_owners_and_host_before_cleanup(self):
        put(self.state/'old-journal','a'*64)
        self.env['FIXTURE_PLUGIN_PREFLIGHT_FAIL']='1';result=self.invoke(self.recovery_flags())
        self.assertEqual(result.returncode,1);self.assertFalse((self.state/'recovery.log').exists())
        self.assertFalse((self.root/'cache').exists());self.env.pop('FIXTURE_PLUGIN_PREFLIGHT_FAIL')
        self.fake_codex(collision=True);result=self.invoke(self.recovery_flags())
        self.assertEqual(result.returncode,1);self.assertFalse((self.state/'recovery.log').exists())
        self.assertFalse((self.root/'cache').exists())

    def test_cleanup_completion_retry_uses_fresh_install_without_repeating_cleanup(self):
        put(self.state/'old-journal','a'*64)
        self.env['FIXTURE_ACTIVATION']='SECRET arbitrary failure';self.env['FIXTURE_ACTIVATION_EXIT']='1'
        result=self.invoke(self.recovery_flags());self.assertEqual(result.returncode,1)
        self.assertFalse((self.state/'old-journal').exists());self.assertFalse(self.plugin.exists())
        self.env.pop('FIXTURE_ACTIVATION');self.env.pop('FIXTURE_ACTIVATION_EXIT')
        result=self.invoke(self.recovery_flags());self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((self.state/'recovery.log').read_text().splitlines(),['recover'])
        self.assertTrue((self.plugin/'installed').exists())

    def test_recovery_retry_resumes_replacement_native_operation_without_uninstall(self):
        self.env['FIXTURE_NATIVE_PENDING']='1'
        result=self.invoke(self.recovery_flags());self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse((self.state/'recovery.log').exists())
        self.assertTrue((self.runner/'installed').exists());self.assertTrue((self.plugin/'installed').exists())

    def test_recovery_owner_change_preserves_original_owner_refusal_after_preflight(self):
        put(self.state/'old-journal','a'*64)
        self.env['FIXTURE_RECOVERY_RESULT']=json.dumps({'schema':'app.loomex.runner.bootstrap-activation/v1','outcome':'blocked','operationId':'fixture-recovery','reasonCode':'RECOVERY_BLOCKED','nextAction':'resume_original_uninstall_owner'})
        result=self.invoke(self.recovery_flags());self.assertEqual(result.returncode,1)
        report=json.loads(result.stderr)
        self.assertEqual(report['outcome'],'blocked')
        self.assertEqual(report['reasonCode'],'RECOVERY_BLOCKED')
        self.assertEqual(report['operationId'],'fixture-recovery')
        self.assertEqual(report['nextAction'],'resume_original_uninstall_owner')
        self.assertEqual(report['phase'],'runner-recovery')
        self.assertEqual((self.state/'preflights.log').read_text().splitlines(),['runner','plugin'])
        self.assertEqual((self.state/'recovery.log').read_text().splitlines(),['recover'])
        self.assertTrue((self.state/'old-journal').exists());self.assert_no_owner()
        self.assertFalse(self.plugin.exists());self.assertFalse((self.state/'runner-args.log').exists())

    def test_pending_cleanup_retains_operation_without_pair_activation(self):
        put(self.state/'old-journal','a'*64);self.env['FIXTURE_RECOVERY_PENDING']='1'
        result=self.invoke(self.recovery_flags());self.assertEqual(result.returncode,3,result.stderr)
        report=json.loads(result.stdout);self.assertEqual(report['operationId'],'fixture-recovery')
        self.assertEqual(report['nextAction'],'resume_bootstrap_uninstall');self.assert_no_owner()
        self.assertTrue((self.state/'old-journal').exists());self.assertFalse(self.plugin.exists())

    def work_fixture(self, action='inspect', outcome='inspected'):
        owner={'owner':'bootstrap_uninstall','journalSchema':'app.loomex.runner.bootstrap-uninstall/v1','journalSha256':'a'*64,'phase':'prepared','adoptionStarted':False}
        assessment={'schema':'app.loomex.runner.managed-state-assessment/v1','assessmentDigest':'b'*64,'resolved':False,'blockers':[{'category':'presentation_delivery_pending','count':13,'references':['c'*64]},{'category':'follow_pending','count':14,'references':['d'*64]}]}
        self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']=json.dumps({'schema':'app.loomex.runner.install-preflight/v2','artifact':{'eligible':True},'activation':{'eligible':False},'uninstallWorkEligibility':{'eligible':True},'ownerReference':owner,'assessment':assessment})
        self.env['FIXTURE_WORK_RESULT']=json.dumps({'schema':'app.loomex.runner.bootstrap-uninstall-work/v1','action':action,'outcome':outcome,'operationId':None,'ownerReference':owner,'assessment':assessment,'reasonCode':'UNINSTALL_WORK_INSPECTED' if outcome=='inspected' else 'MANAGED_WORK_UNRESOLVED','nextAction':'reconcile_managed_work'})
        flags=['--uninstall-work',action,'--expected-old-journal-sha256','a'*64]
        if action=='retire-local':flags+=['--expected-assessment-sha256','b'*64]
        return flags

    def maintenance_fixture(self, action='reconcile', outcome='completed'):
        flags=self.work_fixture(action,outcome)
        reference={'schema':'app.loomex.runner.uninstall-work-reference/v1','operationId':'11111111-1111-4111-8111-111111111111','ownerSha256':'c'*64,'journalSha256':'a'*64,'phase':'settled','generation':0,'releaseManifestSha256':self.manifest['components']['runner']['manifestSha256'],'candidateManifestSha256':self.manifest['components']['runner']['manifestSha256'],'releasePathSha256':'1'*64,'candidateReleasePathSha256':'1'*64,'attemptId':None,'transition':'current_release'}
        for name in ['FIXTURE_RUNNER_PREFLIGHT_JSON','FIXTURE_WORK_RESULT']:
            value=json.loads(self.env[name]);value['maintenanceReference']=copy.deepcopy(reference)
            if name=='FIXTURE_RUNNER_PREFLIGHT_JSON':value['artifact']['manifestSha256']=reference['candidateManifestSha256']
            if name=='FIXTURE_WORK_RESULT':
                value.update(schema='app.loomex.runner.bootstrap-uninstall-work/v2',operationId=reference['operationId'],reasonCode='UNINSTALL_WORK_COMPLETED',nextAction='reconcile_managed_work')
            self.env[name]=json.dumps(value)
        return flags

    def test_maintenance_operation_is_pinned_before_bootstrap_adoption(self):
        flags=self.maintenance_fixture()
        value=json.loads(self.env['FIXTURE_WORK_RESULT']);value['operationId']='22222222-2222-4222-8222-222222222222';value['maintenanceReference']['operationId']=value['operationId']
        self.env['FIXTURE_WORK_RESULT']=json.dumps(value)
        result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout)
        self.assertEqual(json.loads(result.stderr)['outcome'],'unconfirmed');self.assert_no_owner()

    def test_successor_requires_exact_generation_and_candidate_binding(self):
        flags=self.maintenance_fixture()
        before=json.loads(self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']);before['maintenanceReference'].update(transition='eligible_successor',releaseManifestSha256='e'*64)
        self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']=json.dumps(before)
        after=json.loads(self.env['FIXTURE_WORK_RESULT']);after['maintenanceReference'].update(generation=1,ownerSha256='f'*64);after['operationId']=after['maintenanceReference']['operationId']
        for broken in ['generation','candidateManifestSha256','operationId',None]:
            value=copy.deepcopy(after)
            if broken=='generation':value['maintenanceReference'][broken]=2
            if broken=='candidateManifestSha256':value['maintenanceReference'][broken]='e'*64
            if broken=='operationId':value['maintenanceReference'][broken]='22222222-2222-4222-8222-222222222222';value['operationId']=value['maintenanceReference'][broken]
            self.env['FIXTURE_WORK_RESULT']=json.dumps(value)
            result=self.invoke(flags);self.assertEqual(result.returncode,0 if broken is None else 1,result.stderr)
            if broken is None:
                report=json.loads(result.stdout);self.assertEqual(report['maintenanceReference']['generation'],1);self.assertFalse(report['cleanupEligible'])
        self.assert_no_owner();self.assertFalse((self.state/'runner-args.log').exists())

    def test_original_attempt_requires_native_complete_result_before_successor(self):
        flags=self.maintenance_fixture()
        before=json.loads(self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']);before['maintenanceReference'].update(transition='resume_original_attempt',phase='qualified',attemptId='33333333-3333-4333-8333-333333333333',releaseManifestSha256='e'*64)
        after=json.loads(self.env['FIXTURE_WORK_RESULT']);after['maintenanceReference'].update(generation=1,ownerSha256='f'*64)
        self.env['FIXTURE_WORK_RESULT']=json.dumps(after)
        for verified in [False,True]:
            before['uninstallWorkEligibility']['successorAfterOriginalResult']=verified;self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']=json.dumps(before)
            result=self.invoke(flags);self.assertEqual(result.returncode,0 if verified else 1,result.stderr)
        self.assert_no_owner()

    def test_same_manifest_successor_requires_distinct_verified_locator(self):
        flags=self.maintenance_fixture()
        before=json.loads(self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']);before['maintenanceReference'].update(transition='eligible_successor',releasePathSha256='2'*64)
        after=json.loads(self.env['FIXTURE_WORK_RESULT']);after['maintenanceReference'].update(generation=1,ownerSha256='f'*64)
        self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']=json.dumps(before)
        for broken in ['candidateReleasePathSha256','releasePathSha256','generation',None]:
            value=copy.deepcopy(after)
            if broken=='candidateReleasePathSha256':value['maintenanceReference'][broken]='3'*64
            if broken=='releasePathSha256':value['maintenanceReference'][broken]='2'*64
            if broken=='generation':value['maintenanceReference'][broken]=2
            self.env['FIXTURE_WORK_RESULT']=json.dumps(value)
            result=self.invoke(flags);self.assertEqual(result.returncode,0 if broken is None else 1,result.stderr)
            self.assertNotIn(str(self.root),result.stdout)
        before['maintenanceReference']['releasePathSha256']='1'*64;self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']=json.dumps(before)
        result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout)
        self.assert_no_owner()

    def test_original_attempt_locator_cannot_change_without_known_result(self):
        flags=self.maintenance_fixture()
        before=json.loads(self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']);before['maintenanceReference'].update(transition='resume_original_attempt',phase='qualified',attemptId='33333333-3333-4333-8333-333333333333',releasePathSha256='2'*64)
        after=json.loads(self.env['FIXTURE_WORK_RESULT']);after['maintenanceReference'].update(generation=1,ownerSha256='f'*64)
        self.env['FIXTURE_WORK_RESULT']=json.dumps(after)
        for proven in [False,True]:
            before['uninstallWorkEligibility']['successorAfterOriginalResult']=proven;self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']=json.dumps(before)
            result=self.invoke(flags);self.assertEqual(result.returncode,0 if proven else 1,result.stderr)
        # The same generation always retains its exact original locator.
        after['maintenanceReference'].update(generation=0,transition='resume_original_attempt',phase='qualified',attemptId=before['maintenanceReference']['attemptId'])
        self.env['FIXTURE_WORK_RESULT']=json.dumps(after)
        result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout);self.assert_no_owner()

    def test_handover_requires_verified_packaged_artifact_before_mutation(self):
        flags=self.maintenance_fixture()
        before=json.loads(self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']);before['maintenanceReference'].update(transition='eligible_successor',releasePathSha256='2'*64)
        after=json.loads(self.env['FIXTURE_WORK_RESULT']);after['maintenanceReference'].update(generation=1,ownerSha256='f'*64);self.env['FIXTURE_WORK_RESULT']=json.dumps(after)
        for candidate in [None,'e'*64]:
            value=copy.deepcopy(before)
            if candidate is None:del value['artifact']['manifestSha256']
            else:value['artifact']['manifestSha256']=candidate
            self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']=json.dumps(value)
            result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout);self.assertFalse((self.state/'work.log').exists())
        value=copy.deepcopy(before);value['artifact']['manifestSha256']='e'*64;value['maintenanceReference']['candidateManifestSha256']='e'*64
        self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']=json.dumps(value)
        result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout);self.assertFalse((self.state/'work.log').exists());self.assert_no_owner()

    def test_v1_report_has_no_cross_release_authority(self):
        flags=self.maintenance_fixture();value=json.loads(self.env['FIXTURE_WORK_RESULT']);value['schema']='app.loomex.runner.bootstrap-uninstall-work/v1';self.env['FIXTURE_WORK_RESULT']=json.dumps(value)
        result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout);self.assert_no_owner()

    def test_maintenance_reference_and_native_diagnostic_are_bounded_on_failure(self):
        flags=self.maintenance_fixture('reconcile','blocked')
        value=json.loads(self.env['FIXTURE_WORK_RESULT']);value.update(outcome='blocked',reasonCode='OWNER_AUTHORIZATION_REQUIRED',nextAction='inspect_uninstall_work',nativeDiagnostic={'code':'STORE_ACCESS_REQUIRED','failureStage':'protected_store_read','failureCategory':'access_required','nativeOsStatus':-25308,'private':'SECRET','stderr':'SECRET'})
        value['maintenanceReference']['private']='SECRET';self.env['FIXTURE_WORK_RESULT']=json.dumps(value);self.env['FIXTURE_WORK_EXIT']='1'
        result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout);report=json.loads(result.stderr)
        self.assertEqual(report['nativeDiagnostic']['failureCategory'],'access_required');self.assertEqual(report['nativeDiagnostic']['failureStage'],'protected_store_read');self.assertEqual(report['maintenanceReference']['generation'],0);self.assertNotIn('SECRET',result.stderr)
        # A nonzero native preflight retains the same bounded reference, without dispatching work.
        preflight=json.loads(self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']);preflight.update(reasonCode='OWNER_AUTHORIZATION_REQUIRED',nextAction='inspect_uninstall_work',nativeDiagnostic=value['nativeDiagnostic']);preflight['maintenanceReference']['private']='SECRET'
        self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']=json.dumps(preflight);self.env['FIXTURE_RUNNER_PREFLIGHT_EXIT']='1'
        result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout);report=json.loads(result.stderr);self.assertEqual(report['maintenanceReference']['generation'],0);self.assertNotIn('SECRET',result.stderr)

    def test_uninstall_work_inspection_preserves_historical_null_operation_and_13_14_chain(self):
        result=self.invoke(self.work_fixture())
        self.assertEqual(result.returncode,0,result.stderr)
        report=json.loads(result.stdout)
        self.assertIsNone(report['operationId'])
        self.assertFalse(report['ownerReference']['adoptionStarted'])
        self.assertEqual([v['count'] for v in report['assessment']['blockers']],[13,14])
        self.assertEqual((self.state/'preflights.log').read_text().splitlines(),['runner','plugin'])
        self.assertFalse((self.root/'cache').exists());self.assert_no_owner()
        self.assertFalse((self.state/'runner-args.log').exists());self.assertFalse((self.state/'recovery.log').exists())
        self.assertFalse(self.runner.exists());self.assertFalse(self.plugin.exists())

    def scoped_work_fixture(self, action='inspect', outcome='inspected'):
        flags=self.work_fixture(action,outcome)
        for name in ['FIXTURE_RUNNER_PREFLIGHT_JSON','FIXTURE_WORK_RESULT']:
            value=json.loads(self.env[name]);value['retirementScope']='operation-observations'
            if name=='FIXTURE_WORK_RESULT':value.update(actionCompleted=outcome=='completed',cleanupEligible=False)
            self.env[name]=json.dumps(value)
        return flags+['--retirement-scope','operation-observations']

    def test_uninstall_work_default_scope_is_explicit_on_both_native_calls(self):
        result=self.invoke(self.work_fixture());self.assertEqual(result.returncode,0,result.stderr)
        for name in ['runner-preflight-args.log','work.log']:
            args=(self.state/name).read_text().splitlines()[-1].split()
            self.assertEqual(args.count('--retirement-scope'),1)
            self.assertEqual(args[args.index('--retirement-scope')+1],'continuations')
            self.assertEqual(args[args.index('--expected-old-journal-sha256')+1],'a'*64)
        report=json.loads(result.stdout)
        self.assertEqual(report['schema'],'app.loomex.paired-install-result/v4')
        self.assertEqual(report['retirementScope'],'continuations')
        self.assertFalse(report['actionCompleted']);self.assertFalse(report['cleanupEligible'])

    def test_operation_scope_forwards_exact_preflight_and_mutation_arguments(self):
        flags=self.scoped_work_fixture('retire-local','completed')
        value=json.loads(self.env['FIXTURE_WORK_RESULT']);value.update(operationId='11111111-1111-4111-8111-111111111111',reasonCode='UNINSTALL_WORK_COMPLETED',nextAction='reconcile_managed_work')
        self.env['FIXTURE_WORK_RESULT']=json.dumps(value)
        result=self.invoke(flags);self.assertEqual(result.returncode,0,result.stderr)
        preflight=(self.state/'runner-preflight-args.log').read_text().splitlines()[-1].split()
        mutation=(self.state/'work.log').read_text().splitlines()[-1].split()
        for args,action_flag in [(preflight,'--work-action'),(mutation,'--action')]:
            self.assertEqual(args[args.index(action_flag)+1],'retire-local')
            self.assertEqual(args[args.index('--retirement-scope')+1],'operation-observations')
            self.assertEqual(args[args.index('--expected-assessment-sha256')+1],'b'*64)
            self.assertEqual(args[args.index('--expected-old-journal-sha256')+1],'a'*64)
            self.assertEqual(args.count('--retirement-scope'),1)
        report=json.loads(result.stdout)
        self.assertEqual(report['outcome'],'completed');self.assertTrue(report['actionCompleted'])
        self.assertFalse(report['cleanupEligible']);self.assertEqual(report['nextAction'],'reconcile_managed_work')
        self.assertEqual(report['retirementScope'],'operation-observations');self.assert_no_owner()

    def test_scoped_work_refuses_legacy_preflight_or_scope_drift_before_mutation(self):
        flags=self.scoped_work_fixture();valid=json.loads(self.env['FIXTURE_RUNNER_PREFLIGHT_JSON'])
        for scope in [None,'continuations','PRIVATE']:
            value=copy.deepcopy(valid)
            if scope is None:value.pop('retirementScope')
            else:value['retirementScope']=scope
            self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']=json.dumps(value)
            result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout)
            self.assertFalse((self.state/'work.log').exists());self.assertFalse((self.root/'cache').exists())
            self.assertNotIn('PRIVATE',result.stderr)

    def test_scoped_work_requires_fresh_scope_and_completion_evidence(self):
        flags=self.scoped_work_fixture();valid=json.loads(self.env['FIXTURE_WORK_RESULT'])
        for key,replacement in [('retirementScope',None),('retirementScope','continuations'),('actionCompleted',None),('actionCompleted',True),('cleanupEligible',None),('cleanupEligible',True)]:
            value=copy.deepcopy(valid)
            if replacement is None:value.pop(key)
            else:value[key]=replacement
            self.env['FIXTURE_WORK_RESULT']=json.dumps(value)
            result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout)
            self.assertNotEqual(json.loads(result.stderr)['outcome'],'completed');self.assert_no_owner()

    def test_retirement_scope_is_limited_to_explicit_inspect_or_retire_modes(self):
        for flags in [[],self.work_fixture('reconcile'),self.work_fixture()]:
            for scope in (['continuations','operation-observations'] if not flags or 'reconcile' in flags else ['PRIVATE']):
                result=self.invoke(flags+['--retirement-scope',scope]);self.assertEqual(result.returncode,1,result.stdout)
                self.assertFalse((self.state/'preflights.log').exists());self.assertFalse((self.state/'work.log').exists())
                self.assertNotIn('PRIVATE',result.stderr)
        flags=self.scoped_work_fixture('retire-local');flags=flags[:flags.index('--expected-assessment-sha256')]+flags[flags.index('--expected-assessment-sha256')+2:]
        result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout)
        self.assertFalse((self.state/'preflights.log').exists());self.assert_no_owner()

    def test_unresolved_work_cannot_claim_install_ready_next_action(self):
        flags=self.work_fixture('reconcile','completed')
        valid=json.loads(self.env['FIXTURE_WORK_RESULT']);valid.update(operationId='11111111-1111-4111-8111-111111111111',reasonCode='UNINSTALL_WORK_COMPLETED')
        for next_action in ['none','install_candidate']:
            value=copy.deepcopy(valid);value['nextAction']=next_action;self.env['FIXTURE_WORK_RESULT']=json.dumps(value)
            result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout);self.assert_no_owner()

    def test_operation_work_preserves_only_bounded_per_cache_diagnostics(self):
        flags=self.scoped_work_fixture()
        value=json.loads(self.env['FIXTURE_WORK_RESULT'])
        safe={'kind':'operation_cache','recordReference':'c'*64,'recordDigest':'d'*64,'method':'interactions.respond','safeReason':'missing_binding','status':'pending','retirementEligible':True,'cleanupEligible':False,'availableActions':['reconcile','retire-local'],'selected':True}
        private=dict(safe,operationKey='SECRET KEY',path='SECRET PATH',record={'prompt':'SECRET PAYLOAD'},error='SECRET ERROR')
        value['preview']={'records':[private],'acceptanceDependencies':[{'secret':'SECRET DEPENDENCY'}]}
        self.env['FIXTURE_WORK_RESULT']=json.dumps(value)
        result=self.invoke(flags);self.assertEqual(result.returncode,0,result.stderr)
        report=json.loads(result.stdout);self.assertEqual(report['preview']['records'],[safe])
        self.assertNotIn('SECRET',result.stdout);self.assertNotIn('SECRET',result.stderr)
        value['preview']['records'][0].update(method='PRIVATE METHOD',safeReason='PRIVATE REASON',status='PRIVATE STATUS')
        self.env['FIXTURE_WORK_RESULT']=json.dumps(value)
        result=self.invoke(flags);self.assertEqual(result.returncode,0,result.stderr);self.assertNotIn('PRIVATE',result.stdout)
        value['preview']['records'][0]['availableActions']=['PRIVATE ACTION']
        self.env['FIXTURE_WORK_RESULT']=json.dumps(value)
        result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout);self.assertNotIn('PRIVATE',result.stderr)

    def test_uninstall_work_stale_retirement_digest_is_preserved_as_blocked(self):
        flags=self.work_fixture('retire-local','blocked')
        value=json.loads(self.env['FIXTURE_WORK_RESULT']);value['reasonCode']='UNINSTALL_WORK_ASSESSMENT_CHANGED'
        self.env['FIXTURE_WORK_RESULT']=json.dumps(value);self.env['FIXTURE_WORK_EXIT']='1'
        result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout)
        report=json.loads(result.stderr);self.assertEqual(report['reasonCode'],'UNINSTALL_WORK_ASSESSMENT_CHANGED')
        self.assertIn('--expected-assessment-sha256 '+'b'*64,(self.state/'work.log').read_text())
        self.assertTrue((self.root/'cache').exists());self.assert_no_owner()

    def test_typed_preflight_categories_are_preserved_without_private_owner_data(self):
        for reason in ['MANAGED_WORK_UNRESOLVED','OWNER_SCHEMA_UNSUPPORTED','OWNER_STATE_UNSAFE','OWNER_STATE_UNREADABLE','OWNER_STATE_DRIFT','OWNER_SIGNATURE_REJECTED','OWNER_AUTHORIZATION_REQUIRED']:
            self.work_fixture()
            value=json.loads(self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']);value.update(reasonCode=reason,nextAction='reconcile_managed_work',secret='SECRET')
            self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']=json.dumps(value);self.env['FIXTURE_RUNNER_PREFLIGHT_EXIT']='1'
            result=self.invoke(['--preflight-only']);self.assertEqual(result.returncode,1,result.stdout)
            report=json.loads(result.stderr);self.assertEqual(report['reasonCode'],reason)
            self.assertNotIn('SECRET',result.stderr);self.assertFalse((self.root/'cache').exists());self.assert_no_owner()

    def test_uninstall_work_verified_pending_has_exit_three_without_installation(self):
        flags=self.work_fixture('reconcile','pending')
        value=json.loads(self.env['FIXTURE_WORK_RESULT']);value.update(operationId='11111111-1111-4111-8111-111111111111',reasonCode='UNINSTALL_WORK_MAINTENANCE_PENDING',nextAction='resume_uninstall_work')
        self.env['FIXTURE_WORK_RESULT']=json.dumps(value);self.env['FIXTURE_WORK_EXIT']='3'
        result=self.invoke(flags);self.assertEqual(result.returncode,3,result.stderr)
        report=json.loads(result.stdout);self.assertEqual(report['nextAction'],'resume_uninstall_work')
        self.assertEqual(report['operationId'],'11111111-1111-4111-8111-111111111111');self.assert_no_owner()
        self.assertFalse((self.state/'recovery.log').exists());self.assertFalse(self.runner.exists());self.assertFalse(self.plugin.exists())

    def test_uninstall_work_response_requires_fresh_proof_after_valid_preflight(self):
        for outcome in ['completed','pending']:
            flags=self.work_fixture('reconcile',outcome)
            valid=json.loads(self.env['FIXTURE_WORK_RESULT']);valid.update(operationId='11111111-1111-4111-8111-111111111111',reasonCode='UNINSTALL_WORK_COMPLETED' if outcome=='completed' else 'UNINSTALL_WORK_MAINTENANCE_PENDING',nextAction='inspect_uninstall_work' if outcome=='completed' else 'resume_uninstall_work')
            preflight=json.loads(self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']);preflight['recoveryOwnership']={'operationId':'22222222-2222-4222-8222-222222222222'}
            self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']=json.dumps(preflight)
            self.env['FIXTURE_WORK_EXIT']='0' if outcome=='completed' else '3'
            mutations=[('ownerReference','missing'),('ownerReference',None),('ownerReference',{'private':'SECRET'}),('assessment','missing'),('assessment',None),('assessment',{'private':'SECRET'}),('operationId','missing'),('operationId',None),('operationId',{'private':'SECRET'}),('operationId','invalid-operation')]
            for key,replacement in mutations:
                with self.subTest(outcome=outcome,key=key,replacement=replacement):
                    result_value=copy.deepcopy(valid)
                    if replacement=='missing':result_value.pop(key)
                    else:result_value[key]=replacement
                    self.env['FIXTURE_WORK_RESULT']=json.dumps(result_value)
                    result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout)
                    report=json.loads(result.stderr);self.assertNotIn(report['outcome'],['completed','pending'])
                    self.assertNotIn('SECRET',result.stderr);self.assert_no_owner()
            self.env['FIXTURE_WORK_RESULT']=json.dumps(valid)
            result=self.invoke(flags);self.assertEqual(result.returncode,0 if outcome=='completed' else 3,result.stderr)
            self.assertEqual(json.loads(result.stdout)['operationId'],valid['operationId'])
        self.assertFalse((self.state/'runner-args.log').exists());self.assertFalse((self.state/'recovery.log').exists())

    def test_uninstall_work_inspection_cannot_inherit_missing_proof(self):
        flags=self.work_fixture();valid=json.loads(self.env['FIXTURE_WORK_RESULT'])
        for key in ['ownerReference','assessment','operationId']:
            value=copy.deepcopy(valid);value.pop(key);self.env['FIXTURE_WORK_RESULT']=json.dumps(value)
            result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout)
        self.assertFalse((self.root/'cache').exists());self.assert_no_owner()

    def test_uninstall_work_fresh_owner_must_match_original_binding(self):
        flags=self.work_fixture();value=json.loads(self.env['FIXTURE_WORK_RESULT']);value['ownerReference']['journalSha256']='f'*64
        self.env['FIXTURE_WORK_RESULT']=json.dumps(value)
        result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout);self.assert_no_owner()

    def test_uninstall_work_already_adopted_operation_cannot_change(self):
        flags=self.work_fixture('reconcile','pending')
        value=json.loads(self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']);value['ownerReference'].update(adoptionStarted=True,operationId='22222222-2222-4222-8222-222222222222')
        self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']=json.dumps(value)
        value=json.loads(self.env['FIXTURE_WORK_RESULT']);value.update(operationId='11111111-1111-4111-8111-111111111111',reasonCode='UNINSTALL_WORK_MAINTENANCE_PENDING',nextAction='resume_uninstall_work')
        self.env['FIXTURE_WORK_RESULT']=json.dumps(value);self.env['FIXTURE_WORK_EXIT']='3'
        result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout);self.assert_no_owner()

    def test_uninstall_work_refusal_codes_and_null_unavailable_assessment_are_preserved(self):
        flags=self.work_fixture('reconcile','blocked');valid=json.loads(self.env['FIXTURE_WORK_RESULT']);valid['nextAction']='inspect_uninstall_work'
        self.env['FIXTURE_WORK_EXIT']='1'
        for reason in ['UNINSTALL_WORK_AUDIT_LIMIT','UNINSTALL_WORK_PREVIEW_LIMIT','UNINSTALL_WORK_REVIEW_UNAVAILABLE','UNINSTALL_WORK_IDENTITY_CHANGED','UNINSTALL_WORK_RECONCILIATION_REQUIRED','UNINSTALL_WORK_OBSERVATION_INCOMPLETE','UNINSTALL_WORK_DOMAIN_OUTCOME_PENDING','UNINSTALL_WORK_RECEIPT_MISMATCH','UNINSTALL_WORK_RECONCILIATION_UNSUPPORTED']:
            value=copy.deepcopy(valid);value.update(reasonCode=reason,private='SECRET',nativeDiagnostic={'private':'SECRET'})
            if reason=='UNINSTALL_WORK_REVIEW_UNAVAILABLE':value['assessment']=None
            self.env['FIXTURE_WORK_RESULT']=json.dumps(value)
            result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout)
            report=json.loads(result.stderr);self.assertEqual(report['outcome'],'blocked');self.assertEqual(report['reasonCode'],reason)
            self.assertFalse(report['actionCompleted']);self.assertFalse(report['cleanupEligible'])
            self.assertEqual(report['nextAction'],'inspect_uninstall_work');self.assertNotIn('SECRET',result.stderr);self.assertNotIn('SECRET',result.stdout)
        self.assert_no_owner()

    def test_ordinary_install_preflight_cannot_use_maintenance_eligibility(self):
        for flags in [[],['--preflight-only'],self.recovery_flags()]:
            self.work_fixture();result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout)
            self.assertEqual(json.loads(result.stderr)['phase'],'runner-preflight');self.assert_no_owner()
        self.assertFalse((self.root/'cache').exists());self.assertFalse((self.state/'work.log').exists())

    def test_work_preflight_requires_work_eligibility_and_plugin_activation_eligibility(self):
        flags=self.work_fixture();value=json.loads(self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']);value['activation']['eligible']=True;value['uninstallWorkEligibility']['eligible']=False
        self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']=json.dumps(value)
        result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout)
        self.assertEqual(json.loads(result.stderr)['phase'],'runner-preflight')
        flags=self.work_fixture();self.env['FIXTURE_PLUGIN_PREFLIGHT_JSON']=json.dumps({'schema':'app.loomex.plugin.install-preflight/v1','artifact':{'eligible':True},'activation':{'eligible':False},'uninstallWorkEligibility':{'eligible':True}})
        result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout)
        self.assertEqual(json.loads(result.stderr)['phase'],'plugin-preflight')
        self.assertFalse((self.state/'work.log').exists());self.assertFalse((self.root/'cache').exists());self.assert_no_owner()

    def test_mutating_work_forwards_only_explicit_transition_authorization(self):
        for action in ['reconcile','retire-local']:
            for transition in ['eligible','needs_explicit_transition']:
                with self.subTest(action=action,transition=transition):
                    flags=self.work_fixture(action,'pending')
                    value=json.loads(self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']);value['uninstallWorkEligibility']['signingTransition']=transition
                    self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']=json.dumps(value)
                    value=json.loads(self.env['FIXTURE_WORK_RESULT']);value.update(operationId='11111111-1111-4111-8111-111111111111',reasonCode='UNINSTALL_WORK_MAINTENANCE_PENDING',nextAction='resume_uninstall_work')
                    self.env['FIXTURE_WORK_RESULT']=json.dumps(value);self.env['FIXTURE_WORK_EXIT']='3'
                    result=self.invoke(flags+['--authorize-keychain-transition']);self.assertEqual(result.returncode,3,result.stderr)
                    self.assertIn('--authorize-keychain-transition',(self.state/'runner-preflight-args.log').read_text().splitlines()[-1])
                    self.assertIn('--authorize-keychain-transition',(self.state/'work.log').read_text().splitlines()[-1])
                    report=json.loads(result.stdout);self.assertEqual(report['outcome'],'pending');self.assertEqual(report['operationId'],value['operationId'])
                    self.assertEqual(report['nextAction'],'resume_uninstall_work');self.assertEqual(report['ownerReference']['journalSha256'],'a'*64)
        self.assert_no_owner();self.assertFalse((self.state/'runner-args.log').exists());self.assertFalse((self.state/'recovery.log').exists())

    def test_mutating_work_never_adds_native_transition_authorization(self):
        for action in ['reconcile','retire-local']:
            for transition in ['eligible','needs_explicit_transition']:
                flags=self.work_fixture(action,'blocked')
                value=json.loads(self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']);value['uninstallWorkEligibility']['signingTransition']=transition
                self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']=json.dumps(value)
                value=json.loads(self.env['FIXTURE_WORK_RESULT']);value.update(reasonCode='OWNER_AUTHORIZATION_REQUIRED',nextAction='inspect_uninstall_work')
                self.env['FIXTURE_WORK_RESULT']=json.dumps(value);self.env['FIXTURE_WORK_EXIT']='1'
                result=self.invoke(flags);self.assertEqual(result.returncode,1,result.stdout)
                self.assertNotIn('--authorize-keychain-transition',(self.state/'runner-preflight-args.log').read_text().splitlines()[-1])
                self.assertNotIn('--authorize-keychain-transition',(self.state/'work.log').read_text().splitlines()[-1])
        self.assert_no_owner();self.assertFalse((self.state/'runner-args.log').exists());self.assertFalse((self.state/'recovery.log').exists())

    def test_inspection_rejects_transition_authorization_before_any_native_call(self):
        flags=self.work_fixture()
        result=self.invoke(flags+['--authorize-keychain-transition']);self.assertEqual(result.returncode,1,result.stdout)
        self.assertFalse((self.state/'preflights.log').exists());self.assertFalse((self.state/'runner-preflight-args.log').exists())
        self.assertFalse((self.state/'work.log').exists());self.assertFalse((self.root/'cache').exists());self.assert_no_owner()

    def test_explicit_work_transition_requires_supported_native_preflight_enum(self):
        for transition in [None,'unexpected-private-value']:
            flags=self.work_fixture('reconcile','pending')
            value=json.loads(self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']);value['uninstallWorkEligibility']['signingTransition']=transition
            self.env['FIXTURE_RUNNER_PREFLIGHT_JSON']=json.dumps(value)
            result=self.invoke(flags+['--authorize-keychain-transition']);self.assertEqual(result.returncode,1,result.stdout)
            self.assertEqual(json.loads(result.stderr)['phase'],'runner-preflight')
            self.assertFalse((self.state/'work.log').exists());self.assertFalse((self.root/'cache').exists());self.assert_no_owner()
            self.assertNotIn('unexpected-private-value',result.stderr)

    def test_uninstall_work_refuses_mixed_install_and_recovery_modes(self):
        for extra in [['--recover-uninstall'],['--verify-only'],['--preflight-only'],['--runner-only'],['--authorize-keychain-transition']]:
            result=self.invoke(self.work_fixture()+extra);self.assertEqual(result.returncode,1,result.stdout)
            self.assertFalse((self.state/'work.log').exists());self.assert_no_owner()

    def test_uninstall_work_plugin_or_host_failure_precedes_native_work(self):
        flags=self.work_fixture();self.env['FIXTURE_PLUGIN_PREFLIGHT_FAIL']='1'
        self.assertEqual(self.invoke(flags).returncode,1);self.assertFalse((self.state/'work.log').exists())
        self.env.pop('FIXTURE_PLUGIN_PREFLIGHT_FAIL');self.fake_codex(collision=True)
        self.assertEqual(self.invoke(flags).returncode,1);self.assertFalse((self.state/'work.log').exists())
        self.assertFalse((self.root/'cache').exists());self.assert_no_owner()

    def test_cache_conflicts_are_preserved_and_refused(self):
        self.env['FIXTURE_PLUGIN_FAIL']='1';self.assertEqual(self.invoke().returncode,1)
        cache=Path((self.plugin/'pending').read_text().strip()).parent
        path=cache/'compatibility.json';path.write_text('conflict')
        self.env.pop('FIXTURE_PLUGIN_FAIL');result=self.invoke();self.assertEqual(result.returncode,1)
        self.assertEqual(path.read_text(),'conflict');self.assertFalse((self.plugin/'installed').exists())

    def test_offline_success_runner_only(self):
        result=self.invoke(['--runner-only']);self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((self.runner/'installed').is_file());self.assertFalse((self.plugin/'installed').exists())

if __name__=='__main__':unittest.main()
