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
            put(envelope/'loomex-lifecycle-bootstrap','#!/bin/bash\nexit 0\n',0o755)
            side=envelope/'loomex-lifecycle-bootstrap';bootstrap={'file':side.name,'sha256':pack.sha(side),'size':side.stat().st_size}
            put(envelope/'scripts/install.sh',r'''#!/bin/bash
set -euo pipefail
release="$1"; shift
echo "$*" >> "$FIXTURE_STATE/runner-args.log"
base=""
while (($#)); do case "$1" in --install-base) base="$2";shift 2;; --preview-api-origin|--development-api-origin) shift 2;; *) shift;; esac; done
[[ -n "$base" ]]
if [[ ! -f "$base/installed" ]]; then
  /bin/mkdir -p "$base/current/bin"
  echo runner >> "$FIXTURE_STATE/owners.log"
  echo "$release" > "$base/installed"
  /bin/cat > "$base/current/bin/loomex" <<'STATUS'
#!/bin/bash
echo '{"version":"0.5.2","protocol":"loomex.local-control/v2","draining":false,"updateDeferred":false}'
STATUS
  /bin/chmod 0755 "$base/current/bin/loomex"
fi
''',0o755)
        else:
            put(envelope/'source-content.json',provenance)
            source_name='source-content.json';source_root=envelope
            contracts[kind]={'schemaVersion':'loomex.plugin-compatibility-components/v1','fixture':kind}
            put(envelope/'plugin-components.json',contracts[kind])
            put(payload/'plugin/package.json',{'version':version})
            runtime=put(envelope/'lifecycle-runtime/node','#!/bin/bash\nexit 0\n',0o755);manager=put(envelope/'lifecycle.mjs','// compiled fixture owner\n')
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
        self.assertIn('runner remains installed',result.stderr)
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

    def test_offline_success_runner_only(self):
        result=self.invoke(['--runner-only']);self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((self.runner/'installed').is_file());self.assertFalse((self.plugin/'installed').exists())

if __name__=='__main__':unittest.main()
