#!/usr/bin/env python3
"""Create-only, build-time paired release packager. Never installs or publishes."""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
import ipaddress
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = 'loomex-app/loomex-runner'
spec = importlib.util.spec_from_file_location('runner_artifact', ROOT / 'scripts/artifact.py')
artifact = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifact)

def regular(path):
    if not path.is_file() or path.is_symlink():
        raise ValueError(f'regular file required: {path}')

def read(path):
    regular(path)
    return json.loads(path.read_text())

def sha(path): return artifact.digest(path)
def canonical(value): return artifact.canonical(value)
def contract_digest(value): return 'sha256:' + __import__('hashlib').sha256((json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n').encode()).hexdigest()

def validate_deployment(value):
    if not isinstance(value,dict) or value.get('profile') not in ('cloud-preview','local-development') or set(value)!=({'profile','apiOrigin'} if value['profile']=='cloud-preview' else {'profile','apiOrigin','webAppOrigin'}):
        raise ValueError('unsupported deployment profile schema')
    def origin(raw):
        if not isinstance(raw,str) or any(c.isspace() for c in raw) or '?' in raw or '#' in raw: raise ValueError('canonical deployment origin required')
        u=urlsplit(raw)
        if not u.hostname or u.username is not None or u.password is not None or u.path!='/' or u.query or u.fragment: raise ValueError('canonical deployment root required')
        if value['profile']=='cloud-preview':
            try: ipaddress.ip_address(u.hostname); dns=False
            except ValueError: dns=u.hostname!='localhost' and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in u.hostname.split('.'))
            if u.scheme!='https' or not dns: raise ValueError('configured canonical cloud HTTPS DNS root required')
        else:
            try: loopback=ipaddress.ip_address(u.hostname).is_loopback
            except ValueError: loopback=u.hostname=='localhost' or u.hostname.endswith('.localhost')
            if u.scheme!='http' or not loopback: raise ValueError('local-development requires HTTP loopback origin')
        host=u.hostname.encode('idna').decode('ascii').lower()
        if ':' in host: host='['+host+']'
        port=u.port
        if port is not None and not 0<port<=65535: raise ValueError('invalid origin port')
        expected=f"{u.scheme}://{host}"+(f':{port}' if port is not None and port != (443 if u.scheme=='https' else 80) else '')+'/'
        if raw!=expected: raise ValueError('canonical deployment origin required')
    origin(value['apiOrigin'])
    if value['profile']=='local-development' and value['webAppOrigin'] is not None: origin(value['webAppOrigin'])
    return value

def validate_manifest(value):
    keys = {'schema','releaseTag','platform','developmentOnly','protocolVersion','deployment','components','evidence','installer'}
    if not isinstance(value, dict) or set(value) != keys or value['schema'] != 'app.loomex.release-set/v2':
        raise ValueError('release-set schema mismatch')
    if value['platform'] != 'darwin-arm64' or value['developmentOnly'] is not True or value['protocolVersion'] != 'loomex.local-control/v2':
        raise ValueError('unsupported platform/class/protocol')
    validate_deployment(value['deployment'])
    if set(value['components']) != {'runner','plugin'}:
        raise ValueError('both paired components required')
    versions=[]; names=[]
    def validate_asset(asset):
        if set(asset) != {'file','url','size','sha256'} or not re.fullmatch(r'[A-Za-z0-9._-]+',asset['file']) or type(asset['size']) is not int or not 0 < asset['size'] <= 2147483648 or not re.fullmatch(r'[0-9a-f]{64}',asset['sha256']):
            raise ValueError('asset identity invalid')
        if asset['url'] != f"https://github.com/{REPOSITORY}/releases/download/{value['releaseTag']}/{asset['file']}":
            raise ValueError('asset URL must be frozen to paired release')
        names.append(asset['file'])
    for name,c in value['components'].items():
        if set(c) != {'version','sourceRevision','repository','releaseTag','manifestSha256','asset'}:
            raise ValueError('component schema mismatch')
        if not re.fullmatch(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)',c['version']) or not re.fullmatch(r'[0-9a-f]{40}',c['sourceRevision']) or not re.fullmatch(r'[0-9a-f]{64}',c['manifestSha256']):
            raise ValueError('component version/source invalid')
        if c['repository'] != ('loomex-app/loomex-runner' if name=='runner' else 'loomex-app/loomex-codex-plugin') or c['releaseTag'] != value['releaseTag']:
            raise ValueError('wrong component release pair')
        validate_asset(c['asset'])
    expected=f"runner-v{value['components']['runner']['version']}-plugin-v{value['components']['plugin']['version']}"
    if value['releaseTag'] not in (expected, "preview-"+expected):
        raise ValueError('tag differs from component version pair')
    e=value['evidence']
    if set(e) != {'asset','backendSourceRevision','passed'} or e['passed'] is not True or not re.fullmatch(r'[0-9a-f]{40}',e['backendSourceRevision']):
        raise ValueError('required evidence missing')
    validate_asset(e['asset']); validate_asset(value['installer'])
    if len(set(names)) != len(names): raise ValueError('duplicate asset name')
    return value

def asset(path, tag):
    regular(path)
    return {'file':path.name,'url':f'https://github.com/{REPOSITORY}/releases/download/{tag}/{path.name}','size':path.stat().st_size,'sha256':sha(path)}

def safe_extract(path, destination):
    destination.mkdir()
    seen=set()
    with tarfile.open(path,'r:gz') as archive:
        members=archive.getmembers()
        if sum(m.size for m in members) > 2147483648: raise ValueError('archive expansion exceeds limit')
        for m in members:
            if m.name.startswith('/') or '\\' in m.name or any(p in ('','..','.') for p in m.name.rstrip('/').split('/')) or m.name in seen or not(m.isfile() or m.isdir()) or m.mode & ~0o777:
                raise ValueError('unsafe archive member')
            seen.add(m.name)
        archive.extractall(destination,filter='data')

def clean_revision(root):
    head=subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()
    if not re.fullmatch('[0-9a-f]{40}',head) or subprocess.check_output(['git','-C',str(root),'status','--porcelain=v1','--untracked-files=all']):
        raise ValueError('release-set packaging requires clean immutable runner checkout')
    return head

def verify_deployment(payload, component, deployment):
    validate_deployment(deployment)
    local=deployment['profile']=='local-development'
    file='metadata/local-development-origin.json' if local else 'metadata/preview-origin.json'
    other='metadata/preview-origin.json' if local else 'metadata/local-development-origin.json'
    if (payload/other).exists(): raise ValueError('runner deployment profile substitution')
    value=read(payload/file)
    expected={'schema':'app.loomex.runner.local-development-origin/v1' if local else 'app.loomex.runner.preview-origin/v1','apiOrigin':deployment['apiOrigin'],'sourceRevision':component['sourceRevision'],'version':component['version']}
    if local: expected['webAppOrigin']=deployment['webAppOrigin']
    if value!=expected or (payload/file).read_bytes()!=canonical(value): raise ValueError('runner deployment metadata differs from exact reviewed profile/origins/source')
    return value

def package(args):
    output=Path(args.output).absolute()
    if any(parent.is_symlink() for parent in output.parents) or os.path.lexists(output): raise ValueError('output already exists; no overwrite')
    runner=Path(args.runner_release).resolve(); plugin_archive=Path(args.plugin_archive).resolve(); installer=Path(args.installer).resolve()
    regular(installer); regular(plugin_archive)
    source=clean_revision(ROOT)
    runner_manifest=read(runner/'manifest.json')
    runner_members={p.relative_to(runner).as_posix() for p in runner.rglob('*') if p.is_file()}
    if runner_members != {'manifest.json','payload.tar.gz','loomex-lifecycle-bootstrap'} or any(p.is_symlink() or not(p.is_file() or p.is_dir()) for p in runner.rglob('*')): raise ValueError('runner envelope inventory includes unreviewed members')
    if runner_manifest.get('sourceRevision') != source or runner_manifest.get('project') != 'loomex-runner' or runner_manifest.get('platform') != 'darwin-arm64' or runner_manifest.get('developmentOnly') is not True:
        raise ValueError('runner envelope identity differs from clean source/preview')
    plugin_root=Path(args.plugin_source_root).resolve()
    plugin_clean_revision=clean_revision(plugin_root)
    revision=args.backend_source_revision
    if not re.fullmatch('[0-9a-f]{40}',revision): raise ValueError('backend full SHA required')
    gate=read(Path(args.compatibility))
    if gate.get('schemaVersion') != 'loomex/compatibility-manifest/v1' or gate.get('verification',{}).get('sourceRevisions',{}).get('backend') != revision:
        raise ValueError('required compatibility gate/backend source missing')
    with tempfile.TemporaryDirectory() as temporary:
        temporary=Path(temporary)
        verified=temporary/'runner-payload'
        subprocess.run(['python3',str(ROOT/'scripts/artifact.py'),'extract','--release',str(runner),'--project','loomex-runner','--platform','darwin-arm64','--allow-unsigned-development','--extract',str(verified)],check=True)
        deployment={'profile':args.deployment_profile,'apiOrigin':args.api_origin}
        if args.deployment_profile=='local-development': deployment['webAppOrigin']=args.web_app_origin
        elif args.web_app_origin is not None: raise ValueError('cloud web origin belongs to existing compiled configuration')
        verify_deployment(verified,runner_manifest,deployment)
        extracted=temporary/'plugin-envelope';safe_extract(plugin_archive,extracted)
        plugin_manifest=read(extracted/'manifest.json'); public=read(extracted/'public-distribution.json')
        plugin_members={p.relative_to(extracted).as_posix() for p in extracted.rglob('*') if p.is_file()}
        expected_plugin_members={'manifest.json','payload.tar.gz','source-content.json','lifecycle.mjs','lifecycle-runtime/node','scripts/install.sh','scripts/lifecycle.sh','scripts/uninstall.sh','plugin-components.json','public-distribution.json'}
        if plugin_members != expected_plugin_members: raise ValueError('plugin outer inventory includes unreviewed members')
        public_inventory=[f for f in artifact.inventory(extracted) if f['path']!='public-distribution.json']
        if public.get('files') != public_inventory: raise ValueError('plugin outer public inventory differs from actual bytes')
        pv=plugin_manifest.get('version'); tag=f"runner-v{runner_manifest['version']}-plugin-v{pv}"
        if args.release_tag != tag or public.get('releaseTag') != tag or public.get('sourceRevision') != plugin_manifest.get('sourceRevision') or public.get('manifestSha256') != sha(extracted/'manifest.json') or plugin_manifest.get('developmentOnly') is not True or plugin_manifest.get('project') != 'loomex-plugin' or plugin_manifest.get('platform') != 'darwin-arm64':
            raise ValueError('plugin public archive belongs to different pair')
        plugin_source=plugin_manifest['sourceRevision']
        if plugin_source != plugin_clean_revision: raise ValueError('plugin source checkout differs from frozen envelope')
        plugin_payload=temporary/'plugin-payload'
        subprocess.run(['python3',str(plugin_root/'scripts/artifact.py'),'extract','--release',str(extracted),'--project','loomex-plugin','--platform','darwin-arm64','--allow-unsigned-development','--source-root',str(plugin_root),'--extract',str(plugin_payload)],check=True)
        if gate['verification']['sourceRevisions'].get('plugin') != plugin_source:
            raise ValueError('required compatibility gate plugin source mismatch')
        plugin_contract=read(extracted/'plugin-components.json')
        compiled_contract=temporary/'compiled-plugin-components.json'
        subprocess.run([str(plugin_payload/'plugin/runtime/bin/node'),str(plugin_payload/'plugin/dist/compatibility-check.mjs'),'--package-root',str(plugin_payload/'plugin'),'--output',str(compiled_contract)],check=True)
        actual_contract=read(compiled_contract)
        qualified_contract=dict(plugin_contract); qualified_contract.pop('source',None)
        actual_contract.pop('source',None)
        if actual_contract != qualified_contract: raise ValueError('public plugin descriptor differs from actual packaged compiled checker')
        if plugin_contract.get('source') != {'headRevision':plugin_source,'workingTree':'clean'}: raise ValueError('qualified compiled plugin source identity missing')
        runner_contract=read(verified/'metadata/compatibility-manifest.json')
        if gate['components']['runner']['digest'] != contract_digest(runner_contract) or gate['components']['plugin']['digest'] != contract_digest(plugin_contract):
            raise ValueError('gate did not qualify packaged component bytes')
        stage=temporary/'assets';stage.mkdir()
        wrapper=temporary/'runner-envelope';shutil.copytree(runner,wrapper)
        provenance=read(verified/'metadata/source-content-manifest.json')
        launcher=ROOT/'scripts/install.sh'; expected=next((f for f in provenance['files'] if f['path']=='scripts/install.sh'),None)
        if not expected or expected['sha256'] != sha(launcher) or expected['size'] != launcher.stat().st_size or expected['mode'] != ('100755' if launcher.stat().st_mode & 0o111 else '100644'):
            raise ValueError('runner launcher differs from source provenance')
        (wrapper/'scripts').mkdir();shutil.copy2(launcher,wrapper/'scripts/install.sh')
        runner_archive=stage/f"loomex-runner-{runner_manifest['version']}-darwin-arm64.tar.gz"
        artifact.deterministic_tar(wrapper,runner_archive,0)
        shutil.copy2(plugin_archive,stage/plugin_archive.name)
        if installer.name != 'loomex-install-darwin-arm64': raise ValueError('native installer asset must be loomex-install-darwin-arm64')
        shutil.copy2(installer,stage/installer.name)
        evidence={'schema':'app.loomex.release-qualification/v1','sourceRevisions':{'runner':source,'plugin':plugin_source,'backend':revision},'compatibility':gate}
        (stage/'compatibility.json').write_bytes(canonical(evidence))
        components={}
        for name,m,path,repo in [('runner',runner_manifest,runner_archive,REPOSITORY),('plugin',plugin_manifest,stage/plugin_archive.name,'loomex-app/loomex-codex-plugin')]:
            components[name]={'version':m['version'],'sourceRevision':m['sourceRevision'],'repository':repo,'releaseTag':tag,'manifestSha256':sha((runner if name=='runner' else extracted)/'manifest.json'),'asset':asset(path,tag)}
        manifest={'schema':'app.loomex.release-set/v2','releaseTag':tag,'platform':'darwin-arm64','developmentOnly':True,'protocolVersion':'loomex.local-control/v2','deployment':deployment,'components':components,'evidence':{'asset':asset(stage/'compatibility.json',tag),'backendSourceRevision':revision,'passed':True},'installer':asset(stage/installer.name,tag)}
        validate_manifest(manifest)
        (stage/'release-set.json').write_bytes(canonical(manifest))
        manifest_digest=sha(stage/'release-set.json')
        (stage/'install.sh').write_text(launcher_script(manifest,manifest_digest))
        (stage/'install.sh').chmod(0o755)
        if args.offline:
            offline=temporary/'offline';shutil.copytree(stage,offline)
            # Offline invocation still verifies current_exe against installer hash and externally reviewed manifest SHA.
            (offline/'INSTALL.txt').write_text(offline_instructions(manifest,manifest_digest))
            artifact.deterministic_tar(offline,stage/f'{tag}-offline.tar.gz',0)
        (stage/'RELEASE-NOTES.md').write_text(release_notes(manifest,manifest_digest))
        (stage/'SHA256SUMS').write_text(''.join(f'{sha(p)}  {p.name}\n' for p in sorted(stage.iterdir()) if p.is_file()))
        output.parent.mkdir(parents=True,exist_ok=True)
        output.mkdir() # create-only publication staging; never overwrite existing bytes
        for p in stage.iterdir(): shutil.copy2(p,output/p.name)
    return {'releaseTag':tag,'releaseSetSha256':manifest_digest,'output':str(output),'developmentOnly':True}

def legacy_names(manifest): return manifest['releaseTag'].startswith('preview-')
def launcher_name(manifest): return 'install-preview.sh' if legacy_names(manifest) else 'install.sh'
def unsigned_flag(manifest): return '--allow-unsigned-preview' if legacy_names(manifest) else '--allow-unsigned-development'
def offline_instructions(manifest,digest):
    classification='Explicit unsigned preview only.' if legacy_names(manifest) else 'Unsigned distribution; explicit opt-in required.'
    return f'{classification} Verify release-set.json against independently reviewed SHA256 {digest}.\nLOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 ./loomex-install-darwin-arm64 --offline "$PWD" --manifest-sha256 {digest} {unsigned_flag(manifest)}\n'

def release_notes(manifest,digest):
    runner=manifest['components']['runner']; plugin=manifest['components']['plugin']
    notes=f'Unsigned development preview for macOS ARM64 only. Not Developer ID signed or notarized. Explicit opt-in required.\n\nRunner {runner["version"]}: {runner["sourceRevision"]}\nPlugin {plugin["version"]}: {plugin["sourceRevision"]}\nBackend qualified source: {manifest["evidence"]["backendSourceRevision"]}\nRelease-set SHA256: {digest}\nDeployment profile: {manifest["deployment"]["profile"]}\nAPI origin: {manifest["deployment"]["apiOrigin"]}\nWeb app origin: {manifest["deployment"].get("webAppOrigin", "compiled cloud build configuration")}\nProtocol: {manifest["protocolVersion"]}\n\nLicense: existing Proprietary decision; no new license grant.\n\nInspect all assets and inventories before the separate operator publication checkpoint. Installation defaults to runner and plugin; --runner-only is supported. No login or organization selection is forced.\n'

    if legacy_names(manifest): return notes
    notes=notes.replace('Unsigned development preview for macOS ARM64 only.', 'Loomex for macOS Apple silicon. These artifacts are unsigned development builds.')
    url=f'https://github.com/{REPOSITORY}/releases/download/{manifest["releaseTag"]}/install.sh'
    return notes+f'''## Install runner and Codex plugin\n\nA compatible backend must already be available at the API origin above. Provider CLIs and their account access are separate prerequisites.\n\n```sh\nloomex_installer="$(mktemp)" &&\ncurl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' {url} -o "$loomex_installer" &&\nLOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 /bin/bash "$loomex_installer" --allow-unsigned-development\n```\n\nReview the downloaded script before executing it if desired. The release-specific launcher pins the helper and paired manifest hashes; it never mixes component downloads from latest. Restart Codex after installation, then use `$loomex:loomex-connect` to sign in and choose an organization.\n'''

def launcher_script(manifest,digest):
    base=f'https://github.com/{REPOSITORY}/releases/download/{manifest["releaseTag"]}'
    installer=manifest['installer']
    flag=unsigned_flag(manifest)
    classification='unsigned preview' if legacy_names(manifest) else 'unsigned distribution'
    opt_in='preview' if legacy_names(manifest) else 'unsigned'
    return f'''#!/bin/bash
# This release-specific transport launcher contains no lifecycle implementation.
set -euo pipefail
[[ "$(uname -s)-$(uname -m)" == Darwin-arm64 ]] || {{ echo "macOS ARM64 required" >&2; exit 1; }}
[[ "${{LOOMEX_ALLOW_UNSAFE_DEV_INSTALL:-}}" == 1 ]] || {{ echo "Set LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 only after reviewing this {classification}" >&2; exit 1; }}
{opt_in}=0
for option in "$@"; do [[ "$option" != {flag} ]] || {opt_in}=1; done
[[ "${opt_in}" == 1 ]] || {{ echo "{flag} required" >&2; exit 1; }}
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
/usr/bin/curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' '{base}/release-set.json' --output "$work/release-set.json"
[[ "$(/usr/bin/shasum -a 256 "$work/release-set.json" | /usr/bin/awk '{{print $1}}')" == '{digest}' ]] || {{ echo "release-set digest mismatch" >&2; exit 1; }}
/usr/bin/curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' '{installer['url']}' --output "$work/loomex-install"
[[ "$(/usr/bin/stat -f %z "$work/loomex-install")" == '{installer['size']}' && "$(/usr/bin/shasum -a 256 "$work/loomex-install" | /usr/bin/awk '{{print $1}}')" == '{installer['sha256']}' ]] || {{ echo "installer size/digest mismatch" >&2; exit 1; }}
chmod 0700 "$work/loomex-install"
"$work/loomex-install" --manifest "$work/release-set.json" --manifest-sha256 '{digest}' "$@"
'''

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner-release',required=True)
    parser.add_argument('--plugin-archive',required=True)
    parser.add_argument('--plugin-source-root',required=True)
    parser.add_argument('--installer',required=True)
    parser.add_argument('--compatibility',required=True)
    parser.add_argument('--backend-source-revision',required=True)
    parser.add_argument('--release-tag',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--deployment-profile',choices=['cloud-preview','local-development'],required=True)
    parser.add_argument('--api-origin',required=True)
    parser.add_argument('--web-app-origin')
    parser.add_argument('--offline',action='store_true')
    args=parser.parse_args()
    try: print(json.dumps(package(args),sort_keys=True))
    except (ValueError,KeyError,OSError,subprocess.CalledProcessError) as error: parser.exit(1,f'release-set rejected: {error}\n')
if __name__=='__main__': main()
