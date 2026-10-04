#!/usr/bin/env python3
"""Inspect, explicitly stage, resume or publish exact build-once preview assets."""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

spec=importlib.util.spec_from_file_location('release_set',Path(__file__).with_name('release-set.py'))
pack=importlib.util.module_from_spec(spec);spec.loader.exec_module(pack)
REPO=pack.REPOSITORY
API_VERSION='2026-03-10'

def command(*args):
    return subprocess.check_output(list(args),text=True)

def api(endpoint):
    return json.loads(command('gh','api','-H',f'X-GitHub-Api-Version: {API_VERSION}',endpoint))

def local_inventory(directory):
    directory=Path(directory).resolve()
    manifest=pack.validate_manifest(pack.read(directory/'release-set.json'))
    if pack.canonical(manifest) != (directory/'release-set.json').read_bytes(): raise ValueError('noncanonical release-set')
    items={}
    for path in sorted(directory.iterdir()):
        pack.regular(path)
        items[path.name]={'sha256':pack.sha(path),'size':path.stat().st_size}
    manifest_digest=items['release-set.json']['sha256']
    launcher=directory/'install-preview.sh'
    if not launcher.is_file() or launcher.is_symlink() or launcher.read_bytes()!=pack.launcher_script(manifest,manifest_digest).encode(): raise ValueError('mandatory executable launcher differs from approved release-set transport')
    notes=directory/'RELEASE-NOTES.md'
    if not notes.is_file() or notes.is_symlink() or notes.read_bytes()!=pack.release_notes(manifest,manifest_digest).encode(): raise ValueError('mandatory release notes differ from approved source-derived guidance')
    for path in directory.iterdir():
        if path.stat().st_mode & 0o111 and path.name not in {'install-preview.sh',manifest['installer']['file']}: raise ValueError('unreviewed executable release asset')
    expected=[manifest['installer'],manifest['evidence']['asset']]+[c['asset'] for c in manifest['components'].values()]
    for item in expected:
        if items.get(item['file']) != {'sha256':item['sha256'],'size':item['size']}: raise ValueError('asset inventory differs from release-set')
    checks=(directory/'SHA256SUMS').read_text().splitlines()
    values={}
    for line in checks:
        digest,name=line.split('  ',1)
        if name in values or name not in items or items[name]['sha256'] != digest: raise ValueError('checksum inventory invalid')
        values[name]=digest
    if set(values)!=set(items)-{'SHA256SUMS'}: raise ValueError('checksum inventory omits or adds assets')
    allowed={e['file'] for e in expected}|{'release-set.json','SHA256SUMS','install-preview.sh','RELEASE-NOTES.md',f"{manifest['releaseTag']}-offline.tar.gz"}
    if set(items)-allowed: raise ValueError('unreviewed asset in upload inventory')
    # Inspect outer inventories; never execute envelope programs during publication.
    component_inventories={}
    with tempfile.TemporaryDirectory() as temp:
        for name,c in manifest['components'].items():
            root=Path(temp)/name;pack.safe_extract(directory/c['asset']['file'],root)
            if pack.sha(root/'manifest.json')!=c['manifestSha256']:raise ValueError('component manifest binding mismatch')
            m=pack.read(root/'manifest.json')
            if m['version']!=c['version'] or m['sourceRevision']!=c['sourceRevision'] or m['developmentOnly'] is not True:raise ValueError('component identity differs from release set')
            if m.get('payload',{}).get('file') != 'payload.tar.gz' or pack.sha(root/'payload.tar.gz') != m['payload']['sha256']:raise ValueError('component payload digest differs')
            payload=Path(temp)/f'{name}-payload';pack.safe_extract(root/'payload.tar.gz',payload)
            if pack.artifact.inventory(payload) != m['payload']['files']:raise ValueError('component payload file inventory differs')
            component_inventories[name]=m['payload']['files']
            if name=='runner':pack.verify_deployment(payload,c,manifest['deployment'])
            source=m['sourceContent'];source_root=payload if name=='runner' else root
            if source['file'] != ('metadata/source-content-manifest.json' if name=='runner' else 'source-content.json') or pack.sha(source_root/source['file']) != source['sha256']:raise ValueError('source content binding differs')
            source_content=pack.read(source_root/source['file'])
            if source_content.get('schema') != 'app.loomex.source-content/v1' or source_content.get('sourceRevision') != c['sourceRevision']:raise ValueError('source provenance identity differs')
            bootstrap=m['bootstrap'];entries=[bootstrap] if name=='runner' else [bootstrap['runtime'],bootstrap['manager']]
            for entry in entries:
                file=entry['file']
                if file not in ({'loomex-lifecycle-bootstrap'} if name=='runner' else {'lifecycle-runtime/node','lifecycle.mjs'}):raise ValueError('unexpected bootstrap filename')
                pack.regular(root/file)
                if pack.sha(root/file)!=entry['sha256'] or (root/file).stat().st_size!=entry['size']:raise ValueError('bootstrap inventory differs')

        offline=directory/f"{manifest['releaseTag']}-offline.tar.gz"
        if offline.exists():
            root=Path(temp)/'offline';pack.safe_extract(offline,root)
            required={item['file'] for item in expected}|{'release-set.json','install-preview.sh','INSTALL.txt'}
            actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
            if actual!=required:raise ValueError('offline inventory adds or omits reviewed members')
            for name in required-{'INSTALL.txt'}:
                if pack.sha(root/name)!=items[name]['sha256'] or (root/name).stat().st_size!=items[name]['size']:raise ValueError('offline reviewed member bytes differ')
                expected_mode=0o755 if name in {'install-preview.sh',manifest['installer']['file']} else 0o644
                if (root/name).stat().st_mode & 0o777 != expected_mode:raise ValueError('offline executable/mode inventory differs')
            instructions=f'Explicit unsigned preview only. Verify release-set.json against independently reviewed SHA256 {manifest_digest}.\nLOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 ./loomex-install-darwin-arm64 --offline "$PWD" --manifest-sha256 {manifest_digest} --allow-unsigned-preview\n'
            if (root/'INSTALL.txt').read_bytes()!=instructions.encode() or (root/'INSTALL.txt').stat().st_mode & 0o777 != 0o644:raise ValueError('offline instructions differ from approved transport')
            for item in expected:
                if pack.sha(root/item['file'])!=item['sha256'] or (root/item['file']).stat().st_size!=item['size']:raise ValueError('offline asset binding mismatch')
            if pack.sha(root/'release-set.json')!=items['release-set.json']['sha256']:raise ValueError('offline release-set mismatch')
    return directory,manifest,items,component_inventories

def tag_revision(repo,tag):
    obj=api(f'repos/{repo}/git/ref/tags/{tag}')['object']
    for _ in range(5):
        if obj['type']=='commit':return obj['sha']
        if obj['type']!='tag':raise ValueError('tag does not resolve to commit')
        obj=api(f'repos/{repo}/git/tags/{obj["sha"]}')['object']
    raise ValueError('excessive annotated tag depth')

def remote_prerequisites(manifest):
    if api(f'repos/{REPO}/immutable-releases').get('enabled') is not True:raise ValueError('enable repository immutable releases before the separate operator checkpoint')
    for c in manifest['components'].values():
        if tag_revision(c['repository'],manifest['releaseTag'])!=c['sourceRevision']:raise ValueError('remote component paired tag/source mismatch')

def release_by_tag(tag):
    pages=json.loads(command('gh','api','-H',f'X-GitHub-Api-Version: {API_VERSION}','--paginate','--slurp',f'repos/{REPO}/releases?per_page=100'))
    values=[r for page in pages for r in page if r['tag_name']==tag]
    if len(values)>1:raise ValueError('duplicate remote release identity')
    return values[0] if values else None

def verify_remote_assets(release,inventory,complete):
    remote={}
    for item in release.get('assets',[]):
        name=item['name']
        if name in remote or name not in inventory:raise ValueError('unreviewed/duplicate remote release asset')
        expected=inventory[name]
        if item.get('state')!='uploaded' or item.get('size')!=expected['size'] or item.get('digest')!=f'sha256:{expected["sha256"]}':raise ValueError('remote asset hash/size/state differs; no overwrite permitted')
        remote[name]=item
    if complete and set(remote)!=set(inventory):raise ValueError('remote inventory is incomplete')
    return remote

def verify_release_identity(release,tag,marker,release_id=None,*,expected_body,draft=True,immutable=None):
    if not isinstance(release,dict):raise ValueError('remote release identity missing')
    actual_id=release.get('id')
    if type(actual_id) is not int or actual_id<=0 or release_id is not None and actual_id!=release_id:raise ValueError('remote release ID changed or invalid')
    body=release.get('body')
    if not isinstance(body,str) or body!=expected_body:raise ValueError('remote release body differs from exact reviewed installation guidance')
    markers=[line for line in body.splitlines() if line.startswith('Release-set SHA256: ')] if isinstance(body,str) else []
    if release.get('draft') is not draft or release.get('prerelease') is not True or release.get('tag_name')!=tag or markers!=[marker]:raise ValueError('remote release state/tag/approval marker differs')
    if immutable is not None and release.get('immutable') is not immutable:raise ValueError('immutable terminal release state not proved')
    return actual_id

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=['inspect','stage-draft','resume-draft','publish'])
    p.add_argument('--assets',required=True)
    p.add_argument('--approve-manifest-sha256',help='Explicit separate operator checkpoint for these exact reviewed bytes')
    a=p.parse_args()
    try:
        directory,manifest,inventory,component_inventories=local_inventory(a.assets)
        digest=inventory['release-set.json']['sha256'];tag=manifest['releaseTag']
        review={'releaseTag':tag,'releaseSetSha256':digest,'components':manifest['components'],'deployment':manifest['deployment'],'developmentOnly':True,'assets':inventory,'componentInventories':component_inventories}
        if a.action=='inspect':print(json.dumps(review,indent=2,sort_keys=True));return
        if a.approve_manifest_sha256!=digest:raise ValueError('explicit operator approval must match the inspected release-set SHA256')
        remote_prerequisites(manifest)
        release=release_by_tag(tag)
        marker=f'Release-set SHA256: {digest}'
        expected_body=pack.release_notes(manifest,digest)
        if a.action=='stage-draft':
            if release is not None:raise ValueError('release already exists; inspect exact draft then explicitly resume it')
            notes=directory/'RELEASE-NOTES.md'
            command('gh','release','create',tag,'--repo',REPO,'--verify-tag','--draft','--prerelease','--latest=false','--title',f'Unsigned preview {tag}','--notes-file',str(notes))
            release=release_by_tag(tag)
        release_id=verify_release_identity(release,tag,marker,expected_body=expected_body)
        remote=verify_remote_assets(release,inventory,complete=a.action=='publish')
        if a.action in {'stage-draft','resume-draft'}:
            # No --clobber, no replacement and no rebuild. Ambiguity must be inspected using this exact existing draft.
            for name in sorted(set(inventory)-set(remote)):
                command('gh','release','upload',tag,str(directory/name),'--repo',REPO)
            release=release_by_tag(tag)
            verify_release_identity(release,tag,marker,release_id,expected_body=expected_body)
            verify_remote_assets(release,inventory,complete=True)
            print(json.dumps({'state':'draft-ready','releaseTag':tag,'releaseSetSha256':digest,'url':release['html_url'],'publicationRequiresSeparateExplicitApproval':True}));return
        command('gh','release','edit',tag,'--repo',REPO,'--verify-tag','--draft=false','--prerelease','--latest=false')
        published=release_by_tag(tag)
        verify_release_identity(published,tag,marker,release_id,expected_body=expected_body,draft=False,immutable=True)
        verify_remote_assets(published,inventory,complete=True)
        print(json.dumps({'state':'published-immutable-preview','url':published['html_url'],'releaseSetSha256':digest}))
    except (ValueError,KeyError,OSError,subprocess.CalledProcessError) as error:p.exit(1,f'release action rejected: {error}\n')
if __name__=='__main__':main()
