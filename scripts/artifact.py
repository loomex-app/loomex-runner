#!/usr/bin/env python3
"""Create and verify Loomex's deterministic release envelope."""
from __future__ import annotations
import argparse, gzip, hashlib, json, os, shutil, stat, subprocess, tarfile, tempfile
from pathlib import Path, PurePosixPath

def digest(path: Path) -> str:
    value=hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024*1024), b""): value.update(chunk)
    return value.hexdigest()

def inventory(root: Path) -> list[dict[str, object]]:
    result=[]
    for path in sorted(root.rglob("*")):
        relative=path.relative_to(root)
        if path.is_symlink(): raise SystemExit(f"release payload may not contain symlinks: {relative}")
        if path.is_file():
            result.append({"path":relative.as_posix(),"sha256":digest(path),"size":path.stat().st_size,"mode":stat.S_IMODE(path.stat().st_mode)})
    return result

def deterministic_tar(root: Path, output: Path, epoch: int) -> None:
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open("wb") as raw, gzip.GzipFile(filename="",mode="wb",fileobj=raw,mtime=epoch) as zipped, tarfile.open(fileobj=zipped,mode="w",format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(root.rglob("*")):
            relative=path.relative_to(root).as_posix(); info=archive.gettarinfo(str(path),relative)
            info.uid=info.gid=0; info.uname=info.gname=""; info.mtime=epoch
            if info.isfile():
                with path.open("rb") as handle: archive.addfile(info,handle)
            elif info.isdir(): archive.addfile(info)
            else: raise SystemExit(f"unsupported payload entry: {relative}")

def canonical(data: object) -> bytes:
    return (json.dumps(data,sort_keys=True,separators=(",",":"))+"\n").encode()

def git_paths(root: Path, *arguments: str) -> list[str]:
    completed=subprocess.run(
        ["git","-C",str(root),"ls-files","-z",*arguments],
        check=True,capture_output=True,
    )
    try: return [value.decode("utf-8") for value in completed.stdout.split(b"\0") if value]
    except UnicodeDecodeError as error: raise SystemExit("source paths must be valid UTF-8") from error

def source_entry(root: Path, relative: str, tracked: bool) -> dict[str,object]:
    path=root/relative
    try: details=path.lstat()
    except FileNotFoundError:
        if tracked: return {"path":relative,"type":"missing","tracked":True}
        raise SystemExit(f"untracked source disappeared while inventorying: {relative}")
    if stat.S_ISLNK(details.st_mode):
        content=os.fsencode(os.readlink(path)); kind="symlink"; mode="120000"
        sha256=hashlib.sha256(content).hexdigest(); size=len(content)
    elif stat.S_ISREG(details.st_mode):
        kind="file"; mode="100755" if details.st_mode & 0o111 else "100644"
        sha256=digest(path); size=details.st_size
    else: raise SystemExit(f"unsupported source entry: {relative}")
    return {"path":relative,"type":kind,"tracked":tracked,"mode":mode,"size":size,"sha256":sha256}

def source_manifest(root: Path, revision: str) -> dict[str,object]:
    tracked=set(git_paths(root,"--cached"))
    selected=set(git_paths(root,"--cached","--others","--exclude-standard"))
    return {
        "schema":"app.loomex.source-content/v1",
        "sourceRevision":revision,
        "files":[source_entry(root,relative,relative in tracked) for relative in sorted(selected)],
    }

def validate_source_manifest(data: object) -> dict[str,object]:
    if not isinstance(data,dict) or data.get("schema")!="app.loomex.source-content/v1": raise SystemExit("source content manifest schema mismatch")
    if not isinstance(data.get("sourceRevision"),str) or not data["sourceRevision"]: raise SystemExit("source content revision missing")
    files=data.get("files")
    if not isinstance(files,list): raise SystemExit("source content files missing")
    paths=[]
    for entry in files:
        if not isinstance(entry,dict) or not isinstance(entry.get("path"),str) or entry["path"] in paths: raise SystemExit("invalid source content path")
        paths.append(entry["path"])
        if PurePosixPath(entry["path"]).is_absolute() or ".." in PurePosixPath(entry["path"]).parts: raise SystemExit("unsafe source content path")
        expected={"path","type","tracked"} if entry.get("type")=="missing" else {"path","type","tracked","mode","size","sha256"}
        if set(entry)!=expected or entry.get("type") not in {"file","symlink","missing"} or not isinstance(entry.get("tracked"),bool): raise SystemExit(f"invalid source content entry: {entry.get('path','<unknown>')}")
        if entry.get("type")=="missing" and not entry["tracked"]: raise SystemExit("untracked source cannot be missing")
        if entry.get("type")!="missing" and (not isinstance(entry.get("size"),int) or entry["size"]<0 or not isinstance(entry.get("sha256"),str) or len(entry["sha256"])!=64): raise SystemExit(f"invalid source content digest: {entry['path']}")
    if paths!=sorted(paths): raise SystemExit("source content paths are not sorted")
    return data

def write_source(args: argparse.Namespace) -> None:
    root=Path(args.source_root).resolve(); output=Path(args.output).resolve()
    if not root.is_dir(): raise SystemExit("source root does not exist")
    data=source_manifest(root,args.source_revision); output.parent.mkdir(parents=True,exist_ok=True)
    if output.exists(): raise SystemExit("source content manifest already exists")
    output.write_bytes(canonical(data))
    if args.snapshot:
        destination=Path(args.snapshot).resolve()
        try: destination.mkdir(parents=True,exist_ok=False)
        except FileExistsError: raise SystemExit("source snapshot already exists")
        for entry in data["files"]:
            if entry["type"]=="missing": continue
            source=root/str(entry["path"]); target=destination/str(entry["path"]); target.parent.mkdir(parents=True,exist_ok=True)
            if entry["type"]=="symlink": target.symlink_to(os.readlink(source))
            else: shutil.copy2(source,target)
        verify_source_data(data,destination,exact_snapshot=True)

def verify_source_data(data: dict[str,object], root: Path, exact_snapshot: bool=False) -> None:
    expected=data["files"]
    if exact_snapshot:
        actual_paths=sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if not stat.S_ISDIR(path.lstat().st_mode))
        expected_paths=sorted(str(entry["path"]) for entry in expected if entry["type"]!="missing")
        if actual_paths!=expected_paths: raise SystemExit("source snapshot path mismatch")
        actual=[source_entry(root,str(entry["path"]),bool(entry["tracked"])) if entry["type"]!="missing" else entry for entry in expected]
    else:
        actual=source_manifest(root,str(data["sourceRevision"]))["files"]
    if actual!=expected: raise SystemExit("source content mismatch")

def verify_source(args: argparse.Namespace) -> None:
    manifest_path=Path(args.manifest).resolve(); data=validate_source_manifest(json.loads(manifest_path.read_text()))
    if canonical(data)!=manifest_path.read_bytes(): raise SystemExit("source content manifest is not canonical JSON")
    if not args.source_root: return
    root=Path(args.source_root).resolve()
    inside_git=subprocess.run(["git","-C",str(root),"rev-parse","--is-inside-work-tree"],capture_output=True,text=True).stdout.strip()=="true"
    verify_source_data(data,root,exact_snapshot=not inside_git)

def openssl(*arguments: str) -> None:
    subprocess.run(["openssl",*arguments],check=True)

def create(args: argparse.Namespace) -> None:
    root=Path(args.payload).resolve(); destination=Path(args.output).resolve()
    if not root.is_dir(): raise SystemExit("payload directory does not exist")
    if args.unsigned_development == bool(args.signing_key): raise SystemExit("choose exactly one signing mode")
    source_path=root/"metadata/source-content-manifest.json"
    if not source_path.is_file(): raise SystemExit("source content manifest required for artifact creation")
    source_data=validate_source_manifest(json.loads(source_path.read_text()))
    if canonical(source_data)!=source_path.read_bytes() or source_data["sourceRevision"]!=args.source_revision: raise SystemExit("source content manifest does not match release revision")
    epoch=int(os.environ.get("SOURCE_DATE_EPOCH","0"))
    try: destination.mkdir(parents=True,exist_ok=False)
    except FileExistsError: raise SystemExit("release output already exists")
    archive=destination/"payload.tar.gz"; deterministic_tar(root,archive,epoch)
    manifest={"schema":"app.loomex.release/v1","project":args.project,"version":args.version,"platform":args.platform,"sourceRevision":args.source_revision,"sourceDateEpoch":epoch,"developmentOnly":args.unsigned_development,"payload":{"file":archive.name,"sha256":digest(archive),"files":inventory(root)}}
    manifest["sourceContent"]={"file":"metadata/source-content-manifest.json","sha256":digest(source_path)}
    manifest_path=destination/"manifest.json"; manifest_path.write_bytes(canonical(manifest))
    signature=destination/"manifest.sig"
    if args.signing_key: openssl("dgst","-sha256","-sign",args.signing_key,"-out",str(signature),str(manifest_path))
    else: signature.unlink(missing_ok=True)

def verified(args: argparse.Namespace) -> tuple[Path,dict[str,object]]:
    release=Path(args.release).resolve(); manifest_path=release/"manifest.json"; manifest=json.loads(manifest_path.read_text())
    if canonical(manifest)!=manifest_path.read_bytes(): raise SystemExit("manifest is not canonical JSON")
    if manifest.get("schema")!="app.loomex.release/v1" or manifest.get("project")!=args.project or manifest.get("platform")!=args.platform: raise SystemExit("release provenance mismatch")
    signature=release/"manifest.sig"
    if manifest.get("developmentOnly"):
        if not args.allow_unsigned_development: raise SystemExit("unsigned development artifact rejected")
        if signature.exists(): raise SystemExit("development artifact unexpectedly signed")
    else:
        if not args.public_key or not signature.is_file(): raise SystemExit("signed artifact and trusted public key required")
        openssl("dgst","-sha256","-verify",args.public_key,"-signature",str(signature),str(manifest_path))
    archive=release/str(manifest["payload"]["file"])
    if digest(archive)!=manifest["payload"]["sha256"]: raise SystemExit("payload digest mismatch")
    return archive,manifest

def verify_or_extract(args: argparse.Namespace) -> None:
    archive,manifest=verified(args)
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary)
        with tarfile.open(archive,"r:gz") as source:
            for member in source.getmembers():
                value=PurePosixPath(member.name)
                if value.is_absolute() or ".." in value.parts or member.issym() or member.islnk() or member.isdev(): raise SystemExit(f"unsafe archive member: {member.name}")
            for member in source.getmembers(): source.extract(member,root)
        if inventory(root)!=manifest["payload"]["files"]: raise SystemExit("payload inventory mismatch")
        source_binding=manifest.get("sourceContent")
        if source_binding is not None:
            if not isinstance(source_binding,dict) or source_binding.get("file")!="metadata/source-content-manifest.json" or set(source_binding)!={"file","sha256"}: raise SystemExit("source content binding mismatch")
            source_path=root/source_binding["file"]
            if not source_path.is_file() or digest(source_path)!=source_binding["sha256"]: raise SystemExit("source content digest mismatch")
            source_data=validate_source_manifest(json.loads(source_path.read_text()))
            if canonical(source_data)!=source_path.read_bytes() or source_data["sourceRevision"]!=manifest["sourceRevision"]: raise SystemExit("source content provenance mismatch")
            if args.source_root: verify_source_data(source_data,Path(args.source_root).resolve())
        elif not args.allow_legacy_source_provenance: raise SystemExit("release has no source content provenance; explicit legacy compatibility required")
        if args.extract:
            destination=Path(args.extract).resolve()
            if destination.exists(): raise SystemExit("extraction destination already exists")
            shutil.copytree(root,destination)

parser=argparse.ArgumentParser(); sub=parser.add_subparsers(required=True)
source_make=sub.add_parser("source-manifest")
source_make.add_argument("--source-root",required=True); source_make.add_argument("--source-revision",required=True); source_make.add_argument("--output",required=True); source_make.add_argument("--snapshot"); source_make.set_defaults(run=write_source)
source_check=sub.add_parser("verify-source")
source_check.add_argument("--source-root"); source_check.add_argument("--manifest",required=True); source_check.set_defaults(run=verify_source)
make=sub.add_parser("create")
for name in ("payload","output","project","version","platform","source_revision"): make.add_argument("--"+name.replace("_","-"),required=True)
make.add_argument("--signing-key"); make.add_argument("--unsigned-development",action="store_true"); make.set_defaults(run=create)
for command in ("verify","extract"):
    item=sub.add_parser(command); item.add_argument("--release",required=True); item.add_argument("--project",required=True); item.add_argument("--platform",required=True); item.add_argument("--public-key"); item.add_argument("--allow-unsigned-development",action="store_true"); item.add_argument("--allow-legacy-source-provenance",action="store_true"); item.add_argument("--source-root")
    if command=="extract": item.add_argument("--extract",required=True)
    else: item.set_defaults(extract=None)
    item.set_defaults(run=verify_or_extract)
args=parser.parse_args(); args.run(args)
