#!/usr/bin/env bash
# Build and verify a local linux/amd64 image from the public Wolfi repository.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./build.sh [NEW_OUTPUT_DIR]   (default: ./build next to this script)
Requires Linux with an x86_64-capable melange/bubblewrap runner, melange 0.61.1,
apko 1.4.13, Python 3.9+ with PyYAML, OpenSSL, and npm 11 for payload staging.
APKO and MELANGE optionally name the installed tool executables.
STAGED_PAYLOAD optionally names an absolute path to an already staged payload
matching the hash in melange.yaml. All OS packages come from packages.wolfi.dev.
Each run generates a new local signing key and removes the private key at exit.
EOF
}
die() { printf '%s\n' "$*" >&2; exit 1; }
[[ ${1:-} != -h && ${1:-} != --help ]] || { usage; exit 0; }
[[ $# -le 1 && ${1:-} != -* ]] || { usage >&2; exit 2; }
root=$(cd "$(dirname "$0")" && pwd -P)
out=${1:-"$root/build"}
apko=${APKO:-apko}; melange=${MELANGE:-melange}
"$apko" version | grep -Eq '^GitVersion:[[:space:]]+v1\.4\.13$' || die 'Expected apko 1.4.13'
"$melange" version | grep -Eq '^GitVersion:[[:space:]]+v0\.61\.1$' || die 'Expected melange 0.61.1'
python3 -c 'import sys, yaml; sys.exit(0 if sys.version_info >= (3,9) else "Python 3.9+ required")'
if [[ -n ${STAGED_PAYLOAD:-} ]]; then
  [[ $STAGED_PAYLOAD == /* && -f $STAGED_PAYLOAD ]] || die 'STAGED_PAYLOAD must be an existing absolute file path'
else
  [[ $(npm --version) == 11.* ]] || die 'Expected npm 11'
fi
mkdir -p "$(dirname "$out")"
(umask go-w; mkdir "$out") || die 'Use a new output directory for each build'
cd "$out"; out=$(pwd -P)
scratch=$(mktemp -d /tmp/codex-security-build.XXXXXXXX)
trap 'rm -rf -- "$scratch"' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM
unset HTTP_AUTH SOURCE_DATE_EPOCH
mkdir -p src packages sbom
cp "$root"/{wolfi-signing.rsa.pub,apko.yaml,melange.yaml,build-inputs.json} .
(cd "$scratch"; "$melange" keygen melange.rsa)
cp "$scratch/melange.rsa.pub" .
stamp=2026-10-26T11:30:14Z
repo=https://packages.wolfi.dev/os

# The snapshots record every transitive public package, not just the requested tools.
python3 - "$repo" <<'PY'
import hashlib, json, sys
from pathlib import Path
import yaml
m=json.loads(Path("build-inputs.json").read_text()); repo=sys.argv[1]
if m["repository"]!=repo or hashlib.sha256(Path("wolfi-signing.rsa.pub").read_bytes()).hexdigest()!=m["wolfi_key_sha256"]:
    raise ValueError("Unexpected public Wolfi repository or signing key")
snap=m["snapshots"]; wk="./wolfi-signing.rsa.pub"; lk="./melange.rsa.pub"
def save(name,obj): Path(name).write_text(json.dumps(obj,indent=2)+"\n")
save("builder.yaml",{"archs":["x86_64"],"contents":{"repositories":[repo],"keyring":[wk],"packages":snap["builder"]["packages"]}})
cfg=yaml.safe_load(Path("apko.yaml").read_text()); c=cfg["contents"]
if c["repositories"]!=[repo] or c["build_repositories"]!=["./packages"] or c["keyring"]!=[wk,lk] or c.get("runtime_repositories"):
    raise ValueError("Only the public Wolfi repository and the local signed APK repository are expected")
# PyYAML parses YAML 1.2 octal literals as strings. apko accepts numeric modes.
for item in cfg.get("paths",[]):
    if isinstance(item.get("permissions"),str): item["permissions"]=int(item["permissions"],0)
versions=dict(v.split("=",1) for v in snap["runtime"]["packages"])
p=yaml.safe_load(Path("melange.yaml").read_text())["package"]; local=p["name"]+"="+str(p["version"])+"-r"+str(p["epoch"])
if local!=m["local_package"]: raise ValueError(f"Unexpected local release package: {local}")
for spec in c["packages"]:
    if spec==local: continue
    name,_,ver=spec.partition("=")
    if name not in versions or (ver and versions[name]!=ver): raise ValueError(f"Unpinned package: {spec}")
if local not in c["packages"]: raise ValueError(f"The image does not depend on its signed scanner package: {local}")
c["packages"]=sorted(set(snap["runtime"]["packages"])|{local})
save("image.yaml",cfg)
PY

# Verify the lock's origin, architecture, control/data checksums and exact keyring.
check_lock() {
  python3 - "$1" "$2" <<'PY'
import hashlib, json, sys
from pathlib import Path
m=json.loads(Path("build-inputs.json").read_text()); which=sys.argv[1]; snap=m["snapshots"][which]
c=json.loads(Path(sys.argv[2]).read_text())["contents"]; local_spec=m["local_package"]
rows=[]; local=[]
for p in c["packages"]:
    n=p["name"]; v=p["version"]; filename=f"{n}-{v}.apk"
    if p["architecture"]!="x86_64": raise ValueError(f"Unexpected architecture: {n}")
    if p["url"]=="./packages/x86_64/"+filename: local.append(n+"="+v)
    else:
        if p["url"]!=m["repository"]+"/x86_64/"+filename: raise ValueError(f"Unexpected package URL: {n}")
        rows.append({k:v for k,v in p.items() if k!="url"})
rows.sort(key=lambda r:r["name"])
digest=hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(",",":")).encode()).hexdigest()
if digest!=snap["lock_identity_sha256"] or local!=([] if which=="builder" else [local_spec]):
    raise ValueError(f"{which}: package identities differ from the public snapshot")
keys={(Path(k["name"]).name,k["content"]) for k in c["keyring"]}
expected={"wolfi-signing.rsa.pub":Path("wolfi-signing.rsa.pub").read_text()}
if which=="runtime": expected["melange.rsa.pub"]=Path("melange.rsa.pub").read_text()
if keys!=set(expected.items()): raise ValueError(f"{which}: unrecognized or missing APK signing keys")
PY
}
"$apko" lock builder.yaml --arch x86_64 --output builder.lock.json --cache-dir "$scratch/cache"
check_lock builder builder.lock.json
if [[ -n ${STAGED_PAYLOAD:-} ]]; then
  cp "$STAGED_PAYLOAD" src/payload.tar.gz
else
  python3 "$root/payload/stage.py" "$out/src"
fi
pins=$(python3 -c 'import json; print(",".join(json.load(open("builder.yaml"))["contents"]["packages"]))')
"$melange" build melange.yaml --source-dir "$out/src" --arch x86_64 --runner bubblewrap \
  --signing-key "$scratch/melange.rsa" --generate-index --generate-provenance --out-dir "$out/packages" \
  --repository-append "$repo" --keyring-append "$out/wolfi-signing.rsa.pub" --package-append "$pins" \
  --build-date "$stamp" --apk-cache-dir "$scratch/cache" --cache-dir "$scratch/melange-cache"
"$apko" lock image.yaml --arch x86_64 --output image.lock.json --cache-dir "$scratch/cache"
check_lock runtime image.lock.json
tag=codex-security:wolfi
"$apko" build image.yaml "$tag" .image.unverified.tar --arch x86_64 --lockfile image.lock.json \
  --cache-dir "$scratch/cache" --vcs=false --sbom-path ./sbom --build-date "$stamp"

# Inspect the packaged root filesystem, not just the input configuration.
python3 - <<'PY'
import hashlib, json, tarfile
from pathlib import Path
m=json.loads(Path("build-inputs.json").read_text()); lock=json.loads(Path("image.lock.json").read_text())
expected_keys={k:Path(k).read_bytes() for k in ("wolfi-signing.rsa.pub","melange.rsa.pub")}; keys={}; repos=[]
wanted={(p["name"],p["version"]) for p in lock["contents"]["packages"]}; installed=set()
image_cfg=json.loads(Path("image.yaml").read_text()); entrypoint=image_cfg["entrypoint"]["command"]
executable=False
with tarfile.open(".image.unverified.tar") as image:
    manifest,=json.load(image.extractfile("manifest.json")); layer_name,=manifest["Layers"]
    ib=json.load(image.extractfile("index.json")); desc,=ib["manifests"]; ob=image.extractfile(desc["digest"]).read()
    def digest(b): return "sha256:"+hashlib.sha256(b).hexdigest()
    if digest(ob)!=desc["digest"]: raise ValueError("OCI manifest checksum mismatch")
    oci=json.loads(ob); cfg_bytes=image.extractfile(manifest["Config"]).read(); cfg=json.loads(cfg_bytes); c=cfg["config"]
    if digest(cfg_bytes)!=oci["config"]["digest"] or manifest["Config"]!=oci["config"]["digest"]: raise ValueError("Image configuration checksum mismatch")
    if (cfg["os"],cfg["architecture"],c["Entrypoint"],c["Cmd"],c["User"])!=("linux","amd64",[entrypoint],[image_cfg["cmd"]],image_cfg["accounts"]["run-as"]):
        raise ValueError("Image platform, user, entrypoint or default command mismatch")
    compressed=hashlib.sha256()
    with image.extractfile(layer_name) as stream:
        for block in iter(lambda:stream.read(1024*1024),b""): compressed.update(block)
    if "sha256:"+compressed.hexdigest()!=oci["layers"][0]["digest"]: raise ValueError("Compressed layer checksum mismatch")
    with tarfile.open(fileobj=image.extractfile(layer_name),mode="r|gz") as layer:
        for e in layer:
            name=e.name.removeprefix("./")
            if name.startswith("etc/apk/keys/"):
                if not e.isreg(): raise ValueError(f"Unexpected public key format: {name}")
                keys[name.split("/")[-1]]=layer.extractfile(e).read()
            elif name=="etc/apk/repositories": repos=layer.extractfile(e).read().decode().splitlines()
            elif name in ("usr/lib/apk/db/installed","lib/apk/db/installed"):
                for stanza in layer.extractfile(e).read().decode().strip().split("\n\n"):
                    lines=dict(line.split(":",1) for line in stanza.splitlines() if ":" in line)
                    installed.add((lines["P"],lines["V"]))
            elif name==entrypoint.lstrip("/"): executable=e.isreg() and bool(e.mode & 0o111)
            elif Path(name).name == "melange.rsa":
                raise ValueError(f"Signing private key in the image: {name}")
if keys!=expected_keys or repos!=[m["repository"]] or installed!=wanted or not executable:
    raise ValueError("Installed packages, entrypoint or APK trust configuration differ from the reviewed image")
Path("verification.json").write_text(json.dumps({"platform":"linux/amd64","tag":manifest["RepoTags"][0],
    "config_digest":manifest["Config"],"oci_manifest":desc["digest"],"runtime_repositories":repos,
    "entrypoint":entrypoint,"user":c["User"],"public_upstream_packages":len(installed)-1,
    "local_scanner_packages":1,"keyring_sha256":{n:digest(b) for n,b in sorted(keys.items())},
    "signed_build_manifest":"SHA256SUMS","manifest_signature":"SHA256SUMS.sig"},indent=2)+"\n")
PY
python3 "$root/verify-public.py" .image.unverified.tar image.lock.json > public-components.json
mv .image.unverified.tar image.tar
# This single detached signature covers the image, locks, SBOMs and signed local APK evidence.
sha256sum build-inputs.json builder.yaml builder.lock.json apko.yaml image.yaml image.lock.json melange.yaml \
  melange.rsa.pub wolfi-signing.rsa.pub verification.json public-components.json image.tar sbom/*.spdx.json \
  packages/x86_64/APKINDEX.tar.gz packages/x86_64/*.apk packages/x86_64/*.attest.tar.gz > SHA256SUMS
openssl dgst -sha256 -sign "$scratch/melange.rsa" -out SHA256SUMS.sig SHA256SUMS
openssl dgst -sha256 -verify melange.rsa.pub -signature SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS
loaded_tag=$(python3 -c 'import json; print(json.load(open("verification.json"))["tag"])')
printf 'Built %s: %s/image.tar\n' "$loaded_tag" "$out"
