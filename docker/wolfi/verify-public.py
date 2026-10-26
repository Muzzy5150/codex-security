#!/usr/bin/env python3
"""Verify the public package sources and inventory licenses in the delivered image."""
import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path

WOLFI = "https://packages.wolfi.dev/os"
REGISTRY = "https://registry.npmjs.org/"
APP = "usr/lib/codex-security/"
LICENSES = set("""MIT Apache-2.0 BSD-1-Clause BSD-2-Clause BSD-3-Clause BSD-4-Clause-UC
ISC CC0-1.0 MPL-2.0 PSF-2.0 OLDAP-2.8 Artistic-1.0-Perl GPL-1.0-only GPL-1.0-or-later
GPL-2.0-only GPL-2.0-or-later GPL-3.0-or-later LGPL-2.0-or-later LGPL-2.1 LGPL-2.1-only
LGPL-2.1-or-later LGPL-3.0-or-later GCC-exception-3.1 libselinux-1.0 blessing CC-PDDC AND OR WITH""".split())

def check(ok, message):
    if not ok:
        raise SystemExit(message)

def check_license(name, expression):
    terms = set(re.findall(r"[\w.+-]+", expression or ""))
    check(terms and not (terms - LICENSES), f"Unreviewed license for {name}: {expression}")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("lock", type=Path)
    args = parser.parse_args()
    with tarfile.open(args.archive) as tar:
        manifest, = json.load(tar.extractfile("manifest.json"))
        index, = json.load(tar.extractfile("index.json"))["manifests"]
        config = json.load(tar.extractfile(manifest["Config"]))["config"]
        check(index["platform"] == {"architecture":"amd64", "os":"linux"}, "Expected Linux amd64")
        check(config["Entrypoint"] == ["/usr/local/bin/codex-security-entrypoint"] and config["User"] == "10001:10001", "Unexpected entrypoint or user")
        layer, = manifest["Layers"]
        raw, manifests, keys, native = {}, {}, {}, {}
        with tarfile.open(fileobj=tar.extractfile(layer), mode="r|gz") as fs:
            for ent in fs:
                path = ent.name.removeprefix("./")
                if not ent.isfile():
                    continue
                if path in {"etc/apk/repositories", "usr/lib/apk/db/installed", APP+"package-lock.json",
                            "usr/share/licenses/codex-security/SOURCES.json"}:
                    raw[path] = fs.extractfile(ent).read()
                elif path.startswith("etc/apk/keys/"):
                    keys[path.split("/")[-1]] = hashlib.sha256(fs.extractfile(ent).read()).hexdigest()
                elif path.startswith(APP+"node_modules/") and path.endswith("/package.json"):
                    manifests[path[len(APP):-len("/package.json")]] = json.load(fs.extractfile(ent))
                elif ("/@openai/codex-linux-x64/vendor/" in path and ent.mode & 0o111) or (path.startswith(APP) and path.endswith(".node")):
                    stream = fs.extractfile(ent)
                    h = hashlib.sha256()
                    for chunk in iter(lambda:stream.read(1024*1024), b""):
                        h.update(chunk)
                    native[path] = h.hexdigest()
    check(raw["etc/apk/repositories"].decode().splitlines() == [WOLFI], "Unexpected runtime repository")
    check(set(keys) == {"wolfi-signing.rsa.pub", "melange.rsa.pub"}, "Unexpected runtime APK trust keys")
    apks = []
    lock = {p["name"]:p for p in json.loads(args.lock.read_text())["contents"]["packages"]}
    for record in raw["usr/lib/apk/db/installed"].decode().strip().split("\n\n"):
        fields = dict(line.split(":",1) for line in record.splitlines() if line[:2] in {"P:","V:","L:","o:"})
        name, version, license = fields["P"],fields["V"],fields["L"]
        check_license(name, license)
        item = lock.pop(name)
        check(item["version"] == version, "Lock version mismatch: "+name)
        url = f"{WOLFI}/x86_64/{name}-{version}.apk"
        if name == "codex-security":
            url = f"./packages/x86_64/{name}-{version}.apk"
        check(item["url"] == url, "Unexpected package source: "+item["url"])
        apks.append({"name":name, "version":version, "origin":fields["o"], "license":license, "source":url})
    check(not lock, "Missing locked APKs")
    npm = []
    for path,pkg in json.loads(raw[APP+"package-lock.json"])["packages"].items():
        if not path:
            continue
        meta = manifests[path]
        check(pkg["resolved"].startswith(REGISTRY) and pkg["integrity"].startswith("sha512-"), "Unexpected npm source: "+path)
        check(pkg["version"] == meta["version"] and pkg["license"] == meta["license"], "npm metadata mismatch: "+path)
        check_license(path, meta["license"])
        repository = meta.get("repository")
        npm.append({"path":path, "name":meta["name"], "version":meta["version"], "license":meta["license"],
                    "source":pkg["resolved"], "integrity":pkg["integrity"],
                    "source_repository":repository.get("url") if isinstance(repository,dict) else repository})
    src = json.loads(raw["usr/share/licenses/codex-security/SOURCES.json"])
    records = src["native_executables_and_addons"]
    check(len(records) == 6 and all(p["source"].startswith("https://github.com/") for p in records),
          "Unknown native runtime source")
    check({APP+p["path"]:p["sha256"] for p in records} == native, "Native files differ from source inventory")
    print(json.dumps({"image_manifest":index["digest"], "platform":"linux/amd64", "apk_repository":WOLFI,
        "apk_trust_sha256":keys, "apk_count":len(apks), "installed_apks":sorted(apks,key=lambda p:p["name"]),
        "npm_package_count":len(npm), "installed_npm":npm, "bundled_native":records,
        "scope":"Installed package sources and declared licenses. The model service is external to the image."
    }, indent=2))

if __name__ == "__main__":
    main()
