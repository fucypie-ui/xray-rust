"""Audit every manifest dependency against official crates.io stable releases."""

import argparse
import concurrent.futures
import datetime
import json
from pathlib import Path
import re
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
MANIFESTS = [Path("Cargo.toml"), Path("debug_panel/dioxus_app/Cargo.toml")]
USER_AGENT = "xray-rust-dependency-audit/1.0 (https://github.com/fucypie-ui/xray-rust)"
STABLE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:\+[0-9A-Za-z.-]+)?$")


def direct_dependencies(path):
    data = tomllib.loads((ROOT / path).read_text())
    groups = [("", data)] + [(f"target.{target}.", group) for target, group in data.get("target", {}).items()]
    for prefix, group in groups:
        for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
            for alias, value in group.get(kind, {}).items():
                value = {"version": value} if isinstance(value, str) else value
                if "version" not in value:
                    raise ValueError(f"Unversioned dependency needs explicit review: {path}: {alias}")
                yield {"manifest": str(path), "section": prefix + kind, "alias": alias, "crate": value.get("package", alias), "previous_requirement": value["version"]}


def latest(crate):
    url = f"https://crates.io/api/v1/crates/{crate}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=90) as response:
        data = json.load(response)
    releases = [v for v in data["versions"] if not v["yanked"] and STABLE.fullmatch(v["num"])]
    release = max(releases, key=lambda v: tuple(map(int, STABLE.fullmatch(v["num"]).groups())))
    return crate, {"latest_stable": release["num"], "yanked": release["yanked"], "published_at": release["created_at"], "rust_version": release.get("rust_version"), "source": url, "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}


def update_manifest(path, entries):
    lines = (ROOT / path).read_text().splitlines(keepends=True)
    for entry in entries:
        pattern = re.compile(r"^(" + re.escape(entry["alias"]) + r"\s*=\s*)(?:\"([^\"]+)\"|\{.*?\bversion\s*=\s*\"([^\"]+)\")")
        candidates = [(i, pattern.match(line)) for i, line in enumerate(lines) if pattern.match(line)]
        # A crate repeated in multiple target sections still receives the same latest release.
        for i, match in candidates:
            group = 2 if match.group(2) is not None else 3
            start, end = match.span(group)
            lines[i] = lines[i][:start] + entry["requirement"] + lines[i][end:]
        if not candidates:
            raise ValueError(f"Missing dependency assignment: {path}: {entry['alias']}")
    (ROOT / path).write_text("".join(lines))


def verify_lock(metadata_path, manifest):
    evidence = json.loads((ROOT / "md/DEPENDENCY_UPGRADE.json").read_text())
    metadata = json.loads(Path(metadata_path).read_text())
    packages = {p["id"]: p for p in metadata["packages"]}
    root = next(p for p in packages.values() if Path(p["manifest_path"]).resolve() == (ROOT / manifest).resolve())
    node = next(n for n in metadata["resolve"]["nodes"] if n["id"] == root["id"])
    selected = {d["pkg"] for d in node["deps"]}
    current = list(direct_dependencies(Path(manifest)))
    recorded = [e for e in evidence["dependencies"] if e["manifest"] == manifest]
    key = lambda e: (e["section"], e["alias"], e["crate"])
    if sorted(map(key, current)) != sorted(map(key, recorded)):
        raise ValueError(f"{manifest}: dependency sections differ from the official registry audit")
    requirements = {key(e): e["previous_requirement"] for e in current}
    for entry in recorded:
        if requirements[key(entry)] != entry["requirement"]:
            raise ValueError(f"{manifest}: unaudited requirement for {entry['alias']}")
    overrides = evidence.get("source_overrides", {}) if manifest == "Cargo.toml" else {}
    actual_patches = tomllib.loads((ROOT / manifest).read_text()).get("patch", {}).get("crates-io", {})
    if set(actual_patches) != set(overrides):
        raise ValueError(f"{manifest}: unaudited registry source override")
    checked = []
    for entry in evidence["dependencies"]:
        if entry["manifest"] != manifest:
            continue
        matches = [packages[p] for p in selected if packages[p]["name"] == entry["crate"]]
        versions = sorted({p["version"] for p in matches})
        if versions != [entry["latest_stable"]]:
            raise ValueError(f"{manifest}: {entry['alias']}: expected {entry['latest_stable']}, resolved {versions}")
        if override := overrides.get(entry["crate"]):
            patch = actual_patches[entry["crate"]]
            if any(patch.get(k) != override[k] for k in ("git", "rev")):
                raise ValueError(f"Unreviewed source override: {entry['crate']}")
            expected = f"git+{override['git']}?rev={override['rev']}#{override['rev']}"
            if any(p.get("source") != expected for p in matches):
                raise ValueError(f"{entry['crate']}: expected pinned source {expected}")
        checked.append({"alias": entry["alias"], "crate": entry["crate"], "version": versions[0], "section": entry["section"], "sources": sorted({p["source"] for p in matches})})
    print(json.dumps({"manifest": manifest, "direct_dependencies_verified": len(checked), "dependencies": checked}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update", action="store_true")
    parser.add_argument("--verify-metadata")
    parser.add_argument("--manifest", default="Cargo.toml")
    args = parser.parse_args()
    if args.verify_metadata:
        verify_lock(args.verify_metadata, args.manifest)
        return
    entries = [entry for path in MANIFESTS for entry in direct_dependencies(path)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        releases = dict(executor.map(latest, sorted({entry["crate"] for entry in entries})))
    for entry in entries:
        entry.update(releases[entry["crate"]])
        entry["requirement"] = ("=" if entry["previous_requirement"].startswith("=") else "") + entry["latest_stable"]
    if args.update:
        for path in MANIFESTS:
            update_manifest(path, [entry for entry in entries if entry["manifest"] == str(path)])
    evidence = {"selection": "Maximum semantic version with no prerelease component and yanked=false; official crates.io API; all direct, target, dev and build dependency sections in both manifests.", "dependencies": entries}
    previous_path = ROOT / "md/DEPENDENCY_UPGRADE.json"
    if previous_path.exists():
        previous = json.loads(previous_path.read_text())
        for name in ("source_overrides", "replaced_dependencies"):
            if name in previous:
                evidence[name] = previous[name]
    (ROOT / "md/DEPENDENCY_UPGRADE.json").write_text(json.dumps(evidence, indent=2) + "\n")
    report = ["# Dependency upgrade audit", "", f"Verified from the official crates.io API on {datetime.datetime.now(datetime.timezone.utc).isoformat()} (UTC).", "", evidence["selection"], "", "The table records registry evidence, not a build-success claim. Linux resolver and CI results are recorded below after validation. No Rust, Cargo, rustc, or Go installation or execution is performed on Android.", "", "| Manifest / section | Dependency (registry package) | Previous requirement | Latest stable / new requirement | Published (UTC) | Source |", "| --- | --- | --- | --- | --- | --- |"]
    for e in entries:
        report.append(f"| `{e['manifest']}` / `{e['section']}` | `{e['alias']}` (`{e['crate']}`) | `{e['previous_requirement']}` | `{e['latest_stable']}` / `{e['requirement']}` | {e['published_at']} | [crates.io API]({e['source']}) |")
    report.extend(["", "## Migration and Linux validation", "", "Pending Linux resolution, API migrations, strict CI, and pinned Go fixture comparison.", ""])
    (ROOT / "md/DEPENDENCY_UPGRADE.md").write_text("\n".join(report))
    print(json.dumps({"direct_entries": len(entries), "unique_registry_packages": len(releases), "latest": {name: release['latest_stable'] for name, release in releases.items()}}, indent=2))


if __name__ == "__main__":
    main()
