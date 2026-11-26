"""Validate parity dependencies without rewriting the reviewed manifest."""

from pathlib import Path
import tomllib

path = Path("Cargo.toml")
dependencies = tomllib.loads(path.read_text())["dependencies"]
for name in ("blake3", "ml-kem"):
    if name not in dependencies:
        raise SystemExit(f"Missing reviewed parity dependency: {name}")
if "zeroize" not in dependencies["ml-kem"].get("features", []):
    raise SystemExit("Deterministic ML-KEM parity requires the zeroize feature")
print("Validated reviewed BLAKE3 and deterministic ML-KEM dependencies")
