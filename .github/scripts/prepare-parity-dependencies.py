"""Prepare the reviewed dependency additions on a Linux runner."""

from pathlib import Path
import tomllib

path = Path("Cargo.toml")
text = path.read_text()
dependencies = tomllib.loads(text)["dependencies"]
additions = []
if "blake3" not in dependencies:
    additions.append('blake3 = "1.8"')
if "ml-kem" not in dependencies:
    additions.append('ml-kem = { version = "=0.3.2", features = ["zeroize"] }')
if additions:
    marker = 'sha2 = "0.10"\n'
    if text.count(marker) != 1:
        raise SystemExit("Expected one SHA-2 dependency insertion anchor")
    text = text.replace(marker, marker + "\n".join(additions) + "\n", 1)
    path.write_text(text)
prepared = tomllib.loads(text)["dependencies"]
assert prepared["blake3"] == "1.8"
assert prepared["ml-kem"]["version"] == "=0.3.2"
assert "zeroize" in prepared["ml-kem"]["features"]
print("Prepared BLAKE3 and deterministic ML-KEM dependencies")
