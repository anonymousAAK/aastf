"""ScenarioPack abstraction — versioned, composable, verifiable scenario packs."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import tarfile
from collections import defaultdict
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .models.scenario import AttackScenario
from .scenarios.loader import load_directory
from .scenarios.registry import _BUILTIN_DIR

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ScenarioPack(BaseModel):
    """A versioned, signable collection of attack scenarios."""

    name: str
    version: str
    description: str
    author: str
    scenarios: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    signature: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PackManifest(BaseModel):
    """Top-level manifest listing all packs."""

    packs: list[ScenarioPack] = Field(default_factory=list)
    registry_url: str | None = None


# ---------------------------------------------------------------------------
# Builtin pack definitions
# ---------------------------------------------------------------------------

_BUILTIN_PACK_DEFS: dict[str, dict[str, Any]] = {
    "aastf/owasp-asi": {
        "prefix_pattern": r"^ASI\d{2}-\d{3}$",
        "description": "OWASP ASI Top 10 attack scenarios",
        "version": "1.0.0",
    },
    "aastf/mcp": {
        "prefix_pattern": r"^MCP\d{2}-\d{3}$",
        "description": "Model Context Protocol security scenarios",
        "version": "1.0.0",
    },
    "aastf/cve": {
        "prefix_pattern": r"^CVE\d{2}-\d{3}$",
        "description": "CVE-based attack scenarios",
        "version": "1.0.0",
    },
}


# ---------------------------------------------------------------------------
# PackManager
# ---------------------------------------------------------------------------


class PackManager:
    """Manage scenario packs: list, install, sign, verify, export, load, compose."""

    def __init__(self, packs_dir: Path | None = None) -> None:
        self._packs_dir = packs_dir or Path(".aastf/packs")

    @property
    def packs_dir(self) -> Path:
        return self._packs_dir

    # ------------------------------------------------------------------ list

    def list_installed(self) -> list[ScenarioPack]:
        """Return all packs installed in the local packs directory."""
        if not self._packs_dir.exists():
            return []
        packs: list[ScenarioPack] = []
        for manifest_path in sorted(self._packs_dir.rglob("pack.json")):
            raw = manifest_path.read_text(encoding="utf-8")
            packs.append(ScenarioPack.model_validate_json(raw))
        return packs

    def list_builtin(self) -> list[ScenarioPack]:
        """Auto-detect builtin packs by grouping scenarios by ID prefix."""
        scenarios = load_directory(_BUILTIN_DIR)
        grouped: dict[str, list[AttackScenario]] = defaultdict(list)

        for s in scenarios:
            for pack_name, pack_def in _BUILTIN_PACK_DEFS.items():
                if re.match(pack_def["prefix_pattern"], s.id):
                    grouped[pack_name].append(s)
                    break

        packs: list[ScenarioPack] = []
        for pack_name, pack_scenarios in sorted(grouped.items()):
            pack_def = _BUILTIN_PACK_DEFS[pack_name]
            categories = sorted({s.category.value for s in pack_scenarios})
            packs.append(
                ScenarioPack(
                    name=pack_name,
                    version=pack_def["version"],
                    description=pack_def["description"],
                    author="aastf-core",
                    scenarios=sorted([s.id for s in pack_scenarios]),
                    categories=categories,
                    created_at=datetime.now(timezone.utc),
                )
            )
        return packs

    # ---------------------------------------------------------------- install

    def install(self, pack_ref: str) -> ScenarioPack:
        """Install a pack from a local path (directory or .tar.gz).

        URL-based install is not yet implemented.
        """
        ref_path = Path(pack_ref)

        if ref_path.is_dir():
            manifest_path = ref_path / "pack.json"
            if not manifest_path.exists():
                raise FileNotFoundError(f"No pack.json found in {ref_path}")
            pack = ScenarioPack.model_validate_json(
                manifest_path.read_text(encoding="utf-8")
            )
            dest = self._packs_dir / pack.name.replace("/", "_")
            dest.mkdir(parents=True, exist_ok=True)
            # Copy pack.json
            (dest / "pack.json").write_text(
                pack.model_dump_json(indent=2), encoding="utf-8"
            )
            # Copy scenario yamls
            for yaml_file in sorted(ref_path.rglob("*.yaml")):
                rel = yaml_file.relative_to(ref_path)
                target = dest / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(yaml_file.read_text(encoding="utf-8"), encoding="utf-8")
            return pack

        if ref_path.is_file() and (
            ref_path.name.endswith(".tar.gz") or ref_path.name.endswith(".tgz")
        ):
            with tarfile.open(ref_path, "r:gz") as tf:
                # Find pack.json inside the archive
                members = tf.getnames()
                pack_json_member = None
                for m in members:
                    if m.endswith("pack.json"):
                        pack_json_member = m
                        break
                if pack_json_member is None:
                    raise FileNotFoundError("No pack.json found in archive")
                f = tf.extractfile(pack_json_member)
                if f is None:
                    raise FileNotFoundError("Cannot read pack.json from archive")
                pack = ScenarioPack.model_validate_json(f.read())
                dest = self._packs_dir / pack.name.replace("/", "_")
                dest.mkdir(parents=True, exist_ok=True)
                # Extract all files, stripping one level of directory prefix
                _safe_extract(tf, dest)
            return pack

        raise FileNotFoundError(f"Pack reference not found: {pack_ref}")

    # ----------------------------------------------------------- sign / verify

    def sign(self, pack: ScenarioPack, private_key: bytes) -> ScenarioPack:
        """Sign a pack manifest using HMAC-SHA256.

        For ed25519 signatures, install the ``cryptography`` package and use
        ``sign_ed25519()`` instead.
        """
        canon = _canonical_payload(pack)
        sig = hmac.new(private_key, canon, hashlib.sha256).hexdigest()
        return pack.model_copy(update={"signature": f"hmac-sha256:{sig}"})

    def verify(self, pack: ScenarioPack, public_key: bytes | None = None) -> bool:
        """Verify a pack's HMAC-SHA256 signature.

        Returns True if the signature matches, False otherwise.
        Unsigned packs always return False.

        For ed25519 verification, install the ``cryptography`` package.
        """
        if not pack.signature:
            return False

        if pack.signature.startswith("hmac-sha256:"):
            if public_key is None:
                return False
            expected_sig = pack.signature[len("hmac-sha256:"):]
            canon = _canonical_payload(pack)
            actual = hmac.new(public_key, canon, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected_sig, actual)

        if pack.signature.startswith("ed25519:"):
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                    Ed25519PublicKey,
                )
            except ImportError:
                raise NotImplementedError(
                    "ed25519 signature verification requires the 'cryptography' package. "
                    "Install it with: pip install cryptography"
                ) from None
            if public_key is None:
                return False
            canon = _canonical_payload(pack)
            sig_hex = pack.signature[len("ed25519:"):]
            sig_bytes = bytes.fromhex(sig_hex)
            key = Ed25519PublicKey.from_public_bytes(public_key)
            try:
                key.verify(sig_bytes, canon)
                return True
            except Exception:
                return False

        return False

    # ----------------------------------------------------------------- export

    def export(self, pack: ScenarioPack, output_path: Path) -> None:
        """Export a pack as a .tar.gz archive."""
        buf = BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            # Write pack.json
            pack_json = pack.model_dump_json(indent=2).encode("utf-8")
            info = tarfile.TarInfo(name=f"{pack.name.replace('/', '_')}/pack.json")
            info.size = len(pack_json)
            tf.addfile(info, BytesIO(pack_json))

            # If pack is installed, include scenario YAML files
            installed_dir = self._packs_dir / pack.name.replace("/", "_")
            if installed_dir.exists():
                for yaml_file in sorted(installed_dir.rglob("*.yaml")):
                    rel = yaml_file.relative_to(installed_dir)
                    data = yaml_file.read_bytes()
                    info = tarfile.TarInfo(
                        name=f"{pack.name.replace('/', '_')}/{rel.as_posix()}"
                    )
                    info.size = len(data)
                    tf.addfile(info, BytesIO(data))

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(buf.getvalue())

    # ------------------------------------------------------------- load / compose

    def load(self, pack_name: str) -> list[AttackScenario]:
        """Load all scenarios from an installed or builtin pack."""
        # Check installed packs first
        installed_dir = self._packs_dir / pack_name.replace("/", "_")
        if installed_dir.exists():
            yamls = list(installed_dir.rglob("*.yaml"))
            if yamls:
                return load_directory(installed_dir)

        # Fall back to builtin packs
        for bp in self.list_builtin():
            if bp.name == pack_name:
                all_scenarios = load_directory(_BUILTIN_DIR)
                pack_def = _BUILTIN_PACK_DEFS.get(pack_name)
                if not pack_def:
                    return []
                pattern = pack_def["prefix_pattern"]
                return [s for s in all_scenarios if re.match(pattern, s.id)]

        raise KeyError(f"Pack not found: {pack_name!r}")

    def compose(self, *pack_names: str) -> list[AttackScenario]:
        """Merge scenarios from multiple packs, deduplicating by scenario ID."""
        seen: dict[str, AttackScenario] = {}
        for name in pack_names:
            for s in self.load(name):
                seen[s.id] = s
        return sorted(seen.values(), key=lambda s: s.id)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _canonical_payload(pack: ScenarioPack) -> bytes:
    """Produce a deterministic JSON representation for signing."""
    data = {
        "name": pack.name,
        "version": pack.version,
        "description": pack.description,
        "author": pack.author,
        "scenarios": sorted(pack.scenarios),
        "categories": sorted(pack.categories),
    }
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _safe_extract(tf: tarfile.TarFile, dest: Path) -> None:
    """Extract tarfile members safely, stripping one directory level."""
    for member in tf.getmembers():
        # Skip directories
        if member.isdir():
            continue
        # Strip first path component
        parts = Path(member.name).parts
        rel = Path(member.name) if len(parts) <= 1 else Path(*parts[1:])
        target = dest / rel
        # Prevent path traversal
        if ".." in target.parts:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        f = tf.extractfile(member)
        if f:
            target.write_bytes(f.read())
