"""Tests for the ScenarioPack abstraction."""

from __future__ import annotations

import tarfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aastf.packs import PackManager, ScenarioPack

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_packs_dir(tmp_path: Path) -> Path:
    d = tmp_path / "packs"
    d.mkdir()
    return d


@pytest.fixture()
def manager(tmp_packs_dir: Path) -> PackManager:
    return PackManager(packs_dir=tmp_packs_dir)


@pytest.fixture()
def sample_pack() -> ScenarioPack:
    return ScenarioPack(
        name="test/sample",
        version="0.1.0",
        description="A test scenario pack",
        author="test-author",
        scenarios=["ASI01-001", "ASI01-002"],
        categories=["ASI01"],
        created_at=datetime.now(timezone.utc),
    )


@pytest.fixture()
def hmac_key() -> bytes:
    return b"super-secret-test-key-32-bytes!!"


# ---------------------------------------------------------------------------
# Builtin pack detection
# ---------------------------------------------------------------------------


class TestBuiltinDetection:
    def test_list_builtin_returns_packs(self, manager: PackManager) -> None:
        packs = manager.list_builtin()
        assert len(packs) >= 1
        names = {p.name for p in packs}
        assert "aastf/owasp-asi" in names

    def test_builtin_owasp_asi_has_scenarios(self, manager: PackManager) -> None:
        packs = manager.list_builtin()
        asi = next(p for p in packs if p.name == "aastf/owasp-asi")
        assert len(asi.scenarios) > 0
        assert all(s.startswith("ASI") for s in asi.scenarios)

    def test_builtin_mcp_pack(self, manager: PackManager) -> None:
        packs = manager.list_builtin()
        names = {p.name for p in packs}
        if "aastf/mcp" in names:
            mcp = next(p for p in packs if p.name == "aastf/mcp")
            assert all(s.startswith("MCP") for s in mcp.scenarios)

    def test_builtin_cve_pack(self, manager: PackManager) -> None:
        packs = manager.list_builtin()
        names = {p.name for p in packs}
        if "aastf/cve" in names:
            cve = next(p for p in packs if p.name == "aastf/cve")
            assert all(s.startswith("CVE") for s in cve.scenarios)

    def test_builtin_packs_have_categories(self, manager: PackManager) -> None:
        for p in manager.list_builtin():
            assert len(p.categories) > 0

    def test_builtin_packs_are_sorted(self, manager: PackManager) -> None:
        packs = manager.list_builtin()
        names = [p.name for p in packs]
        assert names == sorted(names)


# ---------------------------------------------------------------------------
# Pack compose (merge multiple)
# ---------------------------------------------------------------------------


class TestCompose:
    def test_compose_single_pack(self, manager: PackManager) -> None:
        scenarios = manager.compose("aastf/owasp-asi")
        assert len(scenarios) > 0
        assert all(s.id.startswith("ASI") for s in scenarios)

    def test_compose_multiple_packs_deduplicates(self, manager: PackManager) -> None:
        # Composing same pack twice should not duplicate
        single = manager.compose("aastf/owasp-asi")
        double = manager.compose("aastf/owasp-asi", "aastf/owasp-asi")
        assert len(single) == len(double)

    def test_compose_multiple_different_packs(self, manager: PackManager) -> None:
        packs = manager.list_builtin()
        if len(packs) < 2:
            pytest.skip("Need at least 2 builtin packs")
        names = [p.name for p in packs[:2]]
        composed = manager.compose(*names)
        # Should have scenarios from both
        assert len(composed) > 0

    def test_compose_returns_sorted(self, manager: PackManager) -> None:
        scenarios = manager.compose("aastf/owasp-asi")
        ids = [s.id for s in scenarios]
        assert ids == sorted(ids)


# ---------------------------------------------------------------------------
# Sign + verify roundtrip
# ---------------------------------------------------------------------------


class TestSignVerify:
    def test_sign_adds_signature(
        self, manager: PackManager, sample_pack: ScenarioPack, hmac_key: bytes
    ) -> None:
        signed = manager.sign(sample_pack, hmac_key)
        assert signed.signature is not None
        assert signed.signature.startswith("hmac-sha256:")

    def test_verify_roundtrip(
        self, manager: PackManager, sample_pack: ScenarioPack, hmac_key: bytes
    ) -> None:
        signed = manager.sign(sample_pack, hmac_key)
        assert manager.verify(signed, public_key=hmac_key) is True

    def test_verify_fails_wrong_key(
        self, manager: PackManager, sample_pack: ScenarioPack, hmac_key: bytes
    ) -> None:
        signed = manager.sign(sample_pack, hmac_key)
        wrong_key = b"wrong-key-that-should-not-work!!"
        assert manager.verify(signed, public_key=wrong_key) is False

    def test_verify_unsigned_returns_false(
        self, manager: PackManager, sample_pack: ScenarioPack
    ) -> None:
        assert manager.verify(sample_pack) is False

    def test_verify_no_key_returns_false(
        self, manager: PackManager, sample_pack: ScenarioPack, hmac_key: bytes
    ) -> None:
        signed = manager.sign(sample_pack, hmac_key)
        assert manager.verify(signed, public_key=None) is False

    def test_sign_does_not_mutate_original(
        self, manager: PackManager, sample_pack: ScenarioPack, hmac_key: bytes
    ) -> None:
        manager.sign(sample_pack, hmac_key)
        assert sample_pack.signature is None

    def test_verify_fails_tampered_pack(
        self, manager: PackManager, sample_pack: ScenarioPack, hmac_key: bytes
    ) -> None:
        signed = manager.sign(sample_pack, hmac_key)
        tampered = signed.model_copy(update={"description": "tampered!"})
        assert manager.verify(tampered, public_key=hmac_key) is False


# ---------------------------------------------------------------------------
# Export + re-import
# ---------------------------------------------------------------------------


class TestExportImport:
    def test_export_creates_tarball(
        self, manager: PackManager, sample_pack: ScenarioPack, tmp_path: Path
    ) -> None:
        out = tmp_path / "export.tar.gz"
        manager.export(sample_pack, out)
        assert out.exists()
        assert tarfile.is_tarfile(str(out))

    def test_export_contains_pack_json(
        self, manager: PackManager, sample_pack: ScenarioPack, tmp_path: Path
    ) -> None:
        out = tmp_path / "export.tar.gz"
        manager.export(sample_pack, out)
        with tarfile.open(out, "r:gz") as tf:
            names = tf.getnames()
            assert any("pack.json" in n for n in names)

    def test_export_roundtrip(
        self, manager: PackManager, sample_pack: ScenarioPack, tmp_path: Path
    ) -> None:
        out = tmp_path / "export.tar.gz"
        manager.export(sample_pack, out)

        # Re-import via install
        reimported = manager.install(str(out))
        assert reimported.name == sample_pack.name
        assert reimported.version == sample_pack.version
        assert reimported.scenarios == sample_pack.scenarios

    def test_install_from_directory(
        self, manager: PackManager, tmp_path: Path
    ) -> None:
        pack_dir = tmp_path / "my_pack"
        pack_dir.mkdir()
        pack = ScenarioPack(
            name="local/test",
            version="0.2.0",
            description="Dir install test",
            author="tester",
            scenarios=[],
            categories=[],
        )
        (pack_dir / "pack.json").write_text(
            pack.model_dump_json(indent=2), encoding="utf-8"
        )
        installed = manager.install(str(pack_dir))
        assert installed.name == "local/test"
        # Should now appear in list_installed
        assert any(p.name == "local/test" for p in manager.list_installed())


# ---------------------------------------------------------------------------
# List installed (empty dir)
# ---------------------------------------------------------------------------


class TestListInstalled:
    def test_empty_dir(self, manager: PackManager) -> None:
        assert manager.list_installed() == []

    def test_nonexistent_dir(self, tmp_path: Path) -> None:
        mgr = PackManager(packs_dir=tmp_path / "does_not_exist")
        assert mgr.list_installed() == []

    def test_list_after_install(
        self, manager: PackManager, tmp_path: Path
    ) -> None:
        pack_dir = tmp_path / "installable"
        pack_dir.mkdir()
        pack = ScenarioPack(
            name="installed/pack",
            version="1.0.0",
            description="Installed pack",
            author="tester",
            scenarios=[],
            categories=[],
        )
        (pack_dir / "pack.json").write_text(
            pack.model_dump_json(indent=2), encoding="utf-8"
        )
        manager.install(str(pack_dir))
        installed = manager.list_installed()
        assert len(installed) == 1
        assert installed[0].name == "installed/pack"


# ---------------------------------------------------------------------------
# Install from local path
# ---------------------------------------------------------------------------


class TestInstallLocal:
    def test_install_missing_pack_json_raises(
        self, manager: PackManager, tmp_path: Path
    ) -> None:
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        with pytest.raises(FileNotFoundError, match="No pack.json"):
            manager.install(str(empty_dir))

    def test_install_nonexistent_path_raises(self, manager: PackManager) -> None:
        with pytest.raises(FileNotFoundError, match="Pack reference not found"):
            manager.install("/nonexistent/path")

    def test_install_preserves_pack_metadata(
        self, manager: PackManager, tmp_path: Path
    ) -> None:
        pack_dir = tmp_path / "meta_pack"
        pack_dir.mkdir()
        pack = ScenarioPack(
            name="meta/test",
            version="3.2.1",
            description="Metadata preservation test",
            author="qa-team",
            scenarios=["ASI01-001"],
            categories=["ASI01"],
        )
        (pack_dir / "pack.json").write_text(
            pack.model_dump_json(indent=2), encoding="utf-8"
        )
        installed = manager.install(str(pack_dir))
        assert installed.version == "3.2.1"
        assert installed.author == "qa-team"
        assert installed.description == "Metadata preservation test"


# ---------------------------------------------------------------------------
# Load from builtin
# ---------------------------------------------------------------------------


class TestLoad:
    def test_load_builtin_pack(self, manager: PackManager) -> None:
        scenarios = manager.load("aastf/owasp-asi")
        assert len(scenarios) > 0

    def test_load_unknown_pack_raises(self, manager: PackManager) -> None:
        with pytest.raises(KeyError, match="Pack not found"):
            manager.load("nonexistent/pack")


# ---------------------------------------------------------------------------
# ScenarioPack model
# ---------------------------------------------------------------------------


class TestScenarioPackModel:
    def test_serialization_roundtrip(self, sample_pack: ScenarioPack) -> None:
        raw = sample_pack.model_dump_json()
        reloaded = ScenarioPack.model_validate_json(raw)
        assert reloaded.name == sample_pack.name
        assert reloaded.version == sample_pack.version

    def test_default_signature_is_none(self) -> None:
        p = ScenarioPack(
            name="x/y", version="1.0.0", description="d", author="a"
        )
        assert p.signature is None

    def test_default_created_at(self) -> None:
        p = ScenarioPack(
            name="x/y", version="1.0.0", description="d", author="a"
        )
        assert isinstance(p.created_at, datetime)
