"""Tests for aastf.cloud — cloud platform models and infrastructure."""

from __future__ import annotations

import uuid
from datetime import datetime

import pytest

from aastf.cloud import (
    PLAN_LIMITS,
    AuditLogEntry,
    CIIntegration,
    CloudPlatform,
    Permission,
    PricingTier,
    RBACPolicy,
    RBACRole,
    SSOConfig,
    TicketSync,
    Workspace,
)

# A valid 32-char alphanumeric token used across CloudPlatform tests.
_VALID_TOKEN = "abcdefghijklmnopqrstuvwxyz123456"


def _authed_platform() -> CloudPlatform:
    """Return a CloudPlatform that has already been authenticated."""
    cp = CloudPlatform()
    cp.authenticate(_VALID_TOKEN)
    return cp

# ── PricingTier ──────────────────────────────────────────────────────────────

class TestPricingTier:
    def test_free_tier_exists(self):
        assert PricingTier.FREE == "FREE"

    def test_team_tier_exists(self):
        assert PricingTier.TEAM == "TEAM"

    def test_business_tier_exists(self):
        assert PricingTier.BUSINESS == "BUSINESS"

    def test_enterprise_tier_exists(self):
        assert PricingTier.ENTERPRISE == "ENTERPRISE"

    def test_tier_count(self):
        assert len(PricingTier) == 4


# ── PlanLimits ───────────────────────────────────────────────────────────────

class TestPlanLimits:
    def test_free_limits(self):
        lim = PLAN_LIMITS[PricingTier.FREE]
        assert lim.scans_per_month == 10
        assert lim.scenarios_per_scan == 50
        assert lim.team_members == 1
        assert lim.retention_days == 7
        assert lim.price_usd == 0

    def test_team_limits(self):
        lim = PLAN_LIMITS[PricingTier.TEAM]
        assert lim.scans_per_month == 100
        assert lim.price_usd == 99

    def test_business_limits(self):
        lim = PLAN_LIMITS[PricingTier.BUSINESS]
        assert lim.scans_per_month == 999_999_999
        assert lim.team_members == 50
        assert lim.price_usd == 999

    def test_enterprise_limits(self):
        lim = PLAN_LIMITS[PricingTier.ENTERPRISE]
        assert lim.retention_days == 365
        assert lim.price_usd == -1  # custom

    def test_all_tiers_have_limits(self):
        for tier in PricingTier:
            assert tier in PLAN_LIMITS


# ── Workspace ────────────────────────────────────────────────────────────────

class TestWorkspace:
    def test_default_id_is_uuid(self):
        ws = Workspace(name="test", owner="alice")
        uuid.UUID(ws.id)  # should not raise

    def test_default_tier_is_free(self):
        ws = Workspace(name="test", owner="alice")
        assert ws.tier == PricingTier.FREE

    def test_members_default_empty(self):
        ws = Workspace(name="test", owner="alice")
        assert ws.members == []

    def test_created_at_is_utc(self):
        ws = Workspace(name="test", owner="alice")
        assert ws.created_at.tzinfo is not None

    def test_settings_default_empty(self):
        ws = Workspace(name="test", owner="alice")
        assert ws.settings == {}

    def test_custom_settings(self):
        ws = Workspace(name="test", owner="alice", settings={"k": "v"})
        assert ws.settings["k"] == "v"


# ── AuditLogEntry ────────────────────────────────────────────────────────────

class TestAuditLogEntry:
    def test_fields(self):
        e = AuditLogEntry(actor="bob", action="scan.run", resource="ws-1")
        assert e.actor == "bob"
        assert e.action == "scan.run"
        assert e.details == {}

    def test_timestamp_auto(self):
        e = AuditLogEntry(actor="a", action="b", resource="c")
        assert isinstance(e.timestamp, datetime)

    def test_ip_address_default(self):
        e = AuditLogEntry(actor="a", action="b", resource="c")
        assert e.ip_address == ""


# ── SSOConfig ────────────────────────────────────────────────────────────────

class TestSSOConfig:
    def test_saml_provider(self):
        cfg = SSOConfig(
            provider="saml",
            entity_id="urn:test",
            sso_url="https://idp.example.com/sso",
            certificate="CERT",
        )
        assert cfg.provider == "saml"
        assert cfg.enabled is True

    def test_okta_provider(self):
        cfg = SSOConfig(
            provider="okta",
            entity_id="urn:okta",
            sso_url="https://okta.example.com",
            certificate="X",
        )
        assert cfg.provider == "okta"

    def test_invalid_provider_rejected(self):
        with pytest.raises((TypeError, ValueError)):
            SSOConfig(
                provider="facebook",
                entity_id="x",
                sso_url="x",
                certificate="x",
            )


# ── RBAC ─────────────────────────────────────────────────────────────────────

class TestRBAC:
    def test_owner_has_all_permissions(self):
        policy = RBACPolicy()
        for perm in Permission:
            assert policy.has_permission(RBACRole.OWNER, perm)

    def test_viewer_only_scan_view(self):
        policy = RBACPolicy()
        assert policy.has_permission(RBACRole.VIEWER, Permission.SCAN_VIEW)
        assert not policy.has_permission(RBACRole.VIEWER, Permission.SCAN_RUN)
        assert not policy.has_permission(RBACRole.VIEWER, Permission.BILLING_MANAGE)

    def test_member_can_run_and_view(self):
        policy = RBACPolicy()
        assert policy.has_permission(RBACRole.MEMBER, Permission.SCAN_RUN)
        assert policy.has_permission(RBACRole.MEMBER, Permission.SCAN_VIEW)
        assert not policy.has_permission(RBACRole.MEMBER, Permission.SETTINGS_EDIT)

    def test_admin_cannot_manage_billing(self):
        policy = RBACPolicy()
        assert not policy.has_permission(RBACRole.ADMIN, Permission.BILLING_MANAGE)

    def test_role_permissions_returns_set(self):
        policy = RBACPolicy()
        perms = policy.role_permissions(RBACRole.ADMIN)
        assert isinstance(perms, set)
        assert Permission.SCAN_RUN in perms


# ── CIIntegration ───────────────────────────────────────────────────────────

class TestCIIntegration:
    def test_github_defaults(self):
        ci = CIIntegration(provider="github", repo_url="https://github.com/a/b")
        assert ci.auto_scan is True
        assert ci.sarif_upload is False

    def test_invalid_provider_rejected(self):
        with pytest.raises((TypeError, ValueError)):
            CIIntegration(provider="jenkins", repo_url="x")


# ── TicketSync ───────────────────────────────────────────────────────────────

class TestTicketSync:
    def test_jira_defaults(self):
        ts = TicketSync(provider="jira", project_key="SEC", api_url="https://jira.example.com")
        assert ts.auto_create is True
        assert ts.severity_threshold == "HIGH"

    def test_linear_provider(self):
        ts = TicketSync(provider="linear", project_key="AASTF", api_url="https://api.linear.app")
        assert ts.provider == "linear"

    def test_invalid_provider_rejected(self):
        with pytest.raises((TypeError, ValueError)):
            TicketSync(provider="trello", project_key="X", api_url="x")


# ── CloudPlatform ───────────────────────────────────────────────────────────

class TestCloudPlatform:
    def test_create_workspace(self):
        cp = _authed_platform()
        ws = cp.create_workspace("acme", PricingTier.TEAM, "alice")
        assert ws.name == "acme"
        assert ws.tier == PricingTier.TEAM
        assert ws.owner == "alice"
        assert "alice" in ws.members

    def test_create_workspace_audit_logged(self):
        cp = _authed_platform()
        ws = cp.create_workspace("acme", owner="alice")
        logs = cp.get_audit_log(ws)
        assert len(logs) == 1
        assert logs[0].action == "workspace.create"

    def test_add_member(self):
        cp = _authed_platform()
        ws = cp.create_workspace("acme", PricingTier.TEAM, "alice")
        cp.add_member(ws, "bob", RBACRole.MEMBER)
        assert "bob" in ws.members

    def test_add_member_respects_limits(self):
        cp = _authed_platform()
        ws = cp.create_workspace("tiny", PricingTier.FREE, "alice")
        # FREE allows 1 member; owner is already in
        with pytest.raises(ValueError, match="member limit"):
            cp.add_member(ws, "bob")

    def test_add_member_idempotent(self):
        cp = _authed_platform()
        ws = cp.create_workspace("acme", PricingTier.TEAM, "alice")
        cp.add_member(ws, "bob")
        cp.add_member(ws, "bob")  # should not duplicate
        assert ws.members.count("bob") == 1

    def test_get_member_role(self):
        cp = _authed_platform()
        ws = cp.create_workspace("acme", PricingTier.TEAM, "alice")
        cp.add_member(ws, "bob", RBACRole.VIEWER)
        assert cp.get_member_role(ws, "bob") == RBACRole.VIEWER

    def test_has_permission(self):
        cp = _authed_platform()
        ws = cp.create_workspace("acme", PricingTier.TEAM, "alice")
        assert cp.has_permission(ws, "alice", Permission.BILLING_MANAGE)

    def test_has_permission_non_member(self):
        cp = _authed_platform()
        ws = cp.create_workspace("acme", PricingTier.TEAM, "alice")
        assert not cp.has_permission(ws, "eve", Permission.SCAN_VIEW)

    def test_check_limits_under(self):
        cp = _authed_platform()
        ws = cp.create_workspace("acme", PricingTier.FREE, "alice")
        assert cp.check_limits(ws) is True

    def test_check_limits_exceeded(self):
        cp = _authed_platform()
        ws = cp.create_workspace("acme", PricingTier.FREE, "alice")
        ws.scan_count = 10
        assert cp.check_limits(ws) is False

    def test_increment_scan(self):
        cp = _authed_platform()
        ws = cp.create_workspace("acme", owner="alice")
        cp.increment_scan(ws)
        assert ws.scan_count == 1

    def test_get_audit_log_limit(self):
        cp = _authed_platform()
        ws = cp.create_workspace("acme", owner="alice")
        for i in range(5):
            cp.log_audit(ws, AuditLogEntry(actor="a", action=f"act{i}", resource="r"))
        # 1 from create + 5 manual = 6
        assert len(cp.get_audit_log(ws, limit=3)) == 3

    def test_ci_integration(self):
        cp = _authed_platform()
        ws = cp.create_workspace("acme", owner="alice")
        ci = CIIntegration(provider="github", repo_url="https://github.com/a/b")
        cp.add_ci_integration(ws, ci)
        assert len(cp.get_ci_integrations(ws)) == 1

    def test_ticket_sync(self):
        cp = _authed_platform()
        ws = cp.create_workspace("acme", owner="alice")
        ts = TicketSync(provider="jira", project_key="SEC", api_url="https://jira.example.com")
        cp.add_ticket_sync(ws, ts)
        assert len(cp.get_ticket_syncs(ws)) == 1

    def test_sso_config(self):
        cp = _authed_platform()
        ws = cp.create_workspace("acme", owner="alice")
        sso = SSOConfig(
            provider="azure_ad",
            entity_id="urn:azure",
            sso_url="https://login.microsoftonline.com",
            certificate="CERT",
        )
        cp.set_sso(ws, sso)
        assert cp.get_sso(ws) is not None
        assert cp.get_sso(ws).provider == "azure_ad"

    def test_get_workspace(self):
        cp = _authed_platform()
        ws = cp.create_workspace("acme", owner="alice")
        assert cp.get_workspace(ws.id) is ws
        assert cp.get_workspace("nonexistent") is None


# ── Authentication ──────────────────────────────────────────────────────────

class TestCloudPlatformAuth:
    """Tests for token/API key validation on CloudPlatform."""

    def test_authenticate_valid_token(self):
        cp = CloudPlatform()
        assert cp.authenticate(_VALID_TOKEN) is True

    def test_authenticate_with_hyphens(self):
        token = "abcdefgh-ijklmnop-qrstuvwx-yz1234"  # 35 chars with hyphens
        cp = CloudPlatform()
        assert cp.authenticate(token) is True

    def test_authenticate_empty_string_rejected(self):
        cp = CloudPlatform()
        assert cp.authenticate("") is False

    def test_authenticate_too_short_rejected(self):
        cp = CloudPlatform()
        assert cp.authenticate("abc123") is False  # < 32

    def test_authenticate_31_chars_rejected(self):
        cp = CloudPlatform()
        assert cp.authenticate("a" * 31) is False

    def test_authenticate_32_chars_accepted(self):
        cp = CloudPlatform()
        assert cp.authenticate("a" * 32) is True

    def test_authenticate_special_chars_rejected(self):
        cp = CloudPlatform()
        assert cp.authenticate("a" * 31 + "!") is False

    def test_authenticate_spaces_rejected(self):
        cp = CloudPlatform()
        assert cp.authenticate("a" * 31 + " ") is False

    def test_authenticate_non_string_rejected(self):
        cp = CloudPlatform()
        assert cp.authenticate(12345) is False  # type: ignore[arg-type]

    def test_require_auth_raises_when_unauthenticated(self):
        cp = CloudPlatform()
        with pytest.raises(PermissionError, match="not authenticated"):
            cp.create_workspace("fail")

    def test_require_auth_passes_after_authenticate(self):
        cp = _authed_platform()
        ws = cp.create_workspace("ok", owner="alice")
        assert ws.name == "ok"

    def test_guarded_add_member_requires_auth(self):
        cp = CloudPlatform()
        ws = Workspace(name="x", owner="alice")
        with pytest.raises(PermissionError, match="not authenticated"):
            cp.add_member(ws, "bob")

    def test_guarded_increment_scan_requires_auth(self):
        cp = CloudPlatform()
        ws = Workspace(name="x", owner="alice")
        with pytest.raises(PermissionError, match="not authenticated"):
            cp.increment_scan(ws)

    def test_guarded_set_sso_requires_auth(self):
        cp = CloudPlatform()
        ws = Workspace(name="x", owner="alice")
        sso = SSOConfig(
            provider="saml", entity_id="urn:t", sso_url="https://x", certificate="C",
        )
        with pytest.raises(PermissionError, match="not authenticated"):
            cp.set_sso(ws, sso)

    def test_bad_token_clears_previous_auth(self):
        cp = _authed_platform()
        # re-authenticate with bad token
        assert cp.authenticate("short") is False
        with pytest.raises(PermissionError, match="not authenticated"):
            cp.create_workspace("fail")
