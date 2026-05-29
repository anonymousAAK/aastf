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
        cp = CloudPlatform()
        ws = cp.create_workspace("acme", PricingTier.TEAM, "alice")
        assert ws.name == "acme"
        assert ws.tier == PricingTier.TEAM
        assert ws.owner == "alice"
        assert "alice" in ws.members

    def test_create_workspace_audit_logged(self):
        cp = CloudPlatform()
        ws = cp.create_workspace("acme", owner="alice")
        logs = cp.get_audit_log(ws)
        assert len(logs) == 1
        assert logs[0].action == "workspace.create"

    def test_add_member(self):
        cp = CloudPlatform()
        ws = cp.create_workspace("acme", PricingTier.TEAM, "alice")
        cp.add_member(ws, "bob", RBACRole.MEMBER)
        assert "bob" in ws.members

    def test_add_member_respects_limits(self):
        cp = CloudPlatform()
        ws = cp.create_workspace("tiny", PricingTier.FREE, "alice")
        # FREE allows 1 member; owner is already in
        with pytest.raises(ValueError, match="member limit"):
            cp.add_member(ws, "bob")

    def test_add_member_idempotent(self):
        cp = CloudPlatform()
        ws = cp.create_workspace("acme", PricingTier.TEAM, "alice")
        cp.add_member(ws, "bob")
        cp.add_member(ws, "bob")  # should not duplicate
        assert ws.members.count("bob") == 1

    def test_get_member_role(self):
        cp = CloudPlatform()
        ws = cp.create_workspace("acme", PricingTier.TEAM, "alice")
        cp.add_member(ws, "bob", RBACRole.VIEWER)
        assert cp.get_member_role(ws, "bob") == RBACRole.VIEWER

    def test_has_permission(self):
        cp = CloudPlatform()
        ws = cp.create_workspace("acme", PricingTier.TEAM, "alice")
        assert cp.has_permission(ws, "alice", Permission.BILLING_MANAGE)

    def test_has_permission_non_member(self):
        cp = CloudPlatform()
        ws = cp.create_workspace("acme", PricingTier.TEAM, "alice")
        assert not cp.has_permission(ws, "eve", Permission.SCAN_VIEW)

    def test_check_limits_under(self):
        cp = CloudPlatform()
        ws = cp.create_workspace("acme", PricingTier.FREE, "alice")
        assert cp.check_limits(ws) is True

    def test_check_limits_exceeded(self):
        cp = CloudPlatform()
        ws = cp.create_workspace("acme", PricingTier.FREE, "alice")
        ws.scan_count = 10
        assert cp.check_limits(ws) is False

    def test_increment_scan(self):
        cp = CloudPlatform()
        ws = cp.create_workspace("acme", owner="alice")
        cp.increment_scan(ws)
        assert ws.scan_count == 1

    def test_get_audit_log_limit(self):
        cp = CloudPlatform()
        ws = cp.create_workspace("acme", owner="alice")
        for i in range(5):
            cp.log_audit(ws, AuditLogEntry(actor="a", action=f"act{i}", resource="r"))
        # 1 from create + 5 manual = 6
        assert len(cp.get_audit_log(ws, limit=3)) == 3

    def test_ci_integration(self):
        cp = CloudPlatform()
        ws = cp.create_workspace("acme", owner="alice")
        ci = CIIntegration(provider="github", repo_url="https://github.com/a/b")
        cp.add_ci_integration(ws, ci)
        assert len(cp.get_ci_integrations(ws)) == 1

    def test_ticket_sync(self):
        cp = CloudPlatform()
        ws = cp.create_workspace("acme", owner="alice")
        ts = TicketSync(provider="jira", project_key="SEC", api_url="https://jira.example.com")
        cp.add_ticket_sync(ws, ts)
        assert len(cp.get_ticket_syncs(ws)) == 1

    def test_sso_config(self):
        cp = CloudPlatform()
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
        cp = CloudPlatform()
        ws = cp.create_workspace("acme", owner="alice")
        assert cp.get_workspace(ws.id) is ws
        assert cp.get_workspace("nonexistent") is None
