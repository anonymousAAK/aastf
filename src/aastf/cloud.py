"""Cloud platform models — workspaces, teams, RBAC, SSO, CI, ticket sync.

> **Status: Experimental** — this surface is under active development and
> not yet production-ready. Models and APIs here may change without notice.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

if sys.version_info >= (3, 11):
    from enum import StrEnum
else:

    class StrEnum(str, Enum):  # noqa: N801
        """Backport for Python 3.10."""

        def __str__(self) -> str:
            return self.value


from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Pricing
# ---------------------------------------------------------------------------

_UNLIMITED = 999_999_999


class PricingTier(StrEnum):
    FREE = "FREE"
    TEAM = "TEAM"
    BUSINESS = "BUSINESS"
    ENTERPRISE = "ENTERPRISE"


class PlanLimits(BaseModel):
    """Resource limits for a pricing tier."""

    scans_per_month: int
    scenarios_per_scan: int
    team_members: int
    retention_days: int
    price_usd: int


PLAN_LIMITS: dict[PricingTier, PlanLimits] = {
    PricingTier.FREE: PlanLimits(
        scans_per_month=10,
        scenarios_per_scan=50,
        team_members=1,
        retention_days=7,
        price_usd=0,
    ),
    PricingTier.TEAM: PlanLimits(
        scans_per_month=100,
        scenarios_per_scan=200,
        team_members=10,
        retention_days=30,
        price_usd=99,
    ),
    PricingTier.BUSINESS: PlanLimits(
        scans_per_month=_UNLIMITED,
        scenarios_per_scan=_UNLIMITED,
        team_members=50,
        retention_days=90,
        price_usd=999,
    ),
    PricingTier.ENTERPRISE: PlanLimits(
        scans_per_month=_UNLIMITED,
        scenarios_per_scan=_UNLIMITED,
        team_members=_UNLIMITED,
        retention_days=365,
        price_usd=-1,  # custom pricing
    ),
}

# ---------------------------------------------------------------------------
# Workspace
# ---------------------------------------------------------------------------


class Workspace(BaseModel):
    """A cloud workspace grouping users, scans, and settings."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    tier: PricingTier = PricingTier.FREE
    owner: str
    members: list[str] = Field(default_factory=list)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    settings: dict[str, Any] = Field(default_factory=dict)

    # runtime bookkeeping (not persisted)
    scan_count: int = 0


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


class AuditLogEntry(BaseModel):
    """Immutable record of an action performed in a workspace."""

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    actor: str
    action: str
    resource: str
    details: dict[str, Any] = Field(default_factory=dict)
    ip_address: str = ""


# ---------------------------------------------------------------------------
# SSO
# ---------------------------------------------------------------------------


class SSOConfig(BaseModel):
    """Single-sign-on configuration for a workspace."""

    provider: Literal["saml", "okta", "azure_ad", "google"]
    entity_id: str
    sso_url: str
    certificate: str
    enabled: bool = True


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


class RBACRole(StrEnum):
    OWNER = "OWNER"
    ADMIN = "ADMIN"
    MEMBER = "MEMBER"
    VIEWER = "VIEWER"


class Permission(StrEnum):
    SCAN_RUN = "SCAN_RUN"
    SCAN_VIEW = "SCAN_VIEW"
    SETTINGS_EDIT = "SETTINGS_EDIT"
    MEMBERS_MANAGE = "MEMBERS_MANAGE"
    BILLING_MANAGE = "BILLING_MANAGE"


_ROLE_PERMISSIONS: dict[RBACRole, set[Permission]] = {
    RBACRole.OWNER: set(Permission),
    RBACRole.ADMIN: {
        Permission.SCAN_RUN,
        Permission.SCAN_VIEW,
        Permission.SETTINGS_EDIT,
        Permission.MEMBERS_MANAGE,
    },
    RBACRole.MEMBER: {
        Permission.SCAN_RUN,
        Permission.SCAN_VIEW,
    },
    RBACRole.VIEWER: {
        Permission.SCAN_VIEW,
    },
}


class RBACPolicy:
    """Role-based access control policy."""

    def has_permission(self, role: RBACRole, permission: Permission) -> bool:
        """Return True if *role* grants *permission*."""
        return permission in _ROLE_PERMISSIONS.get(role, set())

    def role_permissions(self, role: RBACRole) -> set[Permission]:
        """Return all permissions granted to *role*."""
        return set(_ROLE_PERMISSIONS.get(role, set()))


# ---------------------------------------------------------------------------
# CI integration
# ---------------------------------------------------------------------------


class CIIntegration(BaseModel):
    """Configuration for a CI/CD pipeline integration."""

    provider: Literal["github", "gitlab", "bitbucket", "azure_devops"]
    repo_url: str
    webhook_secret: str = ""
    auto_scan: bool = True
    sarif_upload: bool = False


# ---------------------------------------------------------------------------
# Ticket sync
# ---------------------------------------------------------------------------


class TicketSync(BaseModel):
    """Configuration for JIRA / Linear ticket synchronisation."""

    provider: Literal["jira", "linear"]
    project_key: str
    api_url: str
    auto_create: bool = True
    severity_threshold: str = "HIGH"


# ---------------------------------------------------------------------------
# CloudPlatform facade
# ---------------------------------------------------------------------------


class CloudPlatform:
    """In-memory cloud platform facade (production would use a database)."""

    def __init__(self) -> None:
        self._workspaces: dict[str, Workspace] = {}
        self._audit_logs: dict[str, list[AuditLogEntry]] = {}
        self._member_roles: dict[str, dict[str, RBACRole]] = {}
        self._ci_integrations: dict[str, list[CIIntegration]] = {}
        self._ticket_syncs: dict[str, list[TicketSync]] = {}
        self._sso_configs: dict[str, SSOConfig] = {}
        self._policy = RBACPolicy()

    # -- workspace -----------------------------------------------------------

    def create_workspace(
        self,
        name: str,
        tier: PricingTier = PricingTier.FREE,
        owner: str = "admin",
    ) -> Workspace:
        ws = Workspace(name=name, tier=tier, owner=owner, members=[owner])
        self._workspaces[ws.id] = ws
        self._audit_logs[ws.id] = []
        self._member_roles[ws.id] = {owner: RBACRole.OWNER}
        self._ci_integrations[ws.id] = []
        self._ticket_syncs[ws.id] = []
        self.log_audit(
            ws,
            AuditLogEntry(
                actor=owner,
                action="workspace.create",
                resource=ws.id,
            ),
        )
        return ws

    def get_workspace(self, workspace_id: str) -> Workspace | None:
        return self._workspaces.get(workspace_id)

    # -- members -------------------------------------------------------------

    def add_member(
        self,
        workspace: Workspace,
        user: str,
        role: RBACRole = RBACRole.MEMBER,
    ) -> None:
        limits = PLAN_LIMITS[workspace.tier]
        if len(workspace.members) >= limits.team_members:
            raise ValueError(
                f"Workspace '{workspace.name}' has reached the member limit "
                f"({limits.team_members}) for the {workspace.tier} plan.",
            )
        if user not in workspace.members:
            workspace.members.append(user)
        self._member_roles.setdefault(workspace.id, {})[user] = role
        self.log_audit(
            workspace,
            AuditLogEntry(
                actor=workspace.owner,
                action="member.add",
                resource=user,
                details={"role": str(role)},
            ),
        )

    def get_member_role(
        self, workspace: Workspace, user: str
    ) -> RBACRole | None:
        return self._member_roles.get(workspace.id, {}).get(user)

    def has_permission(
        self, workspace: Workspace, user: str, permission: Permission
    ) -> bool:
        role = self.get_member_role(workspace, user)
        if role is None:
            return False
        return self._policy.has_permission(role, permission)

    # -- limits --------------------------------------------------------------

    def check_limits(self, workspace: Workspace) -> bool:
        """Return True if the workspace is within its plan limits."""
        limits = PLAN_LIMITS[workspace.tier]
        return workspace.scan_count < limits.scans_per_month

    def increment_scan(self, workspace: Workspace) -> None:
        workspace.scan_count += 1

    # -- audit ---------------------------------------------------------------

    def log_audit(self, workspace: Workspace, entry: AuditLogEntry) -> None:
        self._audit_logs.setdefault(workspace.id, []).append(entry)

    def get_audit_log(
        self, workspace: Workspace, limit: int = 50
    ) -> list[AuditLogEntry]:
        logs = self._audit_logs.get(workspace.id, [])
        return logs[-limit:]

    # -- CI ------------------------------------------------------------------

    def add_ci_integration(
        self, workspace: Workspace, ci: CIIntegration
    ) -> None:
        self._ci_integrations.setdefault(workspace.id, []).append(ci)

    def get_ci_integrations(
        self, workspace: Workspace
    ) -> list[CIIntegration]:
        return list(self._ci_integrations.get(workspace.id, []))

    # -- ticket sync ---------------------------------------------------------

    def add_ticket_sync(
        self, workspace: Workspace, sync: TicketSync
    ) -> None:
        self._ticket_syncs.setdefault(workspace.id, []).append(sync)

    def get_ticket_syncs(self, workspace: Workspace) -> list[TicketSync]:
        return list(self._ticket_syncs.get(workspace.id, []))

    # -- SSO -----------------------------------------------------------------

    def set_sso(self, workspace: Workspace, sso: SSOConfig) -> None:
        self._sso_configs[workspace.id] = sso

    def get_sso(self, workspace: Workspace) -> SSOConfig | None:
        return self._sso_configs.get(workspace.id)
