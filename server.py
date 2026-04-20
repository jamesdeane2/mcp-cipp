"""
mcp-cipp: FastMCP server for the CIPP API
Wraps the CIPP REST API (CyberDrain Improved Partner Portal) for M365 multi-tenant management.

Auth: OAuth2 client credentials flow using the CIPP API client credentials.
"""

import os
import httpx
from datetime import datetime, timedelta
from dotenv import load_dotenv
from fastmcp import FastMCP

load_dotenv()

mcp = FastMCP("mcp-cipp", description="CIPP API server for M365 multi-tenant management")

# --- Config ---

CIPP_API_URL = os.getenv("CIPP_API_URL", "").rstrip("/")
TENANT_ID = os.getenv("CIPP_TENANT_ID", "")
CLIENT_ID = os.getenv("CIPP_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("CIPP_CLIENT_SECRET", "")
SCOPE = f"api://{CLIENT_ID}/.default"

_token_cache: dict = {"token": None, "expires_at": None}


async def get_token() -> str:
    """Get a cached bearer token, refreshing via client credentials if needed."""
    now = datetime.utcnow()
    if _token_cache["token"] and _token_cache["expires_at"] and now < _token_cache["expires_at"]:
        return _token_cache["token"]

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token",
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "scope": SCOPE,
                "grant_type": "client_credentials",
            }
        )
        resp.raise_for_status()
        data = resp.json()

    _token_cache["token"] = data["access_token"]
    _token_cache["expires_at"] = now + timedelta(seconds=data.get("expires_in", 3600) - 60)
    return _token_cache["token"]


async def cipp_get(path: str, params: dict = None) -> dict:
    token = await get_token()
    url = f"{CIPP_API_URL}/{path.lstrip('/')}"
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {token}"}, params=params)
        resp.raise_for_status()
        return resp.json()


async def cipp_post(path: str, body: dict) -> dict:
    token = await get_token()
    url = f"{CIPP_API_URL}/{path.lstrip('/')}"
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=body)
        resp.raise_for_status()
        return resp.json()


# --- Tenant Tools ---

@mcp.tool()
async def list_tenants() -> dict:
    """List all tenants managed in CIPP."""
    return await cipp_get("/api/ListTenants")


@mcp.tool()
async def get_tenant(tenant_filter: str) -> dict:
    """Get details for a specific tenant.

    Args:
        tenant_filter: Tenant domain or ID (e.g. contoso.onmicrosoft.com)
    """
    return await cipp_get("/api/ListTenants", params={"tenantFilter": tenant_filter})


@mcp.tool()
async def get_tenant_details(tenant_filter: str) -> dict:
    """Get detailed information about a tenant including capabilities and settings.

    Args:
        tenant_filter: Tenant domain or ID
    """
    return await cipp_get("/api/ListTenantDetails", params={"tenantFilter": tenant_filter})


@mcp.tool()
async def get_dashboard(tenant_filter: str) -> dict:
    """Get the CIPP dashboard summary for a tenant.

    Args:
        tenant_filter: Tenant domain or ID
    """
    return await cipp_get("/api/ListDashboard", params={"tenantFilter": tenant_filter})


# --- User Tools ---

@mcp.tool()
async def list_users(tenant_filter: str) -> dict:
    """List all users in a tenant.

    Args:
        tenant_filter: Tenant domain or ID
    """
    return await cipp_get("/api/ListUsers", params={"tenantFilter": tenant_filter})


@mcp.tool()
async def get_user(tenant_filter: str, user_id: str) -> dict:
    """Get details for a specific user.

    Args:
        tenant_filter: Tenant domain or ID
        user_id: User UPN or object ID
    """
    return await cipp_get("/api/ListUsers", params={"tenantFilter": tenant_filter, "userId": user_id})


@mcp.tool()
async def list_user_licenses(tenant_filter: str) -> dict:
    """List all users and their assigned licenses in a tenant.

    Args:
        tenant_filter: Tenant domain or ID
    """
    return await cipp_get("/api/ListUserLicenses", params={"tenantFilter": tenant_filter})


@mcp.tool()
async def list_user_sign_in_activity(tenant_filter: str) -> dict:
    """Get sign-in activity for users in a tenant.

    Args:
        tenant_filter: Tenant domain or ID
    """
    return await cipp_get("/api/ListSignIns", params={"tenantFilter": tenant_filter})


@mcp.tool()
async def add_user(
    tenant_filter: str,
    display_name: str,
    user_principal_name: str,
    first_name: str,
    last_name: str,
    usage_location: str = "US",
    auto_password: bool = True,
    must_change_password: bool = True,
) -> dict:
    """Create a new user in a tenant.

    Args:
        tenant_filter: Tenant domain or ID
        display_name: Full display name
        user_principal_name: UPN (e.g. john@contoso.com)
        first_name: First name
        last_name: Last name
        usage_location: Two-letter country code (default: US)
        auto_password: Generate a random password (default: True)
        must_change_password: Force password change on first login (default: True)
    """
    return await cipp_post("/api/AddUser", {
        "tenantFilter": tenant_filter,
        "displayName": display_name,
        "userPrincipalName": user_principal_name,
        "givenName": first_name,
        "surname": last_name,
        "usageLocation": usage_location,
        "autoPassword": auto_password,
        "mustChangePassword": must_change_password,
    })


@mcp.tool()
async def offboard_user(
    tenant_filter: str,
    user_id: str,
    revoke_sessions: bool = True,
    disable_user: bool = True,
    remove_licenses: bool = True,
) -> dict:
    """Offboard a user from a tenant.

    Args:
        tenant_filter: Tenant domain or ID
        user_id: User UPN or object ID
        revoke_sessions: Revoke all active sessions (default: True)
        disable_user: Disable the user account (default: True)
        remove_licenses: Remove all assigned licenses (default: True)
    """
    return await cipp_post("/api/ExecOffboardUser", {
        "tenantFilter": tenant_filter,
        "userId": user_id,
        "RevokeSessions": revoke_sessions,
        "DisableUser": disable_user,
        "RemoveLicenses": remove_licenses,
    })


@mcp.tool()
async def reset_user_password(tenant_filter: str, user_id: str, must_change_password: bool = True) -> dict:
    """Reset a user's password.

    Args:
        tenant_filter: Tenant domain or ID
        user_id: User UPN or object ID
        must_change_password: Force password change on next login (default: True)
    """
    return await cipp_post("/api/ExecResetPass", {
        "tenantFilter": tenant_filter,
        "userId": user_id,
        "mustChangePassword": must_change_password,
    })


@mcp.tool()
async def list_mfa_users(tenant_filter: str) -> dict:
    """Get MFA registration status for all users in a tenant.

    Args:
        tenant_filter: Tenant domain or ID
    """
    return await cipp_get("/api/ListMFAUsers", params={"tenantFilter": tenant_filter})


# --- Group Tools ---

@mcp.tool()
async def list_groups(tenant_filter: str) -> dict:
    """List all groups in a tenant.

    Args:
        tenant_filter: Tenant domain or ID
    """
    return await cipp_get("/api/ListGroups", params={"tenantFilter": tenant_filter})


@mcp.tool()
async def add_member_to_group(tenant_filter: str, group_id: str, user_id: str) -> dict:
    """Add a user to a group.

    Args:
        tenant_filter: Tenant domain or ID
        group_id: Group object ID
        user_id: User UPN or object ID
    """
    return await cipp_post("/api/EditGroup", {
        "tenantFilter": tenant_filter,
        "groupId": group_id,
        "addMember": user_id,
    })


# --- Device / Intune Tools ---

@mcp.tool()
async def list_devices(tenant_filter: str) -> dict:
    """List all devices enrolled in Intune for a tenant.

    Args:
        tenant_filter: Tenant domain or ID
    """
    return await cipp_get("/api/ListDevices", params={"tenantFilter": tenant_filter})


@mcp.tool()
async def list_device_compliance(tenant_filter: str) -> dict:
    """Get device compliance status for a tenant.

    Args:
        tenant_filter: Tenant domain or ID
    """
    return await cipp_get("/api/ListDeviceCompliance", params={"tenantFilter": tenant_filter})


# --- Mailbox / Exchange Tools ---

@mcp.tool()
async def list_mailboxes(tenant_filter: str) -> dict:
    """List all mailboxes in a tenant.

    Args:
        tenant_filter: Tenant domain or ID
    """
    return await cipp_get("/api/ListMailboxes", params={"tenantFilter": tenant_filter})


@mcp.tool()
async def list_mailbox_rules(tenant_filter: str, user_id: str) -> dict:
    """List inbox rules for a mailbox.

    Args:
        tenant_filter: Tenant domain or ID
        user_id: Mailbox UPN or object ID
    """
    return await cipp_get("/api/ListMailboxRules", params={"tenantFilter": tenant_filter, "userId": user_id})


@mcp.tool()
async def list_mailbox_permissions(tenant_filter: str, user_id: str) -> dict:
    """List permissions on a mailbox (delegates, send-as, etc).

    Args:
        tenant_filter: Tenant domain or ID
        user_id: Mailbox UPN or object ID
    """
    return await cipp_get("/api/ListMailboxPermissions", params={"tenantFilter": tenant_filter, "userId": user_id})


# --- Standards & Compliance ---

@mcp.tool()
async def list_standards(tenant_filter: str) -> dict:
    """List applied standards/policies for a tenant.

    Args:
        tenant_filter: Tenant domain or ID
    """
    return await cipp_get("/api/ListStandards", params={"tenantFilter": tenant_filter})


@mcp.tool()
async def list_alerts(tenant_filter: str) -> dict:
    """List active alerts for a tenant.

    Args:
        tenant_filter: Tenant domain or ID
    """
    return await cipp_get("/api/ListAlertsQueue", params={"tenantFilter": tenant_filter})


# --- Conditional Access ---

@mcp.tool()
async def list_conditional_access_policies(tenant_filter: str) -> dict:
    """List Conditional Access policies for a tenant.

    Args:
        tenant_filter: Tenant domain or ID
    """
    return await cipp_get("/api/ListConditionalAccessPolicies", params={"tenantFilter": tenant_filter})


# --- Licenses ---

@mcp.tool()
async def list_licenses(tenant_filter: str) -> dict:
    """List available licenses and their usage in a tenant.

    Args:
        tenant_filter: Tenant domain or ID
    """
    return await cipp_get("/api/ListLicenses", params={"tenantFilter": tenant_filter})


# --- Domains ---

@mcp.tool()
async def list_domains(tenant_filter: str) -> dict:
    """List domains configured for a tenant.

    Args:
        tenant_filter: Tenant domain or ID
    """
    return await cipp_get("/api/ListDomains", params={"tenantFilter": tenant_filter})


if __name__ == "__main__":
    mcp.run()
