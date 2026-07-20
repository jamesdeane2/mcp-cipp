"""
mcp-cipp: FastMCP server for the CIPP API
Wraps the CIPP REST API (CyberDrain Improved Partner Portal) for M365 multi-tenant management.

Auth: OAuth2 client credentials flow using the CIPP API client credentials.
"""

import os
import subprocess
import httpx
from datetime import datetime, timedelta
from dotenv import load_dotenv
from fastmcp import FastMCP

load_dotenv()

mcp = FastMCP("mcp-cipp")

# --- Config ---

KP_GET = os.path.expanduser(os.environ.get("KP_GET_PATH", "~/.soma/scripts/kp-get"))
KP_ENTRY = os.environ.get("CIPP_KP_ENTRY", "API Keys/CIPP")


def _kp_secret() -> str:
    """Fetch the CIPP client secret from KeePass (source of truth).

    Env var CIPP_CLIENT_SECRET takes precedence (headless/CI or rotation).
    """
    try:
        res = subprocess.run([KP_GET, KP_ENTRY, "password"], capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    return res.stdout.strip() if res.returncode == 0 else ""


CIPP_API_URL = os.getenv("CIPP_API_URL", "").rstrip("/")
TENANT_ID = os.getenv("CIPP_TENANT_ID", "")
CLIENT_ID = os.getenv("CIPP_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("CIPP_CLIENT_SECRET") or _kp_secret()
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
        data = resp.json()
        return {"results": data} if isinstance(data, list) else data


async def cipp_post(path: str, body: dict) -> dict:
    token = await get_token()
    url = f"{CIPP_API_URL}/{path.lstrip('/')}"
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=body)
        resp.raise_for_status()
        data = resp.json()
        return {"results": data} if isinstance(data, list) else data


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
        "AddMember": [{"value": user_id}],
    })


@mcp.tool()
async def remove_member_from_group(tenant_filter: str, group_id: str, user_id: str) -> dict:
    """Remove a user from a group or distribution list. Offboarding step.

    Note: CIPP's EditGroup expects RemoveMember as an array of {value} objects.

    Args:
        tenant_filter: Tenant domain or ID
        group_id: Group object ID
        user_id: User UPN or object ID to remove
    """
    return await cipp_post("/api/EditGroup", {
        "tenantFilter": tenant_filter,
        "groupId": group_id,
        "RemoveMember": [{"value": user_id}],
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


@mcp.tool()
async def add_autopilot_device(
    tenant_filter: str,
    serial_number: str,
    hardware_hash: str,
    model: str = None,
    manufacturer: str = None,
    product_key: str = None,
    group_name: str = None,
) -> dict:
    """Register a device into Windows Autopilot (upload the hardware hash) for a tenant.

    This is the "add device to Intune / upload the hash file" build step. Once
    registered, the device is provisioned via the tenant's Autopilot profile.

    Note: CIPP's AddAPDevice expects the tenant as a nested {value} object and the
    device(s) as an array under autopilotData.

    Args:
        tenant_filter: Tenant domain or ID
        serial_number: Device serial number
        hardware_hash: The Autopilot hardware hash (4K HH, base64)
        model: Device model name (optional)
        manufacturer: OEM manufacturer name (optional)
        product_key: Windows product key (optional)
        group_name: Batch/group name for this import (optional)
    """
    device = {
        "SerialNumber": serial_number,
        "hardwareHash": hardware_hash,
        "modelName": model,
        "oemManufacturerName": manufacturer,
        "productKey": product_key,
    }
    body = {
        "TenantFilter": {"value": tenant_filter},
        "autopilotData": [device],
    }
    if group_name:
        body["Groupname"] = group_name
    return await cipp_post("/api/AddAPDevice", body)


@mcp.tool()
async def device_action(tenant_filter: str, device_id: str, action: str) -> dict:
    """Perform an action on an Intune-managed device.

    Offboarding uses this to retire or wipe a leaver's device. The action is
    passed through to Graph, so it accepts standard Intune managedDevice actions.

    Args:
        tenant_filter: Tenant domain or ID
        device_id: Intune managedDevice GUID (from list_devices)
        action: e.g. "retire", "wipe", "delete", "sync", "rebootNow", "shutDown",
                "locateDevice", "remoteLock"
    """
    return await cipp_post("/api/ExecDeviceAction", {
        "tenantFilter": tenant_filter,
        "GUID": device_id,
        "Action": action,
    })


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


@mcp.tool()
async def convert_mailbox(tenant_filter: str, user_id: str, mailbox_type: str = "Shared") -> dict:
    """Convert a mailbox to a different type.

    Part of the offboarding procedure: converting a leaver's mailbox to Shared
    preserves colleague/manager access to the mail without consuming a paid
    licence, so the licence can then be removed.

    Args:
        tenant_filter: Tenant domain or ID
        user_id: Mailbox UPN or object ID (maps to CIPP's ID field)
        mailbox_type: Target type - "Shared" (default), "Regular", "Room", or "Equipment"
    """
    valid_types = {"Shared", "Regular", "Room", "Equipment"}
    if mailbox_type not in valid_types:
        return {"error": f"Invalid mailbox_type '{mailbox_type}'. Must be one of: {', '.join(sorted(valid_types))}"}
    return await cipp_post("/api/ExecConvertMailbox", {
        "tenantFilter": tenant_filter,
        "ID": user_id,
        "MailboxType": mailbox_type,
    })


@mcp.tool()
async def set_hide_from_gal(tenant_filter: str, user_id: str, hide: bool = True) -> dict:
    """Hide (or unhide) a mailbox from the Global Address List. Offboarding step.

    Args:
        tenant_filter: Tenant domain or ID
        user_id: Mailbox UPN or object ID
        hide: True to hide from the GAL (default), False to unhide
    """
    return await cipp_post("/api/ExecHideFromGAL", {
        "tenantFilter": tenant_filter,
        "ID": user_id,
        "HideFromGAL": hide,
    })


@mcp.tool()
async def set_out_of_office(
    tenant_filter: str,
    user_id: str,
    internal_message: str,
    external_message: str = None,
    state: str = "Enabled",
) -> dict:
    """Set an automatic reply (out-of-office) on a mailbox. Offboarding step.

    Args:
        tenant_filter: Tenant domain or ID
        user_id: Mailbox UPN or object ID
        internal_message: Auto-reply text for internal senders
        external_message: Auto-reply for external senders (defaults to internal_message)
        state: "Enabled" (default), "Disabled", or "Scheduled"
    """
    valid_states = {"Enabled", "Disabled", "Scheduled"}
    if state not in valid_states:
        return {"error": f"Invalid state '{state}'. Must be one of: {', '.join(sorted(valid_states))}"}
    return await cipp_post("/api/ExecSetOoO", {
        "tenantFilter": tenant_filter,
        "userId": user_id,
        "AutoReplyState": state,
        "InternalMessage": internal_message,
        "ExternalMessage": external_message if external_message is not None else internal_message,
    })


@mcp.tool()
async def set_mailbox_forwarding(
    tenant_filter: str,
    user_id: str,
    forward_to: str = None,
    forward_option: str = "internalAddress",
    keep_copy: bool = False,
) -> dict:
    """Set or disable mailbox forwarding. Offboarding step (e.g. forward a leaver's
    mail to their manager).

    Args:
        tenant_filter: Tenant domain or ID
        user_id: Mailbox UPN or object ID
        forward_to: Target address to forward to (omit when disabling)
        forward_option: "internalAddress" (default), "ExternalAddress", or "disabled"
        keep_copy: Keep a copy in the original mailbox (default False)
    """
    valid_options = {"internalAddress", "ExternalAddress", "disabled"}
    if forward_option not in valid_options:
        return {"error": f"Invalid forward_option '{forward_option}'. Must be one of: {', '.join(sorted(valid_options))}"}
    body = {
        "tenantFilter": tenant_filter,
        "userID": user_id,
        "forwardOption": forward_option,
        "KeepCopy": keep_copy,
    }
    if forward_option == "internalAddress":
        body["ForwardInternal"] = {"value": forward_to} if forward_to else None
    elif forward_option == "ExternalAddress":
        body["ForwardExternal"] = forward_to
    return await cipp_post("/api/ExecEmailForward", body)


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


# --- Teams Voice ---

@mcp.tool()
async def list_teams_voice(tenant_filter: str) -> dict:
    """List Teams phone number assignments in a tenant.

    Use this to find a leaver's assigned number and its type before removing it.

    Args:
        tenant_filter: Tenant domain or ID
    """
    return await cipp_get("/api/ListTeamsVoice", params={"tenantFilter": tenant_filter})


@mcp.tool()
async def remove_teams_phone_number(
    tenant_filter: str,
    assigned_to: str,
    phone_number: str,
    phone_number_type: str,
) -> dict:
    """Remove a Teams phone number assignment from a user. Offboarding step.

    Look up the number and type first with list_teams_voice.

    Args:
        tenant_filter: Tenant domain or ID
        assigned_to: The user the number is assigned to (UPN or object ID)
        phone_number: The phone number to unassign
        phone_number_type: Number type - "CallingPlan", "DirectRouting", or "OperatorConnect"
    """
    return await cipp_post("/api/ExecRemoveTeamsVoicePhoneNumberAssignment", {
        "tenantFilter": tenant_filter,
        "AssignedTo": assigned_to,
        "PhoneNumber": phone_number,
        "PhoneNumberType": phone_number_type,
    })


if __name__ == "__main__":
    mcp.run()
