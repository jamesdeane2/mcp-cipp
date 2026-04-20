# mcp-cipp

A [FastMCP](https://github.com/jlowin/fastmcp) server for the [CIPP API](https://docs.cipp.app/api-documentation/endpoints) — the CyberDrain Improved Partner Portal for M365 multi-tenant management.

Lets AI assistants (Claude, Copilot, etc.) manage Microsoft 365 tenants through natural language using your existing CIPP deployment.

## Tools

| Category | Tools |
|---|---|
| **Tenants** | `list_tenants`, `get_tenant`, `get_tenant_details`, `get_dashboard` |
| **Users** | `list_users`, `get_user`, `add_user`, `offboard_user`, `reset_user_password`, `set_mfa_methods`, `list_user_licenses`, `list_user_sign_in_activity` |
| **Groups** | `list_groups`, `add_member_to_group` |
| **Devices** | `list_devices`, `list_device_compliance` |
| **Exchange** | `list_mailboxes`, `list_mailbox_rules`, `list_mailbox_permissions` |
| **Standards** | `list_standards`, `list_alerts` |
| **Conditional Access** | `list_conditional_access_policies` |
| **Licenses** | `list_licenses` |
| **Domains** | `list_domains` |

## Requirements

- An existing CIPP deployment (self-hosted or managed)
- CIPP API enabled — set up at **CIPP > Settings > CIPP API**
- Python 3.11+

## Setup

### 1. Clone and install

```bash
git clone https://github.com/jamesdeane2/mcp-cipp.git
cd mcp-cipp
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure credentials

```bash
cp .env.example .env
```

Edit `.env` with your CIPP API credentials. You'll find these in CIPP under **Settings > CIPP API** after enabling the integration:

```env
CIPP_API_URL=https://your-cipp-instance.azurewebsites.net
CIPP_TENANT_ID=your-partner-tenant-id
CIPP_CLIENT_ID=your-app-registration-client-id
CIPP_CLIENT_SECRET=your-app-registration-client-secret
```

### 3. Add to Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cipp": {
      "command": "/path/to/mcp-cipp/.venv/bin/python",
      "args": ["/path/to/mcp-cipp/server.py"],
      "env": {
        "CIPP_API_URL": "https://your-cipp-instance.azurewebsites.net",
        "CIPP_TENANT_ID": "your-tenant-id",
        "CIPP_CLIENT_ID": "your-client-id",
        "CIPP_CLIENT_SECRET": "your-client-secret"
      }
    }
  }
}
```

## Authentication

Uses OAuth 2.0 Client Credentials flow against your CIPP app registration. Tokens are cached and refreshed automatically.

## Contributing

PRs welcome — especially for more endpoint coverage. The CIPP API has 600+ endpoints across Exchange, Intune, Conditional Access, GDAP, and more.
