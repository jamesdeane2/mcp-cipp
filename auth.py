"""
One-time login script for mcp-cipp.
Run this once to authenticate via device code flow and store the refresh token.

Usage:
    python auth.py
"""

import os
import json
from pathlib import Path
from dotenv import load_dotenv, set_key
import msal

load_dotenv()

TENANT_ID = os.getenv("CIPP_TENANT_ID", "")
CLIENT_ID = os.getenv("CIPP_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("CIPP_CLIENT_SECRET", "")
SCOPES = [f"api://{CLIENT_ID}/user_impersonation"]
ENV_FILE = Path(__file__).parent / ".env"


def device_code_login():
    app = msal.PublicClientApplication(
        client_id=CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}",
    )

    flow = app.initiate_device_flow(scopes=SCOPES)
    if "user_code" not in flow:
        raise RuntimeError(f"Failed to start device flow: {flow}")

    print("\n" + "="*60)
    print("CIPP Login Required")
    print("="*60)
    print(f"\n1. Open: {flow['verification_uri']}")
    print(f"2. Enter code: {flow['user_code']}")
    print("\nWaiting for you to log in...\n")

    result = app.acquire_token_by_device_flow(flow)

    if "refresh_token" in result:
        set_key(str(ENV_FILE), "CIPP_REFRESH_TOKEN", result["refresh_token"])
        print("\nLogin successful! Refresh token saved to .env")
        print("You can now run the MCP server.")
    else:
        print(f"\nError: {result.get('error')}: {result.get('error_description')}")


if __name__ == "__main__":
    device_code_login()
