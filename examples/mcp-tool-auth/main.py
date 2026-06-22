#!/usr/bin/env python3
"""
MCP Tool Authorization with ADTP — end-to-end example.

Demonstrates: register agents, issue credentials, delegate with RESTRICT,
verify before tool execution, and revoke the chain.

Requires: a running adtpd on localhost:8080 with an API key.
  export ADTP_API_KEY=<your-key>
  python main.py
"""

import json
import os
import sys
import time
import urllib.request

ADTP_URL = os.environ.get("ADTP_URL", "http://localhost:8080")
API_KEY = os.environ.get("ADTP_API_KEY", "")


def adtp(method, path, body=None):
    """Call the ADTP daemon."""
    url = f"{ADTP_URL}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if API_KEY:
        req.add_header("Authorization", f"Bearer {API_KEY}")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def main():
    if not API_KEY:
        print("Set ADTP_API_KEY environment variable first.")
        print("Start adtpd and copy the generated key.")
        sys.exit(1)

    print("=== MCP Tool Authorization with ADTP ===\n")

    # 1. Health check
    status, resp = adtp("GET", "/health")
    print(f"1. Health check: {resp['status']} (platform: {resp['platform_did'][:30]}...)")

    # 2. Register the orchestrator agent
    status, resp = adtp("POST", "/v1/agents", {"sponsor_did": "orchestrator@example.com"})
    agent_a = resp["did"]
    print(f"2. Registered orchestrator: {agent_a[:40]}...")

    # 3. Register the sub-agent
    status, resp = adtp("POST", "/v1/agents", {"sponsor_did": "orchestrator@example.com"})
    agent_b = resp["did"]
    print(f"3. Registered sub-agent:    {agent_b[:40]}...")

    # 4. Issue a root credential to the orchestrator
    status, resp = adtp("POST", "/v1/credentials", {
        "agent_did": agent_a,
        "capabilities": [
            {"can": "tool/invoke", "with": "tool://search/*"},
            {"can": "agent/delegate", "with": "tool://search/*",
             "constraints": [{"type": "delegation_depth", "max": 3}]},
        ],
        "exp_seconds": 3600,
    })
    root_cid = resp["cid"]
    print(f"4. Issued root credential:  {root_cid[:40]}...")

    # 5. Orchestrator delegates to sub-agent with RESTRICT mode
    now = int(time.time())
    status, resp = adtp("POST", "/v1/delegations", {
        "parent_cid": root_cid,
        "audience_did": agent_b,
        "mode": "restrict",
        "depth_left": 2,
        "caveats": [
            {"type": "resource_restrict", "resource": "tool://search/web"},
            {"type": "time_window", "start": now - 60, "end": now + 1800},
        ],
    })
    delegated_cid = resp["cid"]
    print(f"5. Delegated (RESTRICT):    {delegated_cid[:40]}...")
    print(f"   Caveats: resource_restrict=tool://search/web, time_window=30min")

    # 6. MCP server verifies the sub-agent's credential before executing
    print("\n--- MCP Server: tool invocation request ---")

    status, resp = adtp("POST", "/v1/verify", {
        "chain": [delegated_cid],
        "action": "tool/invoke",
        "resource": "tool://search/web",
    })
    print(f"6. Verify tool://search/web: authorized={resp['authorized']}, depth={resp['chain_depth']}")

    # 7. Try an unauthorized resource — should be denied
    status, resp = adtp("POST", "/v1/verify", {
        "chain": [delegated_cid],
        "action": "tool/invoke",
        "resource": "tool://search/internal",
    })
    print(f"7. Verify tool://search/internal: authorized={resp['authorized']} (correctly denied)")

    # 8. Revoke the root credential — cascade kills the delegation
    print("\n--- Revocation ---")
    status, resp = adtp("POST", "/v1/revoke", {
        "subject_cid": root_cid,
        "scope": "subtree",
        "status": "COMPROMISED",
    })
    print(f"8. Revoked root credential (cascade)")

    # 9. Verify again — should be denied now
    status, resp = adtp("POST", "/v1/verify", {
        "chain": [delegated_cid],
        "action": "tool/invoke",
        "resource": "tool://search/web",
    })
    print(f"9. Verify after revocation:  authorized={resp['authorized']} (correctly denied)")
    if resp.get("error_code"):
        print(f"   Reason: {resp['error_code']}")

    print("\n=== Done ===")


if __name__ == "__main__":
    main()
