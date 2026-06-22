# MCP Tool Authorization with ADTP

This example shows how an MCP server can use ADTP to authorize tool invocations.

## Scenario

1. An orchestrator registers an agent and gets a credential scoped to `tool/invoke` on `tool://search/*`
2. The orchestrator delegates a narrower credential to a sub-agent (RESTRICT mode)
3. When the sub-agent invokes a tool, the MCP server verifies the credential chain with ADTP before executing

## Setup

Start the ADTP daemon:

```bash
adtpd --config config.yaml
# Copy the generated API key
```

## Flow

```
┌─────────────┐     ┌──────────┐     ┌──────────┐
│ Orchestrator │────▶│   ADTP   │     │   MCP    │
│   Agent A    │     │  Daemon  │◀────│  Server  │
└──────┬───────┘     └──────────┘     └────▲─────┘
       │                                    │
       │  delegate (RESTRICT)               │
       ▼                                    │
┌─────────────┐     tool/invoke + cid       │
│  Sub-Agent  │─────────────────────────────┘
│   Agent B   │
└─────────────┘
```

## Run

```bash
# Set your ADTP API key
export ADTP_API_KEY=<your-key>

# Run the example
python main.py
```

## What it demonstrates

- Agent registration via ADTP REST API
- Root credential issuance with capability scoping
- RESTRICT mode delegation with caveats
- Credential verification before tool execution
- Revocation killing the entire delegation chain
