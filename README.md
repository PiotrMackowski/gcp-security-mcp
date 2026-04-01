# gcp-security-mcp

MCP server for opinionated GCP security audits. Wraps GCP APIs into security-focused tools with state tracking and finding diffing across runs.

## Build

```
go build -o gcp-security-mcp ./cmd/gcp-security-mcp
```

## Auth

Uses OAuth2 browser login (same flow as `gcloud auth login`). Call the `gcp_auth` tool from your MCP client to authenticate. Tokens are saved to `~/.config/gcp-security-mcp/token.json`.

Falls back to Application Default Credentials if no OAuth token is saved.

## MCP client config

```json
{
  "mcpServers": {
    "gcp-security": {
      "command": "/path/to/gcp-security-mcp"
    }
  }
}
```

## Tools

| Tool | What it does |
|------|-------------|
| `gcp_auth` | OAuth2 browser login |
| `gcp_auth_status` | Check if authenticated |
| `gcp_logout` | Clear saved credentials |
| `list_projects` | List accessible GCP projects |
| `audit_iam` | IAM policy audit (Owner/Editor roles, external members, admin roles) |
| `audit_sa_keys` | Service account key audit (user-managed keys, age, count) |
| `audit_public_buckets` | Public Cloud Storage bucket detection |
| `audit_firewall_rules` | VPC firewall rule audit (0.0.0.0/0, sensitive ports) |
| `list_scc_findings` | Security Command Center findings (severity/category filtering) |
| `list_unreviewed` | Show unreviewed findings from previous scans |
| `mark_reviewed` | Mark a finding as reviewed |

## State tracking

Findings are tracked in `~/.config/gcp-security-mcp/state.json`. Each scan diffs against the previous run and reports new, still present, and resolved findings.

## Required GCP APIs

Enable these on your project(s):
- Cloud Asset API
- IAM API
- Cloud Storage API
- Compute Engine API
- Security Command Center API (if using SCC tools)
