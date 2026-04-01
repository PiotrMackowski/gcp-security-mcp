// Package tools registers all MCP tools for the GCP security server.
package tools

import (
	"github.com/mark3labs/mcp-go/server"
	"github.com/piotrmackowski/gcp-security-mcp/internal/auth"
	"github.com/piotrmackowski/gcp-security-mcp/internal/state"
	"google.golang.org/api/option"
)

// RegisterAll registers every security tool on the MCP server.
func RegisterAll(s *server.MCPServer, tracker *state.Tracker, tokenStore *auth.TokenStore, opts []option.ClientOption) {
	registerIAMAudit(s, tracker, opts)
	registerSAKeyAudit(s, tracker, opts)
	registerPublicBuckets(s, tracker, opts)
	registerFirewallAudit(s, tracker, opts)
	registerSCCFindings(s, tracker, opts)
	registerDiffFindings(s, tracker)
	registerListProjects(s, opts)
	registerAuthTools(s, tokenStore)
}
