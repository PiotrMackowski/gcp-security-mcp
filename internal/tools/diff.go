package tools

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/piotrmackowski/gcp-security-mcp/internal/state"
)

func registerDiffFindings(s *server.MCPServer, tracker *state.Tracker) {
	listUnreviewed := mcp.NewTool("list_unreviewed",
		mcp.WithDescription(
			"List all unreviewed security findings from previous scans. "+
				"Findings from all tools (IAM, SA keys, buckets, firewall, SCC) "+
				"that have not yet been marked as reviewed.",
		),
	)

	s.AddTool(listUnreviewed, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		findings := tracker.ListUnreviewed()

		result := map[string]any{
			"total_unreviewed": len(findings),
			"findings":         findings,
		}

		out, _ := json.MarshalIndent(result, "", "  ")
		return mcp.NewToolResultText(string(out)), nil
	})

	markReviewed := mcp.NewTool("mark_reviewed",
		mcp.WithDescription(
			"Mark a specific security finding as reviewed. "+
				"Use the finding key from list_unreviewed output. "+
				"Format: tool|project_id|resource_id|title",
		),
		mcp.WithString("finding_key",
			mcp.Required(),
			mcp.Description("Finding key in format: tool|project_id|resource_id|title"),
		),
	)

	s.AddTool(markReviewed, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		key := req.GetString("finding_key", "")
		if key == "" {
			return mcp.NewToolResultError("finding_key is required"), nil
		}

		if err := tracker.MarkReviewed(key); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		result := map[string]any{
			"status":      "reviewed",
			"finding_key": key,
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		return mcp.NewToolResultText(string(out)), nil
	})
}
