package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/piotrmackowski/gcp-security-mcp/internal/state"
	admin "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

func registerSAKeyAudit(s *server.MCPServer, tracker *state.Tracker, opts []option.ClientOption) {
	tool := mcp.NewTool("audit_sa_keys",
		mcp.WithDescription(
			"Audit service account keys for a GCP project. "+
				"Finds user-managed keys, old keys (>90 days), "+
				"and service accounts with multiple active keys. "+
				"Google recommends avoiding user-managed keys entirely.",
		),
		mcp.WithString("project_id",
			mcp.Required(),
			mcp.Description("GCP project ID to audit"),
		),
		mcp.WithNumber("max_key_age_days",
			mcp.Description("Flag keys older than this many days (default: 90)"),
		),
	)

	s.AddTool(tool, makeSAKeyAuditHandler(tracker, opts))
}

type saKeyFinding struct {
	ServiceAccount string   `json:"service_account"`
	Email          string   `json:"email"`
	KeyID          string   `json:"key_id"`
	CreatedAt      string   `json:"created_at"`
	AgeDays        int      `json:"age_days"`
	KeyType        string   `json:"key_type"`
	Issues         []string `json:"issues"`
	Severity       string   `json:"severity"`
}

func makeSAKeyAuditHandler(tracker *state.Tracker, opts []option.ClientOption) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		projectID := req.GetString("project_id", "")
		if projectID == "" {
			return mcp.NewToolResultError("project_id is required"), nil
		}
		maxAge := int(req.GetFloat("max_key_age_days", 90))

		iamService, err := admin.NewService(ctx, opts...)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to create IAM client: %v", err)), nil
		}

		// List all service accounts in the project
		saList, err := iamService.Projects.ServiceAccounts.List(
			fmt.Sprintf("projects/%s", projectID),
		).Context(ctx).Do()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to list service accounts: %v", err)), nil
		}

		var findings []saKeyFinding
		var stateFindings []state.Finding

		for _, sa := range saList.Accounts {
			keysResp, err := iamService.Projects.ServiceAccounts.Keys.List(
				sa.Name,
			).KeyTypes("USER_MANAGED").Context(ctx).Do()
			if err != nil {
				// Skip SAs we can't read keys for
				continue
			}

			for _, key := range keysResp.Keys {
				var issues []string
				severity := "MEDIUM"

				// Parse creation time
				createdAt, _ := time.Parse(time.RFC3339, key.ValidAfterTime)
				ageDays := int(time.Since(createdAt).Hours() / 24)

				issues = append(issues, "User-managed key exists (prefer workload identity or attached SAs)")

				if ageDays > maxAge {
					issues = append(issues, fmt.Sprintf("Key is %d days old (threshold: %d)", ageDays, maxAge))
					severity = "HIGH"
				}

				if len(keysResp.Keys) > 1 {
					issues = append(issues, fmt.Sprintf("SA has %d active user-managed keys", len(keysResp.Keys)))
				}

				// Extract short key ID from the full resource name
				parts := strings.Split(key.Name, "/")
				keyID := parts[len(parts)-1]

				findings = append(findings, saKeyFinding{
					ServiceAccount: sa.Name,
					Email:          sa.Email,
					KeyID:          keyID,
					CreatedAt:      key.ValidAfterTime,
					AgeDays:        ageDays,
					KeyType:        "USER_MANAGED",
					Issues:         issues,
					Severity:       severity,
				})

				stateFindings = append(stateFindings, state.Finding{
					Tool:       "audit_sa_keys",
					ProjectID:  projectID,
					ResourceID: fmt.Sprintf("%s/%s", sa.Email, keyID),
					Severity:   severity,
					Title:      strings.Join(issues, "; "),
					Detail:     fmt.Sprintf("Age: %d days, SA: %s", ageDays, sa.Email),
				})
			}
		}

		diff, err := tracker.Diff("audit_sa_keys", stateFindings)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("State tracking error: %v", err)), nil
		}

		result := map[string]any{
			"project_id":               projectID,
			"service_accounts_scanned": len(saList.Accounts),
			"total_findings":           len(findings),
			"findings":                 findings,
			"diff": map[string]int{
				"new":           len(diff.New),
				"still_present": len(diff.StillPresent),
				"resolved":      len(diff.Resolved),
			},
		}

		out, _ := json.MarshalIndent(result, "", "  ")
		return mcp.NewToolResultText(string(out)), nil
	}
}
