package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	asset "cloud.google.com/go/asset/apiv1"
	"cloud.google.com/go/asset/apiv1/assetpb"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/piotrmackowski/gcp-security-mcp/internal/state"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func registerIAMAudit(s *server.MCPServer, tracker *state.Tracker, opts []option.ClientOption) {
	tool := mcp.NewTool("audit_iam",
		mcp.WithDescription(
			"Audit IAM policies across a GCP project or organization. "+
				"Finds overprivileged accounts, external members, "+
				"and basic roles (Owner/Editor) that should be replaced with granular roles. "+
				"Results are tracked for diffing across runs.",
		),
		mcp.WithString("scope",
			mcp.Required(),
			mcp.Description(
				"Scope to audit. Use 'projects/<id>', 'folders/<id>', or 'organizations/<id>'",
			),
		),
		mcp.WithBoolean("include_google_managed",
			mcp.Description("Include Google-managed service accounts (default: false)"),
		),
	)

	s.AddTool(tool, makeIAMAuditHandler(tracker, opts))
}

// iamFinding is an IAM-specific finding for structured output.
type iamFinding struct {
	Member   string   `json:"member"`
	Roles    []string `json:"roles"`
	Issues   []string `json:"issues"`
	Resource string   `json:"resource"`
	Severity string   `json:"severity"`
}

func makeIAMAuditHandler(tracker *state.Tracker, opts []option.ClientOption) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		scope := req.GetString("scope", "")
		if scope == "" {
			return mcp.NewToolResultError("scope is required"), nil
		}
		includeGoogleManaged := req.GetBool("include_google_managed", false)

		client, err := asset.NewClient(ctx, opts...)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to create asset client: %v", err)), nil
		}
		defer client.Close()

		// Search all IAM policies in the scope
		it := client.SearchAllIamPolicies(ctx, &assetpb.SearchAllIamPoliciesRequest{
			Scope: scope,
		})

		// Aggregate: member -> list of (resource, role)
		type binding struct {
			Resource string
			Role     string
		}
		memberBindings := make(map[string][]binding)

		for {
			result, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Error iterating IAM policies: %v", err)), nil
			}

			if result.Policy == nil {
				continue
			}
			for _, b := range result.Policy.Bindings {
				for _, member := range b.Members {
					if !includeGoogleManaged && isGoogleManaged(member) {
						continue
					}
					memberBindings[member] = append(memberBindings[member], binding{
						Resource: result.Resource,
						Role:     b.Role,
					})
				}
			}
		}

		// Analyze for issues
		var findings []iamFinding
		var stateFindings []state.Finding

		for member, bindings := range memberBindings {
			roles := make(map[string]bool)
			resources := make(map[string]bool)
			for _, b := range bindings {
				roles[b.Role] = true
				resources[b.Resource] = true
			}

			var issues []string
			severity := "INFO"

			// Check for basic roles
			for role := range roles {
				switch {
				case role == "roles/owner":
					issues = append(issues, "Has Owner role — extremely broad permissions")
					severity = "CRITICAL"
				case role == "roles/editor":
					issues = append(issues, "Has Editor role — very broad permissions, use granular roles")
					if severity != "CRITICAL" {
						severity = "HIGH"
					}
				case strings.HasSuffix(role, ".admin"):
					if severity == "INFO" {
						severity = "MEDIUM"
					}
					issues = append(issues, fmt.Sprintf("Has admin role: %s", role))
				}
			}

			// Check for external members
			if isExternal(member) {
				issues = append(issues, "External member (not in organization domain)")
				if severity == "INFO" {
					severity = "MEDIUM"
				}
			}

			if len(issues) == 0 {
				continue
			}

			roleList := mapKeys(roles)
			resourceStr := fmt.Sprintf("%d resources", len(resources))
			if len(resources) == 1 {
				resourceStr = mapKeys(resources)[0]
			}

			findings = append(findings, iamFinding{
				Member:   member,
				Roles:    roleList,
				Issues:   issues,
				Resource: resourceStr,
				Severity: severity,
			})

			stateFindings = append(stateFindings, state.Finding{
				Tool:       "audit_iam",
				ProjectID:  scope,
				ResourceID: member,
				Severity:   severity,
				Title:      strings.Join(issues, "; "),
				Detail:     fmt.Sprintf("Roles: %s", strings.Join(roleList, ", ")),
			})
		}

		// Diff against previous state
		diff, err := tracker.Diff("audit_iam", stateFindings)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("State tracking error: %v", err)), nil
		}

		result := map[string]any{
			"scope":          scope,
			"total_findings": len(findings),
			"findings":       findings,
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

func isGoogleManaged(member string) bool {
	return strings.Contains(member, "gserviceaccount.com") &&
		(strings.Contains(member, "@cloudservices.gserviceaccount.com") ||
			strings.Contains(member, "@system.gserviceaccount.com") ||
			strings.Contains(member, "firebase-adminsdk") ||
			strings.Contains(member, "@developer.gserviceaccount.com"))
}

func isExternal(member string) bool {
	return strings.HasPrefix(member, "user:") &&
		!strings.Contains(member, "@") // heuristic; customize per org domain
}

func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
