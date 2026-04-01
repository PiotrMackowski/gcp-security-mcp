package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/piotrmackowski/gcp-security-mcp/internal/state"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func registerPublicBuckets(s *server.MCPServer, tracker *state.Tracker, opts []option.ClientOption) {
	tool := mcp.NewTool("audit_public_buckets",
		mcp.WithDescription(
			"Check for publicly accessible Cloud Storage buckets in a project. "+
				"Finds buckets with allUsers or allAuthenticatedUsers access. "+
				"Public buckets are a leading cause of cloud data breaches.",
		),
		mcp.WithString("project_id",
			mcp.Required(),
			mcp.Description("GCP project ID to scan"),
		),
	)

	s.AddTool(tool, makePublicBucketsHandler(tracker, opts))
}

type bucketFinding struct {
	Bucket     string   `json:"bucket"`
	Location   string   `json:"location"`
	PublicACLs []string `json:"public_acls"`
	Severity   string   `json:"severity"`
	Uniform    bool     `json:"uniform_bucket_level_access"`
}

func makePublicBucketsHandler(tracker *state.Tracker, opts []option.ClientOption) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		projectID := req.GetString("project_id", "")
		if projectID == "" {
			return mcp.NewToolResultError("project_id is required"), nil
		}

		client, err := storage.NewClient(ctx, opts...)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to create storage client: %v", err)), nil
		}
		defer client.Close()

		var findings []bucketFinding
		var stateFindings []state.Finding

		it := client.Buckets(ctx, projectID)
		for {
			bkt, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Error listing buckets: %v", err)), nil
			}

			var publicACLs []string

			// Check bucket-level IAM policy
			policy, err := client.Bucket(bkt.Name).IAM().Policy(ctx)
			if err == nil {
				for _, role := range policy.Roles() {
					members := policy.Members(role)
					for _, member := range members {
						if member == "allUsers" || member == "allAuthenticatedUsers" {
							publicACLs = append(publicACLs,
								fmt.Sprintf("%s: %s", role, member))
						}
					}
				}
			}

			// Check legacy ACLs if not using uniform bucket-level access
			if !bkt.UniformBucketLevelAccess.Enabled {
				acls, err := client.Bucket(bkt.Name).ACL().List(ctx)
				if err == nil {
					for _, acl := range acls {
						entity := string(acl.Entity)
						if entity == "allUsers" || entity == "allAuthenticatedUsers" {
							publicACLs = append(publicACLs,
								fmt.Sprintf("legacy-acl/%s: %s", acl.Role, entity))
						}
					}
				}
			}

			if len(publicACLs) == 0 {
				continue
			}

			severity := "CRITICAL"
			for _, acl := range publicACLs {
				if strings.Contains(acl, "allAuthenticatedUsers") && !strings.Contains(acl, "allUsers") {
					severity = "HIGH"
				}
			}

			findings = append(findings, bucketFinding{
				Bucket:     bkt.Name,
				Location:   bkt.Location,
				PublicACLs: publicACLs,
				Severity:   severity,
				Uniform:    bkt.UniformBucketLevelAccess.Enabled,
			})

			stateFindings = append(stateFindings, state.Finding{
				Tool:       "audit_public_buckets",
				ProjectID:  projectID,
				ResourceID: bkt.Name,
				Severity:   severity,
				Title:      fmt.Sprintf("Public bucket: %s", bkt.Name),
				Detail:     strings.Join(publicACLs, "; "),
			})
		}

		diff, err := tracker.Diff("audit_public_buckets", stateFindings)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("State tracking error: %v", err)), nil
		}

		result := map[string]any{
			"project_id":     projectID,
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
