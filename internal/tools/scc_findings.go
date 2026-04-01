package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	"cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/piotrmackowski/gcp-security-mcp/internal/state"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func registerSCCFindings(s *server.MCPServer, tracker *state.Tracker, opts []option.ClientOption) {
	tool := mcp.NewTool("list_scc_findings",
		mcp.WithDescription(
			"List active findings from Security Command Center. "+
				"Supports filtering by severity, category, and source. "+
				"SCC aggregates findings from multiple security services: "+
				"Security Health Analytics, Web Security Scanner, Event Threat Detection, etc.",
		),
		mcp.WithString("parent",
			mcp.Required(),
			mcp.Description(
				"SCC parent. Use 'organizations/<org-id>/sources/-' for all sources, "+
					"or a specific source like 'organizations/<org-id>/sources/<source-id>'",
			),
		),
		mcp.WithString("severity",
			mcp.Description("Minimum severity to return: CRITICAL, HIGH, MEDIUM, LOW (default: HIGH)"),
		),
		mcp.WithString("category",
			mcp.Description("Filter by category (e.g., 'PUBLIC_BUCKET_ACL', 'OPEN_FIREWALL')"),
		),
		mcp.WithNumber("max_results",
			mcp.Description("Maximum findings to return (default: 100)"),
		),
	)

	s.AddTool(tool, makeSCCFindingsHandler(tracker, opts))
}

type sccFinding struct {
	Name         string            `json:"name"`
	Category     string            `json:"category"`
	ResourceName string            `json:"resource_name"`
	Severity     string            `json:"severity"`
	State        string            `json:"state"`
	Description  string            `json:"description,omitempty"`
	ExternalURI  string            `json:"external_uri,omitempty"`
	CreateTime   string            `json:"create_time"`
	SourceProps  map[string]string `json:"source_properties,omitempty"`
}

var severityOrder = map[string]int{
	"CRITICAL": 4,
	"HIGH":     3,
	"MEDIUM":   2,
	"LOW":      1,
}

func makeSCCFindingsHandler(tracker *state.Tracker, opts []option.ClientOption) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		parent := req.GetString("parent", "")
		if parent == "" {
			return mcp.NewToolResultError("parent is required (e.g., 'organizations/<org-id>/sources/-')"), nil
		}
		minSeverity := strings.ToUpper(req.GetString("severity", "HIGH"))
		category := req.GetString("category", "")
		maxResults := int(req.GetFloat("max_results", 100))

		client, err := securitycenter.NewClient(ctx, opts...)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to create SCC client: %v", err)), nil
		}
		defer client.Close()

		// Build filter
		filters := []string{"state=\"ACTIVE\""}

		minSevNum, ok := severityOrder[minSeverity]
		if ok {
			var sevFilters []string
			for sev, num := range severityOrder {
				if num >= minSevNum {
					sevFilters = append(sevFilters, fmt.Sprintf("severity=\"%s\"", sev))
				}
			}
			filters = append(filters, fmt.Sprintf("(%s)", strings.Join(sevFilters, " OR ")))
		}

		if category != "" {
			filters = append(filters, fmt.Sprintf("category=\"%s\"", category))
		}

		filter := strings.Join(filters, " AND ")

		it := client.ListFindings(ctx, &securitycenterpb.ListFindingsRequest{
			Parent:  parent,
			Filter:  filter,
			OrderBy: "severity desc",
		})

		var findings []sccFinding
		var stateFindings []state.Finding
		count := 0

		for {
			if count >= maxResults {
				break
			}
			result, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Error listing SCC findings: %v", err)), nil
			}
			count++

			f := result.Finding
			severity := f.GetSeverity().String()

			// Extract source properties as string map (only interesting ones)
			sourceProps := make(map[string]string)
			for k, v := range f.GetSourceProperties() {
				if v != nil {
					sourceProps[k] = fmt.Sprintf("%v", v)
				}
			}
			// Limit to keep output manageable
			if len(sourceProps) > 10 {
				trimmed := make(map[string]string)
				i := 0
				for k, v := range sourceProps {
					if i >= 10 {
						break
					}
					trimmed[k] = v
					i++
				}
				sourceProps = trimmed
			}

			createTime := ""
			if f.GetCreateTime() != nil {
				createTime = f.GetCreateTime().AsTime().String()
			}

			findings = append(findings, sccFinding{
				Name:         f.GetName(),
				Category:     f.GetCategory(),
				ResourceName: f.GetResourceName(),
				Severity:     severity,
				State:        f.GetState().String(),
				Description:  f.GetDescription(),
				ExternalURI:  f.GetExternalUri(),
				CreateTime:   createTime,
				SourceProps:  sourceProps,
			})

			stateFindings = append(stateFindings, state.Finding{
				Tool:       "list_scc_findings",
				ProjectID:  parent,
				ResourceID: f.GetName(),
				Severity:   severity,
				Title:      f.GetCategory(),
				Detail:     fmt.Sprintf("Resource: %s", f.GetResourceName()),
			})
		}

		diff, err := tracker.Diff("list_scc_findings", stateFindings)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("State tracking error: %v", err)), nil
		}

		result := map[string]any{
			"parent":         parent,
			"filter":         filter,
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
