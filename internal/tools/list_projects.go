package tools

import (
	"context"
	"encoding/json"
	"fmt"

	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	"cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func registerListProjects(s *server.MCPServer, opts []option.ClientOption) {
	tool := mcp.NewTool("list_projects",
		mcp.WithDescription(
			"List GCP projects accessible with current credentials. "+
				"Useful for discovering project IDs to pass to other audit tools.",
		),
		mcp.WithString("parent",
			mcp.Description(
				"Optional parent to filter by (e.g., 'folders/123' or 'organizations/456'). "+
					"If omitted, lists all accessible projects.",
			),
		),
	)

	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		parent := req.GetString("parent", "")

		client, err := resourcemanager.NewProjectsClient(ctx, opts...)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to create projects client: %v", err)), nil
		}
		defer client.Close()

		listReq := &resourcemanagerpb.ListProjectsRequest{
			Parent: parent,
		}

		// If no parent, search all projects instead
		if parent == "" {
			searchReq := &resourcemanagerpb.SearchProjectsRequest{}
			it := client.SearchProjects(ctx, searchReq)

			type projectInfo struct {
				ID     string `json:"project_id"`
				Name   string `json:"name"`
				Number int64  `json:"project_number"`
				State  string `json:"state"`
				Parent string `json:"parent,omitempty"`
			}

			var projects []projectInfo
			for {
				p, err := it.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					return mcp.NewToolResultError(fmt.Sprintf("Error listing projects: %v", err)), nil
				}
				parentStr := ""
				if p.Parent != "" {
					parentStr = p.Parent
				}
				projects = append(projects, projectInfo{
					ID:     p.ProjectId,
					Name:   p.DisplayName,
					State:  p.State.String(),
					Parent: parentStr,
				})
			}

			result := map[string]any{
				"total_projects": len(projects),
				"projects":       projects,
			}
			out, _ := json.MarshalIndent(result, "", "  ")
			return mcp.NewToolResultText(string(out)), nil
		}

		it := client.ListProjects(ctx, listReq)
		type projectInfo struct {
			ID     string `json:"project_id"`
			Name   string `json:"name"`
			State  string `json:"state"`
			Parent string `json:"parent,omitempty"`
		}

		var projects []projectInfo
		for {
			p, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Error listing projects: %v", err)), nil
			}
			projects = append(projects, projectInfo{
				ID:    p.ProjectId,
				Name:  p.DisplayName,
				State: p.State.String(),
			})
		}

		result := map[string]any{
			"parent":         parent,
			"total_projects": len(projects),
			"projects":       projects,
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		return mcp.NewToolResultText(string(out)), nil
	})
}
