package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/piotrmackowski/gcp-security-mcp/internal/state"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func registerFirewallAudit(s *server.MCPServer, tracker *state.Tracker, opts []option.ClientOption) {
	tool := mcp.NewTool("audit_firewall_rules",
		mcp.WithDescription(
			"Audit VPC firewall rules for a GCP project. "+
				"Finds overly permissive rules: open to 0.0.0.0/0, "+
				"allowing all ports, or exposing sensitive ports (SSH, RDP, DB) "+
				"to the internet.",
		),
		mcp.WithString("project_id",
			mcp.Required(),
			mcp.Description("GCP project ID to audit"),
		),
	)

	s.AddTool(tool, makeFirewallAuditHandler(tracker, opts))
}

type firewallFinding struct {
	Name         string   `json:"name"`
	Network      string   `json:"network"`
	Direction    string   `json:"direction"`
	Priority     int64    `json:"priority"`
	SourceRanges []string `json:"source_ranges"`
	AllowedPorts []string `json:"allowed_ports"`
	Issues       []string `json:"issues"`
	Severity     string   `json:"severity"`
	Disabled     bool     `json:"disabled"`
}

// Sensitive ports that should never be open to the internet
var sensitivePorts = map[string]string{
	"22":    "SSH",
	"3389":  "RDP",
	"3306":  "MySQL",
	"5432":  "PostgreSQL",
	"27017": "MongoDB",
	"6379":  "Redis",
	"9200":  "Elasticsearch",
	"8080":  "HTTP-alt",
	"8443":  "HTTPS-alt",
	"2379":  "etcd",
	"10250": "Kubelet",
}

func makeFirewallAuditHandler(tracker *state.Tracker, opts []option.ClientOption) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		projectID := req.GetString("project_id", "")
		if projectID == "" {
			return mcp.NewToolResultError("project_id is required"), nil
		}

		client, err := compute.NewFirewallsRESTClient(ctx, opts...)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to create compute client: %v", err)), nil
		}
		defer client.Close()

		it := client.List(ctx, &computepb.ListFirewallsRequest{
			Project: projectID,
		})

		var findings []firewallFinding
		var stateFindings []state.Finding
		totalRules := 0

		for {
			rule, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Error listing firewall rules: %v", err)), nil
			}
			totalRules++

			// Only check INGRESS allow rules
			if rule.GetDirection() != "INGRESS" {
				continue
			}

			var issues []string
			severity := "INFO"
			isOpenToInternet := false

			// Check source ranges
			for _, sr := range rule.GetSourceRanges() {
				if sr == "0.0.0.0/0" || sr == "::/0" {
					isOpenToInternet = true
					break
				}
			}

			if !isOpenToInternet {
				continue
			}

			// Collect allowed ports
			var allowedPorts []string
			allPortsOpen := false

			for _, allowed := range rule.GetAllowed() {
				proto := allowed.GetIPProtocol()
				ports := allowed.GetPorts()

				if len(ports) == 0 {
					// No ports specified = all ports for this protocol
					allowedPorts = append(allowedPorts, fmt.Sprintf("%s:all", proto))
					if proto == "tcp" || proto == "all" {
						allPortsOpen = true
					}
				}
				for _, port := range ports {
					allowedPorts = append(allowedPorts, fmt.Sprintf("%s:%s", proto, port))
				}
			}

			if allPortsOpen {
				issues = append(issues, "All ports open to the internet (0.0.0.0/0)")
				severity = "CRITICAL"
			} else {
				// Check for sensitive ports
				for _, allowed := range rule.GetAllowed() {
					for _, port := range allowed.GetPorts() {
						// Handle port ranges
						if svc, ok := sensitivePorts[port]; ok {
							issues = append(issues, fmt.Sprintf("%s port (%s) open to internet", svc, port))
							if severity != "CRITICAL" {
								severity = "HIGH"
							}
						}
					}
				}
				if len(issues) == 0 {
					issues = append(issues, "Port(s) open to internet (0.0.0.0/0)")
					severity = "MEDIUM"
				}
			}

			// Extract network short name
			networkParts := strings.Split(rule.GetNetwork(), "/")
			network := networkParts[len(networkParts)-1]

			findings = append(findings, firewallFinding{
				Name:         rule.GetName(),
				Network:      network,
				Direction:    rule.GetDirection(),
				Priority:     int64(rule.GetPriority()),
				SourceRanges: rule.GetSourceRanges(),
				AllowedPorts: allowedPorts,
				Issues:       issues,
				Severity:     severity,
				Disabled:     rule.GetDisabled(),
			})

			stateFindings = append(stateFindings, state.Finding{
				Tool:       "audit_firewall_rules",
				ProjectID:  projectID,
				ResourceID: rule.GetName(),
				Severity:   severity,
				Title:      strings.Join(issues, "; "),
				Detail:     fmt.Sprintf("Network: %s, Ports: %s", network, strings.Join(allowedPorts, ", ")),
			})
		}

		diff, err := tracker.Diff("audit_firewall_rules", stateFindings)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("State tracking error: %v", err)), nil
		}

		result := map[string]any{
			"project_id":     projectID,
			"total_rules":    totalRules,
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
