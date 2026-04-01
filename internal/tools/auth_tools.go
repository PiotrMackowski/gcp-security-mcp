package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/piotrmackowski/gcp-security-mcp/internal/auth"
)

func registerAuthTools(s *server.MCPServer, store *auth.TokenStore) {
	// gcp_auth — trigger login flow
	authTool := mcp.NewTool("gcp_auth",
		mcp.WithDescription(
			"Authenticate to GCP using OAuth2 (browser-based login). "+
				"Opens your browser to Google's consent screen. "+
				"After approving, credentials are saved locally for future use. "+
				"This is the same flow that 'gcloud auth login' uses. "+
				"Requires confirm=true to prevent unintended browser opens.",
		),
		mcp.WithBoolean("confirm",
			mcp.Required(),
			mcp.Description("Must be true to proceed. Guards against unintended invocation."),
		),
	)

	s.AddTool(authTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !req.GetBool("confirm", false) {
			return mcp.NewToolResultError("confirm must be true to proceed with authentication"), nil
		}

		tok, authURL, err := auth.Login(ctx, store)
		if err != nil {
			result := map[string]any{
				"status":   "error",
				"error":    err.Error(),
				"auth_url": authURL,
				"hint":     "If the browser didn't open, visit the auth_url manually",
			}
			out, _ := json.MarshalIndent(result, "", "  ")
			return mcp.NewToolResultError(string(out)), nil
		}

		result := map[string]any{
			"status":     "authenticated",
			"token_type": tok.TokenType,
			"expiry":     tok.Expiry.String(),
			"hint":       "Credentials saved. Restart the MCP server for tools to use the new token.",
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		return mcp.NewToolResultText(string(out)), nil
	})

	// gcp_auth_status — check current auth state
	statusTool := mcp.NewTool("gcp_auth_status",
		mcp.WithDescription(
			"Check if GCP OAuth2 credentials are saved and valid. "+
				"Shows token expiry and whether a refresh token is available.",
		),
	)

	s.AddTool(statusTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		tok, err := store.Load()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Error loading token: %v", err)), nil
		}
		if tok == nil {
			result := map[string]any{
				"status": "not_authenticated",
				"hint":   "Run gcp_auth to authenticate",
			}
			out, _ := json.MarshalIndent(result, "", "  ")
			return mcp.NewToolResultText(string(out)), nil
		}

		result := map[string]any{
			"status":            "authenticated",
			"token_type":        tok.TokenType,
			"expiry":            tok.Expiry.String(),
			"expired":           !tok.Valid(),
			"has_refresh_token": tok.RefreshToken != "",
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		return mcp.NewToolResultText(string(out)), nil
	})

	// gcp_logout — clear saved credentials
	logoutTool := mcp.NewTool("gcp_logout",
		mcp.WithDescription(
			"Remove saved GCP OAuth2 credentials. "+
				"After logout, tools will fall back to Application Default Credentials (ADC) "+
				"or fail if ADC is not configured.",
		),
	)

	s.AddTool(logoutTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		err := store.RevokeAndClear()

		status := "logged_out"
		hint := "Restart the MCP server for changes to take effect. Tools will use ADC if available."
		if err != nil {
			// Token was deleted locally but revocation may have failed
			status = "logged_out_with_warning"
			hint = fmt.Sprintf("Local credentials removed but token revocation failed: %v. "+
				"The token may still be valid at Google until it expires.", err)
		}

		result := map[string]any{
			"status": status,
			"hint":   hint,
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		return mcp.NewToolResultText(string(out)), nil
	})
}
