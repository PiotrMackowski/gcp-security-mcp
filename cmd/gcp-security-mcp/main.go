package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/mark3labs/mcp-go/server"
	"github.com/piotrmackowski/gcp-security-mcp/internal/auth"
	"github.com/piotrmackowski/gcp-security-mcp/internal/state"
	"github.com/piotrmackowski/gcp-security-mcp/internal/tools"
	"google.golang.org/api/option"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	tracker, err := state.NewTracker("")
	if err != nil {
		log.Fatalf("Failed to initialize state tracker: %v", err)
	}

	tokenStore, err := auth.NewTokenStore("")
	if err != nil {
		log.Fatalf("Failed to initialize token store: %v", err)
	}

	// Try to load existing credentials
	var gcpOpts []option.ClientOption
	ctx := context.Background()
	opt, err := auth.ClientOption(ctx, tokenStore)
	if err != nil {
		log.Printf("Warning: could not load saved credentials: %v", err)
	}
	if opt != nil {
		gcpOpts = append(gcpOpts, opt)
		log.Println("Loaded saved OAuth2 credentials")
	} else {
		log.Println("No saved credentials — use gcp_auth tool to authenticate")
	}

	s := server.NewMCPServer(
		"gcp-security-mcp",
		"0.1.0",
		server.WithToolCapabilities(true),
	)

	tools.RegisterAll(s, tracker, tokenStore, gcpOpts)

	log.Println("gcp-security-mcp server starting on stdio")
	if err := server.ServeStdio(s); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
