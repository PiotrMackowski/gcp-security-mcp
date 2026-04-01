// Package auth implements OAuth2 loopback redirect authentication for GCP,
// similar to `gcloud auth login`. It starts a local HTTP server, opens the
// browser, captures the auth code, exchanges it for tokens, and persists
// the refresh token for future runs.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

// Scopes required for all security audit tools.
var Scopes = []string{
	"https://www.googleapis.com/auth/cloud-platform.read-only",
	"https://www.googleapis.com/auth/cloud-platform",
}

// These are the "Google Cloud SDK" OAuth2 client credentials. They are public
// and embedded in the gcloud CLI itself — not secret. Using them lets us do
// the same 3-legged OAuth flow gcloud uses.
const (
	gcloudClientID     = "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com"
	gcloudClientSecret = "d-FL95Q19q7MQmFpd7hHD0Ty"
)

// TokenStore handles loading and saving OAuth2 tokens to disk.
type TokenStore struct {
	path string
	mu   sync.Mutex
}

// NewTokenStore creates a token store. If path is empty, defaults to
// ~/.config/gcp-security-mcp/token.json.
func NewTokenStore(path string) (*TokenStore, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("get home dir: %w", err)
		}
		dir := filepath.Join(home, ".config", "gcp-security-mcp")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create config dir: %w", err)
		}
		path = filepath.Join(dir, "token.json")
	}
	return &TokenStore{path: path}, nil
}

// Load reads a saved token from disk. Returns nil if not found.
func (ts *TokenStore) Load() (*oauth2.Token, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	data, err := os.ReadFile(ts.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read token: %w", err)
	}

	var tok oauth2.Token
	if err := json.Unmarshal(data, &tok); err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	return &tok, nil
}

// Save persists a token to disk.
func (ts *TokenStore) Save(tok *oauth2.Token) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	data, err := json.MarshalIndent(tok, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal token: %w", err)
	}
	return os.WriteFile(ts.path, data, 0o600)
}

// Clear removes the saved token.
func (ts *TokenStore) Clear() error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	err := os.Remove(ts.path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func oauthConfig(redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     gcloudClientID,
		ClientSecret: gcloudClientSecret,
		Endpoint:     google.Endpoint,
		Scopes:       Scopes,
		RedirectURL:  redirectURL,
	}
}

// Login performs the full OAuth2 loopback redirect flow:
// 1. Start local HTTP server on a random port
// 2. Open browser to Google's consent screen
// 3. Capture the auth code via redirect
// 4. Exchange code for access + refresh tokens
// 5. Persist tokens
//
// Returns the auth URL for the caller to present if the browser can't be opened.
func Login(ctx context.Context, store *TokenStore) (*oauth2.Token, string, error) {
	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", fmt.Errorf("listen: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirectURL := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	conf := oauthConfig(redirectURL)

	// Generate random state for CSRF protection
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		listener.Close()
		return nil, "", fmt.Errorf("generate state: %w", err)
	}
	state := hex.EncodeToString(stateBytes)

	authURL := conf.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "consent"))

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			errCh <- fmt.Errorf("state mismatch")
			http.Error(w, "State mismatch", http.StatusBadRequest)
			return
		}
		if errStr := r.URL.Query().Get("error"); errStr != "" {
			errCh <- fmt.Errorf("oauth error: %s", errStr)
			fmt.Fprintf(w, "<html><body><h1>Authentication failed</h1><p>%s</p></body></html>", errStr)
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			errCh <- fmt.Errorf("no code in callback")
			http.Error(w, "No code", http.StatusBadRequest)
			return
		}
		codeCh <- code
		fmt.Fprint(w, `<html><body><h1>Authenticated</h1><p>You can close this tab and return to your terminal.</p></body></html>`)
	})

	srv := &http.Server{Handler: mux}
	go func() {
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Try to open browser
	if err := openBrowser(authURL); err != nil {
		log.Printf("Could not open browser: %v", err)
	}

	// Wait for callback or timeout
	var code string
	select {
	case code = <-codeCh:
	case err := <-errCh:
		srv.Shutdown(ctx)
		return nil, authURL, err
	case <-time.After(5 * time.Minute):
		srv.Shutdown(ctx)
		return nil, authURL, fmt.Errorf("login timed out (5 minutes)")
	case <-ctx.Done():
		srv.Shutdown(ctx)
		return nil, authURL, ctx.Err()
	}

	srv.Shutdown(ctx)

	// Exchange code for token
	tok, err := conf.Exchange(ctx, code)
	if err != nil {
		return nil, authURL, fmt.Errorf("token exchange: %w", err)
	}

	if err := store.Save(tok); err != nil {
		return nil, authURL, fmt.Errorf("save token: %w", err)
	}

	return tok, authURL, nil
}

// TokenSource returns an oauth2.TokenSource that auto-refreshes and persists
// tokens. Returns nil if no saved token exists (caller should trigger Login).
func TokenSource(ctx context.Context, store *TokenStore) (oauth2.TokenSource, error) {
	tok, err := store.Load()
	if err != nil {
		return nil, err
	}
	if tok == nil {
		return nil, nil
	}

	conf := oauthConfig("") // redirect URL not needed for refresh
	ts := conf.TokenSource(ctx, tok)

	// Wrap to persist refreshed tokens
	return &persistingTokenSource{
		base:  ts,
		store: store,
		last:  tok,
	}, nil
}

// ClientOption returns a google.api option.ClientOption for use with GCP
// client libraries. Returns nil if not authenticated (fall through to ADC).
func ClientOption(ctx context.Context, store *TokenStore) (option.ClientOption, error) {
	ts, err := TokenSource(ctx, store)
	if err != nil {
		return nil, err
	}
	if ts == nil {
		return nil, nil
	}
	return option.WithTokenSource(ts), nil
}

type persistingTokenSource struct {
	mu    sync.Mutex
	base  oauth2.TokenSource
	store *TokenStore
	last  *oauth2.Token
}

func (pts *persistingTokenSource) Token() (*oauth2.Token, error) {
	pts.mu.Lock()
	defer pts.mu.Unlock()

	tok, err := pts.base.Token()
	if err != nil {
		return nil, err
	}

	// If token was refreshed (new access token), persist it
	if tok.AccessToken != pts.last.AccessToken {
		if err := pts.store.Save(tok); err != nil {
			log.Printf("Warning: failed to persist refreshed token: %v", err)
		}
		pts.last = tok
	}

	return tok, nil
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return fmt.Errorf("unsupported platform")
	}
}
