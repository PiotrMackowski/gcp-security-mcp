// Package state provides a JSON-file-backed state tracker for diffing
// security findings across runs.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Finding represents a single security finding that can be tracked.
type Finding struct {
	Tool       string    `json:"tool"`
	ProjectID  string    `json:"project_id"`
	ResourceID string    `json:"resource_id"`
	Severity   string    `json:"severity"`
	Title      string    `json:"title"`
	Detail     string    `json:"detail"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Reviewed   bool      `json:"reviewed"`
	ReviewedAt time.Time `json:"reviewed_at,omitempty"`
}

// Key returns a unique identifier for deduplication.
func (f Finding) Key() string {
	return fmt.Sprintf("%s|%s|%s|%s", f.Tool, f.ProjectID, f.ResourceID, f.Title)
}

// Snapshot represents the full persisted state.
type Snapshot struct {
	UpdatedAt time.Time          `json:"updated_at"`
	Findings  map[string]Finding `json:"findings"` // keyed by Finding.Key()
}

// Tracker manages finding state across runs.
type Tracker struct {
	mu       sync.Mutex
	path     string
	snapshot Snapshot
}

// NewTracker loads or creates a state file. If path is empty, uses
// ~/.config/gcp-security-mcp/state.json.
func NewTracker(path string) (*Tracker, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("get home dir: %w", err)
		}
		dir := filepath.Join(home, ".config", "gcp-security-mcp")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create config dir: %w", err)
		}
		path = filepath.Join(dir, "state.json")
	}

	t := &Tracker{
		path: path,
		snapshot: Snapshot{
			Findings: make(map[string]Finding),
		},
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return t, nil
		}
		return nil, fmt.Errorf("read state: %w", err)
	}

	if err := json.Unmarshal(data, &t.snapshot); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}

	return t, nil
}

// DiffResult groups findings into new, still-present, and resolved.
type DiffResult struct {
	New          []Finding `json:"new"`
	StillPresent []Finding `json:"still_present"`
	Resolved     []Finding `json:"resolved"`
}

// Diff compares current findings against stored state for a given tool.
// It updates the stored state and persists it.
func (t *Tracker) Diff(tool string, current []Finding) (*DiffResult, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	result := &DiffResult{}
	seen := make(map[string]bool)

	for _, f := range current {
		f.Tool = tool
		f.LastSeen = now
		key := f.Key()
		seen[key] = true

		existing, exists := t.snapshot.Findings[key]
		if !exists {
			f.FirstSeen = now
			t.snapshot.Findings[key] = f
			result.New = append(result.New, f)
		} else {
			existing.LastSeen = now
			existing.Detail = f.Detail
			existing.Severity = f.Severity
			t.snapshot.Findings[key] = existing
			result.StillPresent = append(result.StillPresent, existing)
		}
	}

	// Find resolved: previously seen for this tool but not in current
	for key, f := range t.snapshot.Findings {
		if f.Tool == tool && !seen[key] {
			result.Resolved = append(result.Resolved, f)
			delete(t.snapshot.Findings, key)
		}
	}

	t.snapshot.UpdatedAt = now
	return result, t.persist()
}

// MarkReviewed marks a finding as reviewed by key.
func (t *Tracker) MarkReviewed(key string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	f, ok := t.snapshot.Findings[key]
	if !ok {
		return fmt.Errorf("finding not found: %s", key)
	}
	f.Reviewed = true
	f.ReviewedAt = time.Now()
	t.snapshot.Findings[key] = f
	return t.persist()
}

// ListUnreviewed returns all findings that haven't been reviewed.
func (t *Tracker) ListUnreviewed() []Finding {
	t.mu.Lock()
	defer t.mu.Unlock()

	var out []Finding
	for _, f := range t.snapshot.Findings {
		if !f.Reviewed {
			out = append(out, f)
		}
	}
	return out
}

func (t *Tracker) persist() error {
	data, err := json.MarshalIndent(t.snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	return os.WriteFile(t.path, data, 0o600)
}
