package integration

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const envoyAddr = "http://localhost:8000"

func TestMain(m *testing.M) {
	repoRoot, err := findRepoRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to find repo root: %v\n", err)
		os.Exit(1)
	}

	if err := startCompose(repoRoot); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start docker compose: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	stopCompose(repoRoot)
	os.Exit(code)
}

func findRepoRoot() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func startCompose(repoRoot string) error {
	cmd := exec.Command("docker", "compose", "up", "--build", "-d")
	cmd.Dir = repoRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker compose up: %w", err)
	}
	return waitForReady(envoyAddr+"/service", 60*time.Second)
}

func stopCompose(repoRoot string) {
	cmd := exec.Command("docker", "compose", "down", "-v")
	cmd.Dir = repoRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func waitForReady(url string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for %s to become ready", url)
		case <-ticker.C:
			resp, err := http.Get(url)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return nil
				}
			}
		}
	}
}

// TestPositive_ValidRequest verifies that a normal request passes through the WAF.
func TestPositive_ValidRequest(t *testing.T) {
	resp, err := http.Get(envoyAddr + "/service?id=1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestBlock_QueryArgID0 verifies that id=0 is blocked by WAF rule 1 (phase 1).
func TestBlock_QueryArgID0(t *testing.T) {
	resp, err := http.Get(envoyAddr + "/service?id=0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

// TestBlock_MaliciousBody verifies that a body containing "lalalala" is blocked
// by WAF rule 100005 (phase 2).
func TestBlock_MaliciousBody(t *testing.T) {
	resp, err := http.Post(envoyAddr+"/service?id=1", "application/x-www-form-urlencoded", strings.NewReader("lalalala"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

// TestBlock_ResponseHeader verifies that a response containing a "badheader"
// header is blocked by WAF rule 900005 (phase 3).
func TestBlock_ResponseHeader(t *testing.T) {
	req, err := http.NewRequest("GET", envoyAddr+"/service?id=1", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The echo-basic upstream sets response headers from X-Echo-Set-Header.
	req.Header.Set("X-Echo-Set-Header", "badheader: yeap")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

// TestBlock_ResponseBodyDLP verifies that a response body containing
// "confidential_data" is blocked by WAF rule 900001 (phase 4).
// The echo-basic upstream echoes request headers in the response body,
// so sending a header with value "confidential_data" triggers this rule.
func TestBlock_ResponseBodyDLP(t *testing.T) {
	req, err := http.NewRequest("GET", envoyAddr+"/service", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req.Header.Set("Block", "confidential_data")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	// The WAF clears the body and closes the connection; Envoy returns 500.
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", resp.StatusCode)
	}
}
