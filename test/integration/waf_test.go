package integration

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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
	_ = cmd.Run()
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
				_ = resp.Body.Close()
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
	defer func() { _ = resp.Body.Close() }()

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
	defer func() { _ = resp.Body.Close() }()

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
	defer func() { _ = resp.Body.Close() }()

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
	defer func() { _ = resp.Body.Close() }()

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
	defer func() { _ = resp.Body.Close() }()

	// The WAF clears the body and closes the connection; Envoy returns 500.
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", resp.StatusCode)
	}
}

// TestHotReload_NewRulePickedUp verifies that adding a new rule file to the
// rules directory causes the WAF to reload and enforce the new rule without
// restarting the service.
func TestHotReload_NewRulePickedUp(t *testing.T) {
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("failed to find repo root: %v", err)
	}

	ruleFile := filepath.Join(repoRoot, "config", "rules", "rules", "hotreload_test.conf")
	t.Cleanup(func() {
		_ = os.Remove(ruleFile)
	})

	// Step 1: confirm that the request is allowed before the new rule exists.
	resp, err := http.Get(envoyAddr + "/service?hotreload=yes")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 before rule addition, got %d", resp.StatusCode)
	}

	// Step 2: write a new rule that blocks requests with ?hotreload=yes.
	rule := `SecRule ARGS:hotreload "@streq yes" "id:999999, phase:1, deny, status:403, msg:'Hot reload test rule', log, auditlog"`
	if err := os.WriteFile(ruleFile, []byte(rule), 0644); err != nil {
		t.Fatalf("failed to write rule file: %v", err)
	}

	// Step 3: wait for the WAF to pick up the change and reload.
	// The watcher debounce is 50ms, but filesystem events and WAF init take time.
	var blocked bool
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		resp, err = http.Get(envoyAddr + "/service?hotreload=yes")
		if err != nil {
			t.Logf("request error while polling: %v", err)
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden {
			blocked = true
			break
		}
	}

	if !blocked {
		t.Errorf("expected request to be blocked (403) after hot reload, but it was not")
	}

	// Step 4: remove the rule and verify the request is allowed again.
	if err := os.Remove(ruleFile); err != nil {
		t.Fatalf("failed to remove rule file: %v", err)
	}

	var unblocked bool
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		resp, err = http.Get(envoyAddr + "/service?hotreload=yes")
		if err != nil {
			t.Logf("request error while polling: %v", err)
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			unblocked = true
			break
		}
	}

	if !unblocked {
		t.Errorf("expected request to be allowed (200) after rule removal, but it was not")
	}
}
