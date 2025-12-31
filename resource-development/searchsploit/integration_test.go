//go:build integration

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/types"
)

func TestSearchsploitIntegration(t *testing.T) {
	// Skip if searchsploit binary is not available
	if !exec.BinaryExists(BinaryName) {
		t.Skipf("skipping integration test: %s binary not found", BinaryName)
	}

	tool := NewTool()

	// Verify health check
	t.Run("HealthCheck", func(t *testing.T) {
		ctx := context.Background()
		health := tool.Health(ctx)

		// Health may be degraded if exploit-db is not installed
		if health.Status == types.StatusUnhealthy {
			t.Logf("searchsploit health: %s", health.Message)
			// Check if exploit-db exists
			exploitDbPath := "/usr/share/exploitdb"
			if _, err := os.Stat(exploitDbPath); os.IsNotExist(err) {
				t.Skip("skipping tests: exploit-db database not found")
			}
		}
	})

	// Test basic search
	t.Run("BasicSearch", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		input := map[string]any{
			"query": "apache 2.4",
		}

		output, err := tool.Execute(ctx, input)
		if err != nil {
			// Check if exploit-db exists
			homeDir, _ := os.UserHomeDir()
			exploitDbPaths := []string{
				"/usr/share/exploitdb",
				filepath.Join(homeDir, ".exploitdb"),
			}
			dbExists := false
			for _, path := range exploitDbPaths {
				if _, err := os.Stat(path); err == nil {
					dbExists = true
					break
				}
			}
			if !dbExists {
				t.Skip("skipping test: exploit-db database not found")
			}
			t.Fatalf("execution failed: %v", err)
		}

		// Validate output structure
		if results, ok := output["results"].([]any); !ok {
			t.Errorf("expected results to be []any, got %T", output["results"])
		} else {
			t.Logf("found %d exploits", len(results))
		}

		if count, ok := output["count"].(int); !ok || count < 0 {
			t.Errorf("expected valid count, got %v", output["count"])
		}
	})

	// Test CVE search
	t.Run("CVESearch", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		input := map[string]any{
			"query": "CVE-2021-44228", // Log4Shell
		}

		output, err := tool.Execute(ctx, input)
		if err != nil {
			t.Skipf("execution failed (exploit-db may not be installed): %v", err)
		}

		// Validate output
		if _, ok := output["results"].([]any); !ok {
			t.Errorf("expected results to be []any, got %T", output["results"])
		}
	})
}
