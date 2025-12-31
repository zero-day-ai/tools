//go:build integration

package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/types"
)

func TestGobusterIntegration(t *testing.T) {
	// Skip if gobuster binary is not available
	if !executor.BinaryExists(BinaryName) {
		t.Skipf("skipping integration test: %s binary not found", BinaryName)
	}

	tool := NewTool()

	// Verify health check
	t.Run("HealthCheck", func(t *testing.T) {
		ctx := context.Background()
		health := tool.Health(ctx)

		// Health may be degraded if wordlist is missing
		if health.Status == types.StatusUnhealthy {
			t.Logf("gobuster health: %s", health.Message)
		}
	})

	// Test dir mode with example.com
	t.Run("DirMode", func(t *testing.T) {
		// Create a minimal test wordlist
		tmpFile, err := os.CreateTemp("", "gobuster-test-*.txt")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		// Write some common paths
		tmpFile.WriteString("index.html\n")
		tmpFile.WriteString("robots.txt\n")
		tmpFile.WriteString("sitemap.xml\n")
		tmpFile.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		input := map[string]any{
			"mode":     "dir",
			"url":      "https://example.com",
			"wordlist": tmpFile.Name(),
			"threads":  10,
		}

		output, err := tool.Execute(ctx, input)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}

		// Validate output structure
		if results, ok := output["results"].([]any); !ok {
			t.Errorf("expected results to be []any, got %T", output["results"])
		} else {
			t.Logf("found %d results", len(results))
		}

		if count, ok := output["count"].(int); !ok || count < 0 {
			t.Errorf("expected valid count, got %v", output["count"])
		}
	})

	// Test DNS mode
	t.Run("DNSMode", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode")
		}

		// Create a minimal subdomain wordlist
		tmpFile, err := os.CreateTemp("", "gobuster-dns-*.txt")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		tmpFile.WriteString("www\n")
		tmpFile.WriteString("mail\n")
		tmpFile.WriteString("ftp\n")
		tmpFile.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		input := map[string]any{
			"mode":     "dns",
			"domain":   "example.com",
			"wordlist": tmpFile.Name(),
			"threads":  10,
		}

		output, err := tool.Execute(ctx, input)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}

		// Validate output
		if _, ok := output["results"].([]any); !ok {
			t.Errorf("expected results to be []any, got %T", output["results"])
		}
	})
}
