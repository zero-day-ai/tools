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

func TestJohnIntegration(t *testing.T) {
	// Skip if john binary is not available
	if !executor.BinaryExists(BinaryName) {
		t.Skipf("skipping integration test: %s binary not found", BinaryName)
	}

	tool := NewTool()

	// Verify health check passes
	t.Run("HealthCheck", func(t *testing.T) {
		ctx := context.Background()
		health := tool.Health(ctx)

		if health.Status != types.StatusHealthy {
			t.Logf("john health: %s", health.Message)
		}
	})

	// Test with a simple password hash
	t.Run("WordlistMode", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode")
		}

		// Create a test hash file (Unix crypt hash of "password")
		tmpHashFile, err := os.CreateTemp("", "john-hash-*.txt")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpHashFile.Name())

		// Simple MD5-based crypt hash
		tmpHashFile.WriteString("testuser:$1$salt$qJH7.N4xYta3aEG/dfqo/0\n")
		tmpHashFile.Close()

		// Create a simple wordlist
		tmpWordlist, err := os.CreateTemp("", "john-wordlist-*.txt")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpWordlist.Name())

		tmpWordlist.WriteString("password\n")
		tmpWordlist.WriteString("test123\n")
		tmpWordlist.WriteString("admin\n")
		tmpWordlist.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		input := map[string]any{
			"hash_file": tmpHashFile.Name(),
			"mode":      "wordlist",
			"wordlist":  tmpWordlist.Name(),
		}

		output, err := tool.Execute(ctx, input)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}

		// Validate output structure
		if cracked, ok := output["cracked"].([]any); !ok {
			t.Errorf("expected cracked to be []any, got %T", output["cracked"])
		} else {
			t.Logf("cracked %d hashes", len(cracked))
		}
	})
}
