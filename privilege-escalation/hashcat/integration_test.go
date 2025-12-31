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

func TestHashcatIntegration(t *testing.T) {
	// Skip if hashcat binary is not available
	if !exec.BinaryExists(BinaryName) {
		t.Skipf("skipping integration test: %s binary not found", BinaryName)
	}

	tool := NewTool()

	// Verify health check
	t.Run("HealthCheck", func(t *testing.T) {
		ctx := context.Background()
		health := tool.Health(ctx)

		// Health may be degraded without GPU
		if health.Status == types.StatusUnhealthy {
			t.Logf("hashcat health: %s", health.Message)
		}
	})

	// Test with a simple MD5 hash and dictionary attack
	t.Run("DictionaryAttack", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode")
		}

		// Create a simple test wordlist
		tmpWordlist, err := os.CreateTemp("", "hashcat-wordlist-*.txt")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpWordlist.Name())

		// Write some test passwords
		tmpWordlist.WriteString("password\n")
		tmpWordlist.WriteString("test123\n")
		tmpWordlist.WriteString("admin\n")
		tmpWordlist.Close()

		// Create a test hash file (MD5 hash of "password")
		tmpHashFile, err := os.CreateTemp("", "hashcat-hash-*.txt")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpHashFile.Name())

		// MD5 hash of "password"
		tmpHashFile.WriteString("5f4dcc3b5aa765d61d8327deb882cf99\n")
		tmpHashFile.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		input := map[string]any{
			"hash_file":   tmpHashFile.Name(),
			"hash_type":   0, // MD5
			"attack_mode": 0, // Dictionary
			"wordlist":    tmpWordlist.Name(),
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
