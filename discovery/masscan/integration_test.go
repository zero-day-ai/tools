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

func TestMasscanIntegration(t *testing.T) {
	// Skip if masscan binary is not available
	if !exec.BinaryExists(BinaryName) {
		t.Skipf("skipping integration test: %s binary not found", BinaryName)
	}

	// Masscan requires root or CAP_NET_RAW
	if os.Geteuid() != 0 {
		// Check if binary has capabilities
		t.Log("warning: masscan typically requires root or CAP_NET_RAW capability")
	}

	tool := NewTool()

	// Verify health check
	t.Run("HealthCheck", func(t *testing.T) {
		ctx := context.Background()
		health := tool.Health(ctx)

		if health.Status == types.StatusUnhealthy {
			t.Logf("masscan health: %s", health.Message)
		}
	})

	// Test localhost scan (may fail without root)
	t.Run("LocalhostScan", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("skipping test: masscan requires root privileges")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		input := map[string]any{
			"targets": "127.0.0.1",
			"ports":   "22,80,443",
			"rate":    1000,
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
}
