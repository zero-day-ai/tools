//go:build integration

package main

import (
	"context"
	"testing"

	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/types"
)

func TestSqlmapIntegration(t *testing.T) {
	// Skip if sqlmap binary is not available
	if !exec.BinaryExists(BinaryName) {
		t.Skipf("skipping integration test: %s binary not found", BinaryName)
	}

	tool := NewTool()

	// Verify health check passes
	t.Run("HealthCheck", func(t *testing.T) {
		ctx := context.Background()
		health := tool.Health(ctx)

		if health.Status != types.StatusHealthy {
			t.Errorf("expected health status %s, got %s: %s",
				types.StatusHealthy, health.Status, health.Message)
		}
	})

	// Note: SQLMap integration tests require a vulnerable test application
	// We cannot test against public URLs or localhost without a test target
	// Only verify tool structure and input validation

	t.Run("InvalidInput", func(t *testing.T) {
		ctx := context.Background()

		// Missing URL should fail
		input := map[string]any{}

		_, err := tool.Execute(ctx, input)
		if err == nil {
			t.Error("expected error for missing URL, got nil")
		}
	})

	// Test with a simple URL format validation
	t.Run("ValidInputStructure", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode")
		}

		// This test validates the tool can be called with correct parameters
		// but uses a timeout to abort quickly (we're not actually testing injection)
		t.Skip("skipping actual execution: requires vulnerable test target")
	})
}
