//go:build integration

package main

import (
	"context"
	"testing"

	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/types"
)

func TestHydraIntegration(t *testing.T) {
	// Skip if hydra binary is not available
	if !executor.BinaryExists(BinaryName) {
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

	// Note: Hydra integration tests require:
	// - A target service to test against
	// - Valid test credentials or credential lists
	// - Permission to perform authentication attempts
	// These cannot be safely tested against public services
	// Only verify tool structure and input validation

	t.Run("InvalidInput", func(t *testing.T) {
		ctx := context.Background()

		// Missing required target should fail
		input := map[string]any{}

		_, err := tool.Execute(ctx, input)
		if err == nil {
			t.Error("expected error for missing required fields, got nil")
		}
	})
}
