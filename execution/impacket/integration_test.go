//go:build integration

package main

import (
	"context"
	"testing"

	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/types"
)

func TestImpacketIntegration(t *testing.T) {
	// Check if any of the impacket tools are available
	toolsAvailable := exec.BinaryExists("psexec.py") ||
		exec.BinaryExists("wmiexec.py") ||
		exec.BinaryExists("impacket-psexec") ||
		exec.BinaryExists("impacket-wmiexec")

	if !toolsAvailable {
		t.Skip("skipping integration test: impacket tools not found")
	}

	tool := NewTool()

	// Verify health check
	t.Run("HealthCheck", func(t *testing.T) {
		ctx := context.Background()
		health := tool.Health(ctx)

		if health.Status == types.StatusUnhealthy {
			t.Logf("impacket health: %s", health.Message)
		}
	})

	// Note: Impacket tools require:
	// - A target Windows system
	// - Valid credentials or hashes
	// - Network access to the target
	// These cannot be safely tested against localhost or public targets
	// Only verify tool structure and input validation

	t.Run("InvalidInput", func(t *testing.T) {
		ctx := context.Background()

		// Missing required fields should fail
		input := map[string]any{}

		_, err := tool.Execute(ctx, input)
		if err == nil {
			t.Error("expected error for missing required fields, got nil")
		}
	})
}
