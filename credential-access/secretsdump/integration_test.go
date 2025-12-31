//go:build integration

package main

import (
	"context"
	"testing"

	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/types"
)

func TestSecretsdumpIntegration(t *testing.T) {
	// Skip if secretsdump is not available
	// Check for both impacket-secretsdump and secretsdump.py
	binaryAvailable := exec.BinaryExists("impacket-secretsdump") ||
		exec.BinaryExists("secretsdump.py")

	if !binaryAvailable {
		t.Skip("skipping integration test: secretsdump binary not found")
	}

	tool := NewTool()

	// Verify health check
	t.Run("HealthCheck", func(t *testing.T) {
		ctx := context.Background()
		health := tool.Health(ctx)

		// Health check should pass if binary exists
		if health.Status == types.StatusUnhealthy {
			t.Logf("secretsdump health: %s", health.Message)
		}
	})

	// Note: Integration test for secretsdump requires:
	// - A target Windows system
	// - Valid credentials or hashes
	// - Network access to the target
	// These cannot be safely tested against localhost or public targets
	// so we only verify the tool structure and health check

	t.Run("InvalidInput", func(t *testing.T) {
		ctx := context.Background()

		// Missing required target should fail
		input := map[string]any{}

		_, err := tool.Execute(ctx, input)
		if err == nil {
			t.Error("expected error for missing target, got nil")
		}
	})
}
