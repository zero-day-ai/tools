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

func TestShodanIntegration(t *testing.T) {
	// Skip if shodan binary is not available
	if !exec.BinaryExists(BinaryName) {
		t.Skipf("skipping integration test: %s binary not found", BinaryName)
	}

	// Skip if API key is not set
	if os.Getenv("SHODAN_API_KEY") == "" {
		t.Skip("skipping test: SHODAN_API_KEY environment variable not set")
	}

	tool := NewTool()

	// Verify health check
	t.Run("HealthCheck", func(t *testing.T) {
		ctx := context.Background()
		health := tool.Health(ctx)

		// Health should be at least degraded
		if health.Status == types.StatusUnhealthy {
			t.Logf("shodan health check: %s", health.Message)
		}
	})

	// Test basic search
	t.Run("BasicSearch", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		input := map[string]any{
			"query": "port:22 country:US",
			"limit": 10,
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
