//go:build integration

package main

import (
	"context"
	"testing"
	"time"

	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/types"
)

func TestAmassIntegration(t *testing.T) {
	// Skip if amass binary is not available
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

	// Test passive enumeration
	t.Run("PassiveEnumeration", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		input := map[string]any{
			"domain": "example.com",
			"mode":   "passive",
			"timeout": 60,
		}

		output, err := tool.Execute(ctx, input)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}

		// Validate output structure
		if domain, ok := output["domain"].(string); !ok || domain != "example.com" {
			t.Errorf("expected domain 'example.com', got %v", output["domain"])
		}

		if subdomains, ok := output["subdomains"].([]any); !ok {
			t.Errorf("expected subdomains to be []any, got %T", output["subdomains"])
		} else {
			t.Logf("found %d subdomains", len(subdomains))
		}

		if count, ok := output["count"].(int); !ok || count < 0 {
			t.Errorf("expected valid count, got %v", output["count"])
		}
	})

	// Test active enumeration (may take longer)
	t.Run("ActiveEnumeration", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		input := map[string]any{
			"domain": "example.com",
			"mode":   "active",
			"timeout": 120,
		}

		output, err := tool.Execute(ctx, input)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}

		// Validate output
		if subdomains, ok := output["subdomains"].([]any); !ok {
			t.Errorf("expected subdomains to be []any, got %T", output["subdomains"])
		} else {
			t.Logf("found %d subdomains in active mode", len(subdomains))
		}
	})
}
