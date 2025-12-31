//go:build integration

package main

import (
	"context"
	"testing"
	"time"

	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/types"
)

func TestSubfinderIntegration(t *testing.T) {
	// Skip if subfinder binary is not available
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

	// Test basic subdomain enumeration against example.com
	t.Run("BasicEnumeration", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		input := map[string]any{
			"domain":  "example.com",
			"timeout": 30, // 30 seconds
		}

		output, err := tool.Execute(ctx, input)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}

		// Validate output structure
		if domain, ok := output["domain"].(string); !ok || domain != "example.com" {
			t.Errorf("expected domain 'example.com', got %v", output["domain"])
		}

		if subdomains, ok := output["subdomains"].([]string); !ok {
			t.Errorf("expected subdomains to be []string, got %T", output["subdomains"])
		} else {
			t.Logf("found %d subdomains", len(subdomains))
		}

		if count, ok := output["count"].(int); !ok || count < 0 {
			t.Errorf("expected valid count, got %v", output["count"])
		}

		if scanTime, ok := output["scan_time_ms"].(int); !ok || scanTime <= 0 {
			t.Errorf("expected positive scan_time_ms, got %v", output["scan_time_ms"])
		}

		if _, ok := output["sources_used"].([]string); !ok {
			t.Errorf("expected sources_used to be []string, got %T", output["sources_used"])
		}
	})

	// Test with specific sources
	t.Run("WithSpecificSources", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		input := map[string]any{
			"domain":  "example.com",
			"sources": []any{"crtsh"},
			"timeout": 30,
		}

		output, err := tool.Execute(ctx, input)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}

		// Should have found some subdomains
		if count, ok := output["count"].(int); !ok || count < 0 {
			t.Errorf("expected valid count, got %v", output["count"])
		} else {
			t.Logf("count: %d", count)
		}
	})

	// Test invalid input
	t.Run("InvalidInput", func(t *testing.T) {
		ctx := context.Background()

		// Missing domain should fail
		input := map[string]any{}

		_, err := tool.Execute(ctx, input)
		if err == nil {
			t.Error("expected error for missing domain, got nil")
		}
	})
}
