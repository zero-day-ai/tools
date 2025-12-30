//go:build integration

package main

import (
	"context"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson-tools-official/pkg/executor"
	"github.com/zero-day-ai/sdk/types"
)

func TestHttpxIntegration(t *testing.T) {
	// Skip if httpx binary is not available
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

	// Test basic HTTP probing against localhost
	t.Run("BasicProbe", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		input := map[string]any{
			"targets": []any{"http://localhost"},
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

	// Test with technology detection
	t.Run("TechnologyDetection", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		input := map[string]any{
			"targets":    []any{"https://example.com"},
			"tech_detect": true,
		}

		output, err := tool.Execute(ctx, input)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}

		// Validate output
		if results, ok := output["results"].([]any); !ok {
			t.Errorf("expected results to be []any, got %T", output["results"])
		} else if len(results) > 0 {
			t.Logf("results: %+v", results[0])
		}
	})

	// Test with status code filter
	t.Run("StatusCodeFilter", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		input := map[string]any{
			"targets":      []any{"https://example.com"},
			"status_codes": []any{200, 301, 302},
		}

		output, err := tool.Execute(ctx, input)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}

		// Validate output
		if _, ok := output["results"].([]any); !ok {
			t.Errorf("expected results to be []any, got %T", output["results"])
		}
	})
}
