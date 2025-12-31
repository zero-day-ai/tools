//go:build integration

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/types"
)

func TestNucleiIntegration(t *testing.T) {
	// Skip if nuclei binary is not available
	if !exec.BinaryExists(BinaryName) {
		t.Skipf("skipping integration test: %s binary not found", BinaryName)
	}

	tool := NewTool()

	// Verify health check
	t.Run("HealthCheck", func(t *testing.T) {
		ctx := context.Background()
		health := tool.Health(ctx)

		// Health may be degraded if templates are missing
		if health.Status == types.StatusUnhealthy {
			t.Logf("nuclei health check failed: %s", health.Message)
			t.Skip("skipping tests due to missing nuclei templates")
		}
	})

	// Test basic scan with info severity templates only
	t.Run("BasicScan", func(t *testing.T) {
		// Check if templates exist
		homeDir, err := os.UserHomeDir()
		if err != nil {
			t.Skip("cannot determine home directory")
		}
		templatesDir := filepath.Join(homeDir, "nuclei-templates")
		if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
			t.Skip("nuclei-templates not found, run 'nuclei -update-templates' first")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		input := map[string]any{
			"targets":   []any{"https://example.com"},
			"severity":  []any{"info"},
			"templates": []any{"http/misconfiguration/http-missing-security-headers.yaml"},
		}

		output, err := tool.Execute(ctx, input)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}

		// Validate output structure
		if findings, ok := output["findings"].([]any); !ok {
			t.Errorf("expected findings to be []any, got %T", output["findings"])
		} else {
			t.Logf("found %d findings", len(findings))
		}

		if count, ok := output["count"].(int); !ok || count < 0 {
			t.Errorf("expected valid count, got %v", output["count"])
		}
	})

	// Test with severity filter
	t.Run("SeverityFilter", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode")
		}

		homeDir, err := os.UserHomeDir()
		if err != nil {
			t.Skip("cannot determine home directory")
		}
		templatesDir := filepath.Join(homeDir, "nuclei-templates")
		if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
			t.Skip("nuclei-templates not found")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		input := map[string]any{
			"targets":  []any{"https://example.com"},
			"severity": []any{"low", "info"},
			"tags":     []any{"ssl"},
		}

		output, err := tool.Execute(ctx, input)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}

		// Validate output
		if _, ok := output["findings"].([]any); !ok {
			t.Errorf("expected findings to be []any, got %T", output["findings"])
		}
	})
}
