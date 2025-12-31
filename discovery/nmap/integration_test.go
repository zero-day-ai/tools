//go:build integration

package main

import (
	"context"
	"testing"
	"time"

	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/types"
)

func TestNmapIntegration(t *testing.T) {
	// Skip if nmap binary is not available
	if !exec.BinaryExists(BinaryName) {
		t.Skipf("skipping integration test: %s binary not found", BinaryName)
	}

	tool := NewTool()

	// Verify health check
	t.Run("HealthCheck", func(t *testing.T) {
		ctx := context.Background()
		health := tool.Health(ctx)

		// Health should be at least degraded (healthy or degraded, not unhealthy)
		if health.Status == types.StatusUnhealthy {
			t.Logf("nmap health check unhealthy: %s", health.Message)
		} else {
			t.Logf("nmap health check: %s - %s", health.Status, health.Message)
		}
	})

	// Test localhost scan with connect scan (doesn't require root)
	t.Run("LocalhostConnectScan", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		input := map[string]any{
			"targets":   "127.0.0.1",
			"ports":     "22,80,443",
			"scan_type": "connect", // Connect scan doesn't require root
			"timing":    "aggressive",
		}

		output, err := tool.Execute(ctx, input)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}

		// Validate output structure
		hosts := output["hosts"]
		if hosts == nil {
			t.Error("hosts is nil")
		} else {
			t.Logf("found hosts: %+v", hosts)
		}

		if runStats, ok := output["run_stats"].(map[string]any); !ok {
			t.Errorf("expected run_stats to be map, got %T", output["run_stats"])
		} else {
			t.Logf("run stats: %+v", runStats)
		}
	})

	// Test ping scan (simple host discovery)
	t.Run("PingScan", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		input := map[string]any{
			"targets":   "127.0.0.1",
			"ping_scan": true,
			"timing":    "aggressive",
		}

		output, err := tool.Execute(ctx, input)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}

		// Should return at least one host (localhost)
		hosts := output["hosts"]
		if hosts == nil {
			t.Error("hosts is nil")
		} else {
			t.Logf("ping scan found hosts: %+v", hosts)
		}
	})

	// Test with top ports
	t.Run("TopPortsScan", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		input := map[string]any{
			"targets":   "127.0.0.1",
			"top_ports": 10,
			"scan_type": "connect",
			"timing":    "aggressive",
		}

		output, err := tool.Execute(ctx, input)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}

		// Validate output
		if output["hosts"] == nil {
			t.Error("hosts is nil")
		}
	})

	// Test with service detection
	t.Run("ServiceDetection", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		input := map[string]any{
			"targets":           "127.0.0.1",
			"ports":             "22,80,443",
			"scan_type":         "connect",
			"service_detection": true,
			"timing":            "aggressive",
		}

		output, err := tool.Execute(ctx, input)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}

		// Validate output
		if output["hosts"] == nil {
			t.Error("hosts is nil")
		} else {
			t.Logf("service detection results: %+v", output["hosts"])
		}
	})
}
