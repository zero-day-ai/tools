package main

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "slowhttptest"
	ToolVersion     = "1.0.0"
	ToolDescription = "Stress testing tool for slow HTTP DoS attacks (slowloris, slowread, slowpost, range)"
	BinaryName      = "slowhttptest"
)

// ToolImpl implements the slowhttptest tool
type ToolImpl struct{}

// NewTool creates a new slowhttptest tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"impact",
			"dos",
			"stress-testing",
			"T1499", // Endpoint Denial of Service
		}).
		SetInputSchema(InputSchema()).
		SetOutputSchema(OutputSchema()).
		SetExecuteFunc((&ToolImpl{}).Execute)

	t, _ := tool.New(cfg)
	return &toolWithHealth{Tool: t, impl: &ToolImpl{}}
}

// toolWithHealth wraps the tool to add custom health checks
type toolWithHealth struct {
	tool.Tool
	impl *ToolImpl
}

func (t *toolWithHealth) Health(ctx context.Context) types.HealthStatus {
	return t.impl.Health(ctx)
}

// Execute runs slowhttptest with the provided parameters
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract and validate input parameters
	target := getString(input, "target", "")
	attackType := getString(input, "attack_type", "slowloris")
	connections := getInt(input, "connections", 50)
	duration := getInt(input, "duration", 30)
	rate := getInt(input, "rate", 10)

	// Enforce rate limiting - max 100 connections and 50 conn/sec
	if connections > 100 {
		connections = 100
	}
	if rate > 50 {
		rate = 50
	}

	// Measure initial response time
	initialResponseTime, initialErr := measureResponseTime(ctx, target)

	// Build slowhttptest command arguments
	args := t.buildSlowHttpTestArgs(target, attackType, connections, duration, rate)

	// Execute slowhttptest
	timeout := time.Duration(duration+30) * time.Second
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		return nil, fmt.Errorf("slowhttptest execution failed: %w", err)
	}

	// Parse output to extract metrics
	output := t.parseSlowHttpTestOutput(result.Stdout, result.Stderr, startTime, initialResponseTime, initialErr)

	// Measure final response time
	finalResponseTime, finalErr := measureResponseTime(ctx, target)

	// Update response times in output
	if times, ok := output["response_times_ms"].(map[string]any); ok {
		if initialErr == nil {
			times["initial"] = initialResponseTime
		}
		if finalErr == nil {
			times["final"] = finalResponseTime
		}
	}

	// Determine target status based on response times
	status := "available"
	if finalErr != nil {
		status = "unavailable"
	} else if initialErr == nil && finalResponseTime > initialResponseTime*3 {
		status = "degraded"
	}
	output["target_status"] = status

	return output, nil
}

// buildSlowHttpTestArgs constructs slowhttptest command arguments
func (t *ToolImpl) buildSlowHttpTestArgs(target, attackType string, connections, duration, rate int) []string {
	args := []string{"-u", target}

	// Attack type
	switch attackType {
	case "slowloris":
		args = append(args, "-H") // Slowloris mode
	case "slowread":
		args = append(args, "-X") // Slow read mode
	case "slowpost":
		args = append(args, "-B") // Slow POST mode
	case "range":
		args = append(args, "-R") // Range header attack
	default:
		args = append(args, "-H") // Default to slowloris
	}

	// Number of connections
	args = append(args, "-c", strconv.Itoa(connections))

	// Test duration
	args = append(args, "-l", strconv.Itoa(duration))

	// Rate (connections per second)
	args = append(args, "-r", strconv.Itoa(rate))

	// Generate statistics
	args = append(args, "-g")

	return args
}

// parseSlowHttpTestOutput parses the output from slowhttptest
func (t *ToolImpl) parseSlowHttpTestOutput(stdout, stderr []byte, startTime time.Time, initialRT int, initialErr error) map[string]any {
	output := make(map[string]any)

	// Combine stdout and stderr for parsing
	combinedOutput := string(stdout) + "\n" + string(stderr)

	// Extract connections established
	connectionsEstablished := 0
	if match := regexp.MustCompile(`connected:\s*(\d+)`).FindStringSubmatch(combinedOutput); len(match) > 1 {
		if val, err := strconv.Atoi(match[1]); err == nil {
			connectionsEstablished = val
		}
	}

	// Extract connections from different patterns
	if connectionsEstablished == 0 {
		if match := regexp.MustCompile(`connections\s+established:\s*(\d+)`).FindStringSubmatch(combinedOutput); len(match) > 1 {
			if val, err := strconv.Atoi(match[1]); err == nil {
				connectionsEstablished = val
			}
		}
	}

	// Calculate duration
	duration := int(time.Since(startTime).Seconds())

	// Build response times structure
	responseTimes := map[string]any{
		"initial": 0,
		"final":   0,
	}
	if initialErr == nil && initialRT > 0 {
		responseTimes["initial"] = initialRT
	}

	output["connections_established"] = connectionsEstablished
	output["test_duration_seconds"] = duration
	output["response_times_ms"] = responseTimes
	output["target_status"] = "available" // Will be updated by caller

	return output
}

// measureResponseTime measures the HTTP response time for a target
func measureResponseTime(ctx context.Context, target string) (int, error) {
	// Create timeout context for response measurement
	measureCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	start := time.Now()

	req, err := http.NewRequestWithContext(measureCtx, "GET", target, nil)
	if err != nil {
		return 0, err
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	elapsed := time.Since(start)
	return int(elapsed.Milliseconds()), nil
}

// Health checks the slowhttptest binary
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	// Check if slowhttptest binary exists
	if !exec.BinaryExists(BinaryName) {
		return types.NewUnhealthyStatus("slowhttptest binary not found in PATH", map[string]any{
			"binary": BinaryName,
			"note":   "install slowhttptest (e.g., apt install slowhttptest)",
		})
	}

	return types.NewHealthyStatus("slowhttptest is available")
}

// Helper functions for extracting input parameters

func getString(input map[string]any, key string, defaultVal string) string {
	if val, ok := input[key].(string); ok {
		return val
	}
	return defaultVal
}

func getInt(input map[string]any, key string, defaultVal int) int {
	if val, ok := input[key].(int); ok {
		return val
	}
	if val, ok := input[key].(float64); ok {
		return int(val)
	}
	return defaultVal
}

func getBool(input map[string]any, key string, defaultVal bool) bool {
	if val, ok := input[key].(bool); ok {
		return val
	}
	return defaultVal
}

func getStringSlice(input map[string]any, key string) []string {
	if val, ok := input[key].([]any); ok {
		result := make([]string, 0, len(val))
		for _, v := range val {
			if s, ok := v.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	if val, ok := input[key].([]string); ok {
		return val
	}
	return []string{}
}
