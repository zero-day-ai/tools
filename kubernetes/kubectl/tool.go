package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	sdkinput "github.com/zero-day-ai/sdk/input"
	"github.com/zero-day-ai/sdk/toolerr"
	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "kubectl"
	ToolVersion     = "1.0.0"
	ToolDescription = "Kubernetes kubectl wrapper for cluster interaction, resource management, and security testing"
	BinaryName      = "kubectl"
)

// ToolImpl implements the kubectl tool
type ToolImpl struct{}

// NewTool creates a new kubectl tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"kubernetes",
			"reconnaissance",
			"credential-access",
			"execution",
			"T1613", // Container and Resource Discovery
			"T1552", // Unsecured Credentials
			"T1609", // Container Administration Command
			"T1610", // Deploy Container
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

// Execute implements the kubectl command execution logic
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	start := time.Now()

	// Build kubectl arguments
	args, err := buildKubectlArgs(input)
	if err != nil {
		return nil, err
	}

	// Get timeout
	timeout := 60 * time.Second
	if t := sdkinput.GetInt(input, "timeout"); t > 0 {
		timeout = time.Duration(t) * time.Second
	}

	// Build environment variables
	env := os.Environ()
	if kubeconfig := sdkinput.GetString(input, "kubeconfig"); kubeconfig != "" {
		env = append(env, fmt.Sprintf("KUBECONFIG=%s", kubeconfig))
	}

	// Execute kubectl
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
		Env:     env,
	})

	executionTimeMs := time.Since(start).Milliseconds()
	commandExecuted := fmt.Sprintf("%s %s", BinaryName, strings.Join(args, " "))

	// Handle execution errors
	if err != nil && result == nil {
		return map[string]any{
			"success":           false,
			"exit_code":         -1,
			"stdout":            "",
			"stderr":            err.Error(),
			"data":              nil,
			"items":             []any{},
			"item_count":        0,
			"execution_time_ms": executionTimeMs,
			"command_executed":  commandExecuted,
		}, nil
	}

	success := result.ExitCode == 0
	stdout := string(result.Stdout)
	stderr := string(result.Stderr)

	// Try to parse JSON output
	var data any
	var items []any
	itemCount := 0

	if success && len(result.Stdout) > 0 {
		// Try to parse as JSON
		var parsed any
		if err := json.Unmarshal(result.Stdout, &parsed); err == nil {
			data = parsed

			// Check if it's a list response
			if m, ok := parsed.(map[string]any); ok {
				if kind, ok := m["kind"].(string); ok && strings.HasSuffix(kind, "List") {
					if itemList, ok := m["items"].([]any); ok {
						items = itemList
						itemCount = len(itemList)
					}
				}
			}
		}
	}

	return map[string]any{
		"success":           success,
		"exit_code":         result.ExitCode,
		"stdout":            stdout,
		"stderr":            stderr,
		"data":              data,
		"items":             items,
		"item_count":        itemCount,
		"execution_time_ms": executionTimeMs,
		"command_executed":  commandExecuted,
	}, nil
}

// Health checks if kubectl binary exists and can connect to cluster
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	// Check if kubectl binary exists
	if !executor.BinaryExists(BinaryName) {
		return types.NewUnhealthyStatus(
			fmt.Sprintf("%s binary not found in PATH", BinaryName),
			nil,
		)
	}

	// Try to get cluster version to verify connectivity
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    []string{"version", "--client", "-o", "json"},
		Timeout: 5 * time.Second,
	})

	if err != nil || result.ExitCode != 0 {
		return types.NewUnhealthyStatus(
			fmt.Sprintf("%s client check failed", BinaryName),
			map[string]any{"error": err},
		)
	}

	return types.NewHealthyStatus(fmt.Sprintf("%s is available", BinaryName))
}

// buildKubectlArgs constructs the kubectl command arguments
func buildKubectlArgs(input map[string]any) ([]string, error) {
	// Check for raw command first
	if raw := sdkinput.GetString(input, "raw"); raw != "" {
		// Split raw command into args (simple split, doesn't handle quotes)
		parts := strings.Fields(raw)
		if len(parts) == 0 {
			return nil, fmt.Errorf("raw command is empty")
		}
		// Remove "kubectl" if it's the first part
		if parts[0] == "kubectl" {
			parts = parts[1:]
		}
		return parts, nil
	}

	args := []string{}

	// Add context if specified
	if context := sdkinput.GetString(input, "context"); context != "" {
		args = append(args, "--context", context)
	}

	// Add namespace if specified
	if ns := sdkinput.GetString(input, "namespace"); ns != "" {
		args = append(args, "-n", ns)
	}

	// Add all-namespaces flag
	if sdkinput.GetBool(input, "all_namespaces") {
		args = append(args, "--all-namespaces")
	}

	// Add command
	command := sdkinput.GetString(input, "command")
	if command == "" {
		command = "get" // default to get
	}
	args = append(args, command)

	// Add resource type
	if resource := sdkinput.GetString(input, "resource"); resource != "" {
		args = append(args, resource)
	}

	// Add resource name
	if name := sdkinput.GetString(input, "name"); name != "" {
		args = append(args, name)
	}

	// Add label selector
	if selector := sdkinput.GetString(input, "selector"); selector != "" {
		args = append(args, "-l", selector)
	}

	// Add field selector
	if fieldSelector := sdkinput.GetString(input, "field_selector"); fieldSelector != "" {
		args = append(args, "--field-selector", fieldSelector)
	}

	// Add output format (default to JSON for structured parsing)
	output := sdkinput.GetString(input, "output")
	if output == "" {
		output = "json"
	}
	args = append(args, "-o", output)

	// Add additional args
	if additionalArgs := sdkinput.GetStringSlice(input, "args"); len(additionalArgs) > 0 {
		args = append(args, additionalArgs...)
	}

	return args, nil
}
