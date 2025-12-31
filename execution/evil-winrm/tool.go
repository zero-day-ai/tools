package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	sdkinput "github.com/zero-day-ai/sdk/input"
	"github.com/zero-day-ai/sdk/toolerr"
	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/health"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "evil-winrm"
	ToolVersion     = "1.0.0"
	ToolDescription = "Windows Remote Management shell tool for command execution via WinRM"
	BinaryName      = "evil-winrm"
)

// ToolImpl implements the evil-winrm tool logic
type ToolImpl struct{}

// NewTool creates a new evil-winrm tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"execution",
			"winrm",
			"windows",
			"remote-shell",
			"T1021.006", // Remote Services: Windows Remote Management
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

// Execute runs the evil-winrm tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract required parameters
	target := sdkinput.GetString(input, "target", "")
	if target == "" {
		return nil, fmt.Errorf("target is required")
	}

	username := sdkinput.GetString(input, "username", "")
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}

	// Extract optional parameters
	password := sdkinput.GetString(input, "password", "")
	hash := sdkinput.GetString(input, "hash", "")
	command := sdkinput.GetString(input, "command", "")
	script := sdkinput.GetString(input, "script", "")
	port := sdkinput.GetInt(input, "port", 5985)

	// Validate authentication method
	if password == "" && hash == "" {
		return nil, fmt.Errorf("either password or hash must be provided")
	}

	// Validate that we have something to execute
	if command == "" && script == "" {
		return nil, fmt.Errorf("either command or script must be provided")
	}

	// Build command arguments
	args := buildEvilWinRMArgs(target, username, password, hash, command, script, port)

	// Execute evil-winrm
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: sdkinput.DefaultTimeout(),
	})

	// Calculate execution time
	executionTimeMs := time.Since(startTime).Milliseconds()

	// Build output
	output := map[string]any{
		"execution_time_ms": int(executionTimeMs),
	}

	if err != nil {
		// Execution failed
		output["success"] = false
		output["output"] = string(result.Stdout)
		output["error"] = fmt.Sprintf("failed to execute evil-winrm: %v (exit code: %d, stderr: %s)",
			err, result.ExitCode, strings.TrimSpace(string(result.Stderr)))

		return output, &toolerr.Error{
			Tool:      ToolName,
			Operation: "execute",
			Code:      toolerr.ErrCodeExecutionFailed,
			Message:   output["error"].(string),
			Details:   map[string]any{"exit_code": result.ExitCode},
		}
	}

	// Execution succeeded
	output["success"] = true
	output["output"] = strings.TrimSpace(string(result.Stdout))
	output["error"] = ""

	return output, nil
}

// Health checks if the evil-winrm binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// buildEvilWinRMArgs constructs the command line arguments for evil-winrm
func buildEvilWinRMArgs(target, username, password, hash, command, script string, port int) []string {
	args := []string{
		"-i", target,
		"-u", username,
	}

	// Add port if not default
	if port != 5985 {
		args = append(args, "-P", fmt.Sprintf("%d", port))
	}

	// Add authentication method
	if password != "" {
		args = append(args, "-p", password)
	} else if hash != "" {
		args = append(args, "-H", hash)
	}

	// Add command or script execution
	if command != "" {
		// Use -c flag for single command execution
		args = append(args, "-c", command)
	} else if script != "" {
		// Use -s flag for script execution
		args = append(args, "-s", script)
	}

	return args
}
