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
	ToolName        = "impacket"
	ToolVersion     = "1.0.0"
	ToolDescription = "Impacket suite wrapper for remote command execution via SMB, WMI, DCOM, and scheduled tasks"
)

// ToolImpl implements the Impacket suite wrapper.
type ToolImpl struct{}

// NewTool creates a new Impacket tool instance.
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"execution",
			"windows",
			"lateral-movement",
			"T1021.002", // Remote Services: SMB/Windows Admin Shares
			"T1021.003", // Remote Services: DCOM
			"T1047",     // Windows Management Instrumentation
			"T1053.005", // Scheduled Task/Job: Scheduled Task
		}).
		SetInputSchema(InputSchema()).
		SetOutputSchema(OutputSchema()).
		SetExecuteFunc((&ToolImpl{}).Execute)

	t, _ := tool.New(cfg)
	return &toolWithHealth{Tool: t, impl: &ToolImpl{}}
}

// toolWithHealth wraps the tool to add custom health checks.
type toolWithHealth struct {
	tool.Tool
	impl *ToolImpl
}

func (t *toolWithHealth) Health(ctx context.Context) types.HealthStatus {
	return t.impl.Health(ctx)
}

// Execute runs the Impacket tool with the provided input.
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	toolName := sdkinput.GetString(input, "tool", "")
	target := sdkinput.GetString(input, "target", "")
	domain := sdkinput.GetString(input, "domain", "")
	username := sdkinput.GetString(input, "username", "")
	password := sdkinput.GetString(input, "password", "")
	hash := sdkinput.GetString(input, "hash", "")
	command := sdkinput.GetString(input, "command", "")

	// Determine which Impacket script to use
	scriptName, err := getScriptName(toolName)
	if err != nil {
		return nil, err
	}

	// Build command arguments
	args := buildImpacketArgs(domain, username, password, hash, target, command)

	// Execute the Impacket script
	execCfg := exec.Config{
		Command: "python3",
		Args:    append([]string{scriptName}, args...),
		Timeout: sdkinput.DefaultTimeout(),
	}

	result, err := exec.Run(ctx, execCfg)

	executionTime := time.Since(startTime).Milliseconds()

	// Parse the result
	success := err == nil && result.ExitCode == 0
	outputStr := string(result.Stdout)
	errorStr := string(result.Stderr)

	if !success && err != nil {
		errorStr = err.Error()
	}

	// Build output
	output := map[string]any{
		"success":           success,
		"tool":              toolName,
		"output":            outputStr,
		"error":             errorStr,
		"execution_time_ms": executionTime,
	}

	return output, nil
}

// Health checks the health of the Impacket tool.
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	// Check for python3
	pythonCheck := health.BinaryCheck("python3")
	if pythonCheck.Status != "healthy" {
		return pythonCheck
	}

	// Check for at least one Impacket script
	scripts := []string{
		"psexec.py",
		"wmiexec.py",
		"smbexec.py",
		"atexec.py",
		"dcomexec.py",
	}

	for _, script := range scripts {
		if executor.BinaryExists(script) {
			return types.NewHealthyStatus("impacket scripts available")
		}
	}

	return types.HealthStatus{
		Status:  "unhealthy",
		Message: "no impacket scripts found in PATH",
	}
}

// getScriptName returns the Impacket script name for the given tool.
func getScriptName(toolName string) (string, error) {
	scripts := map[string]string{
		"psexec":   "psexec.py",
		"wmiexec":  "wmiexec.py",
		"smbexec":  "smbexec.py",
		"atexec":   "atexec.py",
		"dcomexec": "dcomexec.py",
	}

	script, ok := scripts[toolName]
	if !ok {
		return "", fmt.Errorf("unknown impacket tool: %s", toolName)
	}

	return script, nil
}

// buildImpacketArgs builds the command-line arguments for Impacket scripts.
func buildImpacketArgs(domain, username, password, hash, target, command string) []string {
	var args []string

	// Build credential string
	var credString string
	if domain != "" {
		credString = fmt.Sprintf("%s/%s", domain, username)
	} else {
		credString = username
	}

	// Add authentication (password or hash)
	if hash != "" {
		// Pass-the-hash: use -hashes LM:NT format
		// If only NT hash is provided, use empty LM hash
		if !strings.Contains(hash, ":") {
			hash = ":" + hash
		}
		args = append(args, "-hashes", hash)
		credString = fmt.Sprintf("%s@%s", credString, target)
	} else if password != "" {
		// Password authentication
		credString = fmt.Sprintf("%s:%s@%s", credString, password, target)
	} else {
		// No authentication provided - this will likely fail but let Impacket handle it
		credString = fmt.Sprintf("%s@%s", credString, target)
	}

	args = append(args, credString)

	// Add the command to execute
	args = append(args, command)

	return args
}
