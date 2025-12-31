package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	sdkexec "github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "xfreerdp"
	ToolVersion     = "1.0.0"
	ToolDescription = "RDP client tool for remote desktop connections with support for password and pass-the-hash authentication, and RemoteApp execution"
	BinaryName      = "xfreerdp"
)

// ToolImpl implements the xfreerdp tool
type ToolImpl struct{}

// NewTool creates a new xfreerdp tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"lateral-movement",
			"rdp",
			"remote-desktop",
			"T1021.001", // Remote Desktop Protocol
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

// Execute implements the xfreerdp connection logic
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	// Extract and validate input parameters
	target, ok := input["target"].(string)
	if !ok || target == "" {
		return nil, fmt.Errorf("target is required and must be a non-empty string")
	}

	username, ok := input["username"].(string)
	if !ok || username == "" {
		return nil, fmt.Errorf("username is required and must be a non-empty string")
	}

	// Extract optional parameters
	password := getString(input, "password", "")
	hash := getString(input, "hash", "")
	domain := getString(input, "domain", "")
	port := getInt(input, "port", 3389)
	command := getString(input, "command", "")

	// Validate authentication method
	if password == "" && hash == "" {
		return nil, fmt.Errorf("either password or hash must be provided for authentication")
	}

	if password != "" && hash != "" {
		return nil, fmt.Errorf("cannot use both password and hash authentication simultaneously")
	}

	// Build xfreerdp command arguments
	args := buildXfreerdpArgs(target, username, password, hash, domain, port, command)

	// Set timeout (RDP connections can take a while to establish)
	timeout := 30 * time.Second
	if t, ok := input["timeout"].(float64); ok && t > 0 {
		timeout = time.Duration(t) * time.Second
	} else if t, ok := input["timeout"].(int); ok && t > 0 {
		timeout = time.Duration(t) * time.Second
	}

	// Execute xfreerdp
	// Note: xfreerdp typically runs interactively, but for automation we use
	// specific flags to attempt connection and report status
	result, err := sdkexec.Run(ctx, sdkexec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	// Parse output and determine connection status
	connected := false
	sessionID := ""
	errorMsg := ""

	if err != nil {
		// Check if it's a timeout
		if strings.Contains(err.Error(), "timed out") {
			errorMsg = "Connection attempt timed out"
		} else {
			errorMsg = err.Error()
		}
	} else if result.ExitCode == 0 {
		// Exit code 0 typically means successful connection
		connected = true
		sessionID = extractSessionID(result)
	} else {
		// Non-zero exit code indicates failure
		errorMsg = parseXfreerdpError(result)
	}

	// Build output
	output := map[string]any{
		"connected":  connected,
		"session_id": sessionID,
		"error":      errorMsg,
	}

	return output, nil
}

// Health checks if xfreerdp binary exists
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	// Check if xfreerdp binary exists
	if !sdkexec.BinaryExists(BinaryName) {
		return types.NewUnhealthyStatus(
			fmt.Sprintf("%s binary not found in PATH", BinaryName),
			map[string]any{
				"binary":      BinaryName,
				"install_cmd": "apt-get install freerdp2-x11 (Debian/Ubuntu) or yum install freerdp (RHEL/CentOS)",
			},
		)
	}

	// Check xfreerdp version to ensure it supports required features
	cmd := exec.Command(BinaryName, "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return types.NewDegradedStatus(
			fmt.Sprintf("%s is installed but version check failed", BinaryName),
			map[string]any{
				"error": err.Error(),
			},
		)
	}

	versionInfo := string(output)
	return types.NewHealthyStatus(
		fmt.Sprintf("%s is available: %s", BinaryName, strings.TrimSpace(versionInfo)),
	)
}

// buildXfreerdpArgs constructs the xfreerdp command arguments
func buildXfreerdpArgs(target, username, password, hash, domain string, port int, command string) []string {
	args := []string{}

	// Build connection string: /v:host:port
	connectionStr := fmt.Sprintf("/v:%s:%d", target, port)
	args = append(args, connectionStr)

	// Username
	if domain != "" {
		args = append(args, fmt.Sprintf("/u:%s\\%s", domain, username))
	} else {
		args = append(args, fmt.Sprintf("/u:%s", username))
	}

	// Authentication
	if password != "" {
		args = append(args, fmt.Sprintf("/p:%s", password))
	} else if hash != "" {
		// For pass-the-hash, use /pth flag
		args = append(args, fmt.Sprintf("/pth:%s", hash))
	}

	// Security and certificate handling
	// /cert:ignore - ignore certificate warnings (as specified in requirements)
	args = append(args, "/cert:ignore")

	// Network level authentication
	args = append(args, "+nego")
	args = append(args, "+sec-nla")

	// RemoteApp support
	if command != "" {
		args = append(args, fmt.Sprintf("/app:%s", command))
		args = append(args, "/app-mode")
	}

	// Connection flags
	args = append(args, "+clipboard")   // Enable clipboard
	args = append(args, "/audio-mode:0") // Redirect audio to client
	args = append(args, "/compression")  // Enable compression

	// Logging and debugging (for status detection)
	args = append(args, "/log-level:INFO")

	return args
}

// extractSessionID attempts to extract a session identifier from command output
// For xfreerdp, we use the process ID as the session identifier
func extractSessionID(result *sdkexec.Result) string {
	// In a real implementation, xfreerdp runs as an interactive process
	// For now, we return a placeholder indicating successful connection
	// In production, you might want to track the background process ID
	return fmt.Sprintf("rdp-session-%d", time.Now().Unix())
}

// parseXfreerdpError extracts error information from xfreerdp output
func parseXfreerdpError(result *sdkexec.Result) string {
	stderr := string(result.Stderr)
	stdout := string(result.Stdout)
	combined := stderr + "\n" + stdout

	// Common error patterns
	errorPatterns := map[string]string{
		"Authentication failure":        "authentication failed - invalid credentials",
		"ERRINFO_LOGON_FAILED":          "logon failed - check username and password",
		"unable to connect":             "unable to connect to target host",
		"connection timed out":          "connection timed out",
		"Network error":                 "network error during connection",
		"Certificate verification":      "certificate verification failed",
		"Security negotiation failed":   "security negotiation failed",
		"Access denied":                 "access denied",
	}

	for pattern, message := range errorPatterns {
		if strings.Contains(combined, pattern) {
			return message
		}
	}

	// If we have stderr output, use that
	if stderr != "" {
		// Extract first meaningful line
		lines := strings.Split(stderr, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "[") {
				return line
			}
		}
		return stderr
	}

	// Generic error based on exit code
	return fmt.Sprintf("RDP connection failed with exit code %d", result.ExitCode)
}

// getString safely extracts a string from input map with default value
func getString(input map[string]any, key string, defaultVal string) string {
	if val, ok := input[key].(string); ok {
		return val
	}
	return defaultVal
}

// getInt safely extracts an int from input map with default value
func getInt(input map[string]any, key string, defaultVal int) int {
	if val, ok := input[key].(float64); ok {
		return int(val)
	}
	if val, ok := input[key].(int); ok {
		return val
	}
	return defaultVal
}
