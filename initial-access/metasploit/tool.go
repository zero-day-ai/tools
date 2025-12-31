package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
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
	ToolName        = "metasploit"
	ToolVersion     = "1.0.0"
	ToolDescription = "Metasploit Framework integration for automated exploitation via resource scripts"
	BinaryName      = "msfconsole"
)

// ToolImpl implements the metasploit tool logic
type ToolImpl struct{}

// NewTool creates a new metasploit tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"initial-access",
			"exploitation",
			"metasploit",
			"T1190", // Exploit Public-Facing Application
			"T1203", // Exploitation for Client Execution
			"T1059", // Command and Scripting Interpreter
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

// Execute runs the metasploit tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	modulePath := sdkinput.GetString(input, "module", "")
	if modulePath == "" {
		return nil, fmt.Errorf("module is required")
	}

	// Get options as map
	options, ok := input["options"].(map[string]any)
	if !ok || options == nil {
		return nil, fmt.Errorf("options is required and must be an object")
	}

	// Get optional payload
	payloadPath := sdkinput.GetString(input, "payload", "")

	// Get optional payload options
	var payloadOptions map[string]any
	if po, ok := input["payload_options"].(map[string]any); ok {
		payloadOptions = po
	}

	// Create resource script
	rcFile, err := createResourceScript(modulePath, options, payloadPath, payloadOptions)
	if err != nil {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "create_rc_script",
			Code:      toolerr.ErrCodeExecutionFailed,
			Message:   fmt.Sprintf("failed to create resource script: %v", err),
		}
	}
	defer os.Remove(rcFile) // Clean up resource script

	// Execute msfconsole with resource script
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    []string{"-q", "-r", rcFile}, // -q for quiet mode, -r for resource script
		Timeout: sdkinput.DefaultTimeout(),
	})

	if err != nil {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "execute",
			Code:      toolerr.ErrCodeExecutionFailed,
			Message:   fmt.Sprintf("failed to execute msfconsole: %v", err),
			Details:   map[string]any{"exit_code": result.ExitCode},
		}
	}

	// Parse output
	sessions, outputStr := parseMsfOutput(result.Stdout)

	// Determine success based on whether sessions were created or module ran
	success := result.ExitCode == 0

	// Calculate execution time
	executionTimeMs := time.Since(startTime).Milliseconds()

	// Build output
	output := map[string]any{
		"success":           success,
		"module":            modulePath,
		"sessions":          sessions,
		"output":            outputStr,
		"execution_time_ms": int(executionTimeMs),
	}

	return output, nil
}

// Health checks if the msfconsole binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// createResourceScript generates a Metasploit resource script (.rc file)
func createResourceScript(modulePath string, options map[string]any, payloadPath string, payloadOptions map[string]any) (string, error) {
	// Create temporary file for resource script
	tmpFile, err := os.CreateTemp("", "msf-rc-*.rc")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmpFile.Close()

	var script strings.Builder

	// Use the module
	script.WriteString(fmt.Sprintf("use %s\n", modulePath))

	// Set module options
	for key, value := range options {
		script.WriteString(fmt.Sprintf("set %s %v\n", key, value))
	}

	// Set payload if provided
	if payloadPath != "" {
		script.WriteString(fmt.Sprintf("set PAYLOAD %s\n", payloadPath))

		// Set payload options if provided
		if payloadOptions != nil {
			for key, value := range payloadOptions {
				script.WriteString(fmt.Sprintf("set %s %v\n", key, value))
			}
		}
	}

	// Show options for debugging (optional)
	script.WriteString("show options\n")

	// Run the module
	script.WriteString("run\n")

	// Show sessions if any were created
	script.WriteString("sessions -l\n")

	// Exit
	script.WriteString("exit\n")

	// Write script to file
	if _, err := tmpFile.WriteString(script.String()); err != nil {
		return "", fmt.Errorf("failed to write resource script: %w", err)
	}

	return tmpFile.Name(), nil
}

// SessionInfo represents a Metasploit session
type SessionInfo struct {
	ID          int
	Type        string
	Info        string
	TunnelLocal string
	TunnelPeer  string
}

// parseMsfOutput parses the msfconsole output to extract session information
func parseMsfOutput(output []byte) ([]map[string]any, string) {
	outputStr := string(output)
	var sessions []map[string]any

	// Parse sessions from "sessions -l" output
	// Expected format:
	// Active sessions
	// ===============
	//
	//   Id  Name  Type                     Information  Connection
	//   --  ----  ----                     -----------  ----------
	//   1         meterpreter x86/windows  WIN-ABC\user 192.168.1.100:4444 -> 192.168.1.10:49152 (10.0.0.1)

	sessionRegex := regexp.MustCompile(`(?m)^\s*(\d+)\s+\S*\s+(\S+(?:\s+\S+)*?)\s{2,}(\S+(?:\s+\S+)*?)\s{2,}(\S+)\s+->\s+(\S+)`)
	matches := sessionRegex.FindAllStringSubmatch(outputStr, -1)

	for _, match := range matches {
		if len(match) >= 6 {
			id, _ := strconv.Atoi(match[1])
			sessionType := strings.TrimSpace(match[2])
			info := strings.TrimSpace(match[3])
			tunnelLocal := strings.TrimSpace(match[4])
			tunnelPeer := strings.TrimSpace(match[5])

			sessions = append(sessions, map[string]any{
				"id":           id,
				"type":         sessionType,
				"info":         info,
				"tunnel_local": tunnelLocal,
				"tunnel_peer":  tunnelPeer,
			})
		}
	}

	// Alternative: Look for session opened messages
	// [*] Sending stage (175174 bytes) to 192.168.1.10
	// [*] Meterpreter session 1 opened (192.168.1.100:4444 -> 192.168.1.10:49152) at 2023-12-29 12:34:56 -0500
	if len(sessions) == 0 {
		sessionOpenedRegex := regexp.MustCompile(`(?m)\[\*\]\s+(\w+)\s+session\s+(\d+)\s+opened\s+\(([^)]+)\)`)
		openedMatches := sessionOpenedRegex.FindAllStringSubmatch(outputStr, -1)

		for _, match := range openedMatches {
			if len(match) >= 4 {
				sessionType := strings.ToLower(match[1])
				id, _ := strconv.Atoi(match[2])
				tunnelInfo := match[3]

				// Parse tunnel info: "192.168.1.100:4444 -> 192.168.1.10:49152"
				parts := strings.Split(tunnelInfo, " -> ")
				tunnelLocal := ""
				tunnelPeer := ""
				if len(parts) == 2 {
					tunnelLocal = strings.TrimSpace(parts[0])
					tunnelPeer = strings.TrimSpace(parts[1])
				}

				sessions = append(sessions, map[string]any{
					"id":           id,
					"type":         sessionType,
					"info":         "",
					"tunnel_local": tunnelLocal,
					"tunnel_peer":  tunnelPeer,
				})
			}
		}
	}

	return sessions, outputStr
}
