package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	sdkinput "github.com/zero-day-ai/sdk/input"
	"github.com/zero-day-ai/sdk/toolerr"
	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/health"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "hydra"
	ToolVersion     = "1.0.0"
	ToolDescription = "Online brute-force authentication tool supporting 50+ protocols"
	BinaryName      = "hydra"
)

// ToolImpl implements the hydra tool logic
type ToolImpl struct{}

// NewTool creates a new hydra tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"initial-access",
			"brute-force",
			"credential-access",
			"T1110",     // Brute Force
			"T1110.001", // Password Guessing
			"T1110.003", // Password Spraying
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

// Execute runs the hydra tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract and validate input parameters
	target := sdkinput.GetString(input, "target", "")
	if target == "" {
		return nil, fmt.Errorf("target is required")
	}

	service := sdkinput.GetString(input, "service", "")
	if service == "" {
		return nil, fmt.Errorf("service is required")
	}

	// Validate that we have at least one username and password source
	username := sdkinput.GetString(input, "username", "")
	usernameFile := sdkinput.GetString(input, "username_file", "")
	password := sdkinput.GetString(input, "password", "")
	passwordFile := sdkinput.GetString(input, "password_file", "")

	if username == "" && usernameFile == "" {
		return nil, fmt.Errorf("either username or username_file must be provided")
	}

	if password == "" && passwordFile == "" {
		return nil, fmt.Errorf("either password or password_file must be provided")
	}

	port := sdkinput.GetInt(input, "port", 0)
	threads := sdkinput.GetInt(input, "threads", 16)
	timeout := sdkinput.GetInt(input, "timeout", 30)
	httpPath := sdkinput.GetString(input, "http_path", "")
	httpForm := sdkinput.GetString(input, "http_form", "")

	// Build command arguments
	args := buildHydraArgs(target, service, port, username, usernameFile, password, passwordFile, threads, timeout, httpPath, httpForm)

	// Execute hydra with JSON output
	execTimeout := sdkinput.DefaultTimeout()
	if timeout > 0 {
		execTimeout = time.Duration(timeout*threads+60) * time.Second // Account for threads and add buffer
	}

	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: execTimeout,
	})

	// Hydra returns exit code 0 if credentials found, 1 if none found
	// We consider both as successful execution, only actual errors are failures
	if err != nil && result.ExitCode != 0 && result.ExitCode != 1 {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "execute",
			Code:      toolerr.ErrCodeExecutionFailed,
			Message:   fmt.Sprintf("failed to execute hydra: %v", err),
			Details:   map[string]any{"exit_code": result.ExitCode, "stderr": string(result.Stderr)},
		}
	}

	// Parse JSON output
	credentials, attempts, parseErr := parseHydraOutput(result.Stdout)
	if parseErr != nil {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "parse",
			Code:      toolerr.ErrCodeParseError,
			Message:   fmt.Sprintf("failed to parse hydra output: %v", parseErr),
		}
	}

	// Calculate scan time
	scanTimeMs := time.Since(startTime).Milliseconds()

	// Build output
	output := map[string]any{
		"success":      len(credentials) > 0,
		"credentials":  credentials,
		"attempts":     attempts,
		"scan_time_ms": int(scanTimeMs),
	}

	return output, nil
}

// Health checks if the hydra binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// buildHydraArgs constructs the command line arguments for hydra
func buildHydraArgs(target, service string, port int, username, usernameFile, password, passwordFile string, threads, timeout int, httpPath, httpForm string) []string {
	args := []string{}

	// Username specification
	if username != "" {
		args = append(args, "-l", username)
	} else if usernameFile != "" {
		args = append(args, "-L", usernameFile)
	}

	// Password specification
	if password != "" {
		args = append(args, "-p", password)
	} else if passwordFile != "" {
		args = append(args, "-P", passwordFile)
	}

	// Threads
	args = append(args, "-t", strconv.Itoa(threads))

	// Timeout
	args = append(args, "-w", strconv.Itoa(timeout))

	// JSON output mode (jsonv1 format)
	args = append(args, "-b", "jsonv1")

	// Exit after first found credential pair
	args = append(args, "-f")

	// Quiet mode (suppress banner)
	args = append(args, "-q")

	// HTTP-specific options
	if httpPath != "" {
		args = append(args, "-m", httpPath)
	}

	// Target and service
	targetSpec := target
	if port > 0 {
		targetSpec = fmt.Sprintf("%s:%d", target, port)
	}

	args = append(args, targetSpec, service)

	// HTTP form parameters (must come after service)
	if httpForm != "" {
		args = append(args, httpForm)
	}

	return args
}

// HydraJSONOutput represents the JSON output structure from hydra -b jsonv1
type HydraJSONOutput struct {
	Generator     string        `json:"generator"`
	Server        string        `json:"server"`
	Port          int           `json:"port"`
	Service       string        `json:"service"`
	Success       bool          `json:"success"`
	QuantityFound int           `json:"quantityfound"`
	Results       []HydraResult `json:"results"`
}

// HydraResult represents a single credential found by hydra
type HydraResult struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Service  string `json:"service"`
	Login    string `json:"login"`
	Password string `json:"password"`
}

// parseHydraOutput parses the JSON output from hydra -b jsonv1
func parseHydraOutput(output []byte) ([]map[string]any, int, error) {
	var hydraOutput HydraJSONOutput

	if len(output) == 0 {
		// No output means no credentials found
		return []map[string]any{}, 0, nil
	}

	if err := json.Unmarshal(output, &hydraOutput); err != nil {
		return nil, 0, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	// Convert results to generic map format
	credentials := make([]map[string]any, 0, len(hydraOutput.Results))
	for _, result := range hydraOutput.Results {
		credentials = append(credentials, map[string]any{
			"host":     result.Host,
			"port":     result.Port,
			"service":  result.Service,
			"username": result.Login,
			"password": result.Password,
		})
	}

	// Hydra doesn't directly report total attempts in JSON, so we estimate
	// from the number of results found. In practice, this would be the number
	// of username/password combinations tried
	attempts := hydraOutput.QuantityFound
	if attempts == 0 {
		// If no credentials found, we don't know the exact count from JSON alone
		// Return 0 as a placeholder
		attempts = 0
	}

	return credentials, attempts, nil
}
