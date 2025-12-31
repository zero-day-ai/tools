package main

import (
	"context"
	"fmt"
	"os"
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
	ToolName        = "john"
	ToolVersion     = "1.0.0"
	ToolDescription = "CPU-based password hash cracking tool using John the Ripper"
	BinaryName      = "john"
)

// ToolImpl implements the john tool logic
type ToolImpl struct{}

// NewTool creates a new john tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"privilege-escalation",
			"password-cracking",
			"credential-access",
			"T1110.002", // Password Cracking
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

// Execute runs the john tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	// Extract input parameters
	hashFile := sdkinput.GetString(input, "hash_file", "")
	if hashFile == "" {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "validate",
			Code:      toolerr.ErrCodeInvalidInput,
			Message:   "hash_file is required",
		}
	}

	// Verify hash file exists
	if _, err := os.Stat(hashFile); err != nil {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "validate",
			Code:      toolerr.ErrCodeInvalidInput,
			Message:   fmt.Sprintf("hash file does not exist: %s", hashFile),
		}
	}

	format := sdkinput.GetString(input, "format", "")
	wordlist := sdkinput.GetString(input, "wordlist", "")
	rules := sdkinput.GetString(input, "rules", "")
	incremental := sdkinput.GetBool(input, "incremental", false)

	// First, run john to crack the hashes
	crackArgs := buildJohnCrackArgs(hashFile, format, wordlist, rules, incremental)

	execTimeout := sdkinput.DefaultTimeout()
	_, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    crackArgs,
		Timeout: execTimeout,
	})

	// Note: John returns non-zero exit codes even on success, so we don't fail on error
	// We'll retrieve the results using --show regardless

	// Now retrieve the cracked passwords using --show
	showArgs := buildJohnShowArgs(hashFile, format)

	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    showArgs,
		Timeout: 30 * time.Second, // Short timeout for --show
	})

	if err != nil {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "execute",
			Code:      toolerr.ErrCodeExecutionFailed,
			Message:   fmt.Sprintf("failed to retrieve cracked passwords: %v", err),
			Details:   map[string]any{"exit_code": result.ExitCode},
		}
	}

	// Parse the output
	cracked, totalHashes, err := parseJohnOutput(result.Stdout, result.Stderr, format)
	if err != nil {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "parse",
			Code:      toolerr.ErrCodeParseError,
			Message:   fmt.Sprintf("failed to parse john output: %v", err),
		}
	}

	// Build output
	output := map[string]any{
		"cracked":       cracked,
		"total_hashes":  totalHashes,
		"cracked_count": len(cracked),
	}

	return output, nil
}

// Health checks if the john binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// buildJohnCrackArgs constructs the command line arguments for cracking
func buildJohnCrackArgs(hashFile, format, wordlist, rules string, incremental bool) []string {
	args := []string{}

	// Add format if specified
	if format != "" {
		args = append(args, "--format="+format)
	}

	// Add wordlist mode
	if wordlist != "" {
		args = append(args, "--wordlist="+wordlist)

		// Add rules if specified with wordlist
		if rules != "" {
			args = append(args, "--rules="+rules)
		}
	} else if incremental {
		// Incremental mode (brute-force)
		args = append(args, "--incremental")
	}

	// Add the hash file
	args = append(args, hashFile)

	return args
}

// buildJohnShowArgs constructs the command line arguments for showing cracked passwords
func buildJohnShowArgs(hashFile, format string) []string {
	args := []string{"--show"}

	// Add format if specified
	if format != "" {
		args = append(args, "--format="+format)
	}

	// Add the hash file
	args = append(args, hashFile)

	return args
}

// CrackedPassword represents a cracked password entry
type CrackedPassword struct {
	Hash      string `json:"hash"`
	Plaintext string `json:"plaintext"`
	Format    string `json:"format"`
}

// parseJohnOutput parses the output from john --show
func parseJohnOutput(stdout, stderr []byte, format string) ([]CrackedPassword, int, error) {
	output := string(stdout)
	errOutput := string(stderr)

	lines := strings.Split(output, "\n")
	cracked := []CrackedPassword{}

	// Parse cracked passwords from stdout
	// John --show output format: username:password:userid:groupid:...
	// Or for raw hashes: hash:password
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Skip summary lines
		if strings.Contains(line, "password hash") {
			continue
		}

		// Parse the line - format is typically "user:password" or "hash:password"
		parts := strings.SplitN(line, ":", 2)
		if len(parts) >= 2 {
			cracked = append(cracked, CrackedPassword{
				Hash:      parts[0],
				Plaintext: parts[1],
				Format:    format,
			})
		}
	}

	// Extract total hash count from stderr
	// John outputs something like "1 password hash cracked, 0 left"
	totalHashes := len(cracked)
	for _, line := range strings.Split(errOutput, "\n") {
		line = strings.TrimSpace(line)

		// Look for pattern like "N password hashes"
		if strings.Contains(line, "password hash") {
			// Parse the count - format varies, but we can extract numbers
			fields := strings.Fields(line)
			for i, field := range fields {
				if strings.Contains(field, "password") && i > 0 {
					// Try to parse the previous field as a number
					var count int
					if _, err := fmt.Sscanf(fields[i-1], "%d", &count); err == nil {
						if count > totalHashes {
							totalHashes = count
						}
					}
				}
			}
		}
	}

	// If we couldn't determine total from stderr, use cracked count
	if totalHashes == 0 && len(cracked) > 0 {
		totalHashes = len(cracked)
	}

	return cracked, totalHashes, nil
}
