package main

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	sdkinput "github.com/zero-day-ai/sdk/input"
	"github.com/zero-day-ai/sdk/toolerr"
	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/health"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "msfvenom"
	ToolVersion     = "1.0.0"
	ToolDescription = "Metasploit payload encoder and generator for creating obfuscated payloads"
	BinaryName      = "msfvenom"
)

// ToolImpl implements the msfvenom tool logic
type ToolImpl struct{}

// NewTool creates a new msfvenom tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"defense-evasion",
			"payload-generation",
			"encoding",
			"obfuscation",
			"T1027", // Obfuscated Files or Information
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

// Execute runs the msfvenom tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	// Extract input parameters
	payload := sdkinput.GetString(input, "payload", "")
	if payload == "" {
		return nil, fmt.Errorf("payload is required")
	}

	format := sdkinput.GetString(input, "format", "")
	if format == "" {
		return nil, fmt.Errorf("format is required")
	}

	lhost := sdkinput.GetString(input, "lhost", "")
	lport := sdkinput.GetInt(input, "lport", 0)
	encoder := sdkinput.GetString(input, "encoder", "")
	iterations := sdkinput.GetInt(input, "iterations", 0)
	platform := sdkinput.GetString(input, "platform", "")
	arch := sdkinput.GetString(input, "arch", "")

	// Create secure temp directory for payload storage
	tempDir, err := createSecureTempDir("msfvenom-")
	if err != nil {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "create_temp_dir",
			Code:      toolerr.ErrCodeExecutionFailed,
			Message:   fmt.Sprintf("failed to create secure temp directory: %v", err),
		}
	}

	// Build output file path with appropriate extension
	outputFile := filepath.Join(tempDir, fmt.Sprintf("payload.%s", format))

	// Build command arguments
	args := buildMsfvenomArgs(payload, format, outputFile, lhost, lport, encoder, iterations, platform, arch)

	// Execute msfvenom
	execTimeout := sdkinput.DefaultTimeout()
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: execTimeout,
	})

	if err != nil {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "execute",
			Code:      toolerr.ErrCodeExecutionFailed,
			Message:   fmt.Sprintf("failed to execute msfvenom: %v", err),
			Details:   map[string]any{"exit_code": result.ExitCode, "stderr": string(result.Stderr)},
		}
	}

	// Verify payload file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "verify_output",
			Code:      toolerr.ErrCodeExecutionFailed,
			Message:   "payload file was not created",
			Details:   map[string]any{"stderr": string(result.Stderr)},
		}
	}

	// Get file size
	fileInfo, err := os.Stat(outputFile)
	if err != nil {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "stat_file",
			Code:      toolerr.ErrCodeExecutionFailed,
			Message:   fmt.Sprintf("failed to stat payload file: %v", err),
		}
	}

	// Calculate hashes
	md5Hash, sha256Hash, err := calculateHashes(outputFile)
	if err != nil {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "hash_file",
			Code:      toolerr.ErrCodeExecutionFailed,
			Message:   fmt.Sprintf("failed to calculate hashes: %v", err),
		}
	}

	// Build output
	output := map[string]any{
		"payload_path": outputFile,
		"payload_size": int(fileInfo.Size()),
		"format":       format,
		"md5":          md5Hash,
		"sha256":       sha256Hash,
	}

	// Add encoder to output if it was used
	if encoder != "" {
		output["encoder"] = encoder
	} else {
		output["encoder"] = ""
	}

	return output, nil
}

// Health checks if the msfvenom binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// buildMsfvenomArgs constructs the command line arguments for msfvenom
func buildMsfvenomArgs(payload, format, outputFile, lhost string, lport int, encoder string, iterations int, platform, arch string) []string {
	args := []string{
		"-p", payload,
		"-f", format,
		"-o", outputFile,
	}

	// Add LHOST if specified
	if lhost != "" {
		args = append(args, "LHOST="+lhost)
	}

	// Add LPORT if specified
	if lport > 0 {
		args = append(args, "LPORT="+strconv.Itoa(lport))
	}

	// Add encoder if specified
	if encoder != "" {
		args = append(args, "-e", encoder)
	}

	// Add iterations if specified
	if iterations > 0 {
		args = append(args, "-i", strconv.Itoa(iterations))
	}

	// Add platform if specified
	if platform != "" {
		args = append(args, "--platform", platform)
	}

	// Add architecture if specified
	if arch != "" {
		args = append(args, "-a", arch)
	}

	return args
}

// createSecureTempDir creates a temporary directory with secure permissions (0700)
func createSecureTempDir(prefix string) (string, error) {
	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		return "", err
	}

	// Set restrictive permissions (owner read/write/execute only)
	if err := os.Chmod(dir, 0700); err != nil {
		os.RemoveAll(dir)
		return "", err
	}

	return dir, nil
}

// calculateHashes calculates MD5 and SHA256 hashes for the given file
func calculateHashes(filePath string) (string, string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", "", err
	}

	// Calculate MD5
	md5Hasher := md5.New()
	md5Hasher.Write(data)
	md5Hash := hex.EncodeToString(md5Hasher.Sum(nil))

	// Calculate SHA256
	sha256Hasher := sha256.New()
	sha256Hasher.Write(data)
	sha256Hash := hex.EncodeToString(sha256Hasher.Sum(nil))

	return md5Hash, sha256Hash, nil
}
