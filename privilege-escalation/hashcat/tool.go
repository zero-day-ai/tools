package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
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
	ToolName        = "hashcat"
	ToolVersion     = "1.0.0"
	ToolDescription = "GPU-accelerated password hash cracking tool supporting dictionary, brute-force, and hybrid attacks"
	BinaryName      = "hashcat"
)

// ToolImpl implements the hashcat tool logic
type ToolImpl struct{}

// NewTool creates a new hashcat tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"privilege-escalation",
			"password-cracking",
			"credential-access",
			"T1110.002", // Brute Force: Password Cracking
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

// Execute runs the hashcat tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract and validate input parameters
	hashFile := sdkinput.GetString(input, "hash_file", "")
	if hashFile == "" {
		return nil, fmt.Errorf("hash_file is required")
	}

	hashType := sdkinput.GetInt(input, "hash_type", -1)
	if hashType < 0 {
		return nil, fmt.Errorf("hash_type is required")
	}

	attackMode := sdkinput.GetString(input, "attack_mode", "")
	if attackMode == "" {
		return nil, fmt.Errorf("attack_mode is required")
	}

	// Validate attack mode specific parameters
	if err := validateAttackModeParams(attackMode, input); err != nil {
		return nil, err
	}

	// Create temp directory for potfile output
	tempDir, err := os.MkdirTemp("", "hashcat-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	potfilePath := filepath.Join(tempDir, "hashcat.potfile")

	// Build command arguments
	args := buildHashcatArgs(hashFile, hashType, attackMode, potfilePath, input)

	// Execute hashcat
	maxRuntime := sdkinput.GetInt(input, "max_runtime", 0)
	execTimeout := sdkinput.DefaultTimeout()
	if maxRuntime > 0 {
		execTimeout = time.Duration(maxRuntime) * time.Second
	}

	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: execTimeout,
	})

	// Hashcat returns exit code 1 when exhausted, which is not an error for us
	if err != nil && result.ExitCode != 1 {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "execute",
			Code:      toolerr.ErrCodeExecutionFailed,
			Message:   fmt.Sprintf("failed to execute hashcat: %v", err),
			Details:   map[string]any{"exit_code": result.ExitCode},
		}
	}

	// Parse potfile for cracked hashes
	cracked, err := parsePotfile(potfilePath)
	if err != nil {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "parse",
			Code:      toolerr.ErrCodeParseError,
			Message:   fmt.Sprintf("failed to parse potfile: %v", err),
		}
	}

	// Count total hashes in input file
	totalHashes, err := countHashes(hashFile)
	if err != nil {
		totalHashes = 0 // Best effort
	}

	// Parse statistics from output
	stats := parseHashcatStats(string(result.Stdout))

	// Calculate runtime
	runtimeSeconds := int(time.Since(startTime).Seconds())

	// Build output
	output := map[string]any{
		"cracked":         cracked,
		"total_hashes":    totalHashes,
		"cracked_count":   len(cracked),
		"exhausted":       result.ExitCode == 1, // Exit code 1 means exhausted
		"speed":           stats.Speed,
		"runtime_seconds": runtimeSeconds,
		"gpu_info":        stats.GPUInfo,
	}

	return output, nil
}

// Health checks if the hashcat binary is available and GPUs are accessible
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	// First check if binary exists
	binaryStatus := health.BinaryCheck(BinaryName)
	if !binaryStatus.IsHealthy() {
		return binaryStatus
	}

	// Check GPU availability by running hashcat with --version
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    []string{"--version"},
		Timeout: 5 * time.Second,
	})

	if err != nil {
		return types.NewDegradedStatus(
			"hashcat binary found but GPU check failed",
			map[string]any{
				"error": err.Error(),
			},
		)
	}

	// Try to detect GPU info
	gpuInfo := detectGPUInfo(string(result.Stdout))

	return types.HealthStatus{
		Status:  types.StatusHealthy,
		Message: "hashcat is available with GPU support",
		Details: map[string]any{
			"gpu_info": gpuInfo,
		},
	}
}

// validateAttackModeParams validates that required parameters for the attack mode are present
func validateAttackModeParams(attackMode string, input map[string]any) error {
	switch attackMode {
	case "dictionary":
		wordlist := sdkinput.GetString(input, "wordlist", "")
		if wordlist == "" {
			return fmt.Errorf("wordlist is required for dictionary attack")
		}
	case "bruteforce":
		mask := sdkinput.GetString(input, "mask", "")
		if mask == "" {
			return fmt.Errorf("mask is required for brute-force attack")
		}
	case "hybrid":
		wordlist := sdkinput.GetString(input, "wordlist", "")
		if wordlist == "" {
			return fmt.Errorf("wordlist is required for hybrid attack")
		}
		mask := sdkinput.GetString(input, "mask", "")
		if mask == "" {
			return fmt.Errorf("mask is required for hybrid attack")
		}
	default:
		return fmt.Errorf("invalid attack_mode: %s (must be dictionary, bruteforce, or hybrid)", attackMode)
	}
	return nil
}

// buildHashcatArgs constructs the command line arguments for hashcat
func buildHashcatArgs(hashFile string, hashType int, attackMode string, potfilePath string, input map[string]any) []string {
	args := []string{
		"--potfile-path", potfilePath,
		"--hash-type", strconv.Itoa(hashType),
		"--quiet", // Reduce output verbosity
	}

	// Set attack mode
	switch attackMode {
	case "dictionary":
		args = append(args, "--attack-mode", "0") // Dictionary attack
	case "bruteforce":
		args = append(args, "--attack-mode", "3") // Brute-force attack
	case "hybrid":
		args = append(args, "--attack-mode", "6") // Hybrid wordlist + mask
	}

	// Workload profile
	workload := sdkinput.GetInt(input, "workload", 2)
	args = append(args, "--workload-profile", strconv.Itoa(workload))

	// Session name (for resumable attacks)
	if sessionName := sdkinput.GetString(input, "session_name", ""); sessionName != "" {
		args = append(args, "--session", sessionName)
	}

	// Max runtime
	if maxRuntime := sdkinput.GetInt(input, "max_runtime", 0); maxRuntime > 0 {
		args = append(args, "--runtime", strconv.Itoa(maxRuntime))
	}

	// Add hash file
	args = append(args, hashFile)

	// Add attack-specific parameters
	switch attackMode {
	case "dictionary":
		wordlist := sdkinput.GetString(input, "wordlist", "")
		args = append(args, wordlist)

		// Add rules if specified
		if rules := sdkinput.GetString(input, "rules", ""); rules != "" {
			args = append(args, "--rules-file", rules)
		}

	case "bruteforce":
		mask := sdkinput.GetString(input, "mask", "")
		args = append(args, mask)

		// Increment mode
		if sdkinput.GetBool(input, "increment", false) {
			args = append(args, "--increment")
		}

	case "hybrid":
		wordlist := sdkinput.GetString(input, "wordlist", "")
		mask := sdkinput.GetString(input, "mask", "")
		args = append(args, wordlist, mask)
	}

	return args
}

// parsePotfile reads the hashcat potfile and extracts cracked hash:password pairs
func parsePotfile(potfilePath string) ([]map[string]any, error) {
	file, err := os.Open(potfilePath)
	if err != nil {
		if os.IsNotExist(err) {
			// No potfile means no cracks
			return []map[string]any{}, nil
		}
		return nil, fmt.Errorf("failed to open potfile: %w", err)
	}
	defer file.Close()

	var cracked []map[string]any
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Potfile format: hash:plaintext
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			cracked = append(cracked, map[string]any{
				"hash":      parts[0],
				"plaintext": parts[1],
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading potfile: %w", err)
	}

	return cracked, nil
}

// countHashes counts the number of hashes in the input file
func countHashes(hashFile string) (int, error) {
	file, err := os.Open(hashFile)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}

	return count, scanner.Err()
}

// HashcatStats holds parsed statistics from hashcat output
type HashcatStats struct {
	Speed   string
	GPUInfo string
}

// parseHashcatStats extracts statistics from hashcat output
func parseHashcatStats(output string) HashcatStats {
	stats := HashcatStats{
		Speed:   "unknown",
		GPUInfo: "unknown",
	}

	// Parse speed (e.g., "Speed.#1.........:  1234.5 MH/s")
	speedRegex := regexp.MustCompile(`Speed\..*?:\s+([\d.]+\s+[KMG]?H/s)`)
	if matches := speedRegex.FindStringSubmatch(output); len(matches) > 1 {
		stats.Speed = matches[1]
	}

	// Parse GPU info (e.g., "Device #1: NVIDIA GeForce RTX 3080")
	gpuRegex := regexp.MustCompile(`Device #\d+:\s+(.+)`)
	if matches := gpuRegex.FindStringSubmatch(output); len(matches) > 1 {
		stats.GPUInfo = matches[1]
	}

	return stats
}

// detectGPUInfo tries to detect GPU information from hashcat version output
func detectGPUInfo(output string) string {
	// Look for GPU-related info in version output
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "CUDA") || strings.Contains(line, "OpenCL") ||
		   strings.Contains(line, "GPU") || strings.Contains(line, "NVIDIA") ||
		   strings.Contains(line, "AMD") {
			return strings.TrimSpace(line)
		}
	}
	return "GPU detection unavailable"
}
