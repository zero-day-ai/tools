package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "bloodhound"
	ToolVersion     = "1.0.0"
	ToolDescription = "Active Directory relationship mapping tool using bloodhound-python for privilege escalation path discovery"
	BinaryName      = "bloodhound-python"
)

// ToolImpl implements the bloodhound tool
type ToolImpl struct{}

// NewTool creates a new bloodhound tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"discovery",
			"active-directory",
			"reconnaissance",
			"graph",
			"T1087",     // Account Discovery
			"T1069",     // Permission Groups Discovery
			"T1087.002", // Domain Account
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

// Execute runs bloodhound-python with the provided parameters
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Create temporary output directory
	outputDir, err := os.MkdirTemp("", "bloodhound-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	// Note: We don't defer removal - caller may need the files

	// Build bloodhound-python command arguments
	args := t.buildBloodhoundArgs(input, outputDir)

	// Execute bloodhound-python
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: t.getTimeout(input),
	})

	if err != nil {
		return nil, fmt.Errorf("bloodhound-python execution failed: %w", err)
	}

	// Check for non-zero exit code
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("bloodhound-python exited with code %d: %s", result.ExitCode, string(result.Stderr))
	}

	// Find generated files
	files, err := t.findOutputFiles(outputDir)
	if err != nil {
		return nil, fmt.Errorf("failed to find output files: %w", err)
	}

	// Parse entity counts from JSON files
	counts, err := t.parseEntityCounts(files)
	if err != nil {
		return nil, fmt.Errorf("failed to parse entity counts: %w", err)
	}

	// Build output
	output := map[string]any{
		"users":              counts["users"],
		"groups":             counts["groups"],
		"computers":          counts["computers"],
		"domains":            counts["domains"],
		"gpos":               counts["gpos"],
		"ous":                counts["ous"],
		"output_files":       files,
		"collection_time_ms": time.Since(startTime).Milliseconds(),
	}

	return output, nil
}

// buildBloodhoundArgs constructs bloodhound-python command arguments from input parameters
func (t *ToolImpl) buildBloodhoundArgs(input map[string]any, outputDir string) []string {
	args := []string{
		"-d", getString(input, "domain", ""),
		"-u", getString(input, "username", ""),
		"-c", getString(input, "collection_method", "default"),
		"--zip",
		"-o", outputDir,
	}

	// Authentication - password or hash
	if pass := getString(input, "password", ""); pass != "" {
		args = append(args, "-p", pass)
	} else if hash := getString(input, "hash", ""); hash != "" {
		args = append(args, "--hashes", hash)
	}

	// Domain Controller IP (optional)
	if dcIP := getString(input, "dc_ip", ""); dcIP != "" {
		args = append(args, "--dc-ip", dcIP)
	}

	return args
}

// findOutputFiles locates generated JSON and ZIP files in output directory
func (t *ToolImpl) findOutputFiles(outputDir string) ([]string, error) {
	var files []string

	// Find JSON files
	jsonFiles, err := filepath.Glob(filepath.Join(outputDir, "*.json"))
	if err != nil {
		return nil, err
	}
	files = append(files, jsonFiles...)

	// Find ZIP files
	zipFiles, err := filepath.Glob(filepath.Join(outputDir, "*.zip"))
	if err != nil {
		return nil, err
	}
	files = append(files, zipFiles...)

	return files, nil
}

// parseEntityCounts extracts entity counts from BloodHound JSON files
func (t *ToolImpl) parseEntityCounts(files []string) (map[string]int, error) {
	counts := map[string]int{
		"users":     0,
		"groups":    0,
		"computers": 0,
		"domains":   0,
		"gpos":      0,
		"ous":       0,
	}

	// Parse each JSON file to extract counts
	for _, file := range files {
		// Skip ZIP files
		if filepath.Ext(file) != ".json" {
			continue
		}

		data, err := os.ReadFile(file)
		if err != nil {
			continue // Skip files we can't read
		}

		var parsed map[string]any
		if err := json.Unmarshal(data, &parsed); err != nil {
			continue // Skip invalid JSON
		}

		// Check for different BloodHound JSON formats
		// Users file
		if users, ok := parsed["users"].([]any); ok {
			counts["users"] += len(users)
		}

		// Groups file
		if groups, ok := parsed["groups"].([]any); ok {
			counts["groups"] += len(groups)
		}

		// Computers file
		if computers, ok := parsed["computers"].([]any); ok {
			counts["computers"] += len(computers)
		}

		// Domains file
		if domains, ok := parsed["domains"].([]any); ok {
			counts["domains"] += len(domains)
		}

		// GPOs file
		if gpos, ok := parsed["gpos"].([]any); ok {
			counts["gpos"] += len(gpos)
		}

		// OUs file
		if ous, ok := parsed["ous"].([]any); ok {
			counts["ous"] += len(ous)
		}

		// Alternative format - check "data" field
		if data, ok := parsed["data"].([]any); ok {
			// Determine type from filename
			filename := filepath.Base(file)
			switch {
			case strings.Contains(filename, "users"):
				counts["users"] += len(data)
			case strings.Contains(filename, "groups"):
				counts["groups"] += len(data)
			case strings.Contains(filename, "computers"):
				counts["computers"] += len(data)
			case strings.Contains(filename, "domains"):
				counts["domains"] += len(data)
			case strings.Contains(filename, "gpos"):
				counts["gpos"] += len(data)
			case strings.Contains(filename, "ous"):
				counts["ous"] += len(data)
			}
		}
	}

	return counts, nil
}

// getTimeout extracts timeout from input or returns default
func (t *ToolImpl) getTimeout(input map[string]any) time.Duration {
	// BloodHound can take a long time on large domains - default to 30 minutes
	return 30 * time.Minute
}

// Health checks the bloodhound-python binary
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	// Check if bloodhound-python binary exists
	if !executor.BinaryExists(BinaryName) {
		return types.NewUnhealthyStatus("bloodhound-python not found in PATH", map[string]any{
			"binary": BinaryName,
			"hint":   "Install with: pip install bloodhound",
		})
	}

	return types.NewHealthyStatus("bloodhound-python is available")
}

// Helper functions for extracting input parameters

func getString(input map[string]any, key string, defaultVal string) string {
	if val, ok := input[key].(string); ok {
		return val
	}
	return defaultVal
}
