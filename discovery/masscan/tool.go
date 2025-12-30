package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson-tools-official/pkg/common"
	"github.com/zero-day-ai/gibson-tools-official/pkg/executor"
	"github.com/zero-day-ai/gibson-tools-official/pkg/health"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "masscan"
	ToolVersion     = "1.0.0"
	ToolDescription = "High-speed network port scanner for large-scale network discovery"
	BinaryName      = "masscan"
)

// ToolImpl implements the masscan tool logic
type ToolImpl struct{}

// NewTool creates a new masscan tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"discovery",
			"network-scanning",
			"port-scanning",
			"T1046", // Network Service Scanning
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

// Execute runs the masscan tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	targets := common.GetString(input, "targets", "")
	if targets == "" {
		return nil, fmt.Errorf("targets is required")
	}

	ports := common.GetString(input, "ports", "")
	if ports == "" {
		return nil, fmt.Errorf("ports is required")
	}

	rate := common.GetInt(input, "rate", 100)
	banners := common.GetBool(input, "banners", false)

	// Create temp file for JSON output
	tmpFile, err := os.CreateTemp("", "masscan-*.json")
	if err != nil {
		return nil, &common.ToolError{
			Tool:      ToolName,
			Operation: "create_temp_file",
			Code:      common.ErrCodeExecutionFailed,
			Message:   fmt.Sprintf("failed to create temp file: %v", err),
		}
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Build command arguments
	args := buildMasscanArgs(targets, ports, rate, banners, tmpFile.Name())

	// Execute masscan
	result, err := executor.Execute(ctx, executor.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: common.DefaultTimeout(),
	})

	if err != nil {
		return nil, &common.ToolError{
			Tool:      ToolName,
			Operation: "execute",
			Code:      common.ErrCodeExecutionFailed,
			Message:   fmt.Sprintf("failed to execute masscan: %v", err),
			Details:   map[string]any{"exit_code": result.ExitCode},
		}
	}

	// Read and parse JSON output file
	outputData, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		return nil, &common.ToolError{
			Tool:      ToolName,
			Operation: "read_output",
			Code:      common.ErrCodeParseError,
			Message:   fmt.Sprintf("failed to read masscan output: %v", err),
		}
	}

	// Parse JSON output
	hosts, totalPorts, err := parseMasscanOutput(outputData)
	if err != nil {
		return nil, &common.ToolError{
			Tool:      ToolName,
			Operation: "parse",
			Code:      common.ErrCodeParseError,
			Message:   fmt.Sprintf("failed to parse masscan output: %v", err),
		}
	}

	// Calculate scan time
	scanTimeMs := time.Since(startTime).Milliseconds()

	// Build output
	output := map[string]any{
		"hosts":        hosts,
		"total_hosts":  len(hosts),
		"total_ports":  totalPorts,
		"scan_rate":    rate,
		"scan_time_ms": int(scanTimeMs),
	}

	return output, nil
}

// Health checks if the masscan binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// buildMasscanArgs constructs the command line arguments for masscan
func buildMasscanArgs(targets, ports string, rate int, banners bool, outputFile string) []string {
	args := []string{
		targets,
		"-p", ports,
		"--rate", strconv.Itoa(rate),
		"-oJ", outputFile, // JSON output to file
	}

	// Add banner grabbing if enabled
	if banners {
		args = append(args, "--banners")
	}

	return args
}

// MasscanOutput represents the structure of masscan JSON output
type MasscanOutput []MasscanResult

// MasscanResult represents a single scan result
type MasscanResult struct {
	IP        string        `json:"ip"`
	Timestamp string        `json:"timestamp"`
	Ports     []MasscanPort `json:"ports"`
}

// MasscanPort represents port information
type MasscanPort struct {
	Port     int               `json:"port"`
	Proto    string            `json:"proto"`
	Status   string            `json:"status"`
	Reason   string            `json:"reason"`
	TTL      int               `json:"ttl"`
	Service  MasscanService    `json:"service,omitempty"`
}

// MasscanService represents service banner information
type MasscanService struct {
	Name   string `json:"name"`
	Banner string `json:"banner"`
}

// parseMasscanOutput parses the JSON output from masscan
func parseMasscanOutput(output []byte) ([]map[string]any, int, error) {
	// Masscan outputs one JSON object per line, not a JSON array
	// We need to parse it line by line
	lines := strings.Split(string(output), "\n")

	// Group ports by IP address
	hostMap := make(map[string][]map[string]any)
	totalPorts := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "{") == false {
			continue
		}

		var result MasscanResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			// Skip lines that can't be parsed
			continue
		}

		// Process each port for this IP
		for _, port := range result.Ports {
			// Only include open ports
			if port.Status != "open" {
				continue
			}

			portInfo := map[string]any{
				"port":     port.Port,
				"protocol": port.Proto,
				"state":    port.Status,
			}

			// Add banner if available
			if port.Service.Banner != "" {
				portInfo["banner"] = port.Service.Banner
			}

			hostMap[result.IP] = append(hostMap[result.IP], portInfo)
			totalPorts++
		}
	}

	// Convert map to slice
	hosts := make([]map[string]any, 0, len(hostMap))
	for ip, ports := range hostMap {
		hosts = append(hosts, map[string]any{
			"ip":    ip,
			"ports": ports,
		})
	}

	return hosts, totalPorts, nil
}
