package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	ToolName        = "spiderfoot"
	ToolVersion     = "1.0.0"
	ToolDescription = "Automated OSINT correlation tool that discovers relationships between target assets using SpiderFoot CLI"
	BinaryName      = "spiderfoot"
	DefaultTimeout  = 5 * time.Minute
)

// ToolImpl implements the SpiderFoot tool
type ToolImpl struct{}

// NewTool creates a new SpiderFoot tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"reconnaissance",
			"osint",
			"passive",
			"T1589", // Gather Victim Identity Information
			"T1590", // Gather Victim Network Information
			"T1591", // Gather Victim Org Information
			"T1592", // Gather Victim Host Information
			"T1593", // Search Open Websites/Domains
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

// Execute runs the SpiderFoot scan
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	start := time.Now()

	// Extract input parameters
	target, ok := input["target"].(string)
	if !ok || target == "" {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "validate_input",
			Code:      toolerr.ErrCodeInvalidInput,
			Message:   "target is required and must be a string",
		}
	}

	scanType := "passive" // default
	if st, ok := input["scan_type"].(string); ok && st != "" {
		scanType = st
	}

	// Create temp directory for output
	tempDir, err := os.MkdirTemp("", "spiderfoot-*")
	if err != nil {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "create_temp_dir",
			Code:      toolerr.ErrCodeExecutionFailed,
			Message:   "failed to create temporary directory",
			Cause:     err,
		}
	}
	defer os.RemoveAll(tempDir)

	outputFile := filepath.Join(tempDir, "results.json")

	// Build command arguments
	args := t.buildArgs(target, scanType, outputFile, input)

	// Execute SpiderFoot
	execCfg := exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: DefaultTimeout,
	}

	result, err := exec.Run(ctx, execCfg)
	if err != nil {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "execute",
			Code:      toolerr.ErrCodeExecutionFailed,
			Message:   fmt.Sprintf("spiderfoot execution failed: %s", string(result.Stderr)),
			Cause:     err,
			Details: map[string]any{
				"exit_code": result.ExitCode,
				"stderr":    string(result.Stderr),
			},
		}
	}

	// Parse the output
	entities, relationships, err := t.parseOutput(outputFile)
	if err != nil {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "parse_output",
			Code:      toolerr.ErrCodeParseError,
			Message:   "failed to parse spiderfoot output",
			Cause:     err,
		}
	}

	// Calculate scan time
	scanTimeMs := int(time.Since(start).Milliseconds())

	return map[string]any{
		"target":        target,
		"entities":      entities,
		"relationships": relationships,
		"scan_time_ms":  scanTimeMs,
	}, nil
}

// buildArgs constructs the command line arguments for SpiderFoot
func (t *ToolImpl) buildArgs(target, scanType, outputFile string, input map[string]any) []string {
	args := []string{
		"-s", target,      // Target
		"-o", "json",      // JSON output format
		"-f", outputFile,  // Output file
		"-q",              // Quiet mode (no banner)
	}

	// Add scan type flags
	switch scanType {
	case "passive":
		args = append(args, "-p") // Passive scan only
	case "active":
		args = append(args, "-a") // Active scan
	case "all":
		// No specific flag - runs all modules
	}

	// Add module filtering if specified
	if modules, ok := input["modules"].([]interface{}); ok && len(modules) > 0 {
		moduleStrs := make([]string, 0, len(modules))
		for _, m := range modules {
			if ms, ok := m.(string); ok {
				moduleStrs = append(moduleStrs, ms)
			}
		}
		if len(moduleStrs) > 0 {
			args = append(args, "-m", strings.Join(moduleStrs, ","))
		}
	}

	// Add max threads if specified
	if maxThreads, ok := input["max_threads"].(float64); ok && maxThreads > 0 {
		args = append(args, "-t", fmt.Sprintf("%.0f", maxThreads))
	}

	return args
}

// parseOutput parses the SpiderFoot JSON output
func (t *ToolImpl) parseOutput(outputFile string) ([]map[string]any, []map[string]any, error) {
	// Read the output file
	data, err := os.ReadFile(outputFile)
	if err != nil {
		// If file doesn't exist, return empty results
		if os.IsNotExist(err) {
			return []map[string]any{}, []map[string]any{}, nil
		}
		return nil, nil, fmt.Errorf("failed to read output file: %w", err)
	}

	// SpiderFoot output structure
	var output struct {
		Data []struct {
			Type         string  `json:"type"`
			Value        string  `json:"value"`
			SourceModule string  `json:"module"`
			Source       string  `json:"source"`
			Confidence   float64 `json:"confidence"`
		} `json:"data"`
	}

	if err := json.Unmarshal(data, &output); err != nil {
		// Try parsing as line-delimited JSON
		return t.parseLineDelimitedJSON(data)
	}

	// Convert to entities and relationships
	entities := make([]map[string]any, 0, len(output.Data))
	relationships := make([]map[string]any, 0)

	entityMap := make(map[string]bool)

	for _, item := range output.Data {
		// Create entity
		entity := map[string]any{
			"type":          item.Type,
			"value":         item.Value,
			"source_module": item.SourceModule,
			"confidence":    item.Confidence,
		}

		entities = append(entities, entity)
		entityMap[item.Value] = true

		// Create relationship if source is present
		if item.Source != "" && item.Source != item.Value {
			relationship := map[string]any{
				"from": item.Source,
				"to":   item.Value,
				"type": "discovered_from",
			}
			relationships = append(relationships, relationship)
		}
	}

	return entities, relationships, nil
}

// parseLineDelimitedJSON handles line-delimited JSON format
func (t *ToolImpl) parseLineDelimitedJSON(data []byte) ([]map[string]any, []map[string]any, error) {
	lines := strings.Split(string(data), "\n")
	entities := make([]map[string]any, 0)
	relationships := make([]map[string]any, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var item map[string]any
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			continue // Skip invalid lines
		}

		// Extract entity information
		entityType, _ := item["type"].(string)
		entityValue, _ := item["value"].(string)
		sourceModule, _ := item["module"].(string)
		confidence, _ := item["confidence"].(float64)
		source, _ := item["source"].(string)

		if entityValue != "" {
			entity := map[string]any{
				"type":          entityType,
				"value":         entityValue,
				"source_module": sourceModule,
				"confidence":    confidence,
			}
			entities = append(entities, entity)

			// Create relationship
			if source != "" && source != entityValue {
				relationship := map[string]any{
					"from": source,
					"to":   entityValue,
					"type": "discovered_from",
				}
				relationships = append(relationships, relationship)
			}
		}
	}

	return entities, relationships, nil
}

// Health checks the operational status of the SpiderFoot tool
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}
