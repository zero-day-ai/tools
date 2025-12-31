package main

import (
	"context"
	"encoding/json"
	"fmt"
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
	ToolName        = "httpx"
	ToolVersion     = "1.0.0"
	ToolDescription = "Fast HTTP probing tool for discovering live hosts and gathering web information"
	BinaryName      = "httpx"
)

// ToolImpl implements the httpx tool
type ToolImpl struct{}

// NewTool creates a new httpx tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"reconnaissance",
			"http",
			"probing",
			"T1595", // Active Scanning
			"T1592", // Gather Victim Host Information
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

// Execute runs the httpx tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	targets := sdkinput.GetStringSlice(input, "targets")
	if len(targets) == 0 {
		return nil, fmt.Errorf("targets is required")
	}

	timeout := sdkinput.GetTimeout(input, "timeout", sdkinput.DefaultTimeout())
	followRedirects := sdkinput.GetBool(input, "follow_redirects", true)
	statusCode := sdkinput.GetBool(input, "status_code", true)
	title := sdkinput.GetBool(input, "title", true)
	techDetect := sdkinput.GetBool(input, "tech_detect", false)

	// Build httpx command arguments
	args := buildArgs(followRedirects, statusCode, title, techDetect)

	// Execute httpx command with stdin input
	result, err := exec.Run(ctx, exec.Config{
		Command:   BinaryName,
		Args:      args,
		StdinData: []byte(strings.Join(targets, "\n")),
		Timeout:   timeout,
	})

	if err != nil {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}

	// Parse httpx JSON output
	output, err := parseOutput(result.Stdout)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).WithCause(err)
	}

	// Add scan time
	output["scan_time_ms"] = int(time.Since(startTime).Milliseconds())

	return output, nil
}

// Health checks if the httpx binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// buildArgs constructs the command-line arguments for httpx
func buildArgs(followRedirects, statusCode, title, techDetect bool) []string {
	args := []string{"-json"}

	if followRedirects {
		args = append(args, "-follow-redirects")
	} else {
		args = append(args, "-no-follow-redirects")
	}

	if statusCode {
		args = append(args, "-status-code")
	}

	if title {
		args = append(args, "-title")
	}

	if techDetect {
		args = append(args, "-tech-detect")
	}

	return args
}

// HttpxOutput represents a single JSON line from httpx output
type HttpxOutput struct {
	URL          string   `json:"url"`
	StatusCode   int      `json:"status_code"`
	Title        string   `json:"title"`
	ContentType  string   `json:"content_type"`
	Technologies []string `json:"tech,omitempty"`
}

// parseOutput parses the JSON output from httpx
func parseOutput(data []byte) (map[string]any, error) {
	lines := strings.Split(string(data), "\n")

	results := []map[string]any{}
	aliveCount := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var entry HttpxOutput
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		results = append(results, map[string]any{
			"url":          entry.URL,
			"status_code":  entry.StatusCode,
			"title":        entry.Title,
			"content_type": entry.ContentType,
			"technologies": entry.Technologies,
		})

		if entry.StatusCode >= 200 && entry.StatusCode < 500 {
			aliveCount++
		}
	}

	return map[string]any{
		"results":      results,
		"total_probed": len(results),
		"alive_count":  aliveCount,
	}, nil
}
