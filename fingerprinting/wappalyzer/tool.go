package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/zero-day-ai/sdk/api/gen/toolspb"
	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/health"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/toolerr"
	"github.com/zero-day-ai/sdk/types"
	"google.golang.org/protobuf/proto"
)

const (
	ToolName        = "wappalyzer"
	ToolVersion     = "1.0.0"
	ToolDescription = "Technology detection tool using webanalyze for identifying web technologies and frameworks"
	BinaryName      = "webanalyze"
)

// ToolImpl implements the wappalyzer tool
type ToolImpl struct{}

// NewTool creates a new wappalyzer tool instance
func NewTool() tool.Tool {
	impl := &ToolImpl{}
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"fingerprinting",
			"technology-detection",
			"web",
			"T1595", // Active Scanning
			"T1594", // Search Victim-Owned Websites
		}).
		SetInputMessageType(impl.InputMessageType()).
		SetOutputMessageType(impl.OutputMessageType()).
		SetExecuteProtoFunc(impl.ExecuteProto)

	t, _ := tool.New(cfg)
	return &toolWithHealth{Tool: t, impl: impl}
}

// toolWithHealth wraps the tool to add custom health checks
type toolWithHealth struct {
	tool.Tool
	impl *ToolImpl
}

func (t *toolWithHealth) Health(ctx context.Context) types.HealthStatus {
	return t.impl.Health(ctx)
}

// InputMessageType returns the protobuf message type for input
func (t *ToolImpl) InputMessageType() string {
	return "gibson.tools.WappalyzerRequest"
}

// OutputMessageType returns the protobuf message type for output
func (t *ToolImpl) OutputMessageType() string {
	return "gibson.tools.WappalyzerResponse"
}

// ExecuteProto runs the wappalyzer tool with the provided proto input
func (t *ToolImpl) ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error) {
	startTime := time.Now()

	// Type assert to WappalyzerRequest
	req, ok := input.(*toolspb.WappalyzerRequest)
	if !ok {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeInvalidInput, "input must be *toolspb.WappalyzerRequest")
	}

	// Validate required fields
	if len(req.Targets) == 0 {
		return nil, toolerr.New(ToolName, "validate", toolerr.ErrCodeInvalidInput, "targets is required")
	}

	// Build webanalyze command arguments
	args := []string{"-output", "json"}

	// Add all targets
	for _, target := range req.Targets {
		args = append(args, "-host", target)
	}

	// Determine timeout
	timeout := time.Duration(60) * time.Second // default
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	// Execute webanalyze command
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}

	// Parse webanalyze JSON output into proto response
	response, err := parseOutputProto(result.Stdout, time.Since(startTime))
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).WithCause(err)
	}

	return response, nil
}

// Health checks if the webanalyze binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// WebanalyzeApp represents a detected technology from webanalyze
type WebanalyzeApp struct {
	Name       string   `json:"app"`
	Version    string   `json:"version"`
	Categories []string `json:"categories"`
	Confidence int      `json:"confidence"`
}

// WebanalyzeOutput represents the JSON output from webanalyze
type WebanalyzeOutput struct {
	Hostname string          `json:"host"`
	Apps     []WebanalyzeApp `json:"matches"`
}

// parseOutputProto parses the JSON output from webanalyze into proto response
func parseOutputProto(data []byte, duration time.Duration) (*toolspb.WappalyzerResponse, error) {
	var entries []WebanalyzeOutput
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse webanalyze output: %w", err)
	}

	results := []*toolspb.WappalyzerResult{}

	for _, entry := range entries {
		// Convert technologies
		technologies := []*toolspb.DetectedTechnology{}
		for _, app := range entry.Apps {
			// Convert categories
			categories := []*toolspb.TechnologyCategory{}
			for _, catName := range app.Categories {
				categories = append(categories, &toolspb.TechnologyCategory{
					Name: catName,
				})
			}

			technologies = append(technologies, &toolspb.DetectedTechnology{
				Name:       app.Name,
				Version:    app.Version,
				Categories: categories,
				Confidence: int32(app.Confidence),
			})
		}

		result := &toolspb.WappalyzerResult{
			Url:               entry.Hostname,
			Technologies:      technologies,
			TotalTechnologies: int32(len(technologies)),
		}

		results = append(results, result)
	}

	return &toolspb.WappalyzerResponse{
		Results:      results,
		TotalTargets: int32(len(results)),
		Duration:     duration.Seconds(),
	}, nil
}
