package main

import (
	"context"
	"fmt"
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
	ToolName        = "gobuster"
	ToolVersion     = "1.0.0"
	ToolDescription = "Directory/file brute-forcing tool for discovering hidden paths and content"
	BinaryName      = "gobuster"
)

// ToolImpl implements the gobuster tool
type ToolImpl struct{}

// NewTool creates a new gobuster tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"initial-access",
			"brute-force",
			"directory",
			"T1190", // Exploit Public-Facing Application
			"T1595", // Active Scanning
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

// Execute runs the gobuster tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	url := sdkinput.GetString(input, "url", "")
	if url == "" {
		return nil, fmt.Errorf("url is required")
	}

	wordlist := sdkinput.GetString(input, "wordlist", "/usr/share/wordlists/dirb/common.txt")
	mode := sdkinput.GetString(input, "mode", "dir")
	extensions := sdkinput.GetStringSlice(input, "extensions")
	threads := sdkinput.GetInt(input, "threads", 10)
	timeout := sdkinput.GetTimeout(input, "timeout", sdkinput.DefaultTimeout())
	statusCodes := sdkinput.GetString(input, "status_codes", "200,204,301,302,307,401,403")

	// Build gobuster command arguments
	args := buildArgs(url, wordlist, mode, extensions, threads, statusCodes)

	// Execute gobuster command
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}

	// Parse gobuster output
	output, err := parseOutput(result.Stdout, url)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).WithCause(err)
	}

	// Add scan time
	output["scan_time_ms"] = int(time.Since(startTime).Milliseconds())

	return output, nil
}

// Health checks if the gobuster binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// buildArgs constructs the command-line arguments for gobuster
func buildArgs(url, wordlist, mode string, extensions []string, threads int, statusCodes string) []string {
	args := []string{mode, "-u", url, "-w", wordlist, "-q"}

	if len(extensions) > 0 {
		args = append(args, "-x", strings.Join(extensions, ","))
	}

	if threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", threads))
	}

	if statusCodes != "" {
		args = append(args, "-s", statusCodes)
	}

	return args
}

// parseOutput parses the output from gobuster
func parseOutput(data []byte, url string) (map[string]any, error) {
	lines := strings.Split(string(data), "\n")

	results := []map[string]any{}
	// Match lines like: /admin (Status: 200) [Size: 1234]
	re := regexp.MustCompile(`^(/[^\s]*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		matches := re.FindStringSubmatch(line)
		if len(matches) >= 3 {
			path := matches[1]
			statusCode, _ := strconv.Atoi(matches[2])
			size := 0
			if len(matches) >= 4 && matches[3] != "" {
				size, _ = strconv.Atoi(matches[3])
			}

			results = append(results, map[string]any{
				"path":        path,
				"status_code": statusCode,
				"size":        size,
			})
		}
	}

	return map[string]any{
		"url":         url,
		"results":     results,
		"total_found": len(results),
	}, nil
}
