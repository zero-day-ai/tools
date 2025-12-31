package main

import (
	"context"
	"fmt"
	"regexp"
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
	ToolName        = "winpeas"
	ToolVersion     = "1.0.0"
	ToolDescription = "Windows privilege escalation enumeration tool"
	BinaryName      = "winPEASx64.exe"
)

// ToolImpl implements the winpeas tool logic
type ToolImpl struct{}

// NewTool creates a new winpeas tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"privilege-escalation",
			"windows",
			"enumeration",
			"T1548", // Abuse Elevation Control Mechanism
			"T1134", // Access Token Manipulation
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

// Execute runs the winpeas tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	targetShell := sdkinput.GetString(input, "target_shell", "")
	if targetShell == "" {
		return nil, fmt.Errorf("target_shell is required")
	}

	checks := sdkinput.GetStringSlice(input, "checks")
	quiet := sdkinput.GetBool(input, "quiet", false)

	// Build winpeas command arguments
	winpeasArgs := buildWinPEASArgs(checks, quiet)

	// Construct the full command to execute on the target
	// The target_shell is used as a command prefix to execute winpeas remotely
	fullCommand := fmt.Sprintf("%s '%s'", targetShell, winpeasArgs)

	// Execute winpeas on target via shell interface
	result, err := exec.Run(ctx, exec.Config{
		Command: "sh",
		Args:    []string{"-c", fullCommand},
		Timeout: sdkinput.DefaultTimeout(),
	})

	if err != nil {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "execute",
			Code:      toolerr.ErrCodeExecutionFailed,
			Message:   fmt.Sprintf("failed to execute winpeas: %v", err),
			Details:   map[string]any{"exit_code": result.ExitCode},
		}
	}

	// Parse winpeas output
	parsed, err := parseWinPEASOutput(result.Stdout)
	if err != nil {
		return nil, &toolerr.Error{
			Tool:      ToolName,
			Operation: "parse",
			Code:      toolerr.ErrCodeParseError,
			Message:   fmt.Sprintf("failed to parse winpeas output: %v", err),
		}
	}

	// Calculate scan time
	scanTimeMs := time.Since(startTime).Milliseconds()
	parsed["scan_time_ms"] = int(scanTimeMs)

	return parsed, nil
}

// Health checks if the winpeas binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// buildWinPEASArgs constructs the command line arguments for winpeas
func buildWinPEASArgs(checks []string, quiet bool) string {
	args := []string{BinaryName}

	// Add specific checks if specified
	if len(checks) > 0 {
		args = append(args, fmt.Sprintf("-checks %s", strings.Join(checks, ",")))
	}

	// Add quiet flag if enabled
	if quiet {
		args = append(args, "-q")
	}

	return strings.Join(args, " ")
}

// parseWinPEASOutput parses the winpeas output into structured data
func parseWinPEASOutput(output []byte) (map[string]any, error) {
	text := string(output)

	result := map[string]any{
		"system_info":       parseSystemInfo(text),
		"users":             parseUsers(text),
		"services":          parseServices(text),
		"scheduled_tasks":   parseScheduledTasks(text),
		"unquoted_paths":    parseUnquotedPaths(text),
		"registry_autoruns": parseRegistryAutoruns(text),
		"possible_exploits": parsePossibleExploits(text),
	}

	return result, nil
}

// parseSystemInfo extracts system information from winpeas output
func parseSystemInfo(text string) map[string]any {
	info := make(map[string]any)

	// Extract hostname
	if match := regexp.MustCompile(`(?i)hostname:\s*(.+)`).FindStringSubmatch(text); len(match) > 1 {
		info["hostname"] = strings.TrimSpace(match[1])
	}

	// Extract OS version
	if match := regexp.MustCompile(`(?i)OS Version:\s*(.+)`).FindStringSubmatch(text); len(match) > 1 {
		info["os_version"] = strings.TrimSpace(match[1])
	}

	// Extract architecture
	if match := regexp.MustCompile(`(?i)Architecture:\s*(.+)`).FindStringSubmatch(text); len(match) > 1 {
		info["architecture"] = strings.TrimSpace(match[1])
	}

	return info
}

// parseUsers extracts user information from winpeas output
func parseUsers(text string) []map[string]any {
	users := []map[string]any{}

	// Look for user enumeration section
	userPattern := regexp.MustCompile(`(?i)User Name:\s*(.+)`)
	matches := userPattern.FindAllStringSubmatch(text, -1)

	for _, match := range matches {
		if len(match) > 1 {
			username := strings.TrimSpace(match[1])
			user := map[string]any{
				"username":   username,
				"groups":     []string{},
				"privileges": []string{},
			}
			users = append(users, user)
		}
	}

	return users
}

// parseServices extracts vulnerable service information
func parseServices(text string) []map[string]any {
	services := []map[string]any{}

	// Look for service misconfigurations
	servicePattern := regexp.MustCompile(`(?i)Service Name:\s*(.+)`)
	matches := servicePattern.FindAllStringSubmatch(text, -1)

	for _, match := range matches {
		if len(match) > 1 {
			serviceName := strings.TrimSpace(match[1])
			service := map[string]any{
				"name":       serviceName,
				"path":       "",
				"vulnerable": false,
				"reason":     "",
			}
			services = append(services, service)
		}
	}

	return services
}

// parseScheduledTasks extracts scheduled task information
func parseScheduledTasks(text string) []map[string]any {
	tasks := []map[string]any{}

	// Look for scheduled tasks
	taskPattern := regexp.MustCompile(`(?i)Task Name:\s*(.+)`)
	matches := taskPattern.FindAllStringSubmatch(text, -1)

	for _, match := range matches {
		if len(match) > 1 {
			taskName := strings.TrimSpace(match[1])
			task := map[string]any{
				"name": taskName,
			}
			tasks = append(tasks, task)
		}
	}

	return tasks
}

// parseUnquotedPaths extracts unquoted service paths
func parseUnquotedPaths(text string) []string {
	paths := []string{}

	// Look for unquoted service paths
	pathPattern := regexp.MustCompile(`(?i)Unquoted.*?:\s*(.+\.exe)`)
	matches := pathPattern.FindAllStringSubmatch(text, -1)

	for _, match := range matches {
		if len(match) > 1 {
			path := strings.TrimSpace(match[1])
			paths = append(paths, path)
		}
	}

	return paths
}

// parseRegistryAutoruns extracts registry autorun entries
func parseRegistryAutoruns(text string) []map[string]any {
	autoruns := []map[string]any{}

	// Look for registry autoruns
	autorunPattern := regexp.MustCompile(`(?i)Autorun.*?:\s*(.+)`)
	matches := autorunPattern.FindAllStringSubmatch(text, -1)

	for _, match := range matches {
		if len(match) > 1 {
			entry := strings.TrimSpace(match[1])
			autorun := map[string]any{
				"entry": entry,
			}
			autoruns = append(autoruns, autorun)
		}
	}

	return autoruns
}

// parsePossibleExploits extracts possible privilege escalation exploits
func parsePossibleExploits(text string) []map[string]any {
	exploits := []map[string]any{}

	// Look for CVE mentions
	cvePattern := regexp.MustCompile(`(CVE-\d{4}-\d+)`)
	matches := cvePattern.FindAllString(text, -1)

	// Deduplicate CVEs
	cveSet := make(map[string]bool)
	for _, cve := range matches {
		if !cveSet[cve] {
			cveSet[cve] = true
			exploit := map[string]any{
				"name":        cve,
				"cve":         cve,
				"description": "Potential privilege escalation vulnerability",
			}
			exploits = append(exploits, exploit)
		}
	}

	return exploits
}
