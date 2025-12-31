package main

import (
	"bufio"
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "crackmapexec"
	ToolVersion     = "1.0.0"
	ToolDescription = "Active Directory enumeration tool using CrackMapExec/NetExec for SMB, WinRM, LDAP, MSSQL, and SSH protocols"
)

var (
	// Binary names to try - netexec is the newer fork of crackmapexec
	BinaryNames = []string{"netexec", "crackmapexec", "cme", "nxc"}
)

// ToolImpl implements the crackmapexec/netexec tool
type ToolImpl struct {
	binaryName string
}

// NewTool creates a new crackmapexec/netexec tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"discovery",
			"active-directory",
			"enumeration",
			"T1087.002", // Domain Account
			"T1018",     // Remote System Discovery
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

// Execute runs crackmapexec/netexec with the provided parameters
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Find available binary
	binaryName, err := t.findBinary()
	if err != nil {
		return nil, fmt.Errorf("crackmapexec/netexec binary not found: %w", err)
	}
	t.binaryName = binaryName

	// Build command arguments
	args := t.buildArgs(input)

	// Execute crackmapexec/netexec
	result, err := exec.Run(ctx, exec.Config{
		Command: binaryName,
		Args:    args,
		Timeout: t.getTimeout(input),
	})

	if err != nil {
		return nil, fmt.Errorf("crackmapexec execution failed: %w", err)
	}

	// Parse output
	output, err := t.parseOutput(result.Stdout, result.Stderr, input)
	if err != nil {
		return nil, fmt.Errorf("failed to parse crackmapexec output: %w", err)
	}

	// Add execution metadata
	output["scan_time_ms"] = time.Since(startTime).Milliseconds()

	return output, nil
}

// findBinary locates an available crackmapexec/netexec binary
func (t *ToolImpl) findBinary() (string, error) {
	for _, name := range BinaryNames {
		if exec.BinaryExists(name) {
			return name, nil
		}
	}
	return "", fmt.Errorf("none of the supported binaries found: %v", BinaryNames)
}

// buildArgs constructs crackmapexec/netexec command arguments from input parameters
func (t *ToolImpl) buildArgs(input map[string]any) []string {
	protocol := getString(input, "protocol", "smb")
	target := getString(input, "target", "")

	args := []string{protocol, target}

	// Authentication options
	if username := getString(input, "username", ""); username != "" {
		args = append(args, "-u", username)
	}

	if password := getString(input, "password", ""); password != "" {
		args = append(args, "-p", password)
	}

	if hash := getString(input, "hash", ""); hash != "" {
		args = append(args, "-H", hash)
	}

	// Module execution
	if module := getString(input, "module", ""); module != "" {
		args = append(args, "-M", module)

		// Module options
		if options, ok := input["options"].(map[string]any); ok && len(options) > 0 {
			for key, value := range options {
				args = append(args, "-o", fmt.Sprintf("%s=%v", key, value))
			}
		}
	}

	return args
}

// parseOutput parses crackmapexec/netexec output into structured format
func (t *ToolImpl) parseOutput(stdout, stderr []byte, input map[string]any) (map[string]any, error) {
	output := map[string]any{
		"hosts":         []map[string]any{},
		"users":         []map[string]any{},
		"shares":        []map[string]any{},
		"module_output": map[string]any{},
	}

	// Parse stdout line by line
	scanner := bufio.NewScanner(strings.NewReader(string(stdout)))

	hosts := []map[string]any{}
	users := []map[string]any{}
	shares := []map[string]any{}
	moduleOutput := map[string]any{}

	// Regex patterns for parsing different output types
	hostPattern := regexp.MustCompile(`(?i)SMB\s+(\S+)\s+(\d+)\s+(\S+)\s+\[(.*?)\]\s+\(name:(\S+)\)\s+\(domain:(\S+)\)`)
	userPattern := regexp.MustCompile(`(?i)\[[\+\*]\]\s+(\S+)\\(\S+)\s+(.*)`)
	sharePattern := regexp.MustCompile(`(?i)(\S+)\s+(READ|WRITE|READ,WRITE)`)

	protocol := getString(input, "protocol", "smb")

	for scanner.Scan() {
		line := scanner.Text()

		// Parse host information
		if matches := hostPattern.FindStringSubmatch(line); matches != nil {
			host := map[string]any{
				"ip":       matches[1],
				"hostname": matches[5],
				"domain":   matches[6],
				"os":       matches[4],
				"signing":  strings.Contains(line, "signing:True") || strings.Contains(line, "signing:true"),
				"smbv1":    strings.Contains(line, "SMBv1:True") || strings.Contains(line, "SMBv1:true"),
			}
			hosts = append(hosts, host)
		}

		// Parse user enumeration
		if matches := userPattern.FindStringSubmatch(line); matches != nil {
			user := map[string]any{
				"username": matches[2],
				"domain":   matches[1],
				"admin":    strings.Contains(matches[3], "Pwn3d!") || strings.Contains(matches[3], "(admin)"),
			}
			users = append(users, user)
		}

		// Parse share enumeration
		if strings.Contains(line, "Disk") || strings.Contains(line, "IPC") {
			if matches := sharePattern.FindStringSubmatch(line); matches != nil {
				share := map[string]any{
					"name":        matches[1],
					"permissions": matches[2],
				}
				shares = append(shares, share)
			}
		}

		// Capture module output
		if strings.Contains(line, "[*]") || strings.Contains(line, "[+]") {
			if !hostPattern.MatchString(line) && !userPattern.MatchString(line) {
				// Store additional module output as structured data
				moduleOutput[fmt.Sprintf("line_%d", len(moduleOutput))] = line
			}
		}
	}

	// Alternative parsing for different protocols
	switch protocol {
	case "winrm":
		output = t.parseWinRMOutput(string(stdout))
	case "ldap":
		output = t.parseLDAPOutput(string(stdout))
	case "mssql":
		output = t.parseMSSQLOutput(string(stdout))
	case "ssh":
		output = t.parseSSHOutput(string(stdout))
	default:
		// Use SMB parsing as default
		output["hosts"] = hosts
		output["users"] = users
		output["shares"] = shares
		output["module_output"] = moduleOutput
	}

	return output, nil
}

// parseWinRMOutput parses WinRM protocol output
func (t *ToolImpl) parseWinRMOutput(stdout string) map[string]any {
	hosts := []map[string]any{}
	users := []map[string]any{}

	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()

		// Parse WinRM host info
		winrmPattern := regexp.MustCompile(`(?i)WINRM\s+(\S+)\s+(\d+)\s+(\S+)`)
		if matches := winrmPattern.FindStringSubmatch(line); matches != nil {
			host := map[string]any{
				"ip":       matches[1],
				"hostname": matches[3],
				"domain":   "",
				"os":       "Windows",
				"signing":  false,
				"smbv1":    false,
			}
			hosts = append(hosts, host)
		}

		// Check for successful authentication
		if strings.Contains(line, "Pwn3d!") {
			userPattern := regexp.MustCompile(`(\S+)\\(\S+)`)
			if matches := userPattern.FindStringSubmatch(line); matches != nil {
				user := map[string]any{
					"username": matches[2],
					"domain":   matches[1],
					"admin":    true,
				}
				users = append(users, user)
			}
		}
	}

	return map[string]any{
		"hosts":         hosts,
		"users":         users,
		"shares":        []map[string]any{},
		"module_output": map[string]any{},
	}
}

// parseLDAPOutput parses LDAP protocol output
func (t *ToolImpl) parseLDAPOutput(stdout string) map[string]any {
	hosts := []map[string]any{}
	users := []map[string]any{}

	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()

		// Parse LDAP host info
		ldapPattern := regexp.MustCompile(`(?i)LDAP\s+(\S+)\s+(\d+)\s+(\S+)`)
		if matches := ldapPattern.FindStringSubmatch(line); matches != nil {
			host := map[string]any{
				"ip":       matches[1],
				"hostname": matches[3],
				"domain":   "",
				"os":       "",
				"signing":  false,
				"smbv1":    false,
			}
			hosts = append(hosts, host)
		}
	}

	return map[string]any{
		"hosts":         hosts,
		"users":         users,
		"shares":        []map[string]any{},
		"module_output": map[string]any{},
	}
}

// parseMSSQLOutput parses MSSQL protocol output
func (t *ToolImpl) parseMSSQLOutput(stdout string) map[string]any {
	hosts := []map[string]any{}

	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()

		// Parse MSSQL host info
		mssqlPattern := regexp.MustCompile(`(?i)MSSQL\s+(\S+)\s+(\d+)`)
		if matches := mssqlPattern.FindStringSubmatch(line); matches != nil {
			host := map[string]any{
				"ip":       matches[1],
				"hostname": "",
				"domain":   "",
				"os":       "",
				"signing":  false,
				"smbv1":    false,
			}
			hosts = append(hosts, host)
		}
	}

	return map[string]any{
		"hosts":         hosts,
		"users":         []map[string]any{},
		"shares":        []map[string]any{},
		"module_output": map[string]any{},
	}
}

// parseSSHOutput parses SSH protocol output
func (t *ToolImpl) parseSSHOutput(stdout string) map[string]any {
	hosts := []map[string]any{}
	users := []map[string]any{}

	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()

		// Parse SSH host info
		sshPattern := regexp.MustCompile(`(?i)SSH\s+(\S+)\s+(\d+)`)
		if matches := sshPattern.FindStringSubmatch(line); matches != nil {
			host := map[string]any{
				"ip":       matches[1],
				"hostname": "",
				"domain":   "",
				"os":       "Linux/Unix",
				"signing":  false,
				"smbv1":    false,
			}
			hosts = append(hosts, host)
		}

		// Check for successful authentication
		if strings.Contains(line, "[+]") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				user := map[string]any{
					"username": strings.TrimSpace(parts[0]),
					"domain":   "",
					"admin":    strings.Contains(line, "root"),
				}
				users = append(users, user)
			}
		}
	}

	return map[string]any{
		"hosts":         hosts,
		"users":         users,
		"shares":        []map[string]any{},
		"module_output": map[string]any{},
	}
}

// getTimeout extracts timeout from input or returns default
func (t *ToolImpl) getTimeout(input map[string]any) time.Duration {
	// Default to 5 minutes
	return 5 * time.Minute
}

// Health checks the crackmapexec/netexec binary availability
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	// Try to find any supported binary
	for _, name := range BinaryNames {
		if exec.BinaryExists(name) {
			return types.NewHealthyStatus(fmt.Sprintf("%s is available", name))
		}
	}

	return types.NewUnhealthyStatus(
		"crackmapexec/netexec binary not found in PATH",
		map[string]any{
			"supported_binaries": BinaryNames,
			"note":               "Install crackmapexec or netexec (pip install crackmapexec or pipx install netexec)",
		},
	)
}

// Helper functions for extracting input parameters

func getString(input map[string]any, key string, defaultVal string) string {
	if val, ok := input[key].(string); ok {
		return val
	}
	return defaultVal
}

func getInt(input map[string]any, key string, defaultVal int) int {
	if val, ok := input[key].(int); ok {
		return val
	}
	if val, ok := input[key].(float64); ok {
		return int(val)
	}
	return defaultVal
}

func getBool(input map[string]any, key string, defaultVal bool) bool {
	if val, ok := input[key].(bool); ok {
		return val
	}
	return defaultVal
}

func getStringSlice(input map[string]any, key string) []string {
	if val, ok := input[key].([]any); ok {
		result := make([]string, 0, len(val))
		for _, v := range val {
			if s, ok := v.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return []string{}
}
