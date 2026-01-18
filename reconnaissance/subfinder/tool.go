package main

import (
	"context"
	"fmt"
	"net"
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
	ToolName        = "subfinder"
	ToolVersion     = "1.0.0"
	ToolDescription = "Fast passive subdomain enumeration tool using multiple online sources"
	BinaryName      = "subfinder"
	DNSTimeout      = 2 * time.Second // Timeout per DNS resolution
)

// SubdomainResult represents a discovered subdomain with DNS resolution
type SubdomainResult struct {
	Name    string   `json:"name"`
	IPs     []string `json:"ips"`
	Sources []string `json:"sources"`
}

// ToolImpl implements the subfinder tool
type ToolImpl struct{}

// NewTool creates a new subfinder tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"reconnaissance",
			"subdomain",
			"osint",
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

// Execute runs the subfinder tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	domain := sdkinput.GetString(input, "domain", "")
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	timeout := sdkinput.GetTimeout(input, "timeout", sdkinput.DefaultTimeout())
	silent := sdkinput.GetBool(input, "silent", false)
	recursive := sdkinput.GetBool(input, "recursive", false)
	all := sdkinput.GetBool(input, "all", true)

	// Build subfinder command arguments
	args := buildArgs(domain, silent, recursive, all)

	// Execute subfinder command
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}

	// Parse subfinder output
	output, err := parseOutput(result.Stdout, domain)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).WithCause(err)
	}

	// Add scan time
	output["scan_time_ms"] = int(time.Since(startTime).Milliseconds())

	return output, nil
}

// Health checks if the subfinder binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// buildArgs constructs the command-line arguments for subfinder
func buildArgs(domain string, silent, recursive, all bool) []string {
	args := []string{"-d", domain}

	if silent {
		args = append(args, "-silent")
	}

	if recursive {
		args = append(args, "-recursive")
	}

	if all {
		args = append(args, "-all")
	}

	return args
}

// resolveSubdomains resolves IP addresses for a list of subdomains
func resolveSubdomains(ctx context.Context, subdomainNames []string) []SubdomainResult {
	results := make([]SubdomainResult, 0, len(subdomainNames))

	for _, name := range subdomainNames {
		result := SubdomainResult{
			Name:    name,
			IPs:     []string{},
			Sources: []string{"subfinder"},
		}

		// Create a context with timeout for DNS resolution
		dnsCtx, cancel := context.WithTimeout(ctx, DNSTimeout)

		// Resolve IP addresses
		ips, err := net.DefaultResolver.LookupIP(dnsCtx, "ip4", name)
		cancel()

		if err == nil {
			// Convert IPs to string format (IPv4 only)
			for _, ip := range ips {
				if ipv4 := ip.To4(); ipv4 != nil {
					result.IPs = append(result.IPs, ipv4.String())
				}
			}
		}
		// If resolution fails, continue with empty IPs array

		results = append(results, result)
	}

	return results
}

// parseOutput parses the output from subfinder and enriches with DNS resolution
func parseOutput(data []byte, domain string) (map[string]any, error) {
	lines := strings.Split(string(data), "\n")

	subdomainNames := []string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			subdomainNames = append(subdomainNames, line)
		}
	}

	// Resolve DNS for all subdomains
	subdomains := resolveSubdomains(context.Background(), subdomainNames)

	return map[string]any{
		"domain":     domain,
		"subdomains": subdomains,
		"count":      len(subdomains),
	}, nil
}
