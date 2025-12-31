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
	ToolName        = "amass"
	ToolVersion     = "1.0.0"
	ToolDescription = "Asset discovery tool providing comprehensive DNS enumeration, WHOIS, and ASN data"
	BinaryName      = "amass"
)

// ToolImpl implements the amass tool
type ToolImpl struct{}

// NewTool creates a new amass tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"reconnaissance",
			"dns",
			"osint",
			"T1595",  // Active Scanning
			"T1592",  // Gather Victim Host Information
			"T1589",  // Gather Victim Identity Information
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

// Execute runs the amass tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	domain := sdkinput.GetString(input, "domain", "")
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	mode := sdkinput.GetString(input, "mode", "passive")
	timeout := sdkinput.GetTimeout(input, "timeout", sdkinput.DefaultTimeout())
	maxDepth := sdkinput.GetInt(input, "max_depth", 0)
	includeWhois := sdkinput.GetBool(input, "include_whois", false)
	includeASN := sdkinput.GetBool(input, "include_asn", false)

	// Build amass command arguments
	args := buildAmassArgs(domain, mode, maxDepth, includeWhois, includeASN)

	// Execute amass command
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}

	// Parse amass JSON output
	output, err := parseAmassOutput(result.Stdout, domain)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).WithCause(err)
	}

	// Add scan time
	output["scan_time_ms"] = int(time.Since(startTime).Milliseconds())

	return output, nil
}

// Health checks if the amass binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// buildAmassArgs constructs the command-line arguments for amass
func buildAmassArgs(domain, mode string, maxDepth int, includeWhois, includeASN bool) []string {
	args := []string{"enum", "-json", "-d", domain}

	// Set enumeration mode
	if mode == "passive" {
		args = append(args, "-passive")
	} else if mode == "active" {
		args = append(args, "-active")
	}

	// Set max DNS recursion depth
	if maxDepth > 0 {
		args = append(args, "-max-depth", fmt.Sprintf("%d", maxDepth))
	}

	// Include WHOIS information
	if includeWhois {
		args = append(args, "-whois")
	}

	// ASN is included by default in amass output when available
	// No specific flag needed for basic ASN info

	return args
}

// AmassOutput represents a single JSON line from amass output
type AmassOutput struct {
	Name      string   `json:"name"`
	Domain    string   `json:"domain"`
	Addresses []string `json:"addresses"`
	Tag       string   `json:"tag"`
	Sources   []string `json:"sources"`
	Type      string   `json:"type"`
	ASN       *int     `json:"asn,omitempty"`
	Desc      string   `json:"desc,omitempty"`
	Country   string   `json:"country,omitempty"`
}

// parseAmassOutput parses the JSON output from amass
func parseAmassOutput(data []byte, domain string) (map[string]any, error) {
	lines := strings.Split(string(data), "\n")

	subdomainsMap := make(map[string]bool)
	ipAddressesMap := make(map[string]bool)
	asnInfoMap := make(map[int]map[string]any)
	dnsRecords := []map[string]any{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var entry AmassOutput
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			// Skip invalid JSON lines
			continue
		}

		// Collect subdomains
		if entry.Name != "" {
			subdomainsMap[entry.Name] = true
		}

		// Collect IP addresses
		for _, addr := range entry.Addresses {
			ipAddressesMap[addr] = true
		}

		// Collect ASN information
		if entry.ASN != nil && *entry.ASN > 0 {
			if _, exists := asnInfoMap[*entry.ASN]; !exists {
				asnInfoMap[*entry.ASN] = map[string]any{
					"asn":         *entry.ASN,
					"description": entry.Desc,
					"country":     entry.Country,
				}
			}
		}

		// Create DNS record entry
		if entry.Name != "" && len(entry.Addresses) > 0 {
			for _, addr := range entry.Addresses {
				dnsRecords = append(dnsRecords, map[string]any{
					"name":  entry.Name,
					"type":  "A", // Amass primarily returns A records
					"value": addr,
				})
			}
		}
	}

	// Convert maps to slices
	subdomains := make([]string, 0, len(subdomainsMap))
	for subdomain := range subdomainsMap {
		subdomains = append(subdomains, subdomain)
	}

	ipAddresses := make([]string, 0, len(ipAddressesMap))
	for ip := range ipAddressesMap {
		ipAddresses = append(ipAddresses, ip)
	}

	asnInfo := make([]map[string]any, 0, len(asnInfoMap))
	for _, asn := range asnInfoMap {
		asnInfo = append(asnInfo, asn)
	}

	return map[string]any{
		"domain":       domain,
		"subdomains":   subdomains,
		"ip_addresses": ipAddresses,
		"asn_info":     asnInfo,
		"dns_records":  dnsRecords,
		"whois":        map[string]any{}, // WHOIS data would require additional parsing
	}, nil
}
