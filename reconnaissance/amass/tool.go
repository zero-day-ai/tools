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
	Name      string            `json:"name"`
	Domain    string            `json:"domain"`
	Addresses []AddressWithASN  `json:"addresses"`
	Tag       string            `json:"tag"`
	Sources   []string          `json:"sources"`
	Type      string            `json:"type"`
}

// AddressWithASN represents an IP address with ASN information from amass
type AddressWithASN struct {
	IP   string `json:"ip"`
	ASN  int    `json:"asn,omitempty"`
	Desc string `json:"desc,omitempty"`
}

// ASNResult represents aggregated ASN information
type ASNResult struct {
	Number      int      `json:"number"`
	Description string   `json:"description"`
	Country     string   `json:"country"`
	IPs         []string `json:"ips"`
}

// DNSRecordResult represents a parsed DNS record with all relevant fields
type DNSRecordResult struct {
	Type     string `json:"type"`     // A, MX, NS, TXT, SOA, CNAME, PTR, etc.
	Name     string `json:"name"`     // Domain name
	Value    string `json:"value"`    // Record value
	Priority int    `json:"priority"` // For MX records (0 for other types)
	TTL      int    `json:"ttl"`      // Time to live (0 if not available)
}

// determineDNSRecordType determines the DNS record type based on tag, type, and sources
func determineDNSRecordType(tag, recordType string, sources []string) string {
	// Check explicit type field first
	recordType = strings.ToUpper(recordType)
	switch recordType {
	case "A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR", "SRV":
		return recordType
	}

	// Check sources for hints about record type first
	// This takes priority over generic tags like "dns"
	for _, source := range sources {
		sourceUpper := strings.ToUpper(source)
		// Use word boundaries or specific patterns to avoid false matches
		// e.g., "DNS" should not match "NS"
		if strings.Contains(sourceUpper, "MX ") || strings.HasPrefix(sourceUpper, "MX") {
			return "MX"
		}
		// Check for NS but not as part of DNS
		if (strings.Contains(sourceUpper, "NS ") || strings.HasPrefix(sourceUpper, "NS")) && !strings.Contains(sourceUpper, "DNS") {
			return "NS"
		}
		if strings.Contains(sourceUpper, "TXT ") || strings.HasPrefix(sourceUpper, "TXT") {
			return "TXT"
		}
		if strings.Contains(sourceUpper, "SOA ") || strings.HasPrefix(sourceUpper, "SOA") {
			return "SOA"
		}
	}

	// Check tag field
	tag = strings.ToUpper(tag)
	switch tag {
	case "MX":
		return "MX"
	case "NS":
		return "NS"
	case "TXT":
		return "TXT"
	case "SOA":
		return "SOA"
	case "CNAME":
		return "CNAME"
	case "PTR":
		return "PTR"
	case "SRV":
		return "SRV"
	}

	// Default to A record if we can't determine
	return "A"
}

// extractDNSRecordValue extracts the DNS record value from the amass output
func extractDNSRecordValue(entry AmassOutput, recordType string) string {
	// For most record types, the value is in the name field or addresses
	switch recordType {
	case "MX", "NS", "CNAME", "PTR":
		// For these record types, amass typically puts the target in the name field
		// or it might be in a separate field depending on amass version
		if entry.Name != "" {
			return entry.Name
		}
	case "TXT":
		// TXT records might be in the type field or need special parsing
		if entry.Type != "" && entry.Type != "txt" && entry.Type != "TXT" {
			return entry.Type
		}
		// Amass might put TXT record content in the name or require special handling
		return entry.Name
	case "SOA":
		// SOA records are complex and might need special parsing
		// For now, return the name field which might contain SOA data
		return entry.Name
	case "A", "AAAA":
		// For A/AAAA records, addresses contain the IP
		if len(entry.Addresses) > 0 {
			return entry.Addresses[0].IP
		}
	}

	return ""
}

// extractMXPriority attempts to extract the priority value from an MX record value
func extractMXPriority(value string) int {
	// MX record format is typically "priority hostname"
	parts := strings.Fields(value)
	if len(parts) >= 2 {
		var priority int
		_, err := fmt.Sscanf(parts[0], "%d", &priority)
		if err == nil {
			return priority
		}
	}
	return 0
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

		// Collect IP addresses and process DNS records
		for _, addrInfo := range entry.Addresses {
			ipAddressesMap[addrInfo.IP] = true

			// Collect ASN information with associated IPs
			if addrInfo.ASN > 0 {
				if existing, exists := asnInfoMap[addrInfo.ASN]; exists {
					// Add IP to existing ASN entry
					ips := existing["ips"].([]string)
					// Check if IP already exists
					ipExists := false
					for _, ip := range ips {
						if ip == addrInfo.IP {
							ipExists = true
							break
						}
					}
					if !ipExists && addrInfo.IP != "" {
						ips = append(ips, addrInfo.IP)
						existing["ips"] = ips
					}
				} else {
					// Create new ASN entry with IPs array
					ips := []string{}
					if addrInfo.IP != "" {
						ips = append(ips, addrInfo.IP)
					}
					asnInfoMap[addrInfo.ASN] = map[string]any{
						"number":      addrInfo.ASN,
						"description": addrInfo.Desc,
						"country":     "", // Not available in this structure
						"ips":         ips,
					}
				}
			}

			// Create A record for IP addresses
			if entry.Name != "" && addrInfo.IP != "" {
				dnsRecords = append(dnsRecords, map[string]any{
					"name":     entry.Name,
					"type":     "A",
					"value":    addrInfo.IP,
					"priority": 0,
					"ttl":      0,
				})
			}
		}

		// Parse DNS record based on tag and type
		recordType := determineDNSRecordType(entry.Tag, entry.Type, entry.Sources)
		if recordType != "" && recordType != "A" && entry.Name != "" {
			// For non-A records, the value might be in different fields
			value := extractDNSRecordValue(entry, recordType)
			if value != "" {
				record := map[string]any{
					"name":     entry.Name,
					"type":     recordType,
					"value":    value,
					"priority": 0,
					"ttl":      0,
				}

				// For MX records, extract priority if available
				if recordType == "MX" {
					priority := extractMXPriority(value)
					if priority > 0 {
						record["priority"] = priority
						// Remove priority from value if it was prepended
						record["value"] = strings.TrimPrefix(value, fmt.Sprintf("%d ", priority))
					}
				}

				dnsRecords = append(dnsRecords, record)
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
