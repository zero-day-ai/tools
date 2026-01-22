package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/zero-day-ai/sdk/api/gen/toolspb"
	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/health"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
	"google.golang.org/protobuf/proto"
)

const (
	ToolName        = "testssl"
	ToolVersion     = "1.0.0"
	ToolDescription = "SSL/TLS security testing tool for analyzing protocols, ciphers, vulnerabilities, and certificate information"
	BinaryName      = "testssl.sh"
)

// ToolImpl implements the testssl tool
type ToolImpl struct{}

// NewTool creates a new testssl tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"fingerprinting",
			"ssl-tls",
			"security-testing",
			"vulnerability-detection",
			"T1595", // Active Scanning
			"T1071", // Application Layer Protocol
		})

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

// InputMessageType returns the fully-qualified proto message type name for input
func (t *toolWithHealth) InputMessageType() string {
	return "gibson.tools.TestsslRequest"
}

// OutputMessageType returns the fully-qualified proto message type name for output
func (t *toolWithHealth) OutputMessageType() string {
	return "gibson.tools.TestsslResponse"
}

// ExecuteProto runs the testssl tool with proto message input/output
func (t *toolWithHealth) ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error) {
	return t.impl.ExecuteProto(ctx, input)
}

// ExecuteProto runs the testssl tool with the provided proto input
func (t *ToolImpl) ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error) {
	startTime := time.Now()

	// Type assert to TestsslRequest
	req, ok := input.(*toolspb.TestsslRequest)
	if !ok {
		return nil, fmt.Errorf("expected *toolspb.TestsslRequest, got %T", input)
	}

	// Validate required fields
	if len(req.Targets) == 0 {
		return nil, fmt.Errorf("targets is required")
	}

	// Set default timeout if not specified
	timeout := 5 * time.Minute
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	// Set default severity
	severity := "LOW"

	// Process each target
	results := []*toolspb.TestsslResult{}
	for _, target := range req.Targets {
		// Build testssl command arguments
		args := []string{
			"--jsonfile=-", // Output JSON to stdout
			"--quiet",
			"--fast", // Faster scan mode
			"--severity", severity,
			target,
		}

		// Execute testssl command
		result, err := exec.Run(ctx, exec.Config{
			Command: BinaryName,
			Args:    args,
			Timeout: timeout,
		})

		if err != nil {
			// Continue with other targets if one fails
			// Create error result
			results = append(results, &toolspb.TestsslResult{
				Target: target,
				Error:  err.Error(),
			})
			continue
		}

		// Parse testssl JSON output
		targetResult, err := parseOutputProto(target, result.Stdout)
		if err != nil {
			// Create error result
			results = append(results, &toolspb.TestsslResult{
				Target: target,
				Error:  err.Error(),
			})
			continue
		}

		results = append(results, targetResult)
	}

	return &toolspb.TestsslResponse{
		Results:      results,
		TotalTargets: int32(len(results)),
		Duration:     time.Since(startTime).Seconds(),
	}, nil
}

// Health checks if the testssl.sh binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// TestSSLEntry represents a single JSON entry from testssl output
type TestSSLEntry struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Finding     string `json:"finding"`
	CVE         string `json:"cve,omitempty"`
	Description string `json:"description,omitempty"`
	IP          string `json:"ip,omitempty"`
}

// parseOutputProto parses the JSON output from testssl into proto format
func parseOutputProto(target string, data []byte) (*toolspb.TestsslResult, error) {
	lines := strings.Split(string(data), "\n")

	protocols := []*toolspb.ProtocolResult{}
	ciphers := []*toolspb.CipherResult{}
	vulnerabilities := []*toolspb.VulnerabilityResult{}
	certificate := &toolspb.CertificateInfo{}
	ip := ""
	port := int32(443) // Default HTTPS port

	// Extract port from target if present
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		if len(parts) == 2 {
			var p int
			fmt.Sscanf(parts[1], "%d", &p)
			port = int32(p)
		}
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var entry TestSSLEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		// Extract IP if available
		if entry.IP != "" {
			ip = entry.IP
		}

		// Categorize findings
		switch {
		case strings.Contains(entry.ID, "protocol_"):
			protocols = append(protocols, &toolspb.ProtocolResult{
				Protocol:  entry.Finding,
				Supported: true,
				Severity:  entry.Severity,
				Finding:   entry.Finding,
			})
		case strings.Contains(entry.ID, "cipher_"):
			ciphers = append(ciphers, &toolspb.CipherResult{
				Cipher:   entry.Finding,
				Severity: entry.Severity,
			})
		case strings.Contains(entry.ID, "cert_"):
			// Parse certificate info
			parseCertificateProto(entry, certificate)
		case entry.CVE != "" || strings.Contains(entry.ID, "vuln_"):
			cves := []string{}
			if entry.CVE != "" {
				cves = append(cves, entry.CVE)
			}
			vulnerabilities = append(vulnerabilities, &toolspb.VulnerabilityResult{
				Id:         entry.ID,
				Name:       entry.Finding,
				Vulnerable: true,
				Severity:   entry.Severity,
				Finding:    entry.Finding,
				Cve:        cves,
			})
		}
	}

	return &toolspb.TestsslResult{
		Target:          target,
		Ip:              ip,
		Port:            port,
		Protocols:       protocols,
		Ciphers:         ciphers,
		Certificate:     certificate,
		Vulnerabilities: vulnerabilities,
	}, nil
}

// parseOutput parses the JSON output from testssl (deprecated - kept for reference)
func parseOutput(target string, data []byte) (map[string]any, error) {
	lines := strings.Split(string(data), "\n")

	protocols := []map[string]any{}
	ciphers := []map[string]any{}
	vulnerabilities := []map[string]any{}
	var certificate map[string]any
	ip := ""
	port := 443 // Default HTTPS port

	// Extract port from target if present
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		if len(parts) == 2 {
			fmt.Sscanf(parts[1], "%d", &port)
		}
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var entry TestSSLEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		// Extract IP if available
		if entry.IP != "" {
			ip = entry.IP
		}

		// Categorize findings
		switch {
		case strings.Contains(entry.ID, "protocol_"):
			protocols = append(protocols, map[string]any{
				"name":     entry.Finding,
				"severity": entry.Severity,
				"finding":  entry.Finding,
			})
		case strings.Contains(entry.ID, "cipher_"):
			ciphers = append(ciphers, map[string]any{
				"name":     entry.Finding,
				"severity": entry.Severity,
				"finding":  entry.Finding,
			})
		case strings.Contains(entry.ID, "cert_"):
			// Parse certificate info
			if certificate == nil {
				certificate = parseCertificate(entry)
			}
		case entry.CVE != "" || strings.Contains(entry.ID, "vuln_"):
			vulnerabilities = append(vulnerabilities, map[string]any{
				"id":          entry.ID,
				"severity":    entry.Severity,
				"finding":     entry.Finding,
				"cve":         entry.CVE,
				"description": entry.Description,
			})
		}
	}

	// Ensure certificate exists even if empty
	if certificate == nil {
		certificate = map[string]any{
			"subject":    "",
			"issuer":     "",
			"not_before": "",
			"not_after":  "",
			"sans":       []string{},
			"expired":    false,
		}
	}

	return map[string]any{
		"target":          target,
		"ip":              ip,
		"port":            port,
		"protocols":       protocols,
		"ciphers":         ciphers,
		"certificate":     certificate,
		"vulnerabilities": vulnerabilities,
	}, nil
}

// parseCertificateProto extracts certificate information from testssl entry into proto format
func parseCertificateProto(entry TestSSLEntry, cert *toolspb.CertificateInfo) {
	// Parse finding for certificate details
	if strings.Contains(entry.ID, "cert_subject") {
		cert.SubjectDn = entry.Finding
	} else if strings.Contains(entry.ID, "cert_issuer") {
		cert.IssuerDn = entry.Finding
	} else if strings.Contains(entry.ID, "cert_notBefore") {
		cert.NotBefore = entry.Finding
	} else if strings.Contains(entry.ID, "cert_notAfter") {
		cert.NotAfter = entry.Finding
	} else if strings.Contains(entry.ID, "cert_expirationStatus") {
		cert.Expired = strings.Contains(strings.ToLower(entry.Finding), "expired")
	}
}

// parseCertificate extracts certificate information from testssl entry (deprecated - kept for reference)
func parseCertificate(entry TestSSLEntry) map[string]any {
	cert := map[string]any{
		"subject":    "",
		"issuer":     "",
		"not_before": "",
		"not_after":  "",
		"sans":       []string{},
		"expired":    false,
	}

	// Parse finding for certificate details
	if strings.Contains(entry.ID, "cert_subject") {
		cert["subject"] = entry.Finding
	} else if strings.Contains(entry.ID, "cert_issuer") {
		cert["issuer"] = entry.Finding
	} else if strings.Contains(entry.ID, "cert_notBefore") {
		cert["not_before"] = entry.Finding
	} else if strings.Contains(entry.ID, "cert_notAfter") {
		cert["not_after"] = entry.Finding
	} else if strings.Contains(entry.ID, "cert_expirationStatus") {
		cert["expired"] = strings.Contains(strings.ToLower(entry.Finding), "expired")
	}

	return cert
}
