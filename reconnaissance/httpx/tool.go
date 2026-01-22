package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
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
		})

	t, _ := tool.New(cfg)
	return &protoTool{Tool: t, impl: &ToolImpl{}}
}

// protoTool wraps the base tool to add proto execution and custom health checks
type protoTool struct {
	tool.Tool
	impl *ToolImpl
}

func (t *protoTool) InputMessageType() string {
	return "tools.v1.HttpxRequest"
}

func (t *protoTool) OutputMessageType() string {
	return "tools.v1.HttpxResponse"
}

func (t *protoTool) ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error) {
	req, ok := input.(*toolspb.HttpxRequest)
	if !ok {
		return nil, fmt.Errorf("expected *toolspb.HttpxRequest, got %T", input)
	}

	return t.impl.ExecuteProto(ctx, req)
}

func (t *protoTool) Health(ctx context.Context) types.HealthStatus {
	return t.impl.Health(ctx)
}

// ExecuteProto runs the httpx tool with the provided proto input
func (t *ToolImpl) ExecuteProto(ctx context.Context, req *toolspb.HttpxRequest) (*toolspb.HttpxResponse, error) {
	startTime := time.Now()

	// Validate input
	if len(req.Targets) == 0 {
		return nil, fmt.Errorf("targets is required")
	}

	// Extract timeout (convert seconds to duration, default to 5 minutes)
	timeout := time.Duration(300) * time.Second
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	// Build httpx command arguments
	// Note: The proto has more options than the current implementation uses
	// We'll use the basic ones that match the current behavior
	args := []string{
		"-json",
		"-include-response-header", // Include response headers in output
		"-include-chain",           // Include redirect chain
		"-tls-grab",                // Extract TLS certificate information
		"-status-code",             // Display status code
		"-title",                   // Display page title
	}

	// Follow redirects (default true if not specified)
	if req.FollowRedirects {
		args = append(args, "-follow-redirects")
	} else {
		args = append(args, "-no-follow-redirects")
	}

	// Tech detect
	if req.TechDetect {
		args = append(args, "-tech-detect")
	}

	// Execute httpx command with stdin input
	result, err := exec.Run(ctx, exec.Config{
		Command:   BinaryName,
		Args:      args,
		StdinData: []byte(strings.Join(req.Targets, "\n")),
		Timeout:   timeout,
	})

	if err != nil {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}

	// Parse httpx JSON output and convert to proto response
	response, err := parseOutputToProto(result.Stdout)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).WithCause(err)
	}

	// Add scan duration
	response.Duration = time.Since(startTime).Seconds()

	return response, nil
}

// Health checks if the httpx binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// RedirectHop represents a single hop in a redirect chain
type RedirectHop struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
}

// TLSInfo represents TLS certificate information from httpx
type TLSInfo struct {
	Host       string   `json:"host"`
	IssuerCN   string   `json:"issuer_cn"`
	IssuerOrg  []string `json:"issuer_org"`
	SubjectCN  string   `json:"subject_cn"`
	SubjectOrg []string `json:"subject_org"`
	NotBefore  string   `json:"not_before"`
	NotAfter   string   `json:"not_after"`
	SubjectAN  []string `json:"subject_an"`
}

// HttpxOutput represents a single JSON line from httpx output
type HttpxOutput struct {
	URL          string            `json:"url"`
	FinalURL     string            `json:"final_url,omitempty"`
	StatusCode   int               `json:"status_code"`
	Title        string            `json:"title"`
	ContentType  string            `json:"content_type"`
	Technologies []string          `json:"tech,omitempty"`
	Header       map[string]string `json:"header,omitempty"`
	Chain        []map[string]any  `json:"chain,omitempty"`
	TLS          *TLSInfo          `json:"tls,omitempty"`
}

// parseOutputToProto parses the JSON output from httpx and converts it to proto response
func parseOutputToProto(data []byte) (*toolspb.HttpxResponse, error) {
	lines := strings.Split(string(data), "\n")

	results := []*toolspb.HttpxResult{}
	totalScanned := 0
	totalSuccess := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var entry HttpxOutput
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		totalScanned++

		// Parse URL to extract host, port, and scheme
		parsedURL, err := url.Parse(entry.URL)
		host := ""
		port := int32(0)
		scheme := ""
		if err == nil {
			scheme = parsedURL.Scheme
			host = parsedURL.Hostname()

			// Extract port (use default if not specified)
			portStr := parsedURL.Port()
			if portStr != "" {
				var p int
				fmt.Sscanf(portStr, "%d", &p)
				port = int32(p)
			} else {
				// Default ports
				if scheme == "https" {
					port = 443
				} else if scheme == "http" {
					port = 80
				}
			}
		}

		// Convert technologies to proto format
		var technologies []*toolspb.Technology
		for _, tech := range entry.Technologies {
			technologies = append(technologies, &toolspb.Technology{
				Name: tech,
			})
		}

		// Build proto result
		result := &toolspb.HttpxResult{
			Url:          entry.URL,
			StatusCode:   int32(entry.StatusCode),
			Title:        entry.Title,
			ContentType:  entry.ContentType,
			Technologies: technologies,
			Headers:      entry.Header,
			Host:         host,
			Port:         port,
			Scheme:       scheme,
		}

		// Extract server header
		if entry.Header != nil {
			if server, ok := entry.Header["server"]; ok {
				result.Server = server
			}
		}

		// Parse and add TLS certificate information
		if entry.TLS != nil {
			result.Tls = &toolspb.TLSInfo{
				SubjectDn: entry.TLS.SubjectCN,
				IssuerDn:  entry.TLS.IssuerCN,
				NotBefore: entry.TLS.NotBefore,
				NotAfter:  entry.TLS.NotAfter,
				Sans:      entry.TLS.SubjectAN,
			}
		}

		results = append(results, result)

		if entry.StatusCode >= 200 && entry.StatusCode < 500 {
			totalSuccess++
		}
	}

	return &toolspb.HttpxResponse{
		Results:      results,
		TotalScanned: int32(totalScanned),
		TotalSuccess: int32(totalSuccess),
		TotalFailed:  int32(totalScanned - totalSuccess),
	}, nil
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

		// Extract specific headers
		server := ""
		xPoweredBy := ""
		if entry.Header != nil {
			server = entry.Header["server"]
			xPoweredBy = entry.Header["x-powered-by"]
		}

		// Parse redirect chain
		redirectChain := []RedirectHop{}
		for _, hop := range entry.Chain {
			hopURL, _ := hop["request"].(string)
			hopStatus := 0
			if statusCode, ok := hop["status_code"].(float64); ok {
				hopStatus = int(statusCode)
			}
			if hopURL != "" {
				redirectChain = append(redirectChain, RedirectHop{
					URL:        hopURL,
					StatusCode: hopStatus,
				})
			}
		}

		// Determine final URL (use FinalURL if present, otherwise URL)
		finalURL := entry.URL
		if entry.FinalURL != "" {
			finalURL = entry.FinalURL
		}

		// Parse URL to extract host, port, and scheme for cross-tool relationships
		parsedURL, err := url.Parse(entry.URL)
		host := ""
		port := 0
		scheme := ""
		if err == nil {
			scheme = parsedURL.Scheme
			host = parsedURL.Hostname()

			// Extract port (use default if not specified)
			portStr := parsedURL.Port()
			if portStr != "" {
				fmt.Sscanf(portStr, "%d", &port)
			} else {
				// Default ports
				if scheme == "https" {
					port = 443
				} else if scheme == "http" {
					port = 80
				}
			}
		}

		result := map[string]any{
			"url":              entry.URL,
			"status_code":      entry.StatusCode,
			"title":            entry.Title,
			"content_type":     entry.ContentType,
			"technologies":     entry.Technologies,
			"server":           server,
			"x_powered_by":     xPoweredBy,
			"response_headers": entry.Header,
			"final_url":        finalURL,
			"host":             host,
			"port":             port,
			"scheme":           scheme,
		}

		// Only add redirect_chain if it exists
		if len(redirectChain) > 0 {
			result["redirect_chain"] = redirectChain
		}

		// Parse and add TLS certificate information (HTTPS only)
		if entry.TLS != nil {
			// Build cert_issuer from CN and Org
			certIssuer := entry.TLS.IssuerCN
			if len(entry.TLS.IssuerOrg) > 0 {
				certIssuer = strings.Join(entry.TLS.IssuerOrg, ", ")
				if entry.TLS.IssuerCN != "" {
					certIssuer = entry.TLS.IssuerCN + " (" + certIssuer + ")"
				}
			}

			// Build cert_subject from CN and Org
			certSubject := entry.TLS.SubjectCN
			if len(entry.TLS.SubjectOrg) > 0 {
				certSubject = strings.Join(entry.TLS.SubjectOrg, ", ")
				if entry.TLS.SubjectCN != "" {
					certSubject = entry.TLS.SubjectCN + " (" + certSubject + ")"
				}
			}

			// Add flat cert fields to endpoint for backward compatibility
			if certIssuer != "" {
				result["cert_issuer"] = certIssuer
			}
			if certSubject != "" {
				result["cert_subject"] = certSubject
			}
			if entry.TLS.NotAfter != "" {
				result["cert_expiry"] = entry.TLS.NotAfter
			}
			if len(entry.TLS.SubjectAN) > 0 {
				result["cert_sans"] = entry.TLS.SubjectAN
			}

			// Create nested certificate object for GraphRAG
			// Only create if we have at least a subject (required for ID)
			if certSubject != "" {
				certificate := map[string]any{
					"subject": certSubject,
				}
				if certIssuer != "" {
					certificate["issuer"] = certIssuer
				}
				if entry.TLS.NotAfter != "" {
					certificate["expiry"] = entry.TLS.NotAfter
				}
				if len(entry.TLS.SubjectAN) > 0 {
					certificate["sans"] = entry.TLS.SubjectAN
				}
				result["certificate"] = certificate
			}
		}

		results = append(results, result)

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
