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
	"github.com/zero-day-ai/sdk/toolerr"
	"github.com/zero-day-ai/sdk/types"
	"google.golang.org/protobuf/proto"
)

const (
	ToolName        = "sslyze"
	ToolVersion     = "1.0.0"
	ToolDescription = "Fast and powerful SSL/TLS scanning library for analyzing security configurations"
	BinaryName      = "sslyze"
)

// ToolImpl implements the sslyze tool
type ToolImpl struct{}

// NewTool creates a new sslyze tool instance
func NewTool() tool.Tool {
	return &ToolImpl{}
}

// Name returns the tool name
func (t *ToolImpl) Name() string {
	return ToolName
}

// Version returns the tool version
func (t *ToolImpl) Version() string {
	return ToolVersion
}

// Description returns the tool description
func (t *ToolImpl) Description() string {
	return ToolDescription
}

// Tags returns the tool tags
func (t *ToolImpl) Tags() []string {
	return []string{
		"fingerprinting",
		"ssl-tls",
		"security-testing",
		"vulnerability-detection",
		"T1595", // Active Scanning
		"T1071", // Application Layer Protocol
	}
}

// InputMessageType returns the fully qualified proto message type for input
func (t *ToolImpl) InputMessageType() string {
	return "gibson.tools.SslyzeRequest"
}

// OutputMessageType returns the fully qualified proto message type for output
func (t *ToolImpl) OutputMessageType() string {
	return "gibson.tools.SslyzeResponse"
}

// ExecuteProto runs the sslyze tool with the provided proto input
func (t *ToolImpl) ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error) {
	startTime := time.Now()

	// Type assert input to SslyzeRequest
	req, ok := input.(*toolspb.SslyzeRequest)
	if !ok {
		return nil, fmt.Errorf("expected *toolspb.SslyzeRequest, got %T", input)
	}

	// Validate input
	if len(req.Targets) == 0 {
		return nil, fmt.Errorf("targets is required")
	}

	// Determine timeout
	timeout := 5 * time.Minute
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	// Build sslyze command arguments
	args := []string{
		"--json_out=-", // Output JSON to stdout
		"--quiet",
	}

	// Add all targets
	args = append(args, req.Targets...)

	// Execute sslyze command
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}

	// Parse sslyze JSON output
	response, err := parseOutputProto(result.Stdout)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).WithCause(err)
	}

	// Add scan duration
	response.Duration = time.Since(startTime).Seconds()

	return response, nil
}

// Health checks if the sslyze binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// SSLyzeServerLocation represents the server connection info
type SSLyzeServerLocation struct {
	Hostname  string `json:"hostname"`
	IPAddress string `json:"ip_address"`
	Port      int    `json:"port"`
}

// SSLyzeCertificate represents certificate info
type SSLyzeCertificate struct {
	Subject    map[string]string `json:"subject"`
	Issuer     map[string]string `json:"issuer"`
	NotBefore  string            `json:"notBefore"`
	NotAfter   string            `json:"notAfter"`
	SubjectAlt []string          `json:"subjectAltName,omitempty"`
}

// SSLyzeScanResult represents scan results for a single server
type SSLyzeScanResult struct {
	ServerLocation SSLyzeServerLocation `json:"server_location"`
	ScanCommands   map[string]any       `json:"scan_commands"`
}

// SSLyzeOutput represents the complete JSON output from sslyze
type SSLyzeOutput struct {
	ServerScanResults []SSLyzeScanResult `json:"server_scan_results"`
}

// parseOutputProto parses the JSON output from sslyze and returns proto response
func parseOutputProto(data []byte) (*toolspb.SslyzeResponse, error) {
	var output SSLyzeOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("failed to parse sslyze output: %w", err)
	}

	results := []*toolspb.SslyzeResult{}

	for _, scanResult := range output.ServerScanResults {
		target := fmt.Sprintf("%s:%d", scanResult.ServerLocation.Hostname, scanResult.ServerLocation.Port)

		result := &toolspb.SslyzeResult{
			Target:       target,
			Ip:           scanResult.ServerLocation.IPAddress,
			Port:         int32(scanResult.ServerLocation.Port),
			CipherSuites: make(map[string]*toolspb.CipherSuiteList),
		}

		// Parse scan commands for protocol and cipher info
		for cmdName, cmdResult := range scanResult.ScanCommands {
			cmdData, ok := cmdResult.(map[string]any)
			if !ok {
				continue
			}

			switch {
			case strings.Contains(cmdName, "ssl_") || strings.Contains(cmdName, "tls_"):
				// Protocol check and cipher suites
				if accepted, ok := cmdData["accepted_cipher_suites"].([]any); ok && len(accepted) > 0 {
					protocolName := strings.ToUpper(strings.Replace(cmdName, "_", " ", -1))
					cipherList := &toolspb.CipherSuiteList{
						Protocol:        protocolName,
						AcceptedCiphers: []*toolspb.CipherSuite{},
					}

					// Extract cipher suites
					for _, cipher := range accepted {
						if cipherMap, ok := cipher.(map[string]any); ok {
							if cipherSuite, ok := cipherMap["cipher_suite"].(map[string]any); ok {
								cs := &toolspb.CipherSuite{}
								if name, ok := cipherSuite["name"].(string); ok {
									cs.Name = name
								}
								if keyExchange, ok := cipherSuite["key_exchange"].(string); ok {
									cs.KeyExchange = keyExchange
								}
								if auth, ok := cipherSuite["authentication"].(string); ok {
									cs.Authentication = auth
								}
								if enc, ok := cipherSuite["encryption"].(string); ok {
									cs.Encryption = enc
								}
								cipherList.AcceptedCiphers = append(cipherList.AcceptedCiphers, cs)
							}
						}
					}
					result.CipherSuites[protocolName] = cipherList
				}
			case cmdName == "certificate_info":
				// Parse certificate information
				if certDeployments, ok := cmdData["certificate_deployments"].([]any); ok && len(certDeployments) > 0 {
					if firstDeploy, ok := certDeployments[0].(map[string]any); ok {
						if receivedCertChain, ok := firstDeploy["received_certificate_chain"].([]any); ok && len(receivedCertChain) > 0 {
							if cert, ok := receivedCertChain[0].(map[string]any); ok {
								result.Certificate = parseCertificateInfoProto(cert)
							}
						}
					}
				}
			case strings.Contains(cmdName, "heartbleed"):
				// Heartbleed vulnerability check
				if vulnerable, ok := cmdData["is_vulnerable_to_heartbleed"].(bool); ok {
					result.Heartbleed = &toolspb.VulnerabilityScanResult{
						Vulnerable: vulnerable,
						Details:    fmt.Sprintf("Heartbleed vulnerability: %v", vulnerable),
					}
				}
			case strings.Contains(cmdName, "robot"):
				// ROBOT vulnerability check
				if vulnerable, ok := cmdData["is_vulnerable_to_robot"].(bool); ok {
					result.Robot = &toolspb.VulnerabilityScanResult{
						Vulnerable: vulnerable,
						Details:    fmt.Sprintf("ROBOT vulnerability: %v", vulnerable),
					}
				}
			case strings.Contains(cmdName, "compression"):
				// TLS compression check
				if supported, ok := cmdData["compression_supported"].(bool); ok {
					result.Compression = &toolspb.CompressionScanResult{
						Supported: supported,
					}
				}
			}
		}

		// Ensure certificate exists even if empty
		if result.Certificate == nil {
			result.Certificate = &toolspb.SslyzeCertificateInfo{}
		}

		results = append(results, result)
	}

	return &toolspb.SslyzeResponse{
		Results:      results,
		TotalTargets: int32(len(results)),
	}, nil
}

// parseCertificateInfoProto extracts certificate details into proto message
func parseCertificateInfoProto(cert map[string]any) *toolspb.SslyzeCertificateInfo {
	certificate := &toolspb.SslyzeCertificateInfo{
		Sans: []string{},
	}

	// Extract subject
	if subject, ok := cert["subject"].(map[string]any); ok {
		if cn, ok := subject["commonName"].(string); ok {
			certificate.SubjectDn = cn
		}
	}

	// Extract issuer
	if issuer, ok := cert["issuer"].(map[string]any); ok {
		if cn, ok := issuer["commonName"].(string); ok {
			certificate.IssuerDn = cn
		}
	}

	// Extract validity dates
	if notBefore, ok := cert["notBefore"].(string); ok {
		certificate.NotBefore = notBefore
	}
	if notAfter, ok := cert["notAfter"].(string); ok {
		certificate.NotAfter = notAfter

		// Check if expired
		notAfterTime, err := time.Parse(time.RFC3339, notAfter)
		if err == nil {
			certificate.Expired = time.Now().After(notAfterTime)
		}
	}

	// Extract SANs
	if sans, ok := cert["subjectAltName"].([]any); ok {
		for _, san := range sans {
			if sanStr, ok := san.(string); ok {
				certificate.Sans = append(certificate.Sans, sanStr)
			}
		}
	}

	// Extract additional certificate fields
	if serialNumber, ok := cert["serialNumber"].(string); ok {
		certificate.SerialNumber = serialNumber
	}
	if sigAlg, ok := cert["signatureAlgorithm"].(string); ok {
		certificate.SignatureAlgorithm = sigAlg
	}
	if pubKeyAlg, ok := cert["publicKeyAlgorithm"].(string); ok {
		certificate.PublicKeyAlgorithm = pubKeyAlg
	}
	if pubKeySize, ok := cert["publicKeySize"].(float64); ok {
		certificate.PublicKeySize = int32(pubKeySize)
	}
	if fp, ok := cert["fingerprintSHA1"].(string); ok {
		certificate.FingerprintSha1 = fp
	}
	if fp, ok := cert["fingerprintSHA256"].(string); ok {
		certificate.FingerprintSha256 = fp
	}
	if selfSigned, ok := cert["selfSigned"].(bool); ok {
		certificate.SelfSigned = selfSigned
	}

	return certificate
}
