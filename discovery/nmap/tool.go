package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/zero-day-ai/sdk/api/gen/toolspb"
	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/graphrag/domain"
	"github.com/zero-day-ai/sdk/health"
	sdkinput "github.com/zero-day-ai/sdk/input"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/toolerr"
	"github.com/zero-day-ai/sdk/types"
	"google.golang.org/protobuf/proto"
)

const (
	ToolName        = "nmap"
	ToolVersion     = "1.0.0"
	ToolDescription = "Network exploration tool and security/port scanner"
	BinaryName      = "nmap"
)


// ToolImpl implements the nmap tool
type ToolImpl struct{}

// NewTool creates a new nmap tool instance
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
		"discovery",
		"network",
		"port-scan",
		"T1046", // Network Service Discovery
		"T1595", // Active Scanning
	}
}

// InputMessageType returns the proto message type for input
func (t *ToolImpl) InputMessageType() string {
	return "gibson.tools.NmapRequest"
}

// OutputMessageType returns the proto message type for output
func (t *ToolImpl) OutputMessageType() string {
	return "gibson.tools.NmapResponse"
}

// ExecuteProto runs the nmap tool with proto message input
func (t *ToolImpl) ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error) {
	startTime := time.Now()

	// Type assert input to NmapRequest
	req, ok := input.(*toolspb.NmapRequest)
	if !ok {
		return nil, fmt.Errorf("invalid input type: expected *toolspb.NmapRequest, got %T", input)
	}

	// Validate required fields
	if len(req.Targets) == 0 {
		return nil, fmt.Errorf("at least one target is required")
	}

	// Use first target for now (nmap can handle multiple targets, but our logic uses single target)
	target := req.Targets[0]

	// Extract parameters with defaults
	ports := req.Ports
	if ports == "" {
		ports = "1-1000"
	}

	// Convert proto scan type to string
	scanType := convertScanType(req.ScanType)
	serviceDetection := req.ServiceDetection
	osDetection := req.OsDetection
	scripts := req.Scripts

	// Convert proto timing template to integer (0-5)
	timing := convertTimingTemplate(req.Timing)

	// Determine timeout from request or use default
	timeout := sdkinput.DefaultTimeout()
	if req.HostTimeout > 0 {
		timeout = time.Duration(req.HostTimeout) * time.Second
	}

	// Build nmap command arguments
	args := buildArgs(target, ports, scanType, serviceDetection, osDetection, scripts, timing)

	// Execute nmap command
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		// Classify execution errors based on underlying cause
		errClass := classifyExecutionError(err)
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).
			WithCause(err).
			WithClass(errClass)
	}

	// Parse nmap XML output to domain types
	discoveryResult, err := parseOutput(result.Stdout)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).
			WithCause(err).
			WithClass(toolerr.ErrorClassSemantic)
	}

	// Convert discovery result to NmapResponse
	scanDuration := time.Since(startTime).Seconds()
	response := convertToProtoResponse(discoveryResult, scanDuration, startTime)

	return response, nil
}

// Health checks if the nmap binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// buildArgs constructs the command-line arguments for nmap
func buildArgs(target, ports, scanType string, serviceDetection, osDetection bool, scripts []string, timing int) []string {
	// Ping scan mode (-sn) is host discovery only, no ports
	if scanType == "ping" {
		args := []string{"-oX", "-", "-sn"}
		if timing >= 0 && timing <= 5 {
			args = append(args, fmt.Sprintf("-T%d", timing))
		}
		args = append(args, target)
		return args
	}

	args := []string{"-oX", "-", "-p", ports}

	// Scan type
	switch scanType {
	case "syn":
		args = append(args, "-sS")
	case "connect":
		args = append(args, "-sT")
	case "udp":
		args = append(args, "-sU")
	case "ack":
		args = append(args, "-sA")
	case "window":
		args = append(args, "-sW")
	case "maimon":
		args = append(args, "-sM")
	}

	if serviceDetection {
		args = append(args, "-sV")
	}

	if osDetection {
		args = append(args, "-O")
	}

	if len(scripts) > 0 {
		args = append(args, "--script", strings.Join(scripts, ","))
	}

	if timing >= 0 && timing <= 5 {
		args = append(args, fmt.Sprintf("-T%d", timing))
	}

	args = append(args, target)

	return args
}

// NmapRun represents the root XML element
type NmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []NmapHost `xml:"host"`
}

// NmapHost represents a scanned host
type NmapHost struct {
	Status    NmapStatus     `xml:"status"`
	Addresses []NmapAddress  `xml:"address"`
	Hostnames []NmapHostname `xml:"hostnames>hostname"`
	Ports     []NmapPort     `xml:"ports>port"`
	OS        NmapOS         `xml:"os"`
}

// NmapStatus represents host status
type NmapStatus struct {
	State string `xml:"state,attr"`
}

// NmapAddress represents an address
type NmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

// NmapHostname represents a hostname
type NmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

// NmapPort represents a port
type NmapPort struct {
	Protocol string        `xml:"protocol,attr"`
	PortID   int           `xml:"portid,attr"`
	State    NmapState     `xml:"state"`
	Service  NmapService   `xml:"service"`
	Scripts  []NmapScript  `xml:"script"`
}

// NmapScript represents an NSE script result
type NmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

// NmapState represents port state
type NmapState struct {
	State string `xml:"state,attr"`
}

// NmapService represents a service
type NmapService struct {
	Name    string   `xml:"name,attr"`
	Product string   `xml:"product,attr"`
	Version string   `xml:"version,attr"`
	CPE     []string `xml:"cpe"`
}

// NmapOS represents OS detection results
type NmapOS struct {
	OSMatches []NmapOSMatch `xml:"osmatch"`
}

// NmapOSMatch represents an OS match
type NmapOSMatch struct {
	Name      string        `xml:"name,attr"`
	Accuracy  string        `xml:"accuracy,attr"`
	OSClasses []NmapOSClass `xml:"osclass"`
}

// NmapOSClass represents an OS classification
type NmapOSClass struct {
	Family   string `xml:"family,attr"`
	Vendor   string `xml:"vendor,attr"`
	OSGen    string `xml:"osgen,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

// parseOutput parses the XML output from nmap and returns domain types
func parseOutput(data []byte) (*domain.DiscoveryResult, error) {
	var nmapRun NmapRun
	if err := xml.Unmarshal(data, &nmapRun); err != nil {
		return nil, fmt.Errorf("failed to parse nmap XML: %w", err)
	}

	result := domain.NewDiscoveryResult()

	for _, host := range nmapRun.Hosts {
		// Get IP address
		ip := ""
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
				ip = addr.Addr
				break
			}
		}

		// Skip if no IP address found
		if ip == "" {
			continue
		}

		// Get hostname
		hostname := ""
		if len(host.Hostnames) > 0 {
			hostname = host.Hostnames[0].Name
		}

		// Get OS information
		os := ""
		if len(host.OS.OSMatches) > 0 {
			os = host.OS.OSMatches[0].Name
		}

		// Create Host node
		hostNode := &domain.Host{
			IP:       ip,
			Hostname: hostname,
			State:    host.Status.State,
			OS:       os,
		}
		result.Hosts = append(result.Hosts, hostNode)

		// Process ports
		for _, port := range host.Ports {
			// Create Port node
			portNode := &domain.Port{
				HostID:   ip,
				Number:   port.PortID,
				Protocol: port.Protocol,
				State:    port.State.State,
			}
			result.Ports = append(result.Ports, portNode)

			// Create Service node if service information is available
			if port.Service.Name != "" {
				// Construct PortID in format "{host_id}:{number}:{protocol}"
				portID := fmt.Sprintf("%s:%d:%s", ip, port.PortID, port.Protocol)

				// Build version string
				version := strings.TrimSpace(port.Service.Product)
				if port.Service.Version != "" {
					if version != "" {
						version = fmt.Sprintf("%s %s", version, port.Service.Version)
					} else {
						version = port.Service.Version
					}
				}

				serviceNode := &domain.Service{
					PortID:  portID,
					Name:    port.Service.Name,
					Version: version,
					Banner:  "", // nmap doesn't provide banner directly, could be extracted from scripts
				}
				result.Services = append(result.Services, serviceNode)
			}
		}
	}

	return result, nil
}

// convertScanType converts proto ScanType enum to nmap string
func convertScanType(scanType toolspb.ScanType) string {
	switch scanType {
	case toolspb.ScanType_SCAN_TYPE_SYN:
		return "syn"
	case toolspb.ScanType_SCAN_TYPE_CONNECT:
		return "connect"
	case toolspb.ScanType_SCAN_TYPE_UDP:
		return "udp"
	case toolspb.ScanType_SCAN_TYPE_ACK:
		return "ack"
	case toolspb.ScanType_SCAN_TYPE_WINDOW:
		return "window"
	case toolspb.ScanType_SCAN_TYPE_MAIMON:
		return "maimon"
	case toolspb.ScanType_SCAN_TYPE_PING:
		return "ping"
	case toolspb.ScanType_SCAN_TYPE_UNSPECIFIED:
		return "connect"
	default:
		return "connect"
	}
}

// convertTimingTemplate converts proto TimingTemplate enum to integer (0-5)
func convertTimingTemplate(timing toolspb.TimingTemplate) int {
	switch timing {
	case toolspb.TimingTemplate_TIMING_TEMPLATE_PARANOID:
		return 0
	case toolspb.TimingTemplate_TIMING_TEMPLATE_SNEAKY:
		return 1
	case toolspb.TimingTemplate_TIMING_TEMPLATE_POLITE:
		return 2
	case toolspb.TimingTemplate_TIMING_TEMPLATE_NORMAL:
		return 3
	case toolspb.TimingTemplate_TIMING_TEMPLATE_AGGRESSIVE:
		return 4
	case toolspb.TimingTemplate_TIMING_TEMPLATE_INSANE:
		return 5
	case toolspb.TimingTemplate_TIMING_TEMPLATE_UNSPECIFIED:
		return 3
	default:
		return 3
	}
}

// convertToProtoResponse converts DiscoveryResult to NmapResponse
func convertToProtoResponse(discoveryResult *domain.DiscoveryResult, scanDuration float64, startTime time.Time) *toolspb.NmapResponse {
	response := &toolspb.NmapResponse{
		TotalHosts:   int32(len(discoveryResult.Hosts)),
		ScanDuration: scanDuration,
		StartTime:    startTime.Unix(),
		EndTime:      time.Now().Unix(),
	}

	// Count hosts that are up
	hostsUp := int32(0)
	for _, host := range discoveryResult.Hosts {
		if host.State == "up" {
			hostsUp++
		}
	}
	response.HostsUp = hostsUp
	response.HostsDown = response.TotalHosts - hostsUp

	// Convert domain hosts to proto hosts
	for _, domainHost := range discoveryResult.Hosts {
		protoHost := &toolspb.NmapHost{
			Ip:       domainHost.IP,
			Hostname: domainHost.Hostname,
			State:    domainHost.State,
		}

		// Add OS information if available
		if domainHost.OS != "" {
			protoHost.OsMatches = []*toolspb.OSMatch{
				{
					Name:     domainHost.OS,
					Accuracy: 100, // Assuming high accuracy for simplicity
				},
			}
		}

		// Find and add ports for this host
		for _, domainPort := range discoveryResult.Ports {
			if domainPort.HostID == domainHost.IP {
				protoPort := &toolspb.NmapPort{
					Number:   int32(domainPort.Number),
					Protocol: domainPort.Protocol,
					State:    domainPort.State,
				}

				// Find service for this port
				portID := fmt.Sprintf("%s:%d:%s", domainHost.IP, domainPort.Number, domainPort.Protocol)
				for _, domainService := range discoveryResult.Services {
					if domainService.PortID == portID {
						protoPort.Service = &toolspb.NmapService{
							Name:    domainService.Name,
							Version: domainService.Version,
						}
						break
					}
				}

				protoHost.Ports = append(protoHost.Ports, protoPort)
			}
		}

		response.Hosts = append(response.Hosts, protoHost)
	}

	return response
}

// classifyExecutionError determines the error class based on the underlying error
func classifyExecutionError(err error) toolerr.ErrorClass {
	if err == nil {
		return toolerr.ErrorClassTransient
	}

	errMsg := err.Error()

	// Check for binary not found errors
	if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "executable file not found") {
		return toolerr.ErrorClassInfrastructure
	}

	// Check for timeout errors
	if strings.Contains(errMsg, "timed out") || strings.Contains(errMsg, "timeout") ||
		strings.Contains(errMsg, "deadline exceeded") {
		return toolerr.ErrorClassTransient
	}

	// Check for permission errors
	if strings.Contains(errMsg, "permission denied") || strings.Contains(errMsg, "access denied") {
		return toolerr.ErrorClassInfrastructure
	}

	// Check for network errors
	if strings.Contains(errMsg, "network") || strings.Contains(errMsg, "connection") ||
		strings.Contains(errMsg, "host unreachable") || strings.Contains(errMsg, "no route to host") {
		return toolerr.ErrorClassTransient
	}

	// Check for cancellation
	if strings.Contains(errMsg, "cancelled") || strings.Contains(errMsg, "canceled") {
		return toolerr.ErrorClassTransient
	}

	// Default to transient for unknown execution errors
	return toolerr.ErrorClassTransient
}
