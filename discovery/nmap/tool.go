package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/zero-day-ai/sdk/api/gen/graphragpb"
	"github.com/zero-day-ai/sdk/api/gen/toolspb"
	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/health"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/toolerr"
	"github.com/zero-day-ai/sdk/types"
	"google.golang.org/protobuf/proto"
)

const (
	ToolName    = "nmap"
	ToolVersion = "1.0.0"
	ToolDescription = `Network mapper and port scanner. Targets and args are passed; tool automatically adds "-oX -" for XML output.

SCAN TYPES:
  -sn          Ping scan (host discovery, no port scan)
  -sS          SYN stealth scan (default, requires root)
  -sT          TCP connect scan (no root required)
  -sU          UDP scan
  -sV          Version detection (identify service versions)
  -sC          Script scan (run default NSE scripts)
  -A           Aggressive (OS detection, version, scripts, traceroute)

TIMING TEMPLATES (-T0 to -T5):
  -T0          Paranoid (IDS evasion, very slow)
  -T1          Sneaky (IDS evasion, slow)
  -T2          Polite (less bandwidth, slower)
  -T3          Normal (default)
  -T4          Aggressive (fast, assumes good network)
  -T5          Insane (extremely fast, may miss ports)

PORT SPECIFICATION:
  -p 22,80,443        Specific ports
  -p 1-1000           Port range
  -p-                 All 65535 ports
  --top-ports N       Scan N most common ports

DETECTION:
  -O               OS detection
  --osscan-guess   Aggressive OS guessing

COMMON EXAMPLES:
  Quick host discovery: ["-sn"]
  Fast port scan: ["-sT", "-T4", "--top-ports", "100"]
  Full service scan: ["-sV", "-sC", "-O", "-T4", "-p-"]
  Stealth scan: ["-sS", "-T2", "-p", "1-1000"]
  Web services: ["-sV", "-p", "80,443,8080,8443"]`
	BinaryName = "nmap"
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

	if len(req.Args) == 0 {
		return nil, fmt.Errorf("at least one argument is required")
	}

	// Validate flags against capabilities
	caps := tool.GetCapabilities(ctx, t)
	if caps != nil {
		if blockedFlag, alternative, blocked := validateFlags(caps, req.Args); blocked {
			errMsg := fmt.Sprintf("flag '%s' requires elevated privileges and is blocked", blockedFlag)
			if alternative != "" {
				errMsg = fmt.Sprintf("%s. Try using '%s' instead", errMsg, alternative)
			}
			return nil, toolerr.New(ToolName, "validate", toolerr.ErrCodeInvalidInput, errMsg).
				WithClass(toolerr.ErrorClassSemantic)
		}
	}

	// Build command arguments: -oX - (XML output to stdout) + user args + targets
	args := []string{"-oX", "-"}
	args = append(args, req.Args...)
	args = append(args, req.Targets...)

	// Execute nmap command
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: 5 * time.Minute, // Default timeout
	})

	if err != nil {
		// Classify execution errors based on underlying cause
		errClass := classifyExecutionError(err)
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).
			WithCause(err).
			WithClass(errClass)
	}

	// Parse nmap XML output to proto types
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

// parseOutput parses the XML output from nmap and returns proto DiscoveryResult directly
func parseOutput(data []byte) (*graphragpb.DiscoveryResult, error) {
	var nmapRun NmapRun
	if err := xml.Unmarshal(data, &nmapRun); err != nil {
		return nil, fmt.Errorf("failed to parse nmap XML: %w", err)
	}

	result := &graphragpb.DiscoveryResult{}

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

		// Create Host node using proto type
		hostNode := &graphragpb.Host{
			Ip:    ip,
			State: ptrStr(host.Status.State),
		}
		if hostname != "" {
			hostNode.Hostname = &hostname
		}
		if os != "" {
			hostNode.Os = &os
		}
		result.Hosts = append(result.Hosts, hostNode)

		// Process ports
		for _, port := range host.Ports {
			// Create Port node using proto type
			portNode := &graphragpb.Port{
				HostId:   ip,
				Number:   int32(port.PortID),
				Protocol: port.Protocol,
				State:    ptrStr(port.State.State),
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

				serviceNode := &graphragpb.Service{
					PortId: portID,
					Name:   port.Service.Name,
				}
				if version != "" {
					serviceNode.Version = &version
				}
				result.Services = append(result.Services, serviceNode)
			}
		}
	}

	return result, nil
}

// ptrStr returns a pointer to the given string
func ptrStr(s string) *string {
	return &s
}

// convertToProtoResponse converts DiscoveryResult to NmapResponse
func convertToProtoResponse(discoveryResult *graphragpb.DiscoveryResult, scanDuration float64, startTime time.Time) *toolspb.NmapResponse {
	hosts := discoveryResult.Hosts
	ports := discoveryResult.Ports
	services := discoveryResult.Services

	response := &toolspb.NmapResponse{
		TotalHosts:   int32(len(hosts)),
		ScanDuration: scanDuration,
		StartTime:    startTime.Unix(),
		EndTime:      time.Now().Unix(),
	}

	// Count hosts that are up
	hostsUp := int32(0)
	for _, host := range hosts {
		state := ""
		if host.State != nil {
			state = *host.State
		}
		if state == "up" {
			hostsUp++
		}
	}
	response.HostsUp = hostsUp
	response.HostsDown = response.TotalHosts - hostsUp

	// Convert graphrag hosts to nmap response hosts
	for _, graphragHost := range hosts {
		hostname := ""
		if graphragHost.Hostname != nil {
			hostname = *graphragHost.Hostname
		}
		state := ""
		if graphragHost.State != nil {
			state = *graphragHost.State
		}
		os := ""
		if graphragHost.Os != nil {
			os = *graphragHost.Os
		}

		nmapHost := &toolspb.NmapHost{
			Ip:       graphragHost.Ip,
			Hostname: hostname,
			State:    state,
		}

		// Add OS information if available
		if os != "" {
			nmapHost.OsMatches = []*toolspb.OSMatch{
				{
					Name:     os,
					Accuracy: 100, // Assuming high accuracy for simplicity
				},
			}
		}

		// Find and add ports for this host
		for _, graphragPort := range ports {
			if graphragPort.HostId == graphragHost.Ip {
				portState := ""
				if graphragPort.State != nil {
					portState = *graphragPort.State
				}
				nmapPort := &toolspb.NmapPort{
					Number:   graphragPort.Number,
					Protocol: graphragPort.Protocol,
					State:    portState,
				}

				// Find service for this port
				portID := fmt.Sprintf("%s:%d:%s", graphragHost.Ip, graphragPort.Number, graphragPort.Protocol)
				for _, graphragService := range services {
					if graphragService.PortId == portID {
						version := ""
						if graphragService.Version != nil {
							version = *graphragService.Version
						}
						nmapPort.Service = &toolspb.NmapService{
							Name:    graphragService.Name,
							Version: version,
						}
						break
					}
				}

				nmapHost.Ports = append(nmapHost.Ports, nmapPort)
			}
		}

		response.Hosts = append(response.Hosts, nmapHost)
	}

	// Populate discovery field for automatic graph storage
	response.Discovery = discoveryResult

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

// validateFlags checks if any requested flags are blocked by capabilities.
// Returns the blocked flag, its alternative (if available), and whether a block was found.
func validateFlags(caps *types.Capabilities, flags []string) (blockedFlag string, alternative string, blocked bool) {
	for _, flag := range flags {
		if caps.IsArgBlocked(flag) {
			alt, _ := caps.GetAlternative(flag)
			return flag, alt, true
		}
	}
	return "", "", false
}

