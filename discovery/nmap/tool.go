package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/health"
	sdkinput "github.com/zero-day-ai/sdk/input"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/toolerr"
	"github.com/zero-day-ai/sdk/types"
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
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"discovery",
			"network",
			"port-scan",
			"T1046", // Network Service Discovery
			"T1595", // Active Scanning
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

// Execute runs the nmap tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	target := sdkinput.GetString(input, "target", "")
	if target == "" {
		return nil, fmt.Errorf("target is required")
	}

	ports := sdkinput.GetString(input, "ports", "1-1000")
	scanType := sdkinput.GetString(input, "scan_type", "syn")
	serviceDetection := sdkinput.GetBool(input, "service_detection", true)
	osDetection := sdkinput.GetBool(input, "os_detection", false)
	scripts := sdkinput.GetStringSlice(input, "scripts")
	timing := sdkinput.GetInt(input, "timing", 3)
	timeout := sdkinput.GetTimeout(input, "timeout", sdkinput.DefaultTimeout())

	// Build nmap command arguments
	args := buildArgs(target, ports, scanType, serviceDetection, osDetection, scripts, timing)

	// Execute nmap command
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}

	// Parse nmap XML output
	output, err := parseOutput(result.Stdout, target)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).WithCause(err)
	}

	// Add scan time
	output["scan_time_ms"] = int(time.Since(startTime).Milliseconds())

	return output, nil
}

// Health checks if the nmap binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// buildArgs constructs the command-line arguments for nmap
func buildArgs(target, ports, scanType string, serviceDetection, osDetection bool, scripts []string, timing int) []string {
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
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    NmapState   `xml:"state"`
	Service  NmapService `xml:"service"`
}

// NmapState represents port state
type NmapState struct {
	State string `xml:"state,attr"`
}

// NmapService represents a service
type NmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

// NmapOS represents OS detection results
type NmapOS struct {
	OSMatches []NmapOSMatch `xml:"osmatch"`
}

// NmapOSMatch represents an OS match
type NmapOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

// parseOutput parses the XML output from nmap
func parseOutput(data []byte, target string) (map[string]any, error) {
	var nmapRun NmapRun
	if err := xml.Unmarshal(data, &nmapRun); err != nil {
		return nil, fmt.Errorf("failed to parse nmap XML: %w", err)
	}

	hosts := []map[string]any{}
	hostsUp := 0

	for _, host := range nmapRun.Hosts {
		if host.Status.State == "up" {
			hostsUp++
		}

		// Get IP address
		ip := ""
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
				ip = addr.Addr
				break
			}
		}

		// Get hostname
		hostname := ""
		if len(host.Hostnames) > 0 {
			hostname = host.Hostnames[0].Name
		}

		// Get OS
		os := ""
		if len(host.OS.OSMatches) > 0 {
			os = host.OS.OSMatches[0].Name
		}

		// Get ports
		ports := []map[string]any{}
		for _, port := range host.Ports {
			version := port.Service.Product
			if port.Service.Version != "" {
				version = fmt.Sprintf("%s %s", version, port.Service.Version)
			}

			ports = append(ports, map[string]any{
				"port":     port.PortID,
				"protocol": port.Protocol,
				"state":    port.State.State,
				"service":  port.Service.Name,
				"version":  strings.TrimSpace(version),
			})
		}

		hosts = append(hosts, map[string]any{
			"ip":       ip,
			"hostname": hostname,
			"state":    host.Status.State,
			"os":       os,
			"ports":    ports,
		})
	}

	return map[string]any{
		"target":      target,
		"hosts":       hosts,
		"total_hosts": len(hosts),
		"hosts_up":    hostsUp,
	}, nil
}
