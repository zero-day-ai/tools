package main

import (
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson-tools-official/pkg/parser"
)

// parseNmapOutput converts nmap XML output to the structured JSON output format
func parseNmapOutput(xmlData []byte, startTime time.Time) (map[string]any, error) {
	// Parse XML
	nmapRun, err := parser.ParseXML[parser.NmapRun](xmlData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse nmap XML: %w", err)
	}

	// Build output structure
	output := map[string]any{
		"scan_info": map[string]any{
			"scanner":         nmapRun.Scanner,
			"args":            nmapRun.Args,
			"start_time":      nmapRun.StartStr,
			"end_time":        nmapRun.RunStats.Finished.TimeStr,
			"elapsed_seconds": nmapRun.RunStats.Finished.Elapsed,
		},
		"hosts":        parseHosts(nmapRun.Hosts),
		"run_stats":    parseRunStats(&nmapRun.RunStats),
		"warnings":     []string{},
		"scan_time_ms": int(time.Since(startTime).Milliseconds()),
	}

	return output, nil
}

// parseHosts converts nmap host data to output format
func parseHosts(nmapHosts []parser.NmapHost) []map[string]any {
	hosts := make([]map[string]any, 0, len(nmapHosts))

	for _, h := range nmapHosts {
		host := map[string]any{
			"ip":        getHostIP(&h),
			"hostnames": getHostnames(h.Hostnames),
			"status":    h.Status.State,
			"ports":     parsePorts(h.Ports.Ports),
		}

		// Add OS detection if available
		if len(h.OS.OSMatch) > 0 {
			host["os"] = parseOS(&h.OS)
		}

		// Add uptime if available
		if h.Uptime.Seconds > 0 {
			host["uptime"] = map[string]any{
				"seconds":  h.Uptime.Seconds,
				"lastboot": h.Uptime.LastBoot,
			}
		}

		// Add distance if available
		if h.Distance.Value > 0 {
			host["distance"] = h.Distance.Value
		}

		// Add MAC address and vendor if available
		for _, addr := range h.Addresses {
			if addr.AddrType == "mac" {
				host["mac_address"] = addr.Addr
				if addr.Vendor != "" {
					host["vendor"] = addr.Vendor
				}
				break
			}
		}

		hosts = append(hosts, host)
	}

	return hosts
}

// getHostIP extracts the primary IP address from a host
func getHostIP(host *parser.NmapHost) string {
	for _, addr := range host.Addresses {
		if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
			return addr.Addr
		}
	}
	return ""
}

// getHostnames extracts hostname list
func getHostnames(nmapHostnames []parser.NmapHostname) []string {
	hostnames := make([]string, 0, len(nmapHostnames))
	for _, hn := range nmapHostnames {
		if hn.Name != "" {
			hostnames = append(hostnames, hn.Name)
		}
	}
	return hostnames
}

// parsePorts converts nmap port data to output format
func parsePorts(nmapPorts []parser.NmapPort) []map[string]any {
	ports := make([]map[string]any, 0, len(nmapPorts))

	for _, p := range nmapPorts {
		port := map[string]any{
			"port":     p.PortID,
			"protocol": p.Protocol,
			"state":    p.State.State,
		}

		// Add service information
		if p.Service.Name != "" {
			service := map[string]any{
				"name": p.Service.Name,
			}
			if p.Service.Product != "" {
				service["product"] = p.Service.Product
			}
			if p.Service.Version != "" {
				service["version"] = p.Service.Version
			}
			if p.Service.ExtraInfo != "" {
				service["extrainfo"] = p.Service.ExtraInfo
			}
			if len(p.Service.CPE) > 0 {
				service["cpe"] = p.Service.CPE
			}
			port["service"] = service
		}

		// Add script results
		if len(p.Scripts) > 0 {
			scripts := make([]map[string]any, 0, len(p.Scripts))
			for _, s := range p.Scripts {
				scripts = append(scripts, map[string]any{
					"id":     s.ID,
					"output": s.Output,
				})
			}
			port["scripts"] = scripts
		}

		ports = append(ports, port)
	}

	return ports
}

// parseOS extracts OS detection results
func parseOS(nmapOS *parser.NmapOS) map[string]any {
	if len(nmapOS.OSMatch) == 0 {
		return map[string]any{}
	}

	// Use the first (highest accuracy) match
	match := nmapOS.OSMatch[0]
	os := map[string]any{
		"name":     match.Name,
		"accuracy": match.Accuracy,
	}

	// Add OS class information if available
	if len(match.OSClass) > 0 {
		osClass := match.OSClass[0]
		if osClass.OSFamily != "" {
			os["family"] = osClass.OSFamily
		}
		if osClass.Vendor != "" {
			os["vendor"] = osClass.Vendor
		}
	}

	return os
}

// parseRunStats converts run statistics to output format
func parseRunStats(stats *parser.NmapStats) map[string]any {
	return map[string]any{
		"hosts_up":    stats.Hosts.Up,
		"hosts_down":  stats.Hosts.Down,
		"hosts_total": stats.Hosts.Total,
	}
}
