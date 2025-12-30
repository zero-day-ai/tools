package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the masscan tool
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"targets": schema.StringWithDesc("CIDR notation or IP range (e.g., 192.168.1.0/24 or 10.0.0.1-10.0.0.254)"),
		"ports":   schema.StringWithDesc("Port specification (e.g., '80,443' or '1-1000' or '0-65535')"),
		"rate": schema.JSON{
			Type:        "integer",
			Description: "Packets per second (optional, default: 100)",
		},
		"banners": schema.JSON{
			Type:        "boolean",
			Description: "Grab service banners (optional, default: false)",
		},
	}, "targets", "ports") // targets and ports are required
}

// OutputSchema defines the output schema for the masscan tool
func OutputSchema() schema.JSON {
	portSchema := schema.Object(map[string]schema.JSON{
		"port":     schema.JSON{Type: "integer", Description: "Port number"},
		"protocol": schema.StringWithDesc("Protocol (tcp or udp)"),
		"state":    schema.StringWithDesc("Port state (open)"),
		"banner":   schema.StringWithDesc("Service banner (if banners enabled)"),
	})

	portsArray := schema.Array(portSchema)
	portsArray.Description = "List of open ports"

	hostSchema := schema.Object(map[string]schema.JSON{
		"ip":    schema.StringWithDesc("IP address of the host"),
		"ports": portsArray,
	})

	hostsArray := schema.Array(hostSchema)
	hostsArray.Description = "List of hosts with open ports"

	return schema.Object(map[string]schema.JSON{
		"hosts": hostsArray,
		"total_hosts": schema.JSON{
			Type:        "integer",
			Description: "Total number of hosts with open ports",
		},
		"total_ports": schema.JSON{
			Type:        "integer",
			Description: "Total number of open ports found",
		},
		"scan_rate": schema.JSON{
			Type:        "integer",
			Description: "Actual scan rate in packets per second",
		},
		"scan_time_ms": schema.JSON{
			Type:        "integer",
			Description: "Scan duration in milliseconds",
		},
	})
}
