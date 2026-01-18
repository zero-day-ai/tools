package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for nmap tool input.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"target": schema.StringWithDesc("Target host, IP, or CIDR range to scan (required)"),
		"ports": schema.JSON{
			Type:        "string",
			Description: "Port specification (e.g., '22,80,443' or '1-1000')",
			Default:     "1-1000",
		},
		"scan_type": schema.JSON{
			Type:        "string",
			Description: "Scan type: connect (default, no root), syn (requires root), udp, ack, window, maimon, ping (host discovery only, no port scan)",
			Enum:        []any{"connect", "syn", "udp", "ack", "window", "maimon", "ping"},
			Default:     "connect",
		},
		"service_detection": schema.JSON{
			Type:        "boolean",
			Description: "Enable service/version detection",
			Default:     true,
		},
		"os_detection": schema.JSON{
			Type:        "boolean",
			Description: "Enable OS detection",
			Default:     false,
		},
		"scripts": schema.JSON{
			Type:        "array",
			Description: "NSE scripts to run (optional)",
			Items:       &schema.JSON{Type: "string"},
		},
		"timing": schema.JSON{
			Type:        "integer",
			Description: "Timing template (0-5, higher is faster)",
			Default:     3,
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
	}, "target") // target is required
}

// OutputSchema returns the JSON schema for nmap tool output.
// Includes embedded taxonomy mappings for GraphRAG integration.
func OutputSchema() schema.JSON {
	// Script schema for NSE script results
	scriptSchema := schema.Object(map[string]schema.JSON{
		"id":     schema.String(),
		"output": schema.String(),
	})

	// Service schema with taxonomy for service nodes
	// Services are created only when service_name is present
	serviceSchema := schema.Object(map[string]schema.JSON{
		"name":    schema.String(),
		"product": schema.String(),
		"version": schema.String(),
		"cpe": schema.JSON{
			Type:        "array",
			Description: "Common Platform Enumeration identifiers",
			Items:       &schema.JSON{Type: "string"},
		},
	}).WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "service",
		IDTemplate: "service:{_parent._parent.ip}:{_parent.port}:{.name}",
		Properties: []schema.PropertyMapping{
			schema.PropMap("name", "name"),
			schema.PropMap("product", "product"),
			schema.PropMap("version", "version"),
			schema.PropMap("cpe", "cpe"),
		},
		Relationships: []schema.RelationshipMapping{
			schema.Rel("RUNS_SERVICE", "port:{_parent._parent.ip}:{_parent.port}:{_parent.protocol}", "service:{_parent._parent.ip}:{_parent.port}:{.name}"),
		},
	})

	// Port schema with taxonomy for port nodes
	portSchema := schema.Object(map[string]schema.JSON{
		"port":     schema.Int(),
		"protocol": schema.String(),
		"state":    schema.String(),
		"service":  schema.String(),
		"version":  schema.String(),
		"cpe": schema.JSON{
			Type:        "array",
			Description: "Common Platform Enumeration identifiers",
			Items:       &schema.JSON{Type: "string"},
		},
		"scripts": schema.JSON{
			Type:        "array",
			Description: "NSE script results",
			Items:       &scriptSchema,
		},
		"service_details": serviceSchema,
	}).WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "port",
		IDTemplate: "port:{_parent.ip}:{.port}:{.protocol}",
		Properties: []schema.PropertyMapping{
			schema.PropMap("port", "number"),
			schema.PropMap("protocol", "protocol"),
			schema.PropMap("state", "state"),
			schema.PropMap("service", "service_name"),
			schema.PropMap("version", "version"),
			schema.PropMap("cpe", "cpe"),
		},
		Relationships: []schema.RelationshipMapping{
			schema.Rel("HAS_PORT", "host:{_parent.ip}", "port:{_parent.ip}:{.port}:{.protocol}"),
		},
	})

	// Host schema with taxonomy for host nodes
	hostSchema := schema.Object(map[string]schema.JSON{
		"ip":       schema.String(),
		"hostname": schema.String(),
		"state":    schema.String(),
		"os":       schema.String(),
		"os_accuracy": schema.JSON{
			Type:        "integer",
			Description: "OS detection accuracy percentage (0-100)",
		},
		"os_family": schema.JSON{
			Type:        "string",
			Description: "Operating system family (e.g., Linux, Windows)",
		},
		"os_vendor": schema.JSON{
			Type:        "string",
			Description: "Operating system vendor (e.g., Microsoft, Linux)",
		},
		"ports": schema.Array(portSchema),
	}).WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "host",
		IDTemplate: "host:{.ip}",
		Properties: []schema.PropertyMapping{
			schema.PropMap("ip", "ip"),
			schema.PropMap("hostname", "hostname"),
			schema.PropMap("state", "state"),
			schema.PropMap("os", "os"),
			schema.PropMap("os_accuracy", "os_accuracy"),
			schema.PropMap("os_family", "os_family"),
			schema.PropMap("os_vendor", "os_vendor"),
		},
		Relationships: []schema.RelationshipMapping{
			schema.Rel("DISCOVERED", "agent_run:{_context.agent_run_id}", "host:{.ip}"),
		},
	})

	return schema.Object(map[string]schema.JSON{
		"target":       schema.String(),
		"hosts":        schema.Array(hostSchema),
		"total_hosts":  schema.Int(),
		"hosts_up":     schema.Int(),
		"scan_time_ms": schema.Int(),
	})
}
