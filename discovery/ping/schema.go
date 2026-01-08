package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for ping tool input.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"targets": schema.JSON{
			Type:        "array",
			Description: "List of target hosts or IPs to ping (required)",
			Items:       &schema.JSON{Type: "string"},
		},
		"count": schema.JSON{
			Type:        "integer",
			Description: "Number of ping requests per target",
			Default:     1,
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Timeout per ping in milliseconds",
			Default:     1000,
		},
		"concurrent": schema.JSON{
			Type:        "integer",
			Description: "Number of concurrent pings",
			Default:     50,
		},
	}, "targets") // targets is required
}

// OutputSchema returns the JSON schema for ping tool output.
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"results": schema.Array(schema.Object(map[string]schema.JSON{
			"ip":     schema.String(),
			"alive":  schema.Bool(),
			"rtt_ms": schema.Number(),
			"error":  schema.String(),
		})),
		"total":        schema.Int(),
		"alive":        schema.Int(),
		"dead":         schema.Int(),
		"scan_time_ms": schema.Int(),
	})
}
