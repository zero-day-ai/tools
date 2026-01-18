package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for subfinder tool input.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"domain": schema.StringWithDesc("Target domain for subdomain enumeration (required)"),
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
		"silent": schema.JSON{
			Type:        "boolean",
			Description: "Silent mode, only output subdomains (optional)",
			Default:     false,
		},
		"recursive": schema.JSON{
			Type:        "boolean",
			Description: "Recursive subdomain enumeration (optional)",
			Default:     false,
		},
		"all": schema.JSON{
			Type:        "boolean",
			Description: "Use all sources for enumeration (optional)",
			Default:     true,
		},
	}, "domain") // domain is required
}

// OutputSchema returns the JSON schema for subfinder tool output.
// Includes embedded taxonomy mappings for GraphRAG integration.
// Note: subdomains is now an array of objects with name, ips, and sources.
func OutputSchema() schema.JSON {
	// IP address schema with taxonomy for host node creation
	ipSchema := schema.String().WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "host",
		IDTemplate: "host:{.}",
		Properties: []schema.PropertyMapping{
			schema.PropMap(".", "ip_address"),
		},
		Relationships: []schema.RelationshipMapping{
			schema.Rel("DISCOVERED", "agent_run:{_context.agent_run_id}", "host:{.}"),
		},
	})

	// Subdomain schema - each object contains name, ips, and sources
	subdomainSchema := schema.Object(map[string]schema.JSON{
		"name": schema.String(),
		"ips":  schema.Array(ipSchema),
		"sources": schema.Array(schema.String()),
	}).WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "subdomain",
		IDTemplate: "subdomain:{.name}",
		Properties: []schema.PropertyMapping{
			schema.PropMap("name", "name"),
			schema.PropMap("ips", "ip_addresses"),
			schema.PropMap("sources", "sources"),
		},
		Relationships: []schema.RelationshipMapping{
			// Link subdomain to parent domain (from root output)
			schema.Rel("HAS_SUBDOMAIN", "domain:{_root.domain}", "subdomain:{.name}"),
			// Link agent run to discovered subdomain
			schema.Rel("DISCOVERED", "agent_run:{_context.agent_run_id}", "subdomain:{.name}"),
			// Link subdomain to resolved IPs
			schema.Rel("RESOLVES_TO", "subdomain:{.name}", "host:{.ips[*]}"),
		},
	})

	// Domain field with taxonomy for domain node creation
	domainSchema := schema.String().WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "domain",
		IDTemplate: "domain:{.}",
		Properties: []schema.PropertyMapping{
			schema.PropMap(".", "name"),
		},
		Relationships: []schema.RelationshipMapping{
			schema.Rel("DISCOVERED", "agent_run:{_context.agent_run_id}", "domain:{.}"),
		},
	})

	return schema.Object(map[string]schema.JSON{
		"domain":       domainSchema,
		"subdomains":   schema.Array(subdomainSchema),
		"count":        schema.Int(),
		"scan_time_ms": schema.Int(),
	})
}
