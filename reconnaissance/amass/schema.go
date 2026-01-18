package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for amass tool input.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"domain": schema.StringWithDesc("Target domain for enumeration (required)"),
		"mode": schema.JSON{
			Type:        "string",
			Description: "Enumeration mode: passive or active",
			Enum:        []any{"passive", "active"},
			Default:     "passive",
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
		"max_depth": schema.JSON{
			Type:        "integer",
			Description: "DNS recursion depth (optional)",
		},
		"include_whois": schema.JSON{
			Type:        "boolean",
			Description: "Include WHOIS information (optional)",
		},
		"include_asn": schema.JSON{
			Type:        "boolean",
			Description: "Include ASN information (optional)",
		},
	}, "domain") // domain is required
}

// OutputSchema returns the JSON schema for amass tool output.
// Includes embedded taxonomy mappings for GraphRAG integration.
func OutputSchema() schema.JSON {
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

	// Subdomain schema - each string is a subdomain FQDN
	subdomainSchema := schema.String().WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "subdomain",
		IDTemplate: "subdomain:{.}",
		Properties: []schema.PropertyMapping{
			schema.PropMap(".", "name"),
		},
		Relationships: []schema.RelationshipMapping{
			schema.Rel("HAS_SUBDOMAIN", "domain:{_root.domain}", "subdomain:{.}"),
			schema.Rel("DISCOVERED", "agent_run:{_context.agent_run_id}", "subdomain:{.}"),
		},
	})

	// IP address schema - each string is a host IP
	ipSchema := schema.String().WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "host",
		IDTemplate: "host:{.}",
		Properties: []schema.PropertyMapping{
			schema.PropMap(".", "ip"),
		},
		Relationships: []schema.RelationshipMapping{
			schema.Rel("DISCOVERED", "agent_run:{_context.agent_run_id}", "host:{.}"),
		},
	})

	// ASN info schema with associated IPs
	asnIPSchema := schema.String().WithTaxonomy(schema.TaxonomyMapping{
		// Create HOSTED_BY relationships from each IP to the parent ASN
		Relationships: []schema.RelationshipMapping{
			schema.Rel("HOSTED_BY", "host:{.}", "asn:{_parent.number}"),
		},
	})

	asnSchema := schema.Object(map[string]schema.JSON{
		"number":      schema.Int(),
		"description": schema.String(),
		"country":     schema.String(),
		"ips":         schema.Array(asnIPSchema),
	}).WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "asn",
		IDTemplate: "asn:{.number}",
		Properties: []schema.PropertyMapping{
			schema.PropMap("number", "number"),
			schema.PropMap("description", "description"),
			schema.PropMap("country", "country"),
		},
		Relationships: []schema.RelationshipMapping{
			schema.Rel("DISCOVERED", "agent_run:{_context.agent_run_id}", "asn:{.number}"),
		},
	})

	// DNS record schema
	dnsRecordSchema := schema.Object(map[string]schema.JSON{
		"name":     schema.String(),
		"type":     schema.String(),
		"value":    schema.String(),
		"priority": schema.Int(),
		"ttl":      schema.Int(),
	}).WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "dns_record",
		IDTemplate: "dns_record:{.name}:{.type}:{.value}",
		Properties: []schema.PropertyMapping{
			schema.PropMap("name", "name"),
			schema.PropMap("type", "record_type"),
			schema.PropMap("value", "value"),
			schema.PropMap("priority", "priority"),
			schema.PropMap("ttl", "ttl"),
		},
		Relationships: []schema.RelationshipMapping{
			// Link subdomain to DNS record
			schema.Rel("HAS_DNS_RECORD", "subdomain:{.name}", "dns_record:{.name}:{.type}:{.value}"),
		},
	})

	return schema.Object(map[string]schema.JSON{
		"domain":       domainSchema,
		"subdomains":   schema.Array(subdomainSchema),
		"ip_addresses": schema.Array(ipSchema),
		"asn_info":     schema.Array(asnSchema),
		"dns_records":  schema.Array(dnsRecordSchema),
		"whois":        schema.Object(map[string]schema.JSON{}), // Generic object for WHOIS data
		"scan_time_ms": schema.Int(),
	})
}
