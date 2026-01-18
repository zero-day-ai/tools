package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for httpx tool input.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"targets": schema.JSON{
			Type:        "array",
			Description: "List of URLs or hosts to probe (required)",
			Items:       &schema.JSON{Type: "string"},
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
		"follow_redirects": schema.JSON{
			Type:        "boolean",
			Description: "Follow HTTP redirects (optional)",
			Default:     true,
		},
		"status_code": schema.JSON{
			Type:        "boolean",
			Description: "Display status code (optional)",
			Default:     true,
		},
		"title": schema.JSON{
			Type:        "boolean",
			Description: "Display page title (optional)",
			Default:     true,
		},
		"tech_detect": schema.JSON{
			Type:        "boolean",
			Description: "Detect technologies (optional)",
			Default:     false,
		},
	}, "targets") // targets is required
}

// OutputSchema returns the JSON schema for httpx tool output.
// Includes embedded taxonomy mappings for GraphRAG integration.
func OutputSchema() schema.JSON {
	// Technology schema - each string in the array is a technology name
	// Since technologies are simple strings, we create nodes from them
	technologySchema := schema.String().WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "technology",
		IDTemplate: "technology:{.}", // {.} refers to the string value itself
		Properties: []schema.PropertyMapping{
			schema.PropMap(".", "name"),
		},
		Relationships: []schema.RelationshipMapping{
			// Link endpoint to technology
			schema.Rel("USES_TECHNOLOGY", "endpoint:{_parent.url}", "technology:{.}"),
		},
	})

	// Certificate schema - created when cert_issuer is present (HTTPS only)
	certificateSchema := schema.Object(map[string]schema.JSON{
		"issuer":  schema.String(),
		"subject": schema.String(),
		"expiry":  schema.String(),
		"sans":    schema.Array(schema.String()),
	}).WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "certificate",
		IDTemplate: "certificate:{.subject}",
		Properties: []schema.PropertyMapping{
			schema.PropMap("issuer", "issuer"),
			schema.PropMap("subject", "subject"),
			schema.PropMap("expiry", "expiry"),
			schema.PropMap("sans", "subject_alternative_names"),
		},
		Relationships: []schema.RelationshipMapping{
			// Link certificate back to the endpoint that serves it
			schema.Rel("SERVED_BY", "certificate:{.subject}", "endpoint:{_parent.url}"),
		},
	})

	// Redirect hop schema
	redirectHopSchema := schema.Object(map[string]schema.JSON{
		"url":         schema.String(),
		"status_code": schema.Int(),
	})

	// Response headers schema - generic object for dynamic headers
	responseHeadersSchema := schema.Object(map[string]schema.JSON{})

	// Result/endpoint schema with taxonomy
	resultSchema := schema.Object(map[string]schema.JSON{
		"url":              schema.String(),
		"status_code":      schema.Int(),
		"title":            schema.String(),
		"content_type":     schema.String(),
		"technologies":     schema.Array(technologySchema),
		"server":           schema.String(),
		"x_powered_by":     schema.String(),
		"response_headers": responseHeadersSchema,
		"final_url":        schema.String(),
		"redirect_chain":   schema.Array(redirectHopSchema),
		"cert_issuer":      schema.String(),
		"cert_subject":     schema.String(),
		"cert_expiry":      schema.String(),
		"cert_sans":        schema.Array(schema.String()),
		"certificate":      certificateSchema, // Nested certificate object (only present for HTTPS)
		"host":             schema.String(),   // Extracted host/IP from URL (for cross-tool linking)
		"port":             schema.Int(),      // Extracted port from URL (for cross-tool linking)
		"scheme":           schema.String(),   // http or https (for protocol detection)
	}).WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "endpoint",
		IDTemplate: "endpoint:{.url}",
		Properties: []schema.PropertyMapping{
			schema.PropMap("url", "url"),
			schema.PropMap("status_code", "status_code"),
			schema.PropMap("title", "page_title"),
			schema.PropMap("content_type", "content_type"),
			schema.PropMap("server", "server"),
			schema.PropMap("x_powered_by", "x_powered_by"),
			schema.PropMap("final_url", "final_url"),
			schema.PropMap("cert_issuer", "tls_cert_issuer"),
			schema.PropMap("cert_subject", "tls_cert_subject"),
			schema.PropMap("cert_expiry", "tls_cert_expiry"),
			schema.PropMap("cert_sans", "tls_cert_sans"),
			schema.PropMap("host", "host"),
			schema.PropMap("port", "port"),
			schema.PropMap("scheme", "scheme"),
		},
		Relationships: []schema.RelationshipMapping{
			// Link agent run to discovered endpoint
			schema.Rel("DISCOVERED", "agent_run:{_context.agent_run_id}", "endpoint:{.url}"),
			// Link endpoint to certificate (when certificate data is present)
			schema.Rel("SERVES_CERTIFICATE", "endpoint:{.url}", "certificate:{.certificate.subject}"),
			// Cross-tool relationship: Link endpoint to underlying port from nmap/masscan
			// This enables attack chain traversal: subdomain → host → port → endpoint
			schema.Rel("HAS_ENDPOINT", "port:{.host}:{.port}:tcp", "endpoint:{.url}"),
			// Direct link to host for easier traversal
			schema.Rel("HOSTED_ON", "endpoint:{.url}", "host:{.host}"),
		},
	})

	return schema.Object(map[string]schema.JSON{
		"results":      schema.Array(resultSchema),
		"total_probed": schema.Int(),
		"alive_count":  schema.Int(),
		"scan_time_ms": schema.Int(),
	})
}
