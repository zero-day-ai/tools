package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the network-policy-test tool
func InputSchema() schema.JSON {
	actionSchema := schema.String()
	actionSchema.Description = "Action: list-policies, test-connectivity, test-egress, test-metadata, analyze-gaps"

	namespaceSchema := schema.String()
	namespaceSchema.Description = "Namespace to test (optional)"

	allNamespacesSchema := schema.Bool()
	allNamespacesSchema.Description = "Check all namespaces"

	sourcePodSchema := schema.String()
	sourcePodSchema.Description = "Source pod for connectivity test (name or label selector)"

	targetHostSchema := schema.String()
	targetHostSchema.Description = "Target host or IP for connectivity test"

	targetPortSchema := schema.Int()
	targetPortSchema.Description = "Target port for connectivity test"

	protocolSchema := schema.String()
	protocolSchema.Description = "Protocol: tcp, udp (default: tcp)"

	metadataIPSchema := schema.String()
	metadataIPSchema.Description = "Cloud metadata IP to test (default: 169.254.169.254)"

	kubeconfigSchema := schema.String()
	kubeconfigSchema.Description = "Path to kubeconfig file (optional)"

	contextSchema := schema.String()
	contextSchema.Description = "Kubernetes context to use (optional)"

	timeoutSchema := schema.Int()
	timeoutSchema.Description = "Timeout in seconds (optional, default: 30)"

	return schema.Object(map[string]schema.JSON{
		"action":         actionSchema,
		"namespace":      namespaceSchema,
		"all_namespaces": allNamespacesSchema,
		"source_pod":     sourcePodSchema,
		"target_host":    targetHostSchema,
		"target_port":    targetPortSchema,
		"protocol":       protocolSchema,
		"metadata_ip":    metadataIPSchema,
		"kubeconfig":     kubeconfigSchema,
		"context":        contextSchema,
		"timeout":        timeoutSchema,
	}, "action")
}

// OutputSchema defines the output schema for the network-policy-test tool
func OutputSchema() schema.JSON {
	successSchema := schema.Bool()
	successSchema.Description = "Whether the action succeeded"

	// Network policies
	policiesSchema := schema.Array(schema.Any())
	policiesSchema.Description = "List of network policies"

	policyCountSchema := schema.Int()
	policyCountSchema.Description = "Number of network policies"

	// Connectivity test results
	connectivitySchema := schema.Object(map[string]schema.JSON{
		"reachable": schema.Bool(),
		"latency":   schema.String(),
		"error":     schema.String(),
	})
	connectivitySchema.Description = "Connectivity test result"

	// Egress test results
	egressTestsSchema := schema.Array(schema.Any())
	egressTestsSchema.Description = "Egress test results"

	// Metadata access test
	metadataAccessibleSchema := schema.Bool()
	metadataAccessibleSchema.Description = "Whether metadata service is accessible"

	metadataResponseSchema := schema.String()
	metadataResponseSchema.Description = "Metadata service response snippet"

	// Gap analysis
	gapsSchema := schema.Array(schema.Any())
	gapsSchema.Description = "Security gaps found in network policies"

	unprotectedPodsSchema := schema.Array(schema.Any())
	unprotectedPodsSchema.Description = "Pods without network policy coverage"

	namespaceCoverageSchema := schema.Object(nil)
	namespaceCoverageSchema.Description = "Namespace-level policy coverage"

	executionTimeSchema := schema.Int()
	executionTimeSchema.Description = "Execution time in milliseconds"

	errorSchema := schema.String()
	errorSchema.Description = "Error message if failed"

	return schema.Object(map[string]schema.JSON{
		"success":              successSchema,
		"policies":             policiesSchema,
		"policy_count":         policyCountSchema,
		"connectivity":         connectivitySchema,
		"egress_tests":         egressTestsSchema,
		"metadata_accessible":  metadataAccessibleSchema,
		"metadata_response":    metadataResponseSchema,
		"gaps":                 gapsSchema,
		"unprotected_pods":     unprotectedPodsSchema,
		"namespace_coverage":   namespaceCoverageSchema,
		"execution_time_ms":    executionTimeSchema,
		"error":                errorSchema,
	})
}
