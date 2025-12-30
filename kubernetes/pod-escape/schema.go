package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the pod-escape tool
func InputSchema() schema.JSON {
	actionSchema := schema.String()
	actionSchema.Description = "Action: scan, analyze-pod, find-privileged, check-capabilities, analyze-mounts"

	namespaceSchema := schema.String()
	namespaceSchema.Description = "Namespace to scan (optional)"

	allNamespacesSchema := schema.Bool()
	allNamespacesSchema.Description = "Scan all namespaces"

	podNameSchema := schema.String()
	podNameSchema.Description = "Specific pod name to analyze"

	labelSelectorSchema := schema.String()
	labelSelectorSchema.Description = "Label selector to filter pods"

	checkPrivilegedSchema := schema.Bool()
	checkPrivilegedSchema.Description = "Check for privileged containers (default: true)"

	checkHostPIDSchema := schema.Bool()
	checkHostPIDSchema.Description = "Check for hostPID (default: true)"

	checkHostNetworkSchema := schema.Bool()
	checkHostNetworkSchema.Description = "Check for hostNetwork (default: true)"

	checkHostPathSchema := schema.Bool()
	checkHostPathSchema.Description = "Check for dangerous hostPath mounts (default: true)"

	checkCapabilitiesSchema := schema.Bool()
	checkCapabilitiesSchema.Description = "Check for dangerous capabilities (default: true)"

	kubeconfigSchema := schema.String()
	kubeconfigSchema.Description = "Path to kubeconfig file (optional)"

	contextSchema := schema.String()
	contextSchema.Description = "Kubernetes context to use (optional)"

	timeoutSchema := schema.Int()
	timeoutSchema.Description = "Timeout in seconds (optional, default: 60)"

	return schema.Object(map[string]schema.JSON{
		"action":            actionSchema,
		"namespace":         namespaceSchema,
		"all_namespaces":    allNamespacesSchema,
		"pod_name":          podNameSchema,
		"label_selector":    labelSelectorSchema,
		"check_privileged":  checkPrivilegedSchema,
		"check_host_pid":    checkHostPIDSchema,
		"check_host_network": checkHostNetworkSchema,
		"check_host_path":   checkHostPathSchema,
		"check_capabilities": checkCapabilitiesSchema,
		"kubeconfig":        kubeconfigSchema,
		"context":           contextSchema,
		"timeout":           timeoutSchema,
	}, "action")
}

// OutputSchema defines the output schema for the pod-escape tool
func OutputSchema() schema.JSON {
	successSchema := schema.Bool()
	successSchema.Description = "Whether the action succeeded"

	podsScannedSchema := schema.Int()
	podsScannedSchema.Description = "Number of pods scanned"

	vulnerablePodsSchema := schema.Array(schema.Any())
	vulnerablePodsSchema.Description = "Pods with escape vectors"

	vulnerableCountSchema := schema.Int()
	vulnerableCountSchema.Description = "Number of vulnerable pods"

	// Escape vectors
	escapeVectorsSchema := schema.Array(schema.Any())
	escapeVectorsSchema.Description = "Detailed escape vectors found"

	// Categorized findings
	privilegedPodsSchema := schema.Array(schema.Any())
	privilegedPodsSchema.Description = "Pods running as privileged"

	hostPIDPodsSchema := schema.Array(schema.Any())
	hostPIDPodsSchema.Description = "Pods with hostPID"

	hostNetworkPodsSchema := schema.Array(schema.Any())
	hostNetworkPodsSchema.Description = "Pods with hostNetwork"

	dangerousMountsSchema := schema.Array(schema.Any())
	dangerousMountsSchema.Description = "Pods with dangerous host mounts"

	dangerousCapabilitiesSchema := schema.Array(schema.Any())
	dangerousCapabilitiesSchema.Description = "Pods with dangerous capabilities"

	// Summary
	summarySchema := schema.Object(nil)
	summarySchema.Description = "Summary of findings by category"

	executionTimeSchema := schema.Int()
	executionTimeSchema.Description = "Execution time in milliseconds"

	errorSchema := schema.String()
	errorSchema.Description = "Error message if failed"

	return schema.Object(map[string]schema.JSON{
		"success":                 successSchema,
		"pods_scanned":            podsScannedSchema,
		"vulnerable_pods":         vulnerablePodsSchema,
		"vulnerable_count":        vulnerableCountSchema,
		"escape_vectors":          escapeVectorsSchema,
		"privileged_pods":         privilegedPodsSchema,
		"host_pid_pods":           hostPIDPodsSchema,
		"host_network_pods":       hostNetworkPodsSchema,
		"dangerous_mounts":        dangerousMountsSchema,
		"dangerous_capabilities":  dangerousCapabilitiesSchema,
		"summary":                 summarySchema,
		"execution_time_ms":       executionTimeSchema,
		"error":                   errorSchema,
	})
}
