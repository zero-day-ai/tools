package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the secret-dump tool
func InputSchema() schema.JSON {
	actionSchema := schema.String()
	actionSchema.Description = "Action: list, dump, decode, search, analyze-types"

	namespaceSchema := schema.String()
	namespaceSchema.Description = "Namespace to query (optional)"

	allNamespacesSchema := schema.Bool()
	allNamespacesSchema.Description = "Query all namespaces"

	secretNameSchema := schema.String()
	secretNameSchema.Description = "Specific secret name to dump"

	secretTypeSchema := schema.String()
	secretTypeSchema.Description = "Filter by secret type (e.g., kubernetes.io/service-account-token, kubernetes.io/tls)"

	labelSelectorSchema := schema.String()
	labelSelectorSchema.Description = "Label selector to filter secrets"

	decodeValuesSchema := schema.Bool()
	decodeValuesSchema.Description = "Decode base64 values (default: true)"

	redactSensitiveSchema := schema.Bool()
	redactSensitiveSchema.Description = "Redact actual secret values in output (default: false)"

	searchPatternSchema := schema.String()
	searchPatternSchema.Description = "Pattern to search for in secret values (for action=search)"

	kubeconfigSchema := schema.String()
	kubeconfigSchema.Description = "Path to kubeconfig file (optional)"

	contextSchema := schema.String()
	contextSchema.Description = "Kubernetes context to use (optional)"

	timeoutSchema := schema.Int()
	timeoutSchema.Description = "Timeout in seconds (optional, default: 60)"

	return schema.Object(map[string]schema.JSON{
		"action":           actionSchema,
		"namespace":        namespaceSchema,
		"all_namespaces":   allNamespacesSchema,
		"secret_name":      secretNameSchema,
		"secret_type":      secretTypeSchema,
		"label_selector":   labelSelectorSchema,
		"decode_values":    decodeValuesSchema,
		"redact_sensitive": redactSensitiveSchema,
		"search_pattern":   searchPatternSchema,
		"kubeconfig":       kubeconfigSchema,
		"context":          contextSchema,
		"timeout":          timeoutSchema,
	}, "action")
}

// OutputSchema defines the output schema for the secret-dump tool
func OutputSchema() schema.JSON {
	successSchema := schema.Bool()
	successSchema.Description = "Whether the action succeeded"

	secretsSchema := schema.Array(schema.Any())
	secretsSchema.Description = "List of secrets"

	secretCountSchema := schema.Int()
	secretCountSchema.Description = "Number of secrets found"

	secretDataSchema := schema.Object(nil)
	secretDataSchema.Description = "Decoded secret data (for dump action)"

	typeAnalysisSchema := schema.Object(nil)
	typeAnalysisSchema.Description = "Breakdown of secret types"

	searchResultsSchema := schema.Array(schema.Any())
	searchResultsSchema.Description = "Search results matching pattern"

	// Sensitive findings
	credentialsFoundSchema := schema.Array(schema.Any())
	credentialsFoundSchema.Description = "Potential credentials identified"

	tokensFoundSchema := schema.Array(schema.Any())
	tokensFoundSchema.Description = "Service account tokens found"

	tlsSecretsSchema := schema.Array(schema.Any())
	tlsSecretsSchema.Description = "TLS/SSL certificates found"

	executionTimeSchema := schema.Int()
	executionTimeSchema.Description = "Execution time in milliseconds"

	errorSchema := schema.String()
	errorSchema.Description = "Error message if failed"

	return schema.Object(map[string]schema.JSON{
		"success":            successSchema,
		"secrets":            secretsSchema,
		"secret_count":       secretCountSchema,
		"secret_data":        secretDataSchema,
		"type_analysis":      typeAnalysisSchema,
		"search_results":     searchResultsSchema,
		"credentials_found":  credentialsFoundSchema,
		"tokens_found":       tokensFoundSchema,
		"tls_secrets":        tlsSecretsSchema,
		"execution_time_ms":  executionTimeSchema,
		"error":              errorSchema,
	})
}
