package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the kubectl tool
func InputSchema() schema.JSON {
	commandSchema := schema.String()
	commandSchema.Description = "kubectl command to execute (e.g., get, describe, create, delete, apply)"

	argsSchema := schema.Array(schema.String())
	argsSchema.Description = "Additional arguments for the command"

	resourceSchema := schema.String()
	resourceSchema.Description = "Resource type (e.g., pods, services, deployments, secrets, configmaps)"

	nameSchema := schema.String()
	nameSchema.Description = "Resource name (optional)"

	namespaceSchema := schema.String()
	namespaceSchema.Description = "Namespace to operate in (optional, uses current context if not specified)"

	allNamespacesSchema := schema.Bool()
	allNamespacesSchema.Description = "Query all namespaces (optional)"

	kubeconfigSchema := schema.String()
	kubeconfigSchema.Description = "Path to kubeconfig file (optional)"

	contextSchema := schema.String()
	contextSchema.Description = "Kubernetes context to use (optional)"

	selectorSchema := schema.String()
	selectorSchema.Description = "Label selector (e.g., app=nginx)"

	fieldSelectorSchema := schema.String()
	fieldSelectorSchema.Description = "Field selector (e.g., status.phase=Running)"

	outputSchema := schema.String()
	outputSchema.Description = "Output format: json, yaml, wide, name (default: json)"

	rawSchema := schema.String()
	rawSchema.Description = "Raw kubectl command to execute (bypasses structured input)"

	timeoutSchema := schema.Int()
	timeoutSchema.Description = "Timeout in seconds (optional, default: 60)"

	return schema.Object(map[string]schema.JSON{
		"command":         commandSchema,
		"args":            argsSchema,
		"resource":        resourceSchema,
		"name":            nameSchema,
		"namespace":       namespaceSchema,
		"all_namespaces":  allNamespacesSchema,
		"kubeconfig":      kubeconfigSchema,
		"context":         contextSchema,
		"selector":        selectorSchema,
		"field_selector":  fieldSelectorSchema,
		"output":          outputSchema,
		"raw":             rawSchema,
		"timeout":         timeoutSchema,
	}) // No required fields - can use raw or structured input
}

// OutputSchema defines the output schema for the kubectl tool
func OutputSchema() schema.JSON {
	successSchema := schema.Bool()
	successSchema.Description = "Whether the command succeeded"

	exitCodeSchema := schema.Int()
	exitCodeSchema.Description = "Exit code of the kubectl command"

	stdoutSchema := schema.String()
	stdoutSchema.Description = "Standard output from kubectl"

	stderrSchema := schema.String()
	stderrSchema.Description = "Standard error from kubectl"

	// Parsed data when output is JSON
	dataSchema := schema.Any()
	dataSchema.Description = "Parsed JSON data from kubectl output (if applicable)"

	itemsSchema := schema.Array(schema.Any())
	itemsSchema.Description = "List of resources if command returned a list"

	itemCountSchema := schema.Int()
	itemCountSchema.Description = "Number of items returned"

	executionTimeSchema := schema.Int()
	executionTimeSchema.Description = "Execution time in milliseconds"

	commandExecutedSchema := schema.String()
	commandExecutedSchema.Description = "The actual command that was executed"

	return schema.Object(map[string]schema.JSON{
		"success":          successSchema,
		"exit_code":        exitCodeSchema,
		"stdout":           stdoutSchema,
		"stderr":           stderrSchema,
		"data":             dataSchema,
		"items":            itemsSchema,
		"item_count":       itemCountSchema,
		"execution_time_ms": executionTimeSchema,
		"command_executed": commandExecutedSchema,
	})
}
