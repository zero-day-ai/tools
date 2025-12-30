package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the crictl tool
func InputSchema() schema.JSON {
	actionSchema := schema.String()
	actionSchema.Description = "Action: detect, list-containers, inspect, exec, logs, images, socket-check"

	runtimeSchema := schema.String()
	runtimeSchema.Description = "Runtime: containerd, docker, crio, auto (auto-detected by default)"

	containerIDSchema := schema.String()
	containerIDSchema.Description = "Container ID for inspect/exec/logs operations"

	commandSchema := schema.Array(schema.String())
	commandSchema.Description = "Command to execute in container (for exec action)"

	socketPathSchema := schema.String()
	socketPathSchema.Description = "Custom socket path (optional)"

	namespaceSchema := schema.String()
	namespaceSchema.Description = "Container namespace filter (optional)"

	allSchema := schema.Bool()
	allSchema.Description = "Show all containers including stopped (for list-containers)"

	tailSchema := schema.Int()
	tailSchema.Description = "Number of log lines to show (for logs action)"

	timeoutSchema := schema.Int()
	timeoutSchema.Description = "Timeout in seconds (optional, default: 30)"

	return schema.Object(map[string]schema.JSON{
		"action":       actionSchema,
		"runtime":      runtimeSchema,
		"container_id": containerIDSchema,
		"command":      commandSchema,
		"socket_path":  socketPathSchema,
		"namespace":    namespaceSchema,
		"all":          allSchema,
		"tail":         tailSchema,
		"timeout":      timeoutSchema,
	}, "action")
}

// OutputSchema defines the output schema for the crictl tool
func OutputSchema() schema.JSON {
	successSchema := schema.Bool()
	successSchema.Description = "Whether the action succeeded"

	runtimeSchema := schema.String()
	runtimeSchema.Description = "Detected container runtime"

	runtimeVersionSchema := schema.String()
	runtimeVersionSchema.Description = "Runtime version"

	socketPathSchema := schema.String()
	socketPathSchema.Description = "Socket path used"

	socketAccessibleSchema := schema.Bool()
	socketAccessibleSchema.Description = "Whether socket is accessible"

	containersSchema := schema.Array(schema.Any())
	containersSchema.Description = "List of containers"

	containerCountSchema := schema.Int()
	containerCountSchema.Description = "Number of containers"

	containerInfoSchema := schema.Any()
	containerInfoSchema.Description = "Container inspection info"

	execOutputSchema := schema.String()
	execOutputSchema.Description = "Output from exec command"

	execExitCodeSchema := schema.Int()
	execExitCodeSchema.Description = "Exit code from exec command"

	logsSchema := schema.String()
	logsSchema.Description = "Container logs"

	imagesSchema := schema.Array(schema.Any())
	imagesSchema.Description = "List of images"

	escapeVectorsSchema := schema.Array(schema.Any())
	escapeVectorsSchema.Description = "Potential escape vectors found"

	executionTimeSchema := schema.Int()
	executionTimeSchema.Description = "Execution time in milliseconds"

	errorSchema := schema.String()
	errorSchema.Description = "Error message if failed"

	return schema.Object(map[string]schema.JSON{
		"success":           successSchema,
		"runtime":           runtimeSchema,
		"runtime_version":   runtimeVersionSchema,
		"socket_path":       socketPathSchema,
		"socket_accessible": socketAccessibleSchema,
		"containers":        containersSchema,
		"container_count":   containerCountSchema,
		"container_info":    containerInfoSchema,
		"exec_output":       execOutputSchema,
		"exec_exit_code":    execExitCodeSchema,
		"logs":              logsSchema,
		"images":            imagesSchema,
		"escape_vectors":    escapeVectorsSchema,
		"execution_time_ms": executionTimeSchema,
		"error":             errorSchema,
	})
}
