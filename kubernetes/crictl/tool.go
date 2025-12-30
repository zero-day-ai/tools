package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson-tools-official/pkg/common"
	"github.com/zero-day-ai/gibson-tools-official/pkg/executor"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "crictl"
	ToolVersion     = "1.0.0"
	ToolDescription = "Container runtime interface tool for container inspection and escape verification"
)

// Known socket paths for different runtimes
var (
	containerdSockets = []string{
		"/run/containerd/containerd.sock",
		"/var/run/containerd/containerd.sock",
	}
	dockerSockets = []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
	}
	crioSockets = []string{
		"/var/run/crio/crio.sock",
		"/run/crio/crio.sock",
	}
)

// RuntimeInfo holds runtime detection info
type RuntimeInfo struct {
	Name       string
	Binary     string
	SocketPath string
	Available  bool
}

// ToolImpl implements the crictl tool
type ToolImpl struct{}

// NewTool creates a new crictl tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"kubernetes",
			"containers",
			"execution",
			"credential-access",
			"T1610", // Deploy Container
			"T1609", // Container Administration Command
			"T1611", // Escape to Host
		}).
		SetInputSchema(InputSchema()).
		SetOutputSchema(OutputSchema()).
		SetExecuteFunc((&ToolImpl{}).Execute)

	t, _ := tool.New(cfg)
	return &toolWithHealth{Tool: t, impl: &ToolImpl{}}
}

type toolWithHealth struct {
	tool.Tool
	impl *ToolImpl
}

func (t *toolWithHealth) Health(ctx context.Context) types.HealthStatus {
	return t.impl.Health(ctx)
}

// Execute implements the container runtime operations
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	start := time.Now()

	action := common.GetString(input, "action")
	if action == "" {
		return nil, fmt.Errorf("action is required")
	}

	timeout := 30 * time.Second
	if to := common.GetInt(input, "timeout"); to > 0 {
		timeout = time.Duration(to) * time.Second
	}

	var result map[string]any
	var err error

	switch action {
	case "detect":
		result, err = t.detectRuntime(ctx, input, timeout)
	case "list-containers":
		result, err = t.listContainers(ctx, input, timeout)
	case "inspect":
		result, err = t.inspectContainer(ctx, input, timeout)
	case "exec":
		result, err = t.execInContainer(ctx, input, timeout)
	case "logs":
		result, err = t.getContainerLogs(ctx, input, timeout)
	case "images":
		result, err = t.listImages(ctx, input, timeout)
	case "socket-check":
		result, err = t.checkSockets(ctx, input, timeout)
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}

	if err != nil {
		return map[string]any{
			"success":           false,
			"error":             err.Error(),
			"execution_time_ms": time.Since(start).Milliseconds(),
		}, nil
	}

	result["success"] = true
	result["execution_time_ms"] = time.Since(start).Milliseconds()
	return result, nil
}

// detectRuntime auto-detects the container runtime
func (t *ToolImpl) detectRuntime(ctx context.Context, input map[string]any, timeout time.Duration) (map[string]any, error) {
	customSocket := common.GetString(input, "socket_path")

	// Check for containerd
	if containerd := t.checkContainerd(ctx, customSocket, timeout); containerd.Available {
		return map[string]any{
			"runtime":           containerd.Name,
			"socket_path":       containerd.SocketPath,
			"socket_accessible": true,
		}, nil
	}

	// Check for Docker
	if docker := t.checkDocker(ctx, customSocket, timeout); docker.Available {
		return map[string]any{
			"runtime":           docker.Name,
			"socket_path":       docker.SocketPath,
			"socket_accessible": true,
		}, nil
	}

	// Check for CRI-O
	if crio := t.checkCRIO(ctx, customSocket, timeout); crio.Available {
		return map[string]any{
			"runtime":           crio.Name,
			"socket_path":       crio.SocketPath,
			"socket_accessible": true,
		}, nil
	}

	return map[string]any{
		"runtime":           "unknown",
		"socket_accessible": false,
	}, nil
}

func (t *ToolImpl) checkContainerd(ctx context.Context, customSocket string, timeout time.Duration) RuntimeInfo {
	info := RuntimeInfo{Name: "containerd", Binary: "crictl"}

	if !executor.BinaryExists("crictl") {
		return info
	}

	sockets := containerdSockets
	if customSocket != "" {
		sockets = []string{customSocket}
	}

	for _, socket := range sockets {
		if _, err := os.Stat(socket); err == nil {
			// Try to connect
			result, err := executor.Execute(ctx, executor.Config{
				Command: "crictl",
				Args:    []string{"--runtime-endpoint", "unix://" + socket, "version"},
				Timeout: timeout,
			})
			if err == nil && result.ExitCode == 0 {
				info.SocketPath = socket
				info.Available = true
				return info
			}
		}
	}
	return info
}

func (t *ToolImpl) checkDocker(ctx context.Context, customSocket string, timeout time.Duration) RuntimeInfo {
	info := RuntimeInfo{Name: "docker", Binary: "docker"}

	if !executor.BinaryExists("docker") {
		return info
	}

	sockets := dockerSockets
	if customSocket != "" {
		sockets = []string{customSocket}
	}

	for _, socket := range sockets {
		if _, err := os.Stat(socket); err == nil {
			result, err := executor.Execute(ctx, executor.Config{
				Command: "docker",
				Args:    []string{"-H", "unix://" + socket, "version", "--format", "json"},
				Timeout: timeout,
			})
			if err == nil && result.ExitCode == 0 {
				info.SocketPath = socket
				info.Available = true
				return info
			}
		}
	}
	return info
}

func (t *ToolImpl) checkCRIO(ctx context.Context, customSocket string, timeout time.Duration) RuntimeInfo {
	info := RuntimeInfo{Name: "crio", Binary: "crictl"}

	if !executor.BinaryExists("crictl") {
		return info
	}

	sockets := crioSockets
	if customSocket != "" {
		sockets = []string{customSocket}
	}

	for _, socket := range sockets {
		if _, err := os.Stat(socket); err == nil {
			result, err := executor.Execute(ctx, executor.Config{
				Command: "crictl",
				Args:    []string{"--runtime-endpoint", "unix://" + socket, "version"},
				Timeout: timeout,
			})
			if err == nil && result.ExitCode == 0 {
				info.SocketPath = socket
				info.Available = true
				return info
			}
		}
	}
	return info
}

// listContainers lists all containers
func (t *ToolImpl) listContainers(ctx context.Context, input map[string]any, timeout time.Duration) (map[string]any, error) {
	runtime := t.getRuntime(ctx, input, timeout)
	if !runtime.Available {
		return nil, fmt.Errorf("no accessible container runtime found")
	}

	var args []string
	var result *executor.Result
	var err error

	if runtime.Name == "docker" {
		args = []string{"-H", "unix://" + runtime.SocketPath, "ps", "--format", "json"}
		if common.GetBool(input, "all") {
			args = append(args[:3], append([]string{"-a"}, args[3:]...)...)
		}
		result, err = executor.Execute(ctx, executor.Config{
			Command: "docker",
			Args:    args,
			Timeout: timeout,
		})
	} else {
		args = []string{"--runtime-endpoint", "unix://" + runtime.SocketPath, "ps", "-o", "json"}
		if common.GetBool(input, "all") {
			args = append(args, "-a")
		}
		result, err = executor.Execute(ctx, executor.Config{
			Command: "crictl",
			Args:    args,
			Timeout: timeout,
		})
	}

	if err != nil && result == nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	containers := []any{}
	if len(result.Stdout) > 0 {
		// Try to parse JSON
		var parsed any
		if err := json.Unmarshal(result.Stdout, &parsed); err == nil {
			if arr, ok := parsed.([]any); ok {
				containers = arr
			} else if obj, ok := parsed.(map[string]any); ok {
				if items, ok := obj["containers"].([]any); ok {
					containers = items
				}
			}
		}
	}

	return map[string]any{
		"runtime":         runtime.Name,
		"socket_path":     runtime.SocketPath,
		"containers":      containers,
		"container_count": len(containers),
	}, nil
}

// inspectContainer inspects a specific container
func (t *ToolImpl) inspectContainer(ctx context.Context, input map[string]any, timeout time.Duration) (map[string]any, error) {
	containerID := common.GetString(input, "container_id")
	if containerID == "" {
		return nil, fmt.Errorf("container_id is required")
	}

	runtime := t.getRuntime(ctx, input, timeout)
	if !runtime.Available {
		return nil, fmt.Errorf("no accessible container runtime found")
	}

	var args []string
	var result *executor.Result
	var err error

	if runtime.Name == "docker" {
		args = []string{"-H", "unix://" + runtime.SocketPath, "inspect", containerID}
		result, err = executor.Execute(ctx, executor.Config{
			Command: "docker",
			Args:    args,
			Timeout: timeout,
		})
	} else {
		args = []string{"--runtime-endpoint", "unix://" + runtime.SocketPath, "inspect", containerID}
		result, err = executor.Execute(ctx, executor.Config{
			Command: "crictl",
			Args:    args,
			Timeout: timeout,
		})
	}

	if err != nil && result == nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	var containerInfo any
	if len(result.Stdout) > 0 {
		json.Unmarshal(result.Stdout, &containerInfo)
	}

	// Check for escape vectors
	escapeVectors := t.analyzeEscapeVectors(containerInfo)

	return map[string]any{
		"runtime":        runtime.Name,
		"socket_path":    runtime.SocketPath,
		"container_info": containerInfo,
		"escape_vectors": escapeVectors,
	}, nil
}

// analyzeEscapeVectors checks container config for escape opportunities
func (t *ToolImpl) analyzeEscapeVectors(containerInfo any) []any {
	vectors := []any{}

	// Handle both Docker and CRI formats
	infoMap, ok := containerInfo.(map[string]any)
	if !ok {
		// Docker returns array, get first element
		if arr, ok := containerInfo.([]any); ok && len(arr) > 0 {
			infoMap, ok = arr[0].(map[string]any)
			if !ok {
				return vectors
			}
		} else {
			return vectors
		}
	}

	// Check Docker format
	if hostConfig, ok := infoMap["HostConfig"].(map[string]any); ok {
		if priv, ok := hostConfig["Privileged"].(bool); ok && priv {
			vectors = append(vectors, map[string]any{
				"type":        "privileged",
				"severity":    "critical",
				"description": "Container is running in privileged mode",
				"technique":   "T1611",
			})
		}
		if pid, ok := hostConfig["PidMode"].(string); ok && pid == "host" {
			vectors = append(vectors, map[string]any{
				"type":        "host_pid",
				"severity":    "high",
				"description": "Container shares host PID namespace",
				"technique":   "T1611",
			})
		}
		if net, ok := hostConfig["NetworkMode"].(string); ok && net == "host" {
			vectors = append(vectors, map[string]any{
				"type":        "host_network",
				"severity":    "medium",
				"description": "Container shares host network namespace",
				"technique":   "T1611",
			})
		}
		if binds, ok := hostConfig["Binds"].([]any); ok {
			for _, bind := range binds {
				if s, ok := bind.(string); ok {
					if strings.HasPrefix(s, "/:/") || strings.Contains(s, "/var/run/docker.sock") {
						vectors = append(vectors, map[string]any{
							"type":        "host_path",
							"severity":    "critical",
							"description": fmt.Sprintf("Dangerous host path mounted: %s", s),
							"technique":   "T1611",
						})
					}
				}
			}
		}
	}

	// Check CRI format
	if info, ok := infoMap["info"].(map[string]any); ok {
		if linux, ok := info["linux"].(map[string]any); ok {
			if security, ok := linux["securityContext"].(map[string]any); ok {
				if priv, ok := security["privileged"].(bool); ok && priv {
					vectors = append(vectors, map[string]any{
						"type":        "privileged",
						"severity":    "critical",
						"description": "Container is running in privileged mode",
						"technique":   "T1611",
					})
				}
				if ns, ok := security["namespaceOptions"].(map[string]any); ok {
					if pid, ok := ns["pid"].(float64); ok && pid == 2 { // NODE mode
						vectors = append(vectors, map[string]any{
							"type":        "host_pid",
							"severity":    "high",
							"description": "Container shares host PID namespace",
							"technique":   "T1611",
						})
					}
				}
			}
		}
	}

	return vectors
}

// execInContainer executes a command in a container
func (t *ToolImpl) execInContainer(ctx context.Context, input map[string]any, timeout time.Duration) (map[string]any, error) {
	containerID := common.GetString(input, "container_id")
	if containerID == "" {
		return nil, fmt.Errorf("container_id is required")
	}

	command := common.GetStringSlice(input, "command")
	if len(command) == 0 {
		return nil, fmt.Errorf("command is required")
	}

	runtime := t.getRuntime(ctx, input, timeout)
	if !runtime.Available {
		return nil, fmt.Errorf("no accessible container runtime found")
	}

	var args []string
	var result *executor.Result
	var err error

	if runtime.Name == "docker" {
		args = []string{"-H", "unix://" + runtime.SocketPath, "exec", containerID}
		args = append(args, command...)
		result, err = executor.Execute(ctx, executor.Config{
			Command: "docker",
			Args:    args,
			Timeout: timeout,
		})
	} else {
		args = []string{"--runtime-endpoint", "unix://" + runtime.SocketPath, "exec", containerID}
		args = append(args, command...)
		result, err = executor.Execute(ctx, executor.Config{
			Command: "crictl",
			Args:    args,
			Timeout: timeout,
		})
	}

	exitCode := -1
	output := ""
	if result != nil {
		exitCode = result.ExitCode
		output = string(result.Stdout) + string(result.Stderr)
	}
	if err != nil && result == nil {
		output = err.Error()
	}

	return map[string]any{
		"runtime":        runtime.Name,
		"exec_output":    output,
		"exec_exit_code": exitCode,
	}, nil
}

// getContainerLogs gets container logs
func (t *ToolImpl) getContainerLogs(ctx context.Context, input map[string]any, timeout time.Duration) (map[string]any, error) {
	containerID := common.GetString(input, "container_id")
	if containerID == "" {
		return nil, fmt.Errorf("container_id is required")
	}

	runtime := t.getRuntime(ctx, input, timeout)
	if !runtime.Available {
		return nil, fmt.Errorf("no accessible container runtime found")
	}

	tail := common.GetInt(input, "tail")
	if tail == 0 {
		tail = 100
	}

	var args []string
	var result *executor.Result
	var err error

	if runtime.Name == "docker" {
		args = []string{"-H", "unix://" + runtime.SocketPath, "logs", "--tail", fmt.Sprintf("%d", tail), containerID}
		result, err = executor.Execute(ctx, executor.Config{
			Command: "docker",
			Args:    args,
			Timeout: timeout,
		})
	} else {
		args = []string{"--runtime-endpoint", "unix://" + runtime.SocketPath, "logs", "--tail", fmt.Sprintf("%d", tail), containerID}
		result, err = executor.Execute(ctx, executor.Config{
			Command: "crictl",
			Args:    args,
			Timeout: timeout,
		})
	}

	logs := ""
	if result != nil {
		logs = string(result.Stdout) + string(result.Stderr)
	}
	if err != nil && result == nil {
		return nil, fmt.Errorf("failed to get logs: %w", err)
	}

	return map[string]any{
		"runtime": runtime.Name,
		"logs":    logs,
	}, nil
}

// listImages lists container images
func (t *ToolImpl) listImages(ctx context.Context, input map[string]any, timeout time.Duration) (map[string]any, error) {
	runtime := t.getRuntime(ctx, input, timeout)
	if !runtime.Available {
		return nil, fmt.Errorf("no accessible container runtime found")
	}

	var args []string
	var result *executor.Result
	var err error

	if runtime.Name == "docker" {
		args = []string{"-H", "unix://" + runtime.SocketPath, "images", "--format", "json"}
		result, err = executor.Execute(ctx, executor.Config{
			Command: "docker",
			Args:    args,
			Timeout: timeout,
		})
	} else {
		args = []string{"--runtime-endpoint", "unix://" + runtime.SocketPath, "images", "-o", "json"}
		result, err = executor.Execute(ctx, executor.Config{
			Command: "crictl",
			Args:    args,
			Timeout: timeout,
		})
	}

	if err != nil && result == nil {
		return nil, fmt.Errorf("failed to list images: %w", err)
	}

	images := []any{}
	if len(result.Stdout) > 0 {
		var parsed any
		if err := json.Unmarshal(result.Stdout, &parsed); err == nil {
			if arr, ok := parsed.([]any); ok {
				images = arr
			} else if obj, ok := parsed.(map[string]any); ok {
				if items, ok := obj["images"].([]any); ok {
					images = items
				}
			}
		}
	}

	return map[string]any{
		"runtime": runtime.Name,
		"images":  images,
	}, nil
}

// checkSockets checks for accessible container runtime sockets
func (t *ToolImpl) checkSockets(ctx context.Context, input map[string]any, timeout time.Duration) (map[string]any, error) {
	results := []any{}

	allSockets := append(append(containerdSockets, dockerSockets...), crioSockets...)

	for _, socket := range allSockets {
		info := map[string]any{
			"path":       socket,
			"exists":     false,
			"accessible": false,
			"runtime":    "unknown",
		}

		if _, err := os.Stat(socket); err == nil {
			info["exists"] = true

			// Determine runtime type
			if strings.Contains(socket, "containerd") {
				info["runtime"] = "containerd"
			} else if strings.Contains(socket, "docker") {
				info["runtime"] = "docker"
			} else if strings.Contains(socket, "crio") {
				info["runtime"] = "crio"
			}

			// Check accessibility
			fi, err := os.Stat(socket)
			if err == nil {
				info["mode"] = fi.Mode().String()
				// Try to open
				if f, err := os.Open(socket); err == nil {
					f.Close()
					info["accessible"] = true
				}
			}
		}

		if info["exists"].(bool) {
			results = append(results, info)
		}
	}

	return map[string]any{
		"sockets": results,
	}, nil
}

// getRuntime determines which runtime to use
func (t *ToolImpl) getRuntime(ctx context.Context, input map[string]any, timeout time.Duration) RuntimeInfo {
	runtimeName := common.GetString(input, "runtime")
	customSocket := common.GetString(input, "socket_path")

	if runtimeName == "" || runtimeName == "auto" {
		// Auto-detect
		if containerd := t.checkContainerd(ctx, customSocket, timeout); containerd.Available {
			return containerd
		}
		if docker := t.checkDocker(ctx, customSocket, timeout); docker.Available {
			return docker
		}
		if crio := t.checkCRIO(ctx, customSocket, timeout); crio.Available {
			return crio
		}
		return RuntimeInfo{}
	}

	switch runtimeName {
	case "containerd":
		return t.checkContainerd(ctx, customSocket, timeout)
	case "docker":
		return t.checkDocker(ctx, customSocket, timeout)
	case "crio":
		return t.checkCRIO(ctx, customSocket, timeout)
	default:
		return RuntimeInfo{}
	}
}

// Health checks if any container runtime is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	if executor.BinaryExists("crictl") {
		return types.NewHealthyStatus("crictl binary available")
	}
	if executor.BinaryExists("docker") {
		return types.NewHealthyStatus("docker binary available")
	}
	return types.NewUnhealthyStatus("no container runtime binaries found (crictl or docker)", nil)
}
