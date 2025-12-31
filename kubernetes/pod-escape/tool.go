package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	sdkinput "github.com/zero-day-ai/sdk/input"
	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "pod-escape"
	ToolVersion     = "1.0.0"
	ToolDescription = "Kubernetes pod security analysis and container escape vector detection"
	BinaryName      = "kubectl"
)

// Dangerous capabilities that can lead to container escape
var dangerousCapabilities = map[string]string{
	"SYS_ADMIN":     "Allows many system administration operations - critical escape vector",
	"SYS_PTRACE":    "Allows process tracing - can inject into other processes",
	"SYS_MODULE":    "Allows kernel module loading - can load malicious modules",
	"DAC_READ_SEARCH": "Bypass file read permission checks - read any file",
	"DAC_OVERRIDE":  "Bypass file permission checks - write any file",
	"NET_ADMIN":     "Allows network administration - can sniff traffic",
	"NET_RAW":       "Allows raw socket access - can craft packets",
	"SYS_RAWIO":     "Allows raw I/O port operations - direct hardware access",
	"MKNOD":         "Allows creation of device files - can create block devices",
	"SYS_CHROOT":    "Allows chroot - can escape chroot jail",
	"SETUID":        "Allows arbitrary setuid - can become any user",
	"SETGID":        "Allows arbitrary setgid - can become any group",
}

// Dangerous host paths
var dangerousHostPaths = []string{
	"/",              // Root filesystem
	"/etc",           // System configuration
	"/var/run/docker.sock", // Docker socket
	"/var/run/containerd", // Containerd socket
	"/var/run/crio",  // CRI-O socket
	"/proc",          // Process filesystem
	"/sys",           // System filesystem
	"/dev",           // Device files
	"/root",          // Root home directory
	"/home",          // User home directories
	"/var/lib/kubelet", // Kubelet data
	"/etc/kubernetes", // Kubernetes configs
}

// ToolImpl implements the pod-escape tool
type ToolImpl struct{}

// NewTool creates a new pod-escape tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"kubernetes",
			"privilege-escalation",
			"reconnaissance",
			"T1611", // Escape to Host
			"T1610", // Deploy Container
			"T1068", // Exploitation for Privilege Escalation
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

// Execute implements the pod escape analysis logic
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	start := time.Now()

	action := sdkinput.GetString(input, "action", "")
	if action == "" {
		return nil, fmt.Errorf("action is required")
	}

	timeout := 60 * time.Second
	if to := sdkinput.GetInt(input, "timeout", 0); to > 0 {
		timeout = time.Duration(to) * time.Second
	}

	env := os.Environ()
	if kubeconfig := sdkinput.GetString(input, "kubeconfig", ""); kubeconfig != "" {
		env = append(env, fmt.Sprintf("KUBECONFIG=%s", kubeconfig))
	}

	var result map[string]any
	var err error

	switch action {
	case "scan":
		result, err = t.scanPods(ctx, input, env, timeout)
	case "analyze-pod":
		result, err = t.analyzePod(ctx, input, env, timeout)
	case "find-privileged":
		result, err = t.findPrivileged(ctx, input, env, timeout)
	case "check-capabilities":
		result, err = t.checkCapabilities(ctx, input, env, timeout)
	case "analyze-mounts":
		result, err = t.analyzeMounts(ctx, input, env, timeout)
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

// PodSpec represents a Kubernetes pod spec for analysis
type PodSpec struct {
	Name       string
	Namespace  string
	Containers []ContainerSpec
	HostPID    bool
	HostNetwork bool
	HostIPC    bool
	Volumes    []VolumeSpec
}

// ContainerSpec represents a container spec
type ContainerSpec struct {
	Name          string
	Image         string
	Privileged    bool
	Capabilities  []string
	RunAsRoot     bool
	ReadOnlyRoot  bool
	VolumeMounts  []string
}

// VolumeSpec represents a volume spec
type VolumeSpec struct {
	Name     string
	HostPath string
	Type     string
}

// scanPods scans all pods for escape vectors
func (t *ToolImpl) scanPods(ctx context.Context, input map[string]any, env []string, timeout time.Duration) (map[string]any, error) {
	pods, err := t.getPods(ctx, input, env, timeout)
	if err != nil {
		return nil, err
	}

	vulnerablePods := []any{}
	escapeVectors := []any{}
	privilegedPods := []any{}
	hostPIDPods := []any{}
	hostNetworkPods := []any{}
	dangerousMounts := []any{}
	dangerousCaps := []any{}

	for _, pod := range pods {
		vectors := t.analyzeEscapeVectors(pod)

		if len(vectors) > 0 {
			podSummary := map[string]any{
				"name":           pod.Name,
				"namespace":      pod.Namespace,
				"vector_count":   len(vectors),
				"vectors":        vectors,
			}
			vulnerablePods = append(vulnerablePods, podSummary)

			for _, v := range vectors {
				vector := v.(map[string]any)
				vector["pod_name"] = pod.Name
				vector["namespace"] = pod.Namespace
				escapeVectors = append(escapeVectors, vector)

				switch vector["type"] {
				case "privileged":
					privilegedPods = append(privilegedPods, podSummary)
				case "host_pid":
					hostPIDPods = append(hostPIDPods, podSummary)
				case "host_network":
					hostNetworkPods = append(hostNetworkPods, podSummary)
				case "dangerous_mount":
					dangerousMounts = append(dangerousMounts, podSummary)
				case "dangerous_capability":
					dangerousCaps = append(dangerousCaps, podSummary)
				}
			}
		}
	}

	return map[string]any{
		"pods_scanned":            len(pods),
		"vulnerable_pods":         vulnerablePods,
		"vulnerable_count":        len(vulnerablePods),
		"escape_vectors":          escapeVectors,
		"privileged_pods":         privilegedPods,
		"host_pid_pods":           hostPIDPods,
		"host_network_pods":       hostNetworkPods,
		"dangerous_mounts":        dangerousMounts,
		"dangerous_capabilities":  dangerousCaps,
		"summary": map[string]any{
			"total_pods":       len(pods),
			"vulnerable_pods":  len(vulnerablePods),
			"total_vectors":    len(escapeVectors),
			"privileged":       len(privilegedPods),
			"host_pid":         len(hostPIDPods),
			"host_network":     len(hostNetworkPods),
			"dangerous_mounts": len(dangerousMounts),
			"dangerous_caps":   len(dangerousCaps),
		},
	}, nil
}

// analyzePod analyzes a specific pod
func (t *ToolImpl) analyzePod(ctx context.Context, input map[string]any, env []string, timeout time.Duration) (map[string]any, error) {
	podName := sdkinput.GetString(input, "pod_name", "")
	if podName == "" {
		return nil, fmt.Errorf("pod_name is required for analyze-pod action")
	}

	args := t.buildBaseArgs(input)
	args = append(args, "get", "pod", podName, "-o", "json")

	if ns := sdkinput.GetString(input, "namespace", ""); ns != "" {
		args = append(args, "-n", ns)
	}

	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Env:     env,
		Timeout: timeout,
	})

	if err != nil && result == nil {
		return nil, fmt.Errorf("failed to get pod: %w", err)
	}

	if result.ExitCode != 0 {
		return nil, fmt.Errorf("pod not found: %s", string(result.Stderr))
	}

	var rawPod map[string]any
	if err := json.Unmarshal(result.Stdout, &rawPod); err != nil {
		return nil, fmt.Errorf("failed to parse pod: %w", err)
	}

	pod := t.parsePod(rawPod)
	vectors := t.analyzeEscapeVectors(pod)

	return map[string]any{
		"pods_scanned":    1,
		"vulnerable_count": len(vectors),
		"escape_vectors":   vectors,
		"vulnerable_pods": []any{
			map[string]any{
				"name":         pod.Name,
				"namespace":    pod.Namespace,
				"host_pid":     pod.HostPID,
				"host_network": pod.HostNetwork,
				"host_ipc":     pod.HostIPC,
				"containers":   pod.Containers,
				"volumes":      pod.Volumes,
				"vector_count": len(vectors),
			},
		},
	}, nil
}

// findPrivileged finds all privileged pods
func (t *ToolImpl) findPrivileged(ctx context.Context, input map[string]any, env []string, timeout time.Duration) (map[string]any, error) {
	pods, err := t.getPods(ctx, input, env, timeout)
	if err != nil {
		return nil, err
	}

	privilegedPods := []any{}

	for _, pod := range pods {
		for _, container := range pod.Containers {
			if container.Privileged {
				privilegedPods = append(privilegedPods, map[string]any{
					"pod_name":       pod.Name,
					"namespace":      pod.Namespace,
					"container_name": container.Name,
					"image":          container.Image,
				})
			}
		}
	}

	return map[string]any{
		"pods_scanned":    len(pods),
		"privileged_pods": privilegedPods,
		"vulnerable_count": len(privilegedPods),
	}, nil
}

// checkCapabilities checks for dangerous capabilities
func (t *ToolImpl) checkCapabilities(ctx context.Context, input map[string]any, env []string, timeout time.Duration) (map[string]any, error) {
	pods, err := t.getPods(ctx, input, env, timeout)
	if err != nil {
		return nil, err
	}

	dangerousCaps := []any{}

	for _, pod := range pods {
		for _, container := range pod.Containers {
			for _, cap := range container.Capabilities {
				if desc, dangerous := dangerousCapabilities[cap]; dangerous {
					dangerousCaps = append(dangerousCaps, map[string]any{
						"pod_name":       pod.Name,
						"namespace":      pod.Namespace,
						"container_name": container.Name,
						"capability":     cap,
						"description":    desc,
						"severity":       t.getCapabilitySeverity(cap),
					})
				}
			}
		}
	}

	return map[string]any{
		"pods_scanned":           len(pods),
		"dangerous_capabilities": dangerousCaps,
		"vulnerable_count":       len(dangerousCaps),
	}, nil
}

// analyzeMounts analyzes dangerous host mounts
func (t *ToolImpl) analyzeMounts(ctx context.Context, input map[string]any, env []string, timeout time.Duration) (map[string]any, error) {
	pods, err := t.getPods(ctx, input, env, timeout)
	if err != nil {
		return nil, err
	}

	dangerousMnts := []any{}

	for _, pod := range pods {
		for _, volume := range pod.Volumes {
			if volume.HostPath != "" {
				danger, severity := t.isDangerousMount(volume.HostPath)
				if danger {
					dangerousMnts = append(dangerousMnts, map[string]any{
						"pod_name":   pod.Name,
						"namespace":  pod.Namespace,
						"volume":     volume.Name,
						"host_path":  volume.HostPath,
						"severity":   severity,
					})
				}
			}
		}
	}

	return map[string]any{
		"pods_scanned":     len(pods),
		"dangerous_mounts": dangerousMnts,
		"vulnerable_count": len(dangerousMnts),
	}, nil
}

// getPods retrieves pods based on input filters
func (t *ToolImpl) getPods(ctx context.Context, input map[string]any, env []string, timeout time.Duration) ([]PodSpec, error) {
	args := t.buildBaseArgs(input)

	if sdkinput.GetBool(input, "all_namespaces", false) {
		args = append(args, "get", "pods", "--all-namespaces", "-o", "json")
	} else if ns := sdkinput.GetString(input, "namespace", ""); ns != "" {
		args = append(args, "get", "pods", "-n", ns, "-o", "json")
	} else {
		args = append(args, "get", "pods", "-o", "json")
	}

	if selector := sdkinput.GetString(input, "label_selector", ""); selector != "" {
		args = append(args, "-l", selector)
	}

	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Env:     env,
		Timeout: timeout,
	})

	if err != nil && result == nil {
		return nil, fmt.Errorf("failed to get pods: %w", err)
	}

	pods := []PodSpec{}
	if len(result.Stdout) > 0 {
		var list struct {
			Items []map[string]any `json:"items"`
		}
		if json.Unmarshal(result.Stdout, &list) == nil {
			for _, item := range list.Items {
				pods = append(pods, t.parsePod(item))
			}
		}
	}

	return pods, nil
}

// parsePod parses a raw pod JSON into PodSpec
func (t *ToolImpl) parsePod(raw map[string]any) PodSpec {
	pod := PodSpec{}

	if metadata, ok := raw["metadata"].(map[string]any); ok {
		pod.Name = metadata["name"].(string)
		if ns, ok := metadata["namespace"].(string); ok {
			pod.Namespace = ns
		}
	}

	if spec, ok := raw["spec"].(map[string]any); ok {
		if hostPID, ok := spec["hostPID"].(bool); ok {
			pod.HostPID = hostPID
		}
		if hostNetwork, ok := spec["hostNetwork"].(bool); ok {
			pod.HostNetwork = hostNetwork
		}
		if hostIPC, ok := spec["hostIPC"].(bool); ok {
			pod.HostIPC = hostIPC
		}

		// Parse containers
		if containers, ok := spec["containers"].([]any); ok {
			for _, c := range containers {
				if container, ok := c.(map[string]any); ok {
					pod.Containers = append(pod.Containers, t.parseContainer(container))
				}
			}
		}

		// Parse volumes
		if volumes, ok := spec["volumes"].([]any); ok {
			for _, v := range volumes {
				if volume, ok := v.(map[string]any); ok {
					pod.Volumes = append(pod.Volumes, t.parseVolume(volume))
				}
			}
		}
	}

	return pod
}

// parseContainer parses a container spec
func (t *ToolImpl) parseContainer(raw map[string]any) ContainerSpec {
	container := ContainerSpec{}

	if name, ok := raw["name"].(string); ok {
		container.Name = name
	}
	if image, ok := raw["image"].(string); ok {
		container.Image = image
	}

	if securityContext, ok := raw["securityContext"].(map[string]any); ok {
		if privileged, ok := securityContext["privileged"].(bool); ok {
			container.Privileged = privileged
		}
		if runAsUser, ok := securityContext["runAsUser"].(float64); ok {
			container.RunAsRoot = runAsUser == 0
		}
		if readOnly, ok := securityContext["readOnlyRootFilesystem"].(bool); ok {
			container.ReadOnlyRoot = readOnly
		}

		if capabilities, ok := securityContext["capabilities"].(map[string]any); ok {
			if add, ok := capabilities["add"].([]any); ok {
				for _, cap := range add {
					if capStr, ok := cap.(string); ok {
						container.Capabilities = append(container.Capabilities, capStr)
					}
				}
			}
		}
	}

	return container
}

// parseVolume parses a volume spec
func (t *ToolImpl) parseVolume(raw map[string]any) VolumeSpec {
	volume := VolumeSpec{}

	if name, ok := raw["name"].(string); ok {
		volume.Name = name
	}

	if hostPath, ok := raw["hostPath"].(map[string]any); ok {
		if path, ok := hostPath["path"].(string); ok {
			volume.HostPath = path
		}
		if vType, ok := hostPath["type"].(string); ok {
			volume.Type = vType
		}
		volume.Type = "hostPath"
	}

	return volume
}

// analyzeEscapeVectors analyzes a pod for escape vectors
func (t *ToolImpl) analyzeEscapeVectors(pod PodSpec) []any {
	vectors := []any{}

	// Check host namespaces
	if pod.HostPID {
		vectors = append(vectors, map[string]any{
			"type":        "host_pid",
			"severity":    "high",
			"description": "Pod shares host PID namespace - can see and interact with host processes",
			"technique":   "T1611",
			"remediation": "Set spec.hostPID: false",
		})
	}

	if pod.HostNetwork {
		vectors = append(vectors, map[string]any{
			"type":        "host_network",
			"severity":    "medium",
			"description": "Pod shares host network namespace - can access localhost services",
			"technique":   "T1611",
			"remediation": "Set spec.hostNetwork: false",
		})
	}

	if pod.HostIPC {
		vectors = append(vectors, map[string]any{
			"type":        "host_ipc",
			"severity":    "medium",
			"description": "Pod shares host IPC namespace - can communicate with host processes",
			"technique":   "T1611",
			"remediation": "Set spec.hostIPC: false",
		})
	}

	// Check containers
	for _, container := range pod.Containers {
		if container.Privileged {
			vectors = append(vectors, map[string]any{
				"type":        "privileged",
				"severity":    "critical",
				"container":   container.Name,
				"description": "Container runs in privileged mode - full host access",
				"technique":   "T1611",
				"remediation": "Set securityContext.privileged: false",
			})
		}

		for _, cap := range container.Capabilities {
			if desc, dangerous := dangerousCapabilities[cap]; dangerous {
				vectors = append(vectors, map[string]any{
					"type":        "dangerous_capability",
					"severity":    t.getCapabilitySeverity(cap),
					"container":   container.Name,
					"capability":  cap,
					"description": desc,
					"technique":   "T1611",
					"remediation": fmt.Sprintf("Remove capability %s", cap),
				})
			}
		}
	}

	// Check volumes
	for _, volume := range pod.Volumes {
		if volume.HostPath != "" {
			if danger, severity := t.isDangerousMount(volume.HostPath); danger {
				vectors = append(vectors, map[string]any{
					"type":        "dangerous_mount",
					"severity":    severity,
					"volume":      volume.Name,
					"host_path":   volume.HostPath,
					"description": fmt.Sprintf("Dangerous host path mounted: %s", volume.HostPath),
					"technique":   "T1611",
					"remediation": "Remove hostPath volume or restrict to specific paths",
				})
			}
		}
	}

	return vectors
}

// isDangerousMount checks if a host path is dangerous
func (t *ToolImpl) isDangerousMount(path string) (bool, string) {
	for _, dangerous := range dangerousHostPaths {
		if path == dangerous || strings.HasPrefix(path, dangerous+"/") {
			if path == "/" || strings.Contains(path, "docker.sock") ||
				strings.Contains(path, "containerd") || path == "/etc" {
				return true, "critical"
			}
			return true, "high"
		}
	}
	return false, ""
}

// getCapabilitySeverity returns the severity of a capability
func (t *ToolImpl) getCapabilitySeverity(cap string) string {
	critical := []string{"SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO", "SYS_PTRACE"}
	for _, c := range critical {
		if cap == c {
			return "critical"
		}
	}
	return "high"
}

// buildBaseArgs builds common kubectl arguments
func (t *ToolImpl) buildBaseArgs(input map[string]any) []string {
	args := []string{}

	if context := sdkinput.GetString(input, "context", ""); context != "" {
		args = append(args, "--context", context)
	}

	return args
}

// Health checks if kubectl binary exists
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	if !exec.BinaryExists(BinaryName) {
		return types.NewUnhealthyStatus(
			fmt.Sprintf("%s binary not found in PATH", BinaryName),
			nil,
		)
	}

	return types.NewHealthyStatus(fmt.Sprintf("%s is available for pod escape analysis", BinaryName))
}
