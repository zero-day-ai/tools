package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTool_PodEscape(t *testing.T) {
	tool := NewTool()
	require.NotNil(t, tool, "NewTool should return a non-nil tool")
}

func TestToolImpl_Execute_ValidationErrors_PodEscape(t *testing.T) {
	tests := []struct {
		name        string
		input       map[string]any
		expectedErr string
	}{
		{
			name:        "missing action",
			input:       map[string]any{},
			expectedErr: "action is required",
		},
		{
			name: "unknown action",
			input: map[string]any{
				"action": "invalid-action",
			},
			expectedErr: "unknown action: invalid-action",
		},
		{
			name: "analyze-pod missing pod_name",
			input: map[string]any{
				"action": "analyze-pod",
			},
			expectedErr: "pod_name is required for analyze-pod action",
		},
	}

	impl := &ToolImpl{}
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := impl.Execute(ctx, tt.input)

			if err != nil {
				assert.Contains(t, err.Error(), tt.expectedErr)
			} else {
				require.NotNil(t, result)
				assert.False(t, result["success"].(bool))
				assert.Contains(t, result["error"].(string), tt.expectedErr)
			}
		})
	}
}

func TestToolImpl_BuildBaseArgs_PodEscape(t *testing.T) {
	impl := &ToolImpl{}

	tests := []struct {
		name     string
		input    map[string]any
		expected []string
	}{
		{
			name:     "no context",
			input:    map[string]any{},
			expected: []string{},
		},
		{
			name: "with context",
			input: map[string]any{
				"context": "prod-cluster",
			},
			expected: []string{"--context", "prod-cluster"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := impl.buildBaseArgs(tt.input)
			assert.Equal(t, tt.expected, args)
		})
	}
}

func TestToolImpl_IsDangerousMount(t *testing.T) {
	impl := &ToolImpl{}

	tests := []struct {
		name           string
		path           string
		shouldDanger   bool
		expectedSeverity string
	}{
		{
			name:           "root mount - critical",
			path:           "/",
			shouldDanger:   true,
			expectedSeverity: "critical",
		},
		{
			name:           "docker socket - critical",
			path:           "/var/run/docker.sock",
			shouldDanger:   true,
			expectedSeverity: "critical",
		},
		{
			name:           "containerd socket - critical",
			path:           "/var/run/containerd/containerd.sock",
			shouldDanger:   true,
			expectedSeverity: "critical",
		},
		{
			name:           "etc directory - critical",
			path:           "/etc",
			shouldDanger:   true,
			expectedSeverity: "critical",
		},
		{
			name:           "proc filesystem - high",
			path:           "/proc",
			shouldDanger:   true,
			expectedSeverity: "high",
		},
		{
			name:           "sys filesystem - high",
			path:           "/sys",
			shouldDanger:   true,
			expectedSeverity: "high",
		},
		{
			name:           "dev filesystem - high",
			path:           "/dev",
			shouldDanger:   true,
			expectedSeverity: "high",
		},
		{
			name:           "kubelet data - high",
			path:           "/var/lib/kubelet",
			shouldDanger:   true,
			expectedSeverity: "high",
		},
		{
			name:           "safe mount",
			path:           "/app/data",
			shouldDanger:   false,
			expectedSeverity: "",
		},
		{
			name:           "subdirectory of dangerous path",
			path:           "/etc/kubernetes/manifests",
			shouldDanger:   true,
			expectedSeverity: "critical",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dangerous, severity := impl.isDangerousMount(tt.path)
			assert.Equal(t, tt.shouldDanger, dangerous)
			if tt.shouldDanger {
				assert.Equal(t, tt.expectedSeverity, severity)
			}
		})
	}
}

func TestToolImpl_GetCapabilitySeverity(t *testing.T) {
	impl := &ToolImpl{}

	tests := []struct {
		name     string
		cap      string
		severity string
	}{
		{
			name:     "SYS_ADMIN - critical",
			cap:      "SYS_ADMIN",
			severity: "critical",
		},
		{
			name:     "SYS_MODULE - critical",
			cap:      "SYS_MODULE",
			severity: "critical",
		},
		{
			name:     "SYS_RAWIO - critical",
			cap:      "SYS_RAWIO",
			severity: "critical",
		},
		{
			name:     "SYS_PTRACE - critical",
			cap:      "SYS_PTRACE",
			severity: "critical",
		},
		{
			name:     "NET_ADMIN - high",
			cap:      "NET_ADMIN",
			severity: "high",
		},
		{
			name:     "DAC_OVERRIDE - high",
			cap:      "DAC_OVERRIDE",
			severity: "high",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			severity := impl.getCapabilitySeverity(tt.cap)
			assert.Equal(t, tt.severity, severity)
		})
	}
}

func TestToolImpl_AnalyzeEscapeVectors(t *testing.T) {
	impl := &ToolImpl{}

	tests := []struct {
		name          string
		pod           PodSpec
		expectedTypes []string
		minVectors    int
	}{
		{
			name: "privileged container",
			pod: PodSpec{
				Name:      "test-pod",
				Namespace: "default",
				Containers: []ContainerSpec{
					{
						Name:       "nginx",
						Privileged: true,
					},
				},
			},
			expectedTypes: []string{"privileged"},
			minVectors:    1,
		},
		{
			name: "host PID namespace",
			pod: PodSpec{
				Name:      "test-pod",
				Namespace: "default",
				HostPID:   true,
			},
			expectedTypes: []string{"host_pid"},
			minVectors:    1,
		},
		{
			name: "host network namespace",
			pod: PodSpec{
				Name:        "test-pod",
				Namespace:   "default",
				HostNetwork: true,
			},
			expectedTypes: []string{"host_network"},
			minVectors:    1,
		},
		{
			name: "dangerous capability",
			pod: PodSpec{
				Name:      "test-pod",
				Namespace: "default",
				Containers: []ContainerSpec{
					{
						Name:         "nginx",
						Capabilities: []string{"SYS_ADMIN"},
					},
				},
			},
			expectedTypes: []string{"dangerous_capability"},
			minVectors:    1,
		},
		{
			name: "dangerous host mount",
			pod: PodSpec{
				Name:      "test-pod",
				Namespace: "default",
				Volumes: []VolumeSpec{
					{
						Name:     "docker-socket",
						HostPath: "/var/run/docker.sock",
					},
				},
			},
			expectedTypes: []string{"dangerous_mount"},
			minVectors:    1,
		},
		{
			name: "multiple vectors",
			pod: PodSpec{
				Name:        "dangerous-pod",
				Namespace:   "default",
				HostPID:     true,
				HostNetwork: true,
				Containers: []ContainerSpec{
					{
						Name:         "nginx",
						Privileged:   true,
						Capabilities: []string{"SYS_ADMIN", "NET_ADMIN"},
					},
				},
				Volumes: []VolumeSpec{
					{
						Name:     "root",
						HostPath: "/",
					},
				},
			},
			expectedTypes: []string{"host_pid", "host_network", "privileged", "dangerous_capability", "dangerous_mount"},
			minVectors:    5,
		},
		{
			name: "safe pod",
			pod: PodSpec{
				Name:      "safe-pod",
				Namespace: "default",
				Containers: []ContainerSpec{
					{
						Name:       "nginx",
						Privileged: false,
					},
				},
			},
			expectedTypes: []string{},
			minVectors:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vectors := impl.analyzeEscapeVectors(tt.pod)
			assert.GreaterOrEqual(t, len(vectors), tt.minVectors)

			// Check for expected vector types
			foundTypes := make(map[string]bool)
			for _, v := range vectors {
				vectorMap := v.(map[string]any)
				vectorType := vectorMap["type"].(string)
				foundTypes[vectorType] = true
			}

			for _, expectedType := range tt.expectedTypes {
				assert.True(t, foundTypes[expectedType], "expected to find vector type: %s", expectedType)
			}
		})
	}
}

func TestToolImpl_ParsePod(t *testing.T) {
	impl := &ToolImpl{}

	podJSON := `{
		"metadata": {
			"name": "test-pod",
			"namespace": "default"
		},
		"spec": {
			"hostPID": true,
			"hostNetwork": false,
			"hostIPC": true,
			"containers": [
				{
					"name": "nginx",
					"image": "nginx:latest",
					"securityContext": {
						"privileged": true,
						"runAsUser": 0,
						"readOnlyRootFilesystem": false,
						"capabilities": {
							"add": ["SYS_ADMIN", "NET_ADMIN"]
						}
					}
				}
			],
			"volumes": [
				{
					"name": "docker-sock",
					"hostPath": {
						"path": "/var/run/docker.sock",
						"type": "Socket"
					}
				}
			]
		}
	}`

	var raw map[string]any
	err := json.Unmarshal([]byte(podJSON), &raw)
	require.NoError(t, err)

	pod := impl.parsePod(raw)

	assert.Equal(t, "test-pod", pod.Name)
	assert.Equal(t, "default", pod.Namespace)
	assert.True(t, pod.HostPID)
	assert.False(t, pod.HostNetwork)
	assert.True(t, pod.HostIPC)
	assert.Len(t, pod.Containers, 1)
	assert.Len(t, pod.Volumes, 1)

	container := pod.Containers[0]
	assert.Equal(t, "nginx", container.Name)
	assert.True(t, container.Privileged)
	assert.True(t, container.RunAsRoot)
	assert.Len(t, container.Capabilities, 2)

	volume := pod.Volumes[0]
	assert.Equal(t, "docker-sock", volume.Name)
	assert.Equal(t, "/var/run/docker.sock", volume.HostPath)
}

func TestDangerousCapabilities(t *testing.T) {
	t.Run("dangerous capabilities are defined", func(t *testing.T) {
		assert.NotEmpty(t, dangerousCapabilities)
		assert.Contains(t, dangerousCapabilities, "SYS_ADMIN")
		assert.Contains(t, dangerousCapabilities, "SYS_MODULE")
		assert.Contains(t, dangerousCapabilities, "SYS_PTRACE")
		assert.Contains(t, dangerousCapabilities, "NET_ADMIN")
	})

	t.Run("capability descriptions", func(t *testing.T) {
		desc := dangerousCapabilities["SYS_ADMIN"]
		assert.Contains(t, strings.ToLower(desc), "escape")
	})
}

func TestDangerousHostPaths(t *testing.T) {
	assert.NotEmpty(t, dangerousHostPaths)
	assert.Contains(t, dangerousHostPaths, "/")
	assert.Contains(t, dangerousHostPaths, "/var/run/docker.sock")
	assert.Contains(t, dangerousHostPaths, "/etc")
	assert.Contains(t, dangerousHostPaths, "/proc")
}

func TestConstants_PodEscape(t *testing.T) {
	assert.Equal(t, "pod-escape", ToolName)
	assert.Equal(t, "1.0.0", ToolVersion)
	assert.NotEmpty(t, ToolDescription)
	assert.Equal(t, "kubectl", BinaryName)
}

// Benchmark tests
func BenchmarkIsDangerousMount(b *testing.B) {
	impl := &ToolImpl{}

	paths := []string{
		"/var/run/docker.sock",
		"/etc/kubernetes",
		"/app/data",
		"/",
		"/proc",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, path := range paths {
			impl.isDangerousMount(path)
		}
	}
}

func BenchmarkAnalyzeEscapeVectors(b *testing.B) {
	impl := &ToolImpl{}

	pod := PodSpec{
		Name:        "test-pod",
		Namespace:   "default",
		HostPID:     true,
		HostNetwork: true,
		Containers: []ContainerSpec{
			{
				Name:         "nginx",
				Privileged:   true,
				Capabilities: []string{"SYS_ADMIN", "NET_ADMIN"},
			},
		},
		Volumes: []VolumeSpec{
			{
				Name:     "root",
				HostPath: "/var/run/docker.sock",
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		impl.analyzeEscapeVectors(pod)
	}
}
