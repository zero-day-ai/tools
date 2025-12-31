package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTool_Kubectl(t *testing.T) {
	tool := NewTool()
	require.NotNil(t, tool, "NewTool should return a non-nil tool")
}

func TestBuildKubectlArgs(t *testing.T) {
	tests := []struct {
		name        string
		input       map[string]any
		expected    []string
		shouldError bool
	}{
		{
			name: "simple get command",
			input: map[string]any{
				"command":  "get",
				"resource": "pods",
			},
			expected: []string{"get", "pods", "-o", "json"},
		},
		{
			name: "with namespace",
			input: map[string]any{
				"command":   "get",
				"resource":  "pods",
				"namespace": "kube-system",
			},
			expected: []string{"-n", "kube-system", "get", "pods", "-o", "json"},
		},
		{
			name: "with context",
			input: map[string]any{
				"command":  "get",
				"resource": "pods",
				"context":  "prod-cluster",
			},
			expected: []string{"--context", "prod-cluster", "get", "pods", "-o", "json"},
		},
		{
			name: "with all-namespaces",
			input: map[string]any{
				"command":        "get",
				"resource":       "pods",
				"all_namespaces": true,
			},
			expected: []string{"--all-namespaces", "get", "pods", "-o", "json"},
		},
		{
			name: "with label selector",
			input: map[string]any{
				"command":  "get",
				"resource": "pods",
				"selector": "app=nginx",
			},
			expected: []string{"get", "pods", "-l", "app=nginx", "-o", "json"},
		},
		{
			name: "with field selector",
			input: map[string]any{
				"command":        "get",
				"resource":       "pods",
				"field_selector": "status.phase=Running",
			},
			expected: []string{"get", "pods", "--field-selector", "status.phase=Running", "-o", "json"},
		},
		{
			name: "with resource name",
			input: map[string]any{
				"command":  "get",
				"resource": "pod",
				"name":     "nginx-pod",
			},
			expected: []string{"get", "pod", "nginx-pod", "-o", "json"},
		},
		{
			name: "with custom output format",
			input: map[string]any{
				"command":  "get",
				"resource": "pods",
				"output":   "yaml",
			},
			expected: []string{"get", "pods", "-o", "yaml"},
		},
		{
			name: "with additional args",
			input: map[string]any{
				"command":  "get",
				"resource": "pods",
				"args":     []any{"--show-labels", "--no-headers"},
			},
			expected: []string{"get", "pods", "-o", "json", "--show-labels", "--no-headers"},
		},
		{
			name: "raw command",
			input: map[string]any{
				"raw": "get pods -n default",
			},
			expected: []string{"get", "pods", "-n", "default"},
		},
		{
			name: "raw command with kubectl prefix",
			input: map[string]any{
				"raw": "kubectl get pods",
			},
			expected: []string{"get", "pods"},
		},
		{
			name: "empty raw command",
			input: map[string]any{
				"raw": "",
			},
			shouldError: true,
		},
		{
			name: "default to get command",
			input: map[string]any{
				"resource": "pods",
			},
			expected: []string{"get", "pods", "-o", "json"},
		},
		{
			name: "complex multi-option command",
			input: map[string]any{
				"context":        "prod",
				"namespace":      "app",
				"command":        "get",
				"resource":       "pods",
				"name":           "nginx",
				"selector":       "tier=frontend",
				"field_selector": "status.phase=Running",
				"output":         "yaml",
				"args":           []any{"--show-labels"},
			},
			expected: []string{
				"--context", "prod",
				"-n", "app",
				"get", "pods", "nginx",
				"-l", "tier=frontend",
				"--field-selector", "status.phase=Running",
				"-o", "yaml",
				"--show-labels",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args, err := buildKubectlArgs(tt.input)

			if tt.shouldError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, args)
			}
		})
	}
}

func TestKubectlJSONParsing(t *testing.T) {
	t.Run("pod list response", func(t *testing.T) {
		listJSON := `{
			"kind": "PodList",
			"items": [
				{"metadata": {"name": "pod1"}},
				{"metadata": {"name": "pod2"}}
			]
		}`

		var parsed map[string]any
		err := json.Unmarshal([]byte(listJSON), &parsed)
		require.NoError(t, err)

		kind := parsed["kind"].(string)
		assert.True(t, strings.HasSuffix(kind, "List"))

		items := parsed["items"].([]any)
		assert.Len(t, items, 2)
	})

	t.Run("single resource response", func(t *testing.T) {
		podJSON := `{
			"kind": "Pod",
			"metadata": {
				"name": "nginx",
				"namespace": "default"
			}
		}`

		var parsed map[string]any
		err := json.Unmarshal([]byte(podJSON), &parsed)
		require.NoError(t, err)

		kind := parsed["kind"].(string)
		assert.Equal(t, "Pod", kind)
	})
}

func TestToolImpl_Execute_Kubectl(t *testing.T) {
	impl := &ToolImpl{}
	ctx := context.Background()

	t.Run("missing command with no raw", func(t *testing.T) {
		input := map[string]any{}

		result, err := impl.Execute(ctx, input)

		// Should use default command (get)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Contains(t, result, "command_executed")
	})

	t.Run("valid input structure", func(t *testing.T) {
		input := map[string]any{
			"command":  "get",
			"resource": "nodes",
		}

		result, err := impl.Execute(ctx, input)

		// Will fail without kubectl, but should have proper structure
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Contains(t, result, "success")
		assert.Contains(t, result, "exit_code")
		assert.Contains(t, result, "stdout")
		assert.Contains(t, result, "stderr")
		assert.Contains(t, result, "execution_time_ms")
		assert.Contains(t, result, "command_executed")
	})
}

func TestRawCommandParsing(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected []string
	}{
		{
			name:     "simple command",
			raw:      "get pods",
			expected: []string{"get", "pods"},
		},
		{
			name:     "with kubectl prefix",
			raw:      "kubectl get pods",
			expected: []string{"get", "pods"},
		},
		{
			name:     "with flags",
			raw:      "get pods -n default -o wide",
			expected: []string{"get", "pods", "-n", "default", "-o", "wide"},
		},
		{
			name:     "complex command",
			raw:      "kubectl get pods --all-namespaces --show-labels",
			expected: []string{"get", "pods", "--all-namespaces", "--show-labels"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := strings.Fields(tt.raw)
			if len(parts) > 0 && parts[0] == "kubectl" {
				parts = parts[1:]
			}
			assert.Equal(t, tt.expected, parts)
		})
	}
}

func TestConstants_Kubectl(t *testing.T) {
	assert.Equal(t, "kubectl", ToolName)
	assert.Equal(t, "1.0.0", ToolVersion)
	assert.NotEmpty(t, ToolDescription)
	assert.Equal(t, "kubectl", BinaryName)
}

// Benchmark tests
func BenchmarkBuildKubectlArgs(b *testing.B) {
	input := map[string]any{
		"context":        "prod",
		"namespace":      "default",
		"command":        "get",
		"resource":       "pods",
		"selector":       "app=nginx",
		"field_selector": "status.phase=Running",
		"output":         "json",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buildKubectlArgs(input)
	}
}

func BenchmarkRawCommandParsing(b *testing.B) {
	raw := "kubectl get pods --all-namespaces -o wide --show-labels"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parts := strings.Fields(raw)
		if len(parts) > 0 && parts[0] == "kubectl" {
			_ = parts[1:]
		}
	}
}
