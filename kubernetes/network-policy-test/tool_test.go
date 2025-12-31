package main

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTool_NetworkPolicy(t *testing.T) {
	tool := NewTool()
	require.NotNil(t, tool, "NewTool should return a non-nil tool")
}

func TestToolImpl_Execute_ValidationErrors_NetworkPolicy(t *testing.T) {
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
			name: "test-connectivity missing target_host",
			input: map[string]any{
				"action": "test-connectivity",
			},
			expectedErr: "target_host is required for connectivity test",
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

func TestToolImpl_BuildBaseArgs_NetworkPolicy(t *testing.T) {
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
				"context": "test-cluster",
			},
			expected: []string{"--context", "test-cluster"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := impl.buildBaseArgs(tt.input)
			assert.Equal(t, tt.expected, args)
		})
	}
}

func TestToolImpl_PodMatchesPolicy(t *testing.T) {
	impl := &ToolImpl{}

	tests := []struct {
		name       string
		podLabels  map[string]string
		policy     any
		shouldMatch bool
	}{
		{
			name: "empty selector matches all",
			podLabels: map[string]string{
				"app": "nginx",
			},
			policy: map[string]any{
				"spec": map[string]any{
					"podSelector": map[string]any{},
				},
			},
			shouldMatch: true,
		},
		{
			name: "matching labels",
			podLabels: map[string]string{
				"app":  "nginx",
				"tier": "frontend",
			},
			policy: map[string]any{
				"spec": map[string]any{
					"podSelector": map[string]any{
						"matchLabels": map[string]any{
							"app": "nginx",
						},
					},
				},
			},
			shouldMatch: true,
		},
		{
			name: "non-matching labels",
			podLabels: map[string]string{
				"app": "redis",
			},
			policy: map[string]any{
				"spec": map[string]any{
					"podSelector": map[string]any{
						"matchLabels": map[string]any{
							"app": "nginx",
						},
					},
				},
			},
			shouldMatch: false,
		},
		{
			name: "multiple label match",
			podLabels: map[string]string{
				"app":  "nginx",
				"tier": "frontend",
				"env":  "prod",
			},
			policy: map[string]any{
				"spec": map[string]any{
					"podSelector": map[string]any{
						"matchLabels": map[string]any{
							"app":  "nginx",
							"tier": "frontend",
						},
					},
				},
			},
			shouldMatch: true,
		},
		{
			name: "partial label match fails",
			podLabels: map[string]string{
				"app": "nginx",
			},
			policy: map[string]any{
				"spec": map[string]any{
					"podSelector": map[string]any{
						"matchLabels": map[string]any{
							"app":  "nginx",
							"tier": "frontend",
						},
					},
				},
			},
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := impl.podMatchesPolicy(tt.podLabels, tt.policy)
			assert.Equal(t, tt.shouldMatch, matches)
		})
	}
}

func TestNetworkConnectivity(t *testing.T) {
	t.Run("localhost connectivity", func(t *testing.T) {
		// Try to connect to localhost on a likely open port
		timeout := 2 * time.Second
		conn, err := net.DialTimeout("tcp", "127.0.0.1:22", timeout)

		// This might fail if SSH isn't running, which is fine
		if err == nil {
			assert.NotNil(t, conn)
			conn.Close()
		}
	})

	t.Run("invalid host", func(t *testing.T) {
		timeout := 1 * time.Second
		_, err := net.DialTimeout("tcp", "192.0.2.1:80", timeout) // TEST-NET-1, should fail
		assert.Error(t, err, "should fail to connect to invalid host")
	})
}

func TestNetworkPolicyJSONParsing(t *testing.T) {
	policyJSON := `{
		"items": [
			{
				"metadata": {
					"name": "deny-all",
					"namespace": "default"
				},
				"spec": {
					"podSelector": {},
					"policyTypes": ["Ingress", "Egress"]
				}
			}
		]
	}`

	var list struct {
		Items []any `json:"items"`
	}

	err := json.Unmarshal([]byte(policyJSON), &list)
	require.NoError(t, err)
	assert.Len(t, list.Items, 1)
}

func TestNamespaceListJSONParsing(t *testing.T) {
	nsJSON := `{
		"items": [
			{
				"metadata": {
					"name": "default"
				}
			},
			{
				"metadata": {
					"name": "kube-system"
				}
			}
		]
	}`

	var list struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}

	err := json.Unmarshal([]byte(nsJSON), &list)
	require.NoError(t, err)
	assert.Len(t, list.Items, 2)
	assert.Equal(t, "default", list.Items[0].Metadata.Name)
	assert.Equal(t, "kube-system", list.Items[1].Metadata.Name)
}

func TestPodListJSONParsing(t *testing.T) {
	podJSON := `{
		"items": [
			{
				"metadata": {
					"name": "nginx-pod",
					"namespace": "default",
					"labels": {
						"app": "nginx",
						"tier": "frontend"
					}
				}
			}
		]
	}`

	var podList struct {
		Items []struct {
			Metadata struct {
				Name      string            `json:"name"`
				Namespace string            `json:"namespace"`
				Labels    map[string]string `json:"labels"`
			} `json:"metadata"`
		} `json:"items"`
	}

	err := json.Unmarshal([]byte(podJSON), &podList)
	require.NoError(t, err)
	assert.Len(t, podList.Items, 1)
	assert.Equal(t, "nginx-pod", podList.Items[0].Metadata.Name)
	assert.Equal(t, "default", podList.Items[0].Metadata.Namespace)
	assert.Len(t, podList.Items[0].Metadata.Labels, 2)
}

func TestConstants_NetworkPolicy(t *testing.T) {
	assert.Equal(t, "network-policy-test", ToolName)
	assert.Equal(t, "1.0.0", ToolVersion)
	assert.NotEmpty(t, ToolDescription)
	assert.Equal(t, "kubectl", BinaryName)
	assert.Equal(t, "169.254.169.254", DefaultMetadataIP)
}

func TestTimeoutDefaults(t *testing.T) {
	impl := &ToolImpl{}
	ctx := context.Background()

	tests := []struct {
		name            string
		input           map[string]any
		expectedTimeout time.Duration
	}{
		{
			name: "default timeout",
			input: map[string]any{
				"action": "list-policies",
			},
			expectedTimeout: 30 * time.Second,
		},
		{
			name: "custom timeout",
			input: map[string]any{
				"action":  "list-policies",
				"timeout": 60,
			},
			expectedTimeout: 60 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify the input is accepted
			result, err := impl.Execute(ctx, tt.input)

			// Will fail without kubectl, but shouldn't panic
			if err == nil {
				assert.NotNil(t, result)
			}
		})
	}
}

// Benchmark tests
func BenchmarkPodMatchesPolicy(b *testing.B) {
	impl := &ToolImpl{}

	podLabels := map[string]string{
		"app":  "nginx",
		"tier": "frontend",
	}

	policy := map[string]any{
		"spec": map[string]any{
			"podSelector": map[string]any{
				"matchLabels": map[string]any{
					"app": "nginx",
				},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		impl.podMatchesPolicy(podLabels, policy)
	}
}
