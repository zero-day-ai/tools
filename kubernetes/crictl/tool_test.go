package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTool_Crictl(t *testing.T) {
	tool := NewTool()
	require.NotNil(t, tool, "NewTool should return a non-nil tool")
}

func TestToolImpl_Execute_ValidationErrors_Crictl(t *testing.T) {
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
			name: "inspect without container_id",
			input: map[string]any{
				"action": "inspect",
			},
			expectedErr: "container_id is required",
		},
		{
			name: "exec without container_id",
			input: map[string]any{
				"action":  "exec",
				"command": []any{"ls"},
			},
			expectedErr: "container_id is required",
		},
		{
			name: "exec without command",
			input: map[string]any{
				"action":       "exec",
				"container_id": "abc123",
			},
			expectedErr: "command is required",
		},
		{
			name: "logs without container_id",
			input: map[string]any{
				"action": "logs",
			},
			expectedErr: "container_id is required",
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

func TestSocketPaths(t *testing.T) {
	t.Run("containerd sockets", func(t *testing.T) {
		assert.NotEmpty(t, containerdSockets)
		assert.Contains(t, containerdSockets, "/run/containerd/containerd.sock")
		assert.Contains(t, containerdSockets, "/var/run/containerd/containerd.sock")
	})

	t.Run("docker sockets", func(t *testing.T) {
		assert.NotEmpty(t, dockerSockets)
		assert.Contains(t, dockerSockets, "/var/run/docker.sock")
		assert.Contains(t, dockerSockets, "/run/docker.sock")
	})

	t.Run("crio sockets", func(t *testing.T) {
		assert.NotEmpty(t, crioSockets)
		assert.Contains(t, crioSockets, "/var/run/crio/crio.sock")
		assert.Contains(t, crioSockets, "/run/crio/crio.sock")
	})
}

func TestRuntimeInfo(t *testing.T) {
	info := RuntimeInfo{
		Name:       "containerd",
		Binary:     "crictl",
		SocketPath: "/run/containerd/containerd.sock",
		Available:  true,
	}

	assert.Equal(t, "containerd", info.Name)
	assert.Equal(t, "crictl", info.Binary)
	assert.True(t, info.Available)
}

func TestToolImpl_AnalyzeEscapeVectors_Docker(t *testing.T) {
	impl := &ToolImpl{}

	t.Run("privileged container - docker format", func(t *testing.T) {
		containerInfo := []any{
			map[string]any{
				"HostConfig": map[string]any{
					"Privileged": true,
				},
			},
		}

		vectors := impl.analyzeEscapeVectors(containerInfo)

		assert.GreaterOrEqual(t, len(vectors), 1)
		found := false
		for _, v := range vectors {
			vectorMap := v.(map[string]any)
			if vectorMap["type"] == "privileged" {
				found = true
				assert.Equal(t, "critical", vectorMap["severity"])
			}
		}
		assert.True(t, found)
	})

	t.Run("host PID - docker format", func(t *testing.T) {
		containerInfo := []any{
			map[string]any{
				"HostConfig": map[string]any{
					"PidMode": "host",
				},
			},
		}

		vectors := impl.analyzeEscapeVectors(containerInfo)

		assert.GreaterOrEqual(t, len(vectors), 1)
		found := false
		for _, v := range vectors {
			vectorMap := v.(map[string]any)
			if vectorMap["type"] == "host_pid" {
				found = true
				assert.Equal(t, "high", vectorMap["severity"])
			}
		}
		assert.True(t, found)
	})

	t.Run("host network - docker format", func(t *testing.T) {
		containerInfo := []any{
			map[string]any{
				"HostConfig": map[string]any{
					"NetworkMode": "host",
				},
			},
		}

		vectors := impl.analyzeEscapeVectors(containerInfo)

		assert.GreaterOrEqual(t, len(vectors), 1)
		found := false
		for _, v := range vectors {
			vectorMap := v.(map[string]any)
			if vectorMap["type"] == "host_network" {
				found = true
				assert.Equal(t, "medium", vectorMap["severity"])
			}
		}
		assert.True(t, found)
	})

	t.Run("dangerous host path - docker socket", func(t *testing.T) {
		containerInfo := []any{
			map[string]any{
				"HostConfig": map[string]any{
					"Binds": []any{
						"/var/run/docker.sock:/var/run/docker.sock",
					},
				},
			},
		}

		vectors := impl.analyzeEscapeVectors(containerInfo)

		assert.GreaterOrEqual(t, len(vectors), 1)
		found := false
		for _, v := range vectors {
			vectorMap := v.(map[string]any)
			if vectorMap["type"] == "host_path" {
				found = true
				assert.Equal(t, "critical", vectorMap["severity"])
			}
		}
		assert.True(t, found)
	})

	t.Run("dangerous host path - root mount", func(t *testing.T) {
		containerInfo := []any{
			map[string]any{
				"HostConfig": map[string]any{
					"Binds": []any{
						"/:/host",
					},
				},
			},
		}

		vectors := impl.analyzeEscapeVectors(containerInfo)

		assert.GreaterOrEqual(t, len(vectors), 1)
		found := false
		for _, v := range vectors {
			vectorMap := v.(map[string]any)
			if vectorMap["type"] == "host_path" {
				found = true
				assert.Equal(t, "critical", vectorMap["severity"])
			}
		}
		assert.True(t, found)
	})

	t.Run("safe container", func(t *testing.T) {
		containerInfo := []any{
			map[string]any{
				"HostConfig": map[string]any{
					"Privileged":  false,
					"PidMode":     "container",
					"NetworkMode": "bridge",
				},
			},
		}

		vectors := impl.analyzeEscapeVectors(containerInfo)
		assert.Equal(t, 0, len(vectors))
	})
}

func TestToolImpl_AnalyzeEscapeVectors_CRI(t *testing.T) {
	impl := &ToolImpl{}

	t.Run("privileged container - CRI format", func(t *testing.T) {
		containerInfo := map[string]any{
			"info": map[string]any{
				"linux": map[string]any{
					"securityContext": map[string]any{
						"privileged": true,
					},
				},
			},
		}

		vectors := impl.analyzeEscapeVectors(containerInfo)

		assert.GreaterOrEqual(t, len(vectors), 1)
		found := false
		for _, v := range vectors {
			vectorMap := v.(map[string]any)
			if vectorMap["type"] == "privileged" {
				found = true
				assert.Equal(t, "critical", vectorMap["severity"])
			}
		}
		assert.True(t, found)
	})

	t.Run("host PID namespace - CRI format", func(t *testing.T) {
		containerInfo := map[string]any{
			"info": map[string]any{
				"linux": map[string]any{
					"securityContext": map[string]any{
						"namespaceOptions": map[string]any{
							"pid": float64(2), // NODE mode
						},
					},
				},
			},
		}

		vectors := impl.analyzeEscapeVectors(containerInfo)

		assert.GreaterOrEqual(t, len(vectors), 1)
		found := false
		for _, v := range vectors {
			vectorMap := v.(map[string]any)
			if vectorMap["type"] == "host_pid" {
				found = true
				assert.Equal(t, "high", vectorMap["severity"])
			}
		}
		assert.True(t, found)
	})
}

func TestContainerListJSONParsing(t *testing.T) {
	t.Run("docker format", func(t *testing.T) {
		dockerJSON := `[
			{"ID": "abc123", "Names": "nginx"},
			{"ID": "def456", "Names": "redis"}
		]`

		var parsed []any
		err := json.Unmarshal([]byte(dockerJSON), &parsed)
		require.NoError(t, err)
		assert.Len(t, parsed, 2)
	})

	t.Run("crictl format", func(t *testing.T) {
		crictlJSON := `{
			"containers": [
				{"id": "abc123", "metadata": {"name": "nginx"}},
				{"id": "def456", "metadata": {"name": "redis"}}
			]
		}`

		var parsed map[string]any
		err := json.Unmarshal([]byte(crictlJSON), &parsed)
		require.NoError(t, err)

		containers := parsed["containers"].([]any)
		assert.Len(t, containers, 2)
	})
}

func TestSocketFileChecking(t *testing.T) {
	// Create a temporary file to test file existence
	tmpFile, err := os.CreateTemp("", "test-socket-*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	t.Run("file exists", func(t *testing.T) {
		_, err := os.Stat(tmpFile.Name())
		assert.NoError(t, err)
	})

	t.Run("file does not exist", func(t *testing.T) {
		_, err := os.Stat("/nonexistent/socket.sock")
		assert.Error(t, err)
		assert.True(t, os.IsNotExist(err))
	})
}

func TestConstants_Crictl(t *testing.T) {
	assert.Equal(t, "crictl", ToolName)
	assert.Equal(t, "1.0.0", ToolVersion)
	assert.NotEmpty(t, ToolDescription)
}

// Benchmark tests
func BenchmarkAnalyzeEscapeVectors(b *testing.B) {
	impl := &ToolImpl{}

	containerInfo := []any{
		map[string]any{
			"HostConfig": map[string]any{
				"Privileged":  true,
				"PidMode":     "host",
				"NetworkMode": "host",
				"Binds": []any{
					"/var/run/docker.sock:/var/run/docker.sock",
					"/:/host",
				},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		impl.analyzeEscapeVectors(containerInfo)
	}
}
