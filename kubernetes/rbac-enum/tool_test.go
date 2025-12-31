package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTool(t *testing.T) {
	tool := NewTool()
	require.NotNil(t, tool, "NewTool should return a non-nil tool")
}

func TestToolImpl_Execute_ValidationErrors(t *testing.T) {
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
				"action": "unknown-action",
			},
			expectedErr: "unknown action: unknown-action",
		},
		{
			name: "can-i missing verb",
			input: map[string]any{
				"action":   "can-i",
				"resource": "pods",
			},
			expectedErr: "verb and resource are required for can-i",
		},
		{
			name: "can-i missing resource",
			input: map[string]any{
				"action": "can-i",
				"verb":   "get",
			},
			expectedErr: "verb and resource are required for can-i",
		},
	}

	impl := &ToolImpl{}
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := impl.Execute(ctx, tt.input)

			// These should return error results, not Go errors
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

func TestToolImpl_Execute_Timeout(t *testing.T) {
	impl := &ToolImpl{}

	tests := []struct {
		name            string
		input           map[string]any
		expectedTimeout time.Duration
	}{
		{
			name: "default timeout",
			input: map[string]any{
				"action": "whoami",
			},
			expectedTimeout: 60 * time.Second,
		},
		{
			name: "custom timeout",
			input: map[string]any{
				"action":  "whoami",
				"timeout": 30,
			},
			expectedTimeout: 30 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We're just verifying the input is accepted without error
			// The actual execution will fail without kubectl, which is expected
			ctx := context.Background()
			result, err := impl.Execute(ctx, tt.input)

			// We expect this to fail (no kubectl), but it shouldn't panic
			// and should have proper error handling
			if err == nil {
				assert.NotNil(t, result)
				assert.Contains(t, result, "success")
			}
		})
	}
}

func TestToolImpl_BuildBaseArgs(t *testing.T) {
	impl := &ToolImpl{}

	tests := []struct {
		name     string
		input    map[string]any
		expected []string
	}{
		{
			name:     "no arguments",
			input:    map[string]any{},
			expected: []string{},
		},
		{
			name: "with context",
			input: map[string]any{
				"context": "my-cluster",
			},
			expected: []string{"--context", "my-cluster"},
		},
		{
			name: "with as_user",
			input: map[string]any{
				"as_user": "admin",
			},
			expected: []string{"--as", "admin"},
		},
		{
			name: "with as_group",
			input: map[string]any{
				"as_group": []any{"group1", "group2"},
			},
			expected: []string{"--as-group", "group1", "--as-group", "group2"},
		},
		{
			name: "with all options",
			input: map[string]any{
				"context":  "my-cluster",
				"as_user":  "admin",
				"as_group": []any{"group1"},
			},
			expected: []string{"--context", "my-cluster", "--as", "admin", "--as-group", "group1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := impl.buildBaseArgs(tt.input)
			assert.Equal(t, tt.expected, args)
		})
	}
}

func TestToolImpl_CheckEscalationPattern(t *testing.T) {
	impl := &ToolImpl{}

	tests := []struct {
		name       string
		verb       string
		resource   string
		shouldFind bool
		severity   string
		techID     string
	}{
		{
			name:       "create pods - critical",
			verb:       "create",
			resource:   "pods",
			shouldFind: true,
			severity:   "high",
			techID:     "T1610",
		},
		{
			name:       "exec pods - critical",
			verb:       "exec",
			resource:   "pods",
			shouldFind: true,
			severity:   "critical",
			techID:     "T1609",
		},
		{
			name:       "create secrets - high",
			verb:       "create",
			resource:   "secrets",
			shouldFind: true,
			severity:   "high",
			techID:     "T1552.007",
		},
		{
			name:       "create clusterrolebindings - critical",
			verb:       "create",
			resource:   "clusterrolebindings",
			shouldFind: true,
			severity:   "critical",
			techID:     "T1078.004",
		},
		{
			name:       "impersonate serviceaccounts - critical",
			verb:       "impersonate",
			resource:   "serviceaccounts",
			shouldFind: true,
			severity:   "critical",
			techID:     "T1078.004",
		},
		{
			name:       "create daemonsets - high",
			verb:       "create",
			resource:   "daemonsets",
			shouldFind: true,
			severity:   "high",
			techID:     "T1053.007",
		},
		{
			name:       "get pods - safe",
			verb:       "get",
			resource:   "pods",
			shouldFind: false,
		},
		{
			name:       "list secrets - safe",
			verb:       "list",
			resource:   "secrets",
			shouldFind: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern := impl.checkEscalationPattern(tt.verb, tt.resource)

			if tt.shouldFind {
				require.NotNil(t, pattern, "expected to find escalation pattern")
				assert.Equal(t, tt.verb, pattern["verb"])
				assert.Equal(t, tt.resource, pattern["resource"])
				assert.Equal(t, tt.severity, pattern["severity"])
				assert.Equal(t, tt.techID, pattern["technique"])
				assert.NotEmpty(t, pattern["description"])
			} else {
				assert.Nil(t, pattern, "expected no escalation pattern")
			}
		})
	}
}

func TestToolImpl_WhoamiJSONParsing(t *testing.T) {
	// Test JSON parsing of whoami response
	whoamiJSON := `{
		"status": {
			"userInfo": {
				"username": "system:serviceaccount:default:test",
				"uid": "abc-123",
				"groups": ["system:serviceaccounts", "system:authenticated"]
			}
		}
	}`

	var whoami struct {
		Status struct {
			UserInfo struct {
				Username string   `json:"username"`
				UID      string   `json:"uid"`
				Groups   []string `json:"groups"`
			} `json:"userInfo"`
		} `json:"status"`
	}

	err := json.Unmarshal([]byte(whoamiJSON), &whoami)
	require.NoError(t, err)
	assert.Equal(t, "system:serviceaccount:default:test", whoami.Status.UserInfo.Username)
	assert.Equal(t, "abc-123", whoami.Status.UserInfo.UID)
	assert.Len(t, whoami.Status.UserInfo.Groups, 2)
}

func TestToolImpl_RolesJSONParsing(t *testing.T) {
	// Test JSON parsing of roles list
	rolesJSON := `{
		"items": [
			{"metadata": {"name": "role1"}},
			{"metadata": {"name": "role2"}}
		]
	}`

	var list struct {
		Items []any `json:"items"`
	}

	err := json.Unmarshal([]byte(rolesJSON), &list)
	require.NoError(t, err)
	assert.Len(t, list.Items, 2)
}

func TestDangerousVerbsAndResources(t *testing.T) {
	t.Run("dangerous verbs are defined", func(t *testing.T) {
		assert.NotEmpty(t, defaultDangerousVerbs)
		assert.Contains(t, defaultDangerousVerbs, "create")
		assert.Contains(t, defaultDangerousVerbs, "delete")
		assert.Contains(t, defaultDangerousVerbs, "exec")
		assert.Contains(t, defaultDangerousVerbs, "impersonate")
	})

	t.Run("dangerous resources are defined", func(t *testing.T) {
		assert.NotEmpty(t, dangerousResources)
		assert.Contains(t, dangerousResources, "secrets")
		assert.Contains(t, dangerousResources, "pods")
		assert.Contains(t, dangerousResources, "clusterroles")
	})
}

func TestConstants(t *testing.T) {
	assert.Equal(t, "rbac-enum", ToolName)
	assert.Equal(t, "1.0.0", ToolVersion)
	assert.NotEmpty(t, ToolDescription)
	assert.Equal(t, "kubectl", BinaryName)
}

// Benchmark tests
func BenchmarkBuildBaseArgs(b *testing.B) {
	impl := &ToolImpl{}
	input := map[string]any{
		"context":  "test-context",
		"as_user":  "admin",
		"as_group": []any{"group1", "group2"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		impl.buildBaseArgs(input)
	}
}

func BenchmarkCheckEscalationPattern(b *testing.B) {
	impl := &ToolImpl{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		impl.checkEscalationPattern("create", "pods")
		impl.checkEscalationPattern("get", "configmaps")
	}
}
