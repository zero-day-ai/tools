package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTool_SecretDump(t *testing.T) {
	tool := NewTool()
	require.NotNil(t, tool, "NewTool should return a non-nil tool")
}

func TestToolImpl_Execute_ValidationErrors_SecretDump(t *testing.T) {
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
			name: "dump without secret_name",
			input: map[string]any{
				"action": "dump",
			},
			expectedErr: "secret_name is required for dump action",
		},
		{
			name: "search without search_pattern",
			input: map[string]any{
				"action": "search",
			},
			expectedErr: "search_pattern is required for search action",
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

func TestToolImpl_BuildBaseArgs_SecretDump(t *testing.T) {
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
				"context": "my-cluster",
			},
			expected: []string{"--context", "my-cluster"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := impl.buildBaseArgs(tt.input)
			assert.Equal(t, tt.expected, args)
		})
	}
}

func TestGetSecretKeys(t *testing.T) {
	tests := []struct {
		name     string
		secret   map[string]any
		expected []string
	}{
		{
			name: "secret with data",
			secret: map[string]any{
				"data": map[string]any{
					"username": "dXNlcg==",
					"password": "cGFzcw==",
					"token":    "dG9rZW4=",
				},
			},
			expected: []string{"username", "password", "token"},
		},
		{
			name:     "secret without data",
			secret:   map[string]any{},
			expected: []string{},
		},
		{
			name: "secret with empty data",
			secret: map[string]any{
				"data": map[string]any{},
			},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys := getSecretKeys(tt.secret)
			// Sort both slices for comparison since map iteration order is random
			assert.ElementsMatch(t, tt.expected, keys)
		})
	}
}

func TestSecretTypes(t *testing.T) {
	t.Run("known secret types are defined", func(t *testing.T) {
		assert.NotEmpty(t, secretTypes)
		assert.Contains(t, secretTypes, "kubernetes.io/service-account-token")
		assert.Contains(t, secretTypes, "kubernetes.io/dockerconfigjson")
		assert.Contains(t, secretTypes, "kubernetes.io/tls")
		assert.Contains(t, secretTypes, "Opaque")
	})

	t.Run("secret type descriptions", func(t *testing.T) {
		assert.Equal(t, "Service Account Token", secretTypes["kubernetes.io/service-account-token"])
		assert.Equal(t, "Docker Config JSON", secretTypes["kubernetes.io/dockerconfigjson"])
		assert.Equal(t, "TLS Certificate", secretTypes["kubernetes.io/tls"])
	})
}

func TestCredentialPatterns(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		matches bool
	}{
		{
			name:    "password pattern",
			input:   `password: "mysecretpassword"`,
			matches: true,
		},
		{
			name:    "api key pattern",
			input:   `api_key: "abc123xyz"`,
			matches: true,
		},
		{
			name:    "AWS access key",
			input:   "AKIAIOSFODNN7EXAMPLE",
			matches: true,
		},
		{
			name:    "MongoDB connection string",
			input:   "mongodb://user:pass@localhost:27017/db",
			matches: true,
		},
		{
			name:    "PostgreSQL connection string",
			input:   "postgresql://user:pass@localhost:5432/db",
			matches: true,
		},
		{
			name:    "MySQL connection string",
			input:   "mysql://user:pass@localhost:3306/db",
			matches: true,
		},
		{
			name:    "no credential",
			input:   "just some regular text",
			matches: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found := false
			for _, pattern := range credentialPatterns {
				if pattern.MatchString(tt.input) {
					found = true
					break
				}
			}
			assert.Equal(t, tt.matches, found)
		})
	}
}

func TestBase64Decoding(t *testing.T) {
	tests := []struct {
		name     string
		encoded  string
		expected string
	}{
		{
			name:     "simple string",
			encoded:  base64.StdEncoding.EncodeToString([]byte("hello")),
			expected: "hello",
		},
		{
			name:     "username",
			encoded:  base64.StdEncoding.EncodeToString([]byte("admin")),
			expected: "admin",
		},
		{
			name:     "password",
			encoded:  base64.StdEncoding.EncodeToString([]byte("P@ssw0rd123!")),
			expected: "P@ssw0rd123!",
		},
		{
			name:     "json data",
			encoded:  base64.StdEncoding.EncodeToString([]byte(`{"key":"value"}`)),
			expected: `{"key":"value"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoded, err := base64.StdEncoding.DecodeString(tt.encoded)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(decoded))
		})
	}
}

func TestSecretListJSONParsing(t *testing.T) {
	secretJSON := `{
		"items": [
			{
				"metadata": {
					"name": "my-secret",
					"namespace": "default"
				},
				"type": "Opaque",
				"data": {
					"username": "YWRtaW4=",
					"password": "cGFzc3dvcmQ="
				}
			}
		]
	}`

	var list struct {
		Items []map[string]any `json:"items"`
	}

	err := json.Unmarshal([]byte(secretJSON), &list)
	require.NoError(t, err)
	assert.Len(t, list.Items, 1)

	secret := list.Items[0]
	metadata := secret["metadata"].(map[string]any)
	assert.Equal(t, "my-secret", metadata["name"])
	assert.Equal(t, "default", metadata["namespace"])
	assert.Equal(t, "Opaque", secret["type"])
}

func TestSearchPatternCompilation(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		shouldError bool
	}{
		{
			name:        "valid simple pattern",
			pattern:     "password",
			shouldError: false,
		},
		{
			name:        "valid regex pattern",
			pattern:     "[a-z]+",
			shouldError: false,
		},
		{
			name:        "invalid regex pattern",
			pattern:     "[invalid",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := regexp.Compile("(?i)" + tt.pattern)
			if tt.shouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConstants_SecretDump(t *testing.T) {
	assert.Equal(t, "secret-dump", ToolName)
	assert.Equal(t, "1.0.0", ToolVersion)
	assert.NotEmpty(t, ToolDescription)
	assert.Equal(t, "kubectl", BinaryName)
}

// Benchmark tests
func BenchmarkGetSecretKeys(b *testing.B) {
	secret := map[string]any{
		"data": map[string]any{
			"key1": "value1",
			"key2": "value2",
			"key3": "value3",
			"key4": "value4",
			"key5": "value5",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		getSecretKeys(secret)
	}
}

func BenchmarkCredentialPatternMatching(b *testing.B) {
	testString := `{
		"password": "mysecret",
		"api_key": "abc123",
		"database": "postgresql://user:pass@host/db"
	}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, pattern := range credentialPatterns {
			pattern.MatchString(testString)
		}
	}
}

func BenchmarkBase64Decode(b *testing.B) {
	encoded := base64.StdEncoding.EncodeToString([]byte("test data to encode and decode"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		base64.StdEncoding.DecodeString(encoded)
	}
}
