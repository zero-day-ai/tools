package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"time"

	sdkinput "github.com/zero-day-ai/sdk/input"
	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "secret-dump"
	ToolVersion     = "1.0.0"
	ToolDescription = "Kubernetes secret enumeration and extraction for security testing"
	BinaryName      = "kubectl"
)

// Known secret types
var secretTypes = map[string]string{
	"kubernetes.io/service-account-token": "Service Account Token",
	"kubernetes.io/dockercfg":             "Docker Config (legacy)",
	"kubernetes.io/dockerconfigjson":      "Docker Config JSON",
	"kubernetes.io/tls":                   "TLS Certificate",
	"kubernetes.io/ssh-auth":              "SSH Auth",
	"kubernetes.io/basic-auth":            "Basic Auth",
	"Opaque":                              "Opaque (generic)",
}

// Credential patterns to detect
var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|passwd|pwd)["\s:=]+["']?([^"'\s,}]+)`),
	regexp.MustCompile(`(?i)(api[_-]?key|apikey)["\s:=]+["']?([^"'\s,}]+)`),
	regexp.MustCompile(`(?i)(secret[_-]?key|secretkey)["\s:=]+["']?([^"'\s,}]+)`),
	regexp.MustCompile(`(?i)(access[_-]?key)["\s:=]+["']?([^"'\s,}]+)`),
	regexp.MustCompile(`(?i)(auth[_-]?token|authtoken)["\s:=]+["']?([^"'\s,}]+)`),
	regexp.MustCompile(`(?i)(bearer[_-]?token)["\s:=]+["']?([^"'\s,}]+)`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`), // AWS Access Key
	regexp.MustCompile(`(?i)mongodb(\+srv)?://[^/\s]+`), // MongoDB connection string
	regexp.MustCompile(`(?i)postgres(ql)?://[^/\s]+`), // PostgreSQL connection string
	regexp.MustCompile(`(?i)mysql://[^/\s]+`), // MySQL connection string
}

// ToolImpl implements the secret-dump tool
type ToolImpl struct{}

// NewTool creates a new secret-dump tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"kubernetes",
			"credential-access",
			"reconnaissance",
			"T1552.001", // Unsecured Credentials: Credentials In Files
			"T1552.007", // Unsecured Credentials: Container API
			"T1555",     // Credentials from Password Stores
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

// Execute implements the secret extraction logic
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
	case "list":
		result, err = t.listSecrets(ctx, input, env, timeout)
	case "dump":
		result, err = t.dumpSecret(ctx, input, env, timeout)
	case "decode":
		result, err = t.decodeSecrets(ctx, input, env, timeout)
	case "search":
		result, err = t.searchSecrets(ctx, input, env, timeout)
	case "analyze-types":
		result, err = t.analyzeTypes(ctx, input, env, timeout)
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

// listSecrets lists secrets in the cluster
func (t *ToolImpl) listSecrets(ctx context.Context, input map[string]any, env []string, timeout time.Duration) (map[string]any, error) {
	args := t.buildBaseArgs(input)

	if sdkinput.GetBool(input, "all_namespaces", false) {
		args = append(args, "get", "secrets", "--all-namespaces", "-o", "json")
	} else if ns := sdkinput.GetString(input, "namespace", ""); ns != "" {
		args = append(args, "get", "secrets", "-n", ns, "-o", "json")
	} else {
		args = append(args, "get", "secrets", "-o", "json")
	}

	// Add label selector if specified
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
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	secrets := []any{}
	tokensFound := []any{}
	tlsSecrets := []any{}

	if len(result.Stdout) > 0 {
		var list struct {
			Items []map[string]any `json:"items"`
		}
		if json.Unmarshal(result.Stdout, &list) == nil {
			secretType := sdkinput.GetString(input, "secret_type", "")

			for _, secret := range list.Items {
				metadata := secret["metadata"].(map[string]any)
				sType := secret["type"].(string)

				// Filter by type if specified
				if secretType != "" && sType != secretType {
					continue
				}

				summary := map[string]any{
					"name":      metadata["name"],
					"namespace": metadata["namespace"],
					"type":      sType,
					"type_name": secretTypes[sType],
					"keys":      getSecretKeys(secret),
				}

				secrets = append(secrets, summary)

				// Track service account tokens
				if sType == "kubernetes.io/service-account-token" {
					tokensFound = append(tokensFound, summary)
				}

				// Track TLS secrets
				if sType == "kubernetes.io/tls" {
					tlsSecrets = append(tlsSecrets, summary)
				}
			}
		}
	}

	return map[string]any{
		"secrets":      secrets,
		"secret_count": len(secrets),
		"tokens_found": tokensFound,
		"tls_secrets":  tlsSecrets,
	}, nil
}

// dumpSecret dumps a specific secret
func (t *ToolImpl) dumpSecret(ctx context.Context, input map[string]any, env []string, timeout time.Duration) (map[string]any, error) {
	secretName := sdkinput.GetString(input, "secret_name", "")
	if secretName == "" {
		return nil, fmt.Errorf("secret_name is required for dump action")
	}

	args := t.buildBaseArgs(input)
	args = append(args, "get", "secret", secretName, "-o", "json")

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
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	if result.ExitCode != 0 {
		return nil, fmt.Errorf("secret not found: %s", string(result.Stderr))
	}

	var secret map[string]any
	if err := json.Unmarshal(result.Stdout, &secret); err != nil {
		return nil, fmt.Errorf("failed to parse secret: %w", err)
	}

	metadata := secret["metadata"].(map[string]any)
	sType := secret["type"].(string)

	// Decode secret data
	secretData := map[string]any{}
	credentialsFound := []any{}
	decodeValues := true
	if dv, ok := input["decode_values"].(bool); ok {
		decodeValues = dv
	}
	redactSensitive := sdkinput.GetBool(input, "redact_sensitive", false)

	if data, ok := secret["data"].(map[string]any); ok {
		for key, value := range data {
			if encoded, ok := value.(string); ok {
				decoded, err := base64.StdEncoding.DecodeString(encoded)
				if err == nil && decodeValues {
					decodedStr := string(decoded)

					if redactSensitive {
						secretData[key] = "[REDACTED - " + fmt.Sprintf("%d bytes", len(decoded)) + "]"
					} else {
						secretData[key] = decodedStr
					}

					// Check for credential patterns
					for _, pattern := range credentialPatterns {
						if pattern.MatchString(decodedStr) {
							credentialsFound = append(credentialsFound, map[string]any{
								"key":     key,
								"pattern": pattern.String(),
								"type":    "potential_credential",
							})
							break
						}
					}
				} else {
					secretData[key] = encoded
				}
			}
		}
	}

	return map[string]any{
		"secrets": []any{
			map[string]any{
				"name":      metadata["name"],
				"namespace": metadata["namespace"],
				"type":      sType,
				"type_name": secretTypes[sType],
			},
		},
		"secret_count":      1,
		"secret_data":       secretData,
		"credentials_found": credentialsFound,
	}, nil
}

// decodeSecrets decodes and analyzes secrets for credentials
func (t *ToolImpl) decodeSecrets(ctx context.Context, input map[string]any, env []string, timeout time.Duration) (map[string]any, error) {
	// First list all secrets
	listResult, err := t.listSecrets(ctx, input, env, timeout)
	if err != nil {
		return nil, err
	}

	secrets := listResult["secrets"].([]any)
	credentialsFound := []any{}
	decodedSecrets := []any{}

	redactSensitive := sdkinput.GetBool(input, "redact_sensitive", false)

	for _, s := range secrets {
		secret := s.(map[string]any)
		name := secret["name"].(string)
		namespace := secret["namespace"].(string)

		// Get and decode each secret
		dumpInput := map[string]any{
			"action":           "dump",
			"secret_name":      name,
			"namespace":        namespace,
			"decode_values":    true,
			"redact_sensitive": redactSensitive,
		}
		if context := sdkinput.GetString(input, "context", ""); context != "" {
			dumpInput["context"] = context
		}

		dumpResult, err := t.dumpSecret(ctx, dumpInput, env, timeout)
		if err != nil {
			continue
		}

		if creds, ok := dumpResult["credentials_found"].([]any); ok && len(creds) > 0 {
			for _, cred := range creds {
				credMap := cred.(map[string]any)
				credMap["secret_name"] = name
				credMap["namespace"] = namespace
				credentialsFound = append(credentialsFound, credMap)
			}
		}

		decodedSecrets = append(decodedSecrets, map[string]any{
			"name":        name,
			"namespace":   namespace,
			"type":        secret["type"],
			"secret_data": dumpResult["secret_data"],
		})
	}

	return map[string]any{
		"secrets":           decodedSecrets,
		"secret_count":      len(decodedSecrets),
		"credentials_found": credentialsFound,
	}, nil
}

// searchSecrets searches for patterns in secrets
func (t *ToolImpl) searchSecrets(ctx context.Context, input map[string]any, env []string, timeout time.Duration) (map[string]any, error) {
	pattern := sdkinput.GetString(input, "search_pattern", "")
	if pattern == "" {
		return nil, fmt.Errorf("search_pattern is required for search action")
	}

	searchRegex, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid search pattern: %w", err)
	}

	// Decode all secrets
	input["decode_values"] = true
	input["redact_sensitive"] = false
	decodeResult, err := t.decodeSecrets(ctx, input, env, timeout)
	if err != nil {
		return nil, err
	}

	searchResults := []any{}
	secrets := decodeResult["secrets"].([]any)

	for _, s := range secrets {
		secret := s.(map[string]any)
		if secretData, ok := secret["secret_data"].(map[string]any); ok {
			for key, value := range secretData {
				if valueStr, ok := value.(string); ok {
					if searchRegex.MatchString(valueStr) || searchRegex.MatchString(key) {
						matches := searchRegex.FindAllString(valueStr, -1)
						searchResults = append(searchResults, map[string]any{
							"secret_name": secret["name"],
							"namespace":   secret["namespace"],
							"key":         key,
							"matches":     matches,
							"match_count": len(matches),
						})
					}
				}
			}
		}
	}

	return map[string]any{
		"search_results": searchResults,
		"secret_count":   len(searchResults),
	}, nil
}

// analyzeTypes analyzes secret types in the cluster
func (t *ToolImpl) analyzeTypes(ctx context.Context, input map[string]any, env []string, timeout time.Duration) (map[string]any, error) {
	listResult, err := t.listSecrets(ctx, input, env, timeout)
	if err != nil {
		return nil, err
	}

	secrets := listResult["secrets"].([]any)
	typeAnalysis := map[string]any{}

	for _, s := range secrets {
		secret := s.(map[string]any)
		sType := secret["type"].(string)

		if _, exists := typeAnalysis[sType]; !exists {
			typeAnalysis[sType] = map[string]any{
				"count":     0,
				"type_name": secretTypes[sType],
				"secrets":   []string{},
			}
		}

		analysis := typeAnalysis[sType].(map[string]any)
		analysis["count"] = analysis["count"].(int) + 1
		analysis["secrets"] = append(analysis["secrets"].([]string),
			fmt.Sprintf("%s/%s", secret["namespace"], secret["name"]))
	}

	return map[string]any{
		"type_analysis": typeAnalysis,
		"secret_count":  len(secrets),
		"tokens_found":  listResult["tokens_found"],
		"tls_secrets":   listResult["tls_secrets"],
	}, nil
}

// getSecretKeys extracts the keys from secret data
func getSecretKeys(secret map[string]any) []string {
	keys := []string{}
	if data, ok := secret["data"].(map[string]any); ok {
		for key := range data {
			keys = append(keys, key)
		}
	}
	return keys
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

	return types.NewHealthyStatus(fmt.Sprintf("%s is available for secret extraction", BinaryName))
}
