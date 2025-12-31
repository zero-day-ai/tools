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
	ToolName        = "rbac-enum"
	ToolVersion     = "1.0.0"
	ToolDescription = "Kubernetes RBAC enumeration and permission testing for security assessment"
	BinaryName      = "kubectl"
)

// Default dangerous verbs and resources to check for escalation
var (
	defaultDangerousVerbs = []string{
		"create", "delete", "patch", "update", "exec", "impersonate",
		"bind", "escalate", "deletecollection",
	}
	dangerousResources = []string{
		"secrets", "pods", "pods/exec", "pods/attach", "deployments",
		"daemonsets", "serviceaccounts", "clusterroles", "clusterrolebindings",
		"roles", "rolebindings", "nodes", "persistentvolumes",
		"mutatingwebhookconfigurations", "validatingwebhookconfigurations",
	}
)

// ToolImpl implements the rbac-enum tool
type ToolImpl struct{}

// NewTool creates a new rbac-enum tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"kubernetes",
			"reconnaissance",
			"privilege-escalation",
			"T1078.004", // Valid Accounts: Cloud Accounts
			"T1552.007", // Unsecured Credentials: Container API
			"T1613",     // Container and Resource Discovery
		}).
		SetInputSchema(InputSchema()).
		SetOutputSchema(OutputSchema()).
		SetExecuteFunc((&ToolImpl{}).Execute)

	t, _ := tool.New(cfg)
	return &toolWithHealth{Tool: t, impl: &ToolImpl{}}
}

// toolWithHealth wraps the tool to add custom health checks
type toolWithHealth struct {
	tool.Tool
	impl *ToolImpl
}

func (t *toolWithHealth) Health(ctx context.Context) types.HealthStatus {
	return t.impl.Health(ctx)
}

// Execute implements the RBAC enumeration logic
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	start := time.Now()

	action := sdkinput.GetString(input, "action", "")
	if action == "" {
		return nil, fmt.Errorf("action is required")
	}

	timeout := 60 * time.Second
	if t := sdkinput.GetInt(input, "timeout", 0); t > 0 {
		timeout = time.Duration(t) * time.Second
	}

	// Build environment
	env := os.Environ()
	if kubeconfig := sdkinput.GetString(input, "kubeconfig", ""); kubeconfig != "" {
		env = append(env, fmt.Sprintf("KUBECONFIG=%s", kubeconfig))
	}

	var result map[string]any
	var err error

	switch action {
	case "whoami":
		result, err = t.whoami(ctx, input, env, timeout)
	case "can-i":
		result, err = t.canI(ctx, input, env, timeout)
	case "list-roles":
		result, err = t.listRoles(ctx, input, env, timeout)
	case "list-bindings":
		result, err = t.listBindings(ctx, input, env, timeout)
	case "list-all":
		result, err = t.listAll(ctx, input, env, timeout)
	case "check-escalation":
		result, err = t.checkEscalation(ctx, input, env, timeout)
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

// whoami returns the current authenticated identity
func (t *ToolImpl) whoami(ctx context.Context, input map[string]any, env []string, timeout time.Duration) (map[string]any, error) {
	args := t.buildBaseArgs(input)
	args = append(args, "auth", "whoami", "-o", "json")

	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Env:     env,
		Timeout: timeout,
	})

	if err != nil && result == nil {
		return nil, fmt.Errorf("whoami failed: %w", err)
	}

	// Parse JSON output
	var whoami struct {
		Status struct {
			UserInfo struct {
				Username string   `json:"username"`
				UID      string   `json:"uid"`
				Groups   []string `json:"groups"`
			} `json:"userInfo"`
		} `json:"status"`
	}

	if err := json.Unmarshal(result.Stdout, &whoami); err != nil {
		// Fallback: try to get info from auth can-i
		return t.whoamiFallback(ctx, input, env, timeout)
	}

	return map[string]any{
		"username": whoami.Status.UserInfo.Username,
		"uid":      whoami.Status.UserInfo.UID,
		"groups":   whoami.Status.UserInfo.Groups,
	}, nil
}

// whoamiFallback uses auth can-i to get user info
func (t *ToolImpl) whoamiFallback(ctx context.Context, input map[string]any, env []string, timeout time.Duration) (map[string]any, error) {
	args := t.buildBaseArgs(input)
	args = append(args, "auth", "can-i", "--list")

	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Env:     env,
		Timeout: timeout,
	})

	if err != nil && result == nil {
		return nil, fmt.Errorf("whoami fallback failed: %w", err)
	}

	// Return basic info
	return map[string]any{
		"username": "unknown (use 'kubectl auth whoami' for details)",
		"groups":   []string{},
		"uid":      "",
	}, nil
}

// canI checks if an action is allowed
func (t *ToolImpl) canI(ctx context.Context, input map[string]any, env []string, timeout time.Duration) (map[string]any, error) {
	verb := sdkinput.GetString(input, "verb", "")
	resource := sdkinput.GetString(input, "resource", "")

	if verb == "" || resource == "" {
		return nil, fmt.Errorf("verb and resource are required for can-i")
	}

	args := t.buildBaseArgs(input)
	args = append(args, "auth", "can-i", verb, resource)

	// Add subresource if specified
	if subresource := sdkinput.GetString(input, "subresource", ""); subresource != "" {
		args[len(args)-1] = resource + "/" + subresource
	}

	// Add resource name if specified
	if resourceName := sdkinput.GetString(input, "resource_name", ""); resourceName != "" {
		args = append(args, resourceName)
	}

	// Add namespace
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
		return nil, fmt.Errorf("can-i check failed: %w", err)
	}

	allowed := result.ExitCode == 0
	reason := strings.TrimSpace(string(result.Stdout))

	return map[string]any{
		"allowed": allowed,
		"reason":  reason,
		"verb":    verb,
		"resource": resource,
	}, nil
}

// listRoles lists roles and cluster roles
func (t *ToolImpl) listRoles(ctx context.Context, input map[string]any, env []string, timeout time.Duration) (map[string]any, error) {
	roles := []any{}
	clusterRoles := []any{}

	// Get roles
	args := t.buildBaseArgs(input)
	if sdkinput.GetBool(input, "all_namespaces", false) {
		args = append(args, "get", "roles", "--all-namespaces", "-o", "json")
	} else if ns := sdkinput.GetString(input, "namespace", ""); ns != "" {
		args = append(args, "get", "roles", "-n", ns, "-o", "json")
	} else {
		args = append(args, "get", "roles", "-o", "json")
	}

	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Env:     env,
		Timeout: timeout,
	})

	if err == nil && result.ExitCode == 0 {
		var list struct {
			Items []any `json:"items"`
		}
		if json.Unmarshal(result.Stdout, &list) == nil {
			roles = list.Items
		}
	}

	// Get cluster roles
	args = t.buildBaseArgs(input)
	args = append(args, "get", "clusterroles", "-o", "json")

	result, err = exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Env:     env,
		Timeout: timeout,
	})

	if err == nil && result.ExitCode == 0 {
		var list struct {
			Items []any `json:"items"`
		}
		if json.Unmarshal(result.Stdout, &list) == nil {
			clusterRoles = list.Items
		}
	}

	return map[string]any{
		"roles":         roles,
		"cluster_roles": clusterRoles,
	}, nil
}

// listBindings lists role bindings and cluster role bindings
func (t *ToolImpl) listBindings(ctx context.Context, input map[string]any, env []string, timeout time.Duration) (map[string]any, error) {
	roleBindings := []any{}
	clusterRoleBindings := []any{}

	// Get role bindings
	args := t.buildBaseArgs(input)
	if sdkinput.GetBool(input, "all_namespaces", false) {
		args = append(args, "get", "rolebindings", "--all-namespaces", "-o", "json")
	} else if ns := sdkinput.GetString(input, "namespace", ""); ns != "" {
		args = append(args, "get", "rolebindings", "-n", ns, "-o", "json")
	} else {
		args = append(args, "get", "rolebindings", "-o", "json")
	}

	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Env:     env,
		Timeout: timeout,
	})

	if err == nil && result.ExitCode == 0 {
		var list struct {
			Items []any `json:"items"`
		}
		if json.Unmarshal(result.Stdout, &list) == nil {
			roleBindings = list.Items
		}
	}

	// Get cluster role bindings
	args = t.buildBaseArgs(input)
	args = append(args, "get", "clusterrolebindings", "-o", "json")

	result, err = exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Env:     env,
		Timeout: timeout,
	})

	if err == nil && result.ExitCode == 0 {
		var list struct {
			Items []any `json:"items"`
		}
		if json.Unmarshal(result.Stdout, &list) == nil {
			clusterRoleBindings = list.Items
		}
	}

	return map[string]any{
		"role_bindings":         roleBindings,
		"cluster_role_bindings": clusterRoleBindings,
	}, nil
}

// listAll lists all RBAC resources
func (t *ToolImpl) listAll(ctx context.Context, input map[string]any, env []string, timeout time.Duration) (map[string]any, error) {
	rolesResult, _ := t.listRoles(ctx, input, env, timeout)
	bindingsResult, _ := t.listBindings(ctx, input, env, timeout)

	return map[string]any{
		"roles":                 rolesResult["roles"],
		"cluster_roles":         rolesResult["cluster_roles"],
		"role_bindings":         bindingsResult["role_bindings"],
		"cluster_role_bindings": bindingsResult["cluster_role_bindings"],
	}, nil
}

// checkEscalation checks for privilege escalation opportunities
func (t *ToolImpl) checkEscalation(ctx context.Context, input map[string]any, env []string, timeout time.Duration) (map[string]any, error) {
	dangerousPermissions := []any{}
	escalationPaths := []any{}

	// Get dangerous verbs to check
	dangerousVerbs := defaultDangerousVerbs
	if customVerbs := sdkinput.GetStringSlice(input, "dangerous_verbs"); len(customVerbs) > 0 {
		dangerousVerbs = customVerbs
	}

	// Check each dangerous resource/verb combination
	for _, resource := range dangerousResources {
		for _, verb := range dangerousVerbs {
			checkInput := map[string]any{
				"verb":     verb,
				"resource": resource,
			}
			if ns := sdkinput.GetString(input, "namespace", ""); ns != "" {
				checkInput["namespace"] = ns
			}
			if context := sdkinput.GetString(input, "context", ""); context != "" {
				checkInput["context"] = context
			}

			result, err := t.canI(ctx, checkInput, env, timeout)
			if err != nil {
				continue
			}

			if allowed, ok := result["allowed"].(bool); ok && allowed {
				perm := map[string]any{
					"verb":     verb,
					"resource": resource,
				}
				dangerousPermissions = append(dangerousPermissions, perm)

				// Check for known escalation patterns
				if escalation := t.checkEscalationPattern(verb, resource); escalation != nil {
					escalationPaths = append(escalationPaths, escalation)
				}
			}
		}
	}

	return map[string]any{
		"dangerous_permissions": dangerousPermissions,
		"escalation_paths":      escalationPaths,
	}, nil
}

// checkEscalationPattern identifies known privilege escalation patterns
func (t *ToolImpl) checkEscalationPattern(verb, resource string) map[string]any {
	patterns := map[string]map[string]any{
		"create:pods": {
			"type":        "container-creation",
			"severity":    "high",
			"description": "Can create pods - potential for container escape or secret access",
			"technique":   "T1610",
		},
		"create:pods/exec": {
			"type":        "container-exec",
			"severity":    "critical",
			"description": "Can execute commands in existing containers",
			"technique":   "T1609",
		},
		"exec:pods": {
			"type":        "container-exec",
			"severity":    "critical",
			"description": "Can execute commands in existing containers",
			"technique":   "T1609",
		},
		"create:secrets": {
			"type":        "secret-creation",
			"severity":    "high",
			"description": "Can create secrets - potential for credential injection",
			"technique":   "T1552.007",
		},
		"patch:secrets": {
			"type":        "secret-modification",
			"severity":    "high",
			"description": "Can modify existing secrets",
			"technique":   "T1552.007",
		},
		"create:clusterrolebindings": {
			"type":        "rbac-escalation",
			"severity":    "critical",
			"description": "Can create cluster role bindings - potential for cluster-admin access",
			"technique":   "T1078.004",
		},
		"create:rolebindings": {
			"type":        "rbac-escalation",
			"severity":    "high",
			"description": "Can create role bindings - potential for namespace admin access",
			"technique":   "T1078.004",
		},
		"impersonate:serviceaccounts": {
			"type":        "impersonation",
			"severity":    "critical",
			"description": "Can impersonate service accounts - potential for privilege escalation",
			"technique":   "T1078.004",
		},
		"create:daemonsets": {
			"type":        "persistence",
			"severity":    "high",
			"description": "Can create daemonsets - potential for cluster-wide persistence",
			"technique":   "T1053.007",
		},
	}

	key := verb + ":" + resource
	if pattern, exists := patterns[key]; exists {
		pattern["verb"] = verb
		pattern["resource"] = resource
		return pattern
	}
	return nil
}

// buildBaseArgs builds common kubectl arguments
func (t *ToolImpl) buildBaseArgs(input map[string]any) []string {
	args := []string{}

	if context := sdkinput.GetString(input, "context", ""); context != "" {
		args = append(args, "--context", context)
	}

	if asUser := sdkinput.GetString(input, "as_user", ""); asUser != "" {
		args = append(args, "--as", asUser)
	}

	if asGroups := sdkinput.GetStringSlice(input, "as_group"); len(asGroups) > 0 {
		for _, group := range asGroups {
			args = append(args, "--as-group", group)
		}
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

	return types.NewHealthyStatus(fmt.Sprintf("%s is available for RBAC enumeration", BinaryName))
}
