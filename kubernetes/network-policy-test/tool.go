package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	sdkinput "github.com/zero-day-ai/sdk/input"
	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName          = "network-policy-test"
	ToolVersion       = "1.0.0"
	ToolDescription   = "Network policy testing and bypass detection for Kubernetes clusters"
	BinaryName        = "kubectl"
	DefaultMetadataIP = "169.254.169.254"
)

// ToolImpl implements the network-policy-test tool
type ToolImpl struct{}

// NewTool creates a new network-policy-test tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"kubernetes",
			"network",
			"reconnaissance",
			"defense-evasion",
			"T1046", // Network Service Discovery
			"T1562.007", // Impair Defenses: Disable or Modify Cloud Firewall
			"T1552.005", // Unsecured Credentials: Cloud Instance Metadata API
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

// Execute implements the network policy testing logic
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	start := time.Now()

	action := sdkinput.GetString(input, "action", "")
	if action == "" {
		return nil, fmt.Errorf("action is required")
	}

	timeout := 30 * time.Second
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
	case "list-policies":
		result, err = t.listPolicies(ctx, input, env, timeout)
	case "test-connectivity":
		result, err = t.testConnectivity(ctx, input, timeout)
	case "test-egress":
		result, err = t.testEgress(ctx, input, timeout)
	case "test-metadata":
		result, err = t.testMetadataAccess(ctx, input, timeout)
	case "analyze-gaps":
		result, err = t.analyzeGaps(ctx, input, env, timeout)
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

// listPolicies lists network policies in the cluster
func (t *ToolImpl) listPolicies(ctx context.Context, input map[string]any, env []string, timeout time.Duration) (map[string]any, error) {
	args := t.buildBaseArgs(input)

	if sdkinput.GetBool(input, "all_namespaces", false) {
		args = append(args, "get", "networkpolicies", "--all-namespaces", "-o", "json")
	} else if ns := sdkinput.GetString(input, "namespace", ""); ns != "" {
		args = append(args, "get", "networkpolicies", "-n", ns, "-o", "json")
	} else {
		args = append(args, "get", "networkpolicies", "-o", "json")
	}

	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Env:     env,
		Timeout: timeout,
	})

	if err != nil && result == nil {
		return nil, fmt.Errorf("failed to list network policies: %w", err)
	}

	policies := []any{}
	if len(result.Stdout) > 0 {
		var list struct {
			Items []any `json:"items"`
		}
		if json.Unmarshal(result.Stdout, &list) == nil {
			policies = list.Items
		}
	}

	return map[string]any{
		"policies":     policies,
		"policy_count": len(policies),
	}, nil
}

// testConnectivity tests network connectivity between pods or to external hosts
func (t *ToolImpl) testConnectivity(ctx context.Context, input map[string]any, timeout time.Duration) (map[string]any, error) {
	targetHost := sdkinput.GetString(input, "target_host", "")
	if targetHost == "" {
		return nil, fmt.Errorf("target_host is required for connectivity test")
	}

	targetPort := sdkinput.GetInt(input, "target_port", 0)
	if targetPort == 0 {
		targetPort = 80
	}

	protocol := sdkinput.GetString(input, "protocol", "")
	if protocol == "" {
		protocol = "tcp"
	}

	start := time.Now()
	address := fmt.Sprintf("%s:%d", targetHost, targetPort)

	conn, err := net.DialTimeout(protocol, address, timeout)
	latency := time.Since(start)

	connectivity := map[string]any{
		"target_host": targetHost,
		"target_port": targetPort,
		"protocol":    protocol,
		"reachable":   false,
		"latency":     latency.String(),
	}

	if err != nil {
		connectivity["error"] = err.Error()
	} else {
		connectivity["reachable"] = true
		conn.Close()
	}

	return map[string]any{
		"connectivity": connectivity,
	}, nil
}

// testEgress tests common egress destinations
func (t *ToolImpl) testEgress(ctx context.Context, input map[string]any, timeout time.Duration) (map[string]any, error) {
	// Common egress targets to test
	targets := []struct {
		Name    string
		Host    string
		Port    int
		Type    string
	}{
		{"DNS (Google)", "8.8.8.8", 53, "dns"},
		{"DNS (Cloudflare)", "1.1.1.1", 53, "dns"},
		{"HTTPS (Google)", "google.com", 443, "https"},
		{"HTTP (httpbin)", "httpbin.org", 80, "http"},
		{"Cloud Metadata (AWS/GCP)", "169.254.169.254", 80, "metadata"},
		{"Kubernetes API", "kubernetes.default.svc", 443, "api"},
	}

	results := []any{}

	for _, target := range targets {
		start := time.Now()
		address := fmt.Sprintf("%s:%d", target.Host, target.Port)

		testResult := map[string]any{
			"name":      target.Name,
			"host":      target.Host,
			"port":      target.Port,
			"type":      target.Type,
			"reachable": false,
		}

		conn, err := net.DialTimeout("tcp", address, 5*time.Second)
		testResult["latency"] = time.Since(start).String()

		if err != nil {
			testResult["error"] = err.Error()
		} else {
			testResult["reachable"] = true
			conn.Close()
		}

		results = append(results, testResult)
	}

	return map[string]any{
		"egress_tests": results,
	}, nil
}

// testMetadataAccess tests if cloud metadata service is accessible
func (t *ToolImpl) testMetadataAccess(ctx context.Context, input map[string]any, timeout time.Duration) (map[string]any, error) {
	metadataIP := sdkinput.GetString(input, "metadata_ip", "")
	if metadataIP == "" {
		metadataIP = DefaultMetadataIP
	}

	client := &http.Client{Timeout: timeout}

	// Try different cloud providers
	providers := []struct {
		Name    string
		URL     string
		Headers map[string]string
	}{
		{
			"AWS",
			fmt.Sprintf("http://%s/latest/meta-data/", metadataIP),
			nil,
		},
		{
			"GCP",
			fmt.Sprintf("http://%s/computeMetadata/v1/", metadataIP),
			map[string]string{"Metadata-Flavor": "Google"},
		},
		{
			"Azure",
			fmt.Sprintf("http://%s/metadata/instance?api-version=2021-02-01", metadataIP),
			map[string]string{"Metadata": "true"},
		},
	}

	for _, provider := range providers {
		req, err := http.NewRequestWithContext(ctx, "GET", provider.URL, nil)
		if err != nil {
			continue
		}

		for k, v := range provider.Headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(resp.Body)
			snippet := string(body)
			if len(snippet) > 200 {
				snippet = snippet[:200] + "..."
			}

			return map[string]any{
				"metadata_accessible": true,
				"provider":            provider.Name,
				"metadata_response":   snippet,
				"gaps": []any{
					map[string]any{
						"type":        "metadata-access",
						"severity":    "high",
						"description": fmt.Sprintf("%s metadata service is accessible from pod", provider.Name),
						"technique":   "T1552.005",
						"remediation": "Block egress to 169.254.169.254 using NetworkPolicy",
					},
				},
			}, nil
		}
	}

	return map[string]any{
		"metadata_accessible": false,
		"metadata_response":   "",
	}, nil
}

// analyzeGaps analyzes network policy coverage gaps
func (t *ToolImpl) analyzeGaps(ctx context.Context, input map[string]any, env []string, timeout time.Duration) (map[string]any, error) {
	gaps := []any{}
	unprotectedPods := []any{}
	namespaceCoverage := map[string]any{}

	// Get all network policies
	policiesResult, err := t.listPolicies(ctx, input, env, timeout)
	if err != nil {
		return nil, err
	}

	policies := policiesResult["policies"].([]any)

	// Get all namespaces
	args := t.buildBaseArgs(input)
	args = append(args, "get", "namespaces", "-o", "json")

	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Env:     env,
		Timeout: timeout,
	})

	namespaces := []string{}
	if err == nil && len(result.Stdout) > 0 {
		var list struct {
			Items []struct {
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
			} `json:"items"`
		}
		if json.Unmarshal(result.Stdout, &list) == nil {
			for _, item := range list.Items {
				namespaces = append(namespaces, item.Metadata.Name)
			}
		}
	}

	// Build map of namespaces with policies
	nsWithPolicies := make(map[string]bool)
	for _, policy := range policies {
		if p, ok := policy.(map[string]any); ok {
			if metadata, ok := p["metadata"].(map[string]any); ok {
				if ns, ok := metadata["namespace"].(string); ok {
					nsWithPolicies[ns] = true
				}
			}
		}
	}

	// Check each namespace
	for _, ns := range namespaces {
		coverage := map[string]any{
			"has_policy": nsWithPolicies[ns],
			"policy_count": 0,
		}

		// Count policies per namespace
		for _, policy := range policies {
			if p, ok := policy.(map[string]any); ok {
				if metadata, ok := p["metadata"].(map[string]any); ok {
					if pns, ok := metadata["namespace"].(string); ok && pns == ns {
						coverage["policy_count"] = coverage["policy_count"].(int) + 1
					}
				}
			}
		}

		namespaceCoverage[ns] = coverage

		// Skip system namespaces for gap analysis
		if strings.HasPrefix(ns, "kube-") || ns == "default" {
			continue
		}

		if !nsWithPolicies[ns] {
			gaps = append(gaps, map[string]any{
				"type":        "namespace-no-policy",
				"severity":    "medium",
				"namespace":   ns,
				"description": fmt.Sprintf("Namespace '%s' has no network policies", ns),
				"remediation": "Create default-deny ingress/egress policies",
			})
		}
	}

	// Get pods without coverage
	if len(namespaces) > 0 {
		for ns := range nsWithPolicies {
			// Get pods in this namespace
			args = t.buildBaseArgs(input)
			args = append(args, "get", "pods", "-n", ns, "-o", "json")

			result, err := exec.Run(ctx, exec.Config{
				Command: BinaryName,
				Args:    args,
				Env:     env,
				Timeout: timeout,
			})

			if err == nil && len(result.Stdout) > 0 {
				var podList struct {
					Items []struct {
						Metadata struct {
							Name      string            `json:"name"`
							Namespace string            `json:"namespace"`
							Labels    map[string]string `json:"labels"`
						} `json:"metadata"`
					} `json:"items"`
				}

				if json.Unmarshal(result.Stdout, &podList) == nil {
					for _, pod := range podList.Items {
						// Check if pod matches any policy selector
						matched := false
						for _, policy := range policies {
							if t.podMatchesPolicy(pod.Metadata.Labels, policy) {
								matched = true
								break
							}
						}

						if !matched {
							unprotectedPods = append(unprotectedPods, map[string]any{
								"name":      pod.Metadata.Name,
								"namespace": pod.Metadata.Namespace,
								"labels":    pod.Metadata.Labels,
							})
						}
					}
				}
			}
		}
	}

	// Check for common security gaps
	if len(policies) == 0 {
		gaps = append(gaps, map[string]any{
			"type":        "no-policies",
			"severity":    "high",
			"description": "Cluster has no network policies configured",
			"remediation": "Implement network policies for network segmentation",
		})
	}

	return map[string]any{
		"policies":           policies,
		"policy_count":       len(policies),
		"gaps":               gaps,
		"unprotected_pods":   unprotectedPods,
		"namespace_coverage": namespaceCoverage,
	}, nil
}

// podMatchesPolicy checks if a pod's labels match a network policy's pod selector
func (t *ToolImpl) podMatchesPolicy(podLabels map[string]string, policy any) bool {
	p, ok := policy.(map[string]any)
	if !ok {
		return false
	}

	spec, ok := p["spec"].(map[string]any)
	if !ok {
		return false
	}

	podSelector, ok := spec["podSelector"].(map[string]any)
	if !ok {
		return true // Empty selector matches all
	}

	matchLabels, ok := podSelector["matchLabels"].(map[string]any)
	if !ok {
		return true // Empty matchLabels matches all
	}

	for k, v := range matchLabels {
		if podLabels[k] != v {
			return false
		}
	}

	return true
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

	return types.NewHealthyStatus(fmt.Sprintf("%s is available for network policy testing", BinaryName))
}
