package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTool_CloudMetadata(t *testing.T) {
	tool := NewTool()
	require.NotNil(t, tool, "NewTool should return a non-nil tool")
}

func TestToolImpl_Execute_ValidationErrors_CloudMetadata(t *testing.T) {
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
			name: "custom without path",
			input: map[string]any{
				"action": "custom",
			},
			expectedErr: "path is required for custom queries",
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

func TestMetadataEndpoints(t *testing.T) {
	t.Run("AWS endpoints", func(t *testing.T) {
		metadataIP := "169.254.169.254"
		assert.Equal(t, "http://169.254.169.254/latest/meta-data/", fmt.Sprintf(awsMetadataBase, metadataIP))
		assert.Equal(t, "http://169.254.169.254/latest/meta-data/iam/security-credentials/", fmt.Sprintf(awsCredentialsBase, metadataIP))
		assert.Equal(t, "http://169.254.169.254/latest/dynamic/instance-identity/document", fmt.Sprintf(awsIdentityDoc, metadataIP))
		assert.Equal(t, "http://169.254.169.254/latest/api/token", fmt.Sprintf(awsTokenEndpoint, metadataIP))
	})

	t.Run("GCP endpoints", func(t *testing.T) {
		metadataIP := "169.254.169.254"
		assert.Equal(t, "http://169.254.169.254/computeMetadata/v1/", fmt.Sprintf(gcpMetadataBase, metadataIP))
		assert.Equal(t, "http://169.254.169.254/computeMetadata/v1/instance/", fmt.Sprintf(gcpIdentity, metadataIP))
		assert.Equal(t, "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/", fmt.Sprintf(gcpServiceAccount, metadataIP))
	})

	t.Run("Azure endpoints", func(t *testing.T) {
		metadataIP := "169.254.169.254"
		assert.Equal(t, "http://169.254.169.254/metadata/instance", fmt.Sprintf(azureMetadataBase, metadataIP))
		assert.Equal(t, "http://169.254.169.254/metadata/identity/oauth2/token", fmt.Sprintf(azureIdentity, metadataIP))
	})
}

func TestAWSCredentialsParsing(t *testing.T) {
	credsJSON := `{
		"AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
		"SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"Token": "IQoJb3JpZ2luX2VjEDQaCXVzLWVhc3QtMSJHMEUCIQDxE...",
		"Expiration": "2023-12-31T23:59:59Z"
	}`

	var creds struct {
		AccessKeyId     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
		Expiration      string `json:"Expiration"`
	}

	err := json.Unmarshal([]byte(credsJSON), &creds)
	require.NoError(t, err)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", creds.AccessKeyId)
	assert.NotEmpty(t, creds.SecretAccessKey)
	assert.NotEmpty(t, creds.Token)
	assert.NotEmpty(t, creds.Expiration)
}

func TestAWSIdentityDocumentParsing(t *testing.T) {
	identityJSON := `{
		"accountId": "123456789012",
		"instanceId": "i-0abc123def456",
		"region": "us-east-1",
		"availabilityZone": "us-east-1a",
		"instanceType": "t2.micro",
		"privateIp": "10.0.1.100"
	}`

	var identity struct {
		AccountId        string `json:"accountId"`
		InstanceId       string `json:"instanceId"`
		Region           string `json:"region"`
		AvailabilityZone string `json:"availabilityZone"`
		InstanceType     string `json:"instanceType"`
		PrivateIp        string `json:"privateIp"`
	}

	err := json.Unmarshal([]byte(identityJSON), &identity)
	require.NoError(t, err)
	assert.Equal(t, "123456789012", identity.AccountId)
	assert.Equal(t, "i-0abc123def456", identity.InstanceId)
	assert.Equal(t, "us-east-1", identity.Region)
	assert.Equal(t, "us-east-1a", identity.AvailabilityZone)
	assert.Equal(t, "t2.micro", identity.InstanceType)
	assert.Equal(t, "10.0.1.100", identity.PrivateIp)
}

func TestGCPTokenParsing(t *testing.T) {
	tokenJSON := `{
		"access_token": "ya29.c.Kl6iB...",
		"expires_in": 3599,
		"token_type": "Bearer"
	}`

	var token struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}

	err := json.Unmarshal([]byte(tokenJSON), &token)
	require.NoError(t, err)
	assert.NotEmpty(t, token.AccessToken)
	assert.Equal(t, 3599, token.ExpiresIn)
	assert.Equal(t, "Bearer", token.TokenType)
}

func TestAzureTokenParsing(t *testing.T) {
	tokenJSON := `{
		"access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
		"expires_on": "1672531199",
		"resource": "https://management.azure.com/",
		"token_type": "Bearer",
		"client_id": "12345678-1234-1234-1234-123456789012"
	}`

	var token struct {
		AccessToken string `json:"access_token"`
		ExpiresOn   string `json:"expires_on"`
		Resource    string `json:"resource"`
		TokenType   string `json:"token_type"`
		ClientId    string `json:"client_id"`
	}

	err := json.Unmarshal([]byte(tokenJSON), &token)
	require.NoError(t, err)
	assert.NotEmpty(t, token.AccessToken)
	assert.NotEmpty(t, token.ExpiresOn)
	assert.Equal(t, "https://management.azure.com/", token.Resource)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.NotEmpty(t, token.ClientId)
}

func TestAzureInstanceParsing(t *testing.T) {
	instanceJSON := `{
		"compute": {
			"subscriptionId": "12345678-1234-1234-1234-123456789012",
			"vmId": "abcd1234-ab12-cd34-ef56-abcdef123456",
			"location": "eastus",
			"vmSize": "Standard_D2s_v3",
			"zone": "1"
		},
		"network": {
			"interface": [
				{
					"ipv4": {
						"ipAddress": [
							{
								"privateIpAddress": "10.0.1.5",
								"publicIpAddress": "52.168.1.100"
							}
						]
					}
				}
			]
		}
	}`

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

	err := json.Unmarshal([]byte(instanceJSON), &instance)
	require.NoError(t, err)
	assert.NotEmpty(t, instance.Compute.SubscriptionId)
	assert.NotEmpty(t, instance.Compute.VmId)
	assert.Equal(t, "eastus", instance.Compute.Location)
	assert.Len(t, instance.Network.Interface, 1)
}

func TestMockMetadataServer_AWS(t *testing.T) {
	// Create a mock AWS metadata server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/meta-data/":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ami-id\ninstance-id"))
		case "/latest/dynamic/instance-identity/document":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"accountId":"123456789012","instanceId":"i-test"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	t.Run("metadata endpoint returns 200", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/latest/meta-data/")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestMockMetadataServer_GCP(t *testing.T) {
	// Create a mock GCP metadata server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for required header
		if r.Header.Get("Metadata-Flavor") != "Google" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		switch r.URL.Path {
		case "/computeMetadata/v1/":
			w.WriteHeader(http.StatusOK)
		case "/computeMetadata/v1/instance/service-accounts/default/token":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"access_token":"test-token","expires_in":3600,"token_type":"Bearer"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	t.Run("requires Metadata-Flavor header", func(t *testing.T) {
		// Without header
		resp, err := http.Get(server.URL + "/computeMetadata/v1/")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)

		// With header
		req, _ := http.NewRequest("GET", server.URL+"/computeMetadata/v1/", nil)
		req.Header.Set("Metadata-Flavor", "Google")
		resp2, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp2.Body.Close()
		assert.Equal(t, http.StatusOK, resp2.StatusCode)
	})
}

func TestMockMetadataServer_Azure(t *testing.T) {
	// Create a mock Azure metadata server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for required header
		if r.Header.Get("Metadata") != "true" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		if r.URL.Path == "/metadata/instance" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"compute":{"subscriptionId":"test"}}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	t.Run("requires Metadata header", func(t *testing.T) {
		// Without header
		resp, err := http.Get(server.URL + "/metadata/instance")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)

		// With header
		req, _ := http.NewRequest("GET", server.URL+"/metadata/instance", nil)
		req.Header.Set("Metadata", "true")
		resp2, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp2.Body.Close()
		assert.Equal(t, http.StatusOK, resp2.StatusCode)
	})
}

func TestConstants_CloudMetadata(t *testing.T) {
	assert.Equal(t, "cloud-metadata", ToolName)
	assert.Equal(t, "1.0.0", ToolVersion)
	assert.NotEmpty(t, ToolDescription)
	assert.Equal(t, "169.254.169.254", DefaultMetadataIP)
}

// Benchmark tests
func BenchmarkJSONParsing_AWSIdentity(b *testing.B) {
	identityJSON := []byte(`{
		"accountId": "123456789012",
		"instanceId": "i-0abc123def456",
		"region": "us-east-1",
		"availabilityZone": "us-east-1a",
		"instanceType": "t2.micro",
		"privateIp": "10.0.1.100"
	}`)

	var identity struct {
		AccountId        string `json:"accountId"`
		InstanceId       string `json:"instanceId"`
		Region           string `json:"region"`
		AvailabilityZone string `json:"availabilityZone"`
		InstanceType     string `json:"instanceType"`
		PrivateIp        string `json:"privateIp"`
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		json.Unmarshal(identityJSON, &identity)
	}
}
