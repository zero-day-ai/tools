package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the cloud-metadata tool
func InputSchema() schema.JSON {
	actionSchema := schema.String()
	actionSchema.Description = "Action to perform: detect, get-credentials, get-identity, get-all, custom"

	providerSchema := schema.String()
	providerSchema.Description = "Cloud provider: aws, gcp, azure, auto (optional, auto-detected by default)"

	pathSchema := schema.String()
	pathSchema.Description = "Custom metadata path to query (for action=custom)"

	metadataIPSchema := schema.String()
	metadataIPSchema.Description = "Metadata service IP (default: 169.254.169.254)"

	imdsVersionSchema := schema.Int()
	imdsVersionSchema.Description = "AWS IMDS version to use: 1 or 2 (default: 2 with fallback to 1)"

	timeoutSchema := schema.Int()
	timeoutSchema.Description = "Timeout in seconds (optional, default: 10)"

	headersSchema := schema.Object(nil)
	headersSchema.Description = "Custom headers to send with request"

	return schema.Object(map[string]schema.JSON{
		"action":       actionSchema,
		"provider":     providerSchema,
		"path":         pathSchema,
		"metadata_ip":  metadataIPSchema,
		"imds_version": imdsVersionSchema,
		"timeout":      timeoutSchema,
		"headers":      headersSchema,
	}, "action") // action is required
}

// OutputSchema defines the output schema for the cloud-metadata tool
func OutputSchema() schema.JSON {
	successSchema := schema.Bool()
	successSchema.Description = "Whether the action succeeded"

	providerSchema := schema.String()
	providerSchema.Description = "Detected cloud provider"

	providerVersionSchema := schema.String()
	providerVersionSchema.Description = "Provider service version/region info"

	// Identity information
	identitySchema := schema.Object(map[string]schema.JSON{
		"account_id":        schema.String(),
		"instance_id":       schema.String(),
		"region":            schema.String(),
		"availability_zone": schema.String(),
		"instance_type":     schema.String(),
		"role_name":         schema.String(),
		"role_arn":          schema.String(),
	})
	identitySchema.Description = "Cloud identity information"

	// Credentials
	credentialsSchema := schema.Object(map[string]schema.JSON{
		"access_key_id":     schema.String(),
		"secret_access_key": schema.String(),
		"session_token":     schema.String(),
		"expiration":        schema.String(),
		"token_type":        schema.String(),
	})
	credentialsSchema.Description = "Cloud credentials (if accessible)"

	credentialsFoundSchema := schema.Bool()
	credentialsFoundSchema.Description = "Whether credentials were found"

	// Network info
	networkInfoSchema := schema.Object(map[string]schema.JSON{
		"local_ipv4":  schema.String(),
		"public_ipv4": schema.String(),
		"mac":         schema.String(),
		"vpc_id":      schema.String(),
		"subnet_id":   schema.String(),
	})
	networkInfoSchema.Description = "Network information from metadata"

	// Raw response for custom queries
	rawResponseSchema := schema.String()
	rawResponseSchema.Description = "Raw response from metadata service"

	metadataAccessibleSchema := schema.Bool()
	metadataAccessibleSchema.Description = "Whether metadata service is accessible"

	imdsVersionUsedSchema := schema.Int()
	imdsVersionUsedSchema.Description = "IMDS version that was used (AWS)"

	executionTimeSchema := schema.Int()
	executionTimeSchema.Description = "Execution time in milliseconds"

	errorSchema := schema.String()
	errorSchema.Description = "Error message if failed"

	warningsSchema := schema.Array(schema.String())
	warningsSchema.Description = "Warning messages"

	return schema.Object(map[string]schema.JSON{
		"success":              successSchema,
		"provider":             providerSchema,
		"provider_version":     providerVersionSchema,
		"identity":             identitySchema,
		"credentials":          credentialsSchema,
		"credentials_found":    credentialsFoundSchema,
		"network_info":         networkInfoSchema,
		"raw_response":         rawResponseSchema,
		"metadata_accessible":  metadataAccessibleSchema,
		"imds_version_used":    imdsVersionUsedSchema,
		"execution_time_ms":    executionTimeSchema,
		"error":                errorSchema,
		"warnings":             warningsSchema,
	})
}
