package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetermineDNSRecordType(t *testing.T) {
	tests := []struct {
		name       string
		tag        string
		recordType string
		sources    []string
		expected   string
	}{
		{
			name:       "explicit MX type",
			tag:        "dns",
			recordType: "MX",
			sources:    []string{"DNS"},
			expected:   "MX",
		},
		{
			name:       "explicit NS type",
			tag:        "dns",
			recordType: "NS",
			sources:    []string{"DNS"},
			expected:   "NS",
		},
		{
			name:       "explicit TXT type",
			tag:        "dns",
			recordType: "TXT",
			sources:    []string{"DNS"},
			expected:   "TXT",
		},
		{
			name:       "explicit SOA type",
			tag:        "dns",
			recordType: "SOA",
			sources:    []string{"DNS"},
			expected:   "SOA",
		},
		{
			name:       "MX tag",
			tag:        "mx",
			recordType: "",
			sources:    []string{"DNS"},
			expected:   "MX",
		},
		{
			name:       "NS tag",
			tag:        "ns",
			recordType: "",
			sources:    []string{"DNS"},
			expected:   "NS",
		},
		{
			name:       "MX in sources",
			tag:        "dns",
			recordType: "",
			sources:    []string{"MX Query"},
			expected:   "MX",
		},
		{
			name:       "default to A record",
			tag:        "dns",
			recordType: "",
			sources:    []string{"DNS"},
			expected:   "A",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineDNSRecordType(tt.tag, tt.recordType, tt.sources)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractMXPriority(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected int
	}{
		{
			name:     "valid MX with priority",
			value:    "10 mail.example.com",
			expected: 10,
		},
		{
			name:     "valid MX with high priority",
			value:    "100 backup.example.com",
			expected: 100,
		},
		{
			name:     "no priority",
			value:    "mail.example.com",
			expected: 0,
		},
		{
			name:     "invalid format",
			value:    "priority mail.example.com",
			expected: 0,
		},
		{
			name:     "empty string",
			value:    "",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractMXPriority(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseAmassOutput(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedDomain string
		validateFunc   func(t *testing.T, output map[string]any)
	}{
		{
			name: "A records with IP addresses",
			input: `{"name":"example.com","domain":"example.com","addresses":[{"ip":"93.184.216.34","asn":15133,"desc":"EDGECAST"}],"tag":"dns","sources":["DNS"],"type":""}
{"name":"www.example.com","domain":"example.com","addresses":[{"ip":"93.184.216.34"}],"tag":"dns","sources":["DNS"],"type":""}`,
			expectedDomain: "test.com",
			validateFunc: func(t *testing.T, output map[string]any) {
				dnsRecords, ok := output["dns_records"].([]map[string]any)
				require.True(t, ok, "dns_records should be []map[string]any")
				assert.GreaterOrEqual(t, len(dnsRecords), 2, "should have at least 2 DNS records")

				// Check for A record
				foundARecord := false
				for _, record := range dnsRecords {
					if record["type"] == "A" && record["name"] == "example.com" {
						foundARecord = true
						assert.Equal(t, "93.184.216.34", record["value"])
						assert.Equal(t, 0, record["priority"])
						assert.Equal(t, 0, record["ttl"])
					}
				}
				assert.True(t, foundARecord, "should find A record for example.com")

				// Check ASN info
				asnInfo, ok := output["asn_info"].([]map[string]any)
				require.True(t, ok, "asn_info should be []map[string]any")
				assert.GreaterOrEqual(t, len(asnInfo), 1, "should have at least 1 ASN")
			},
		},
		{
			name: "MX records",
			input: `{"name":"mail.example.com","domain":"example.com","addresses":[],"tag":"mx","sources":["DNS"],"type":"MX"}
{"name":"backup.example.com","domain":"example.com","addresses":[],"tag":"mx","sources":["DNS"],"type":"MX"}`,
			expectedDomain: "test.com",
			validateFunc: func(t *testing.T, output map[string]any) {
				dnsRecords, ok := output["dns_records"].([]map[string]any)
				require.True(t, ok, "dns_records should be []map[string]any")

				// Check for MX records
				mxCount := 0
				for _, record := range dnsRecords {
					if record["type"] == "MX" {
						mxCount++
						assert.Contains(t, []string{"mail.example.com", "backup.example.com"}, record["name"])
					}
				}
				assert.Equal(t, 2, mxCount, "should have 2 MX records")
			},
		},
		{
			name: "NS records",
			input: `{"name":"ns1.example.com","domain":"example.com","addresses":[],"tag":"ns","sources":["DNS"],"type":"NS"}
{"name":"ns2.example.com","domain":"example.com","addresses":[],"tag":"ns","sources":["DNS"],"type":"NS"}`,
			expectedDomain: "test.com",
			validateFunc: func(t *testing.T, output map[string]any) {
				dnsRecords, ok := output["dns_records"].([]map[string]any)
				require.True(t, ok, "dns_records should be []map[string]any")

				// Check for NS records
				nsCount := 0
				for _, record := range dnsRecords {
					if record["type"] == "NS" {
						nsCount++
						assert.Contains(t, []string{"ns1.example.com", "ns2.example.com"}, record["name"])
					}
				}
				assert.Equal(t, 2, nsCount, "should have 2 NS records")
			},
		},
		{
			name: "TXT records",
			input: `{"name":"example.com","domain":"example.com","addresses":[],"tag":"txt","sources":["DNS"],"type":"TXT"}`,
			expectedDomain: "test.com",
			validateFunc: func(t *testing.T, output map[string]any) {
				dnsRecords, ok := output["dns_records"].([]map[string]any)
				require.True(t, ok, "dns_records should be []map[string]any")

				// Check for TXT record
				foundTXT := false
				for _, record := range dnsRecords {
					if record["type"] == "TXT" {
						foundTXT = true
						assert.Equal(t, "example.com", record["name"])
					}
				}
				assert.True(t, foundTXT, "should find TXT record")
			},
		},
		{
			name: "mixed record types",
			input: `{"name":"example.com","domain":"example.com","addresses":[{"ip":"93.184.216.34"}],"tag":"dns","sources":["DNS"],"type":""}
{"name":"mail.example.com","domain":"example.com","addresses":[],"tag":"mx","sources":["DNS"],"type":"MX"}
{"name":"ns1.example.com","domain":"example.com","addresses":[],"tag":"ns","sources":["DNS"],"type":"NS"}`,
			expectedDomain: "test.com",
			validateFunc: func(t *testing.T, output map[string]any) {
				dnsRecords, ok := output["dns_records"].([]map[string]any)
				require.True(t, ok, "dns_records should be []map[string]any")
				assert.GreaterOrEqual(t, len(dnsRecords), 3, "should have at least 3 DNS records")

				recordTypes := make(map[string]int)
				for _, record := range dnsRecords {
					recordType := record["type"].(string)
					recordTypes[recordType]++
				}

				assert.GreaterOrEqual(t, recordTypes["A"], 1, "should have at least 1 A record")
				assert.Equal(t, 1, recordTypes["MX"], "should have 1 MX record")
				assert.Equal(t, 1, recordTypes["NS"], "should have 1 NS record")
			},
		},
		{
			name:           "empty input",
			input:          "",
			expectedDomain: "test.com",
			validateFunc: func(t *testing.T, output map[string]any) {
				dnsRecords, ok := output["dns_records"].([]map[string]any)
				require.True(t, ok, "dns_records should be []map[string]any")
				assert.Equal(t, 0, len(dnsRecords), "should have no DNS records")
			},
		},
		{
			name:           "invalid JSON",
			input:          "{invalid json}",
			expectedDomain: "test.com",
			validateFunc: func(t *testing.T, output map[string]any) {
				// Should not fail, just skip invalid lines
				_, ok := output["dns_records"].([]map[string]any)
				require.True(t, ok, "dns_records should be []map[string]any")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := parseAmassOutput([]byte(tt.input), tt.expectedDomain)
			require.NoError(t, err, "parseAmassOutput should not return error")
			assert.Equal(t, tt.expectedDomain, output["domain"])
			tt.validateFunc(t, output)
		})
	}
}

func TestExtractDNSRecordValue(t *testing.T) {
	tests := []struct {
		name       string
		entry      AmassOutput
		recordType string
		expected   string
	}{
		{
			name: "A record with IP",
			entry: AmassOutput{
				Name: "example.com",
				Addresses: []AddressWithASN{
					{IP: "93.184.216.34"},
				},
			},
			recordType: "A",
			expected:   "93.184.216.34",
		},
		{
			name: "MX record",
			entry: AmassOutput{
				Name: "mail.example.com",
			},
			recordType: "MX",
			expected:   "mail.example.com",
		},
		{
			name: "NS record",
			entry: AmassOutput{
				Name: "ns1.example.com",
			},
			recordType: "NS",
			expected:   "ns1.example.com",
		},
		{
			name: "TXT record",
			entry: AmassOutput{
				Name: "example.com",
				Type: "v=spf1 include:_spf.example.com ~all",
			},
			recordType: "TXT",
			expected:   "v=spf1 include:_spf.example.com ~all",
		},
		{
			name: "SOA record",
			entry: AmassOutput{
				Name: "example.com",
			},
			recordType: "SOA",
			expected:   "example.com",
		},
		{
			name: "CNAME record",
			entry: AmassOutput{
				Name: "www.example.com",
			},
			recordType: "CNAME",
			expected:   "www.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractDNSRecordValue(tt.entry, tt.recordType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDNSRecordResultSerialization(t *testing.T) {
	record := DNSRecordResult{
		Type:     "MX",
		Name:     "example.com",
		Value:    "mail.example.com",
		Priority: 10,
		TTL:      3600,
	}

	data, err := json.Marshal(record)
	require.NoError(t, err)

	var decoded DNSRecordResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, record.Type, decoded.Type)
	assert.Equal(t, record.Name, decoded.Name)
	assert.Equal(t, record.Value, decoded.Value)
	assert.Equal(t, record.Priority, decoded.Priority)
	assert.Equal(t, record.TTL, decoded.TTL)
}

func TestParseAmassOutputWithASN(t *testing.T) {
	// Sample amass JSON output with ASN information
	amassOutput := `{"name":"example.com","domain":"example.com","addresses":[{"ip":"93.184.216.34","asn":15133,"desc":"EDGECAST"}],"tag":"dns","sources":["DNS"],"type":"fqdn"}
{"name":"www.example.com","domain":"example.com","addresses":[{"ip":"93.184.216.34","asn":15133,"desc":"EDGECAST"}],"tag":"dns","sources":["DNS"],"type":"fqdn"}
{"name":"mail.example.com","domain":"example.com","addresses":[{"ip":"192.0.2.1","asn":12345,"desc":"EXAMPLE-ASN"}],"tag":"dns","sources":["DNS"],"type":"fqdn"}
`

	result, err := parseAmassOutput([]byte(amassOutput), "example.com")
	require.NoError(t, err, "parseAmassOutput should not fail")

	// Verify domain
	assert.Equal(t, "example.com", result["domain"], "domain should match")

	// Verify subdomains
	subdomains, ok := result["subdomains"].([]string)
	require.True(t, ok, "subdomains should be []string")
	assert.Equal(t, 3, len(subdomains), "should have 3 subdomains")

	// Verify IP addresses
	ipAddresses, ok := result["ip_addresses"].([]string)
	require.True(t, ok, "ip_addresses should be []string")
	assert.Equal(t, 2, len(ipAddresses), "should have 2 unique IP addresses")

	// Verify ASN information
	asnInfo, ok := result["asn_info"].([]map[string]any)
	require.True(t, ok, "asn_info should be []map[string]any")
	assert.Equal(t, 2, len(asnInfo), "should have 2 unique ASN entries")

	// Verify ASN structure and content
	asnMap := make(map[int]map[string]any)
	for _, asn := range asnInfo {
		number, ok := asn["number"].(int)
		require.True(t, ok, "ASN should have number field")
		asnMap[number] = asn
	}

	// Verify ASN 15133
	asn15133, exists := asnMap[15133]
	require.True(t, exists, "should have ASN 15133")
	assert.Equal(t, "EDGECAST", asn15133["description"], "ASN 15133 should have correct description")
	ips15133, ok := asn15133["ips"].([]string)
	require.True(t, ok, "ASN should have ips array")
	assert.Equal(t, 1, len(ips15133), "ASN 15133 should have 1 unique IP")
	assert.Contains(t, ips15133, "93.184.216.34", "ASN 15133 should contain correct IP")

	// Verify ASN 12345
	asn12345, exists := asnMap[12345]
	require.True(t, exists, "should have ASN 12345")
	assert.Equal(t, "EXAMPLE-ASN", asn12345["description"], "ASN 12345 should have correct description")
	ips12345, ok := asn12345["ips"].([]string)
	require.True(t, ok, "ASN should have ips array")
	assert.Equal(t, 1, len(ips12345), "ASN 12345 should have 1 IP")
	assert.Contains(t, ips12345, "192.0.2.1", "ASN 12345 should contain correct IP")

	// Print result for debugging
	prettyResult, _ := json.MarshalIndent(result, "", "  ")
	t.Logf("Parsed result:\n%s", string(prettyResult))
}

func TestASNResultStructure(t *testing.T) {
	// Test ASNResult struct marshaling
	asn := ASNResult{
		Number:      15133,
		Description: "EDGECAST",
		Country:     "US",
		IPs:         []string{"93.184.216.34", "93.184.216.35"},
	}

	data, err := json.Marshal(asn)
	require.NoError(t, err, "should marshal ASNResult")

	var unmarshaled ASNResult
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err, "should unmarshal ASNResult")

	assert.Equal(t, asn.Number, unmarshaled.Number, "number should match")
	assert.Equal(t, asn.Description, unmarshaled.Description, "description should match")
	assert.Equal(t, asn.Country, unmarshaled.Country, "country should match")
	assert.Equal(t, asn.IPs, unmarshaled.IPs, "IPs should match")
}

func TestAddressWithASNParsing(t *testing.T) {
	// Test parsing of AddressWithASN structure
	jsonData := `{"ip":"93.184.216.34","asn":15133,"desc":"EDGECAST"}`

	var addr AddressWithASN
	err := json.Unmarshal([]byte(jsonData), &addr)
	require.NoError(t, err, "should unmarshal AddressWithASN")

	assert.Equal(t, "93.184.216.34", addr.IP, "IP should match")
	assert.Equal(t, 15133, addr.ASN, "ASN should match")
	assert.Equal(t, "EDGECAST", addr.Desc, "description should match")
}

func TestASNDeduplication(t *testing.T) {
	// Test that multiple IPs with same ASN are aggregated correctly
	amassOutput := `{"name":"host1.example.com","domain":"example.com","addresses":[{"ip":"93.184.216.34","asn":15133,"desc":"EDGECAST"}],"tag":"dns","sources":["DNS"],"type":"fqdn"}
{"name":"host2.example.com","domain":"example.com","addresses":[{"ip":"93.184.216.35","asn":15133,"desc":"EDGECAST"}],"tag":"dns","sources":["DNS"],"type":"fqdn"}
{"name":"host3.example.com","domain":"example.com","addresses":[{"ip":"93.184.216.36","asn":15133,"desc":"EDGECAST"}],"tag":"dns","sources":["DNS"],"type":"fqdn"}
`

	result, err := parseAmassOutput([]byte(amassOutput), "example.com")
	require.NoError(t, err, "parseAmassOutput should not fail")

	// Should have only 1 ASN entry
	asnInfo, ok := result["asn_info"].([]map[string]any)
	require.True(t, ok, "asn_info should be []map[string]any")
	assert.Equal(t, 1, len(asnInfo), "should have 1 ASN entry")

	// Verify the ASN has all 3 IPs
	asn := asnInfo[0]
	assert.Equal(t, 15133, asn["number"], "should be ASN 15133")
	ips, ok := asn["ips"].([]string)
	require.True(t, ok, "ASN should have ips array")
	assert.Equal(t, 3, len(ips), "ASN should have 3 IPs")
	assert.Contains(t, ips, "93.184.216.34", "should contain first IP")
	assert.Contains(t, ips, "93.184.216.35", "should contain second IP")
	assert.Contains(t, ips, "93.184.216.36", "should contain third IP")
}
