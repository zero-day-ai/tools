package main

import (
	"encoding/json"
	"testing"
)

func TestParseTLSInfo(t *testing.T) {
	// Sample httpx output with TLS information
	httpxJSON := `{
  "url": "https://example.com",
  "status_code": 200,
  "title": "Example Domain",
  "content_type": "text/html",
  "tls": {
    "host": "example.com",
    "issuer_cn": "R3",
    "issuer_org": ["Let's Encrypt"],
    "subject_cn": "example.com",
    "subject_org": ["Example Inc"],
    "not_before": "2024-01-01T00:00:00Z",
    "not_after": "2024-04-01T00:00:00Z",
    "subject_an": ["example.com", "www.example.com"]
  }
}`

	var entry HttpxOutput
	err := json.Unmarshal([]byte(httpxJSON), &entry)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Verify TLS data is parsed
	if entry.TLS == nil {
		t.Fatal("Expected TLS data to be present")
	}

	if entry.TLS.Host != "example.com" {
		t.Errorf("Expected host to be 'example.com', got '%s'", entry.TLS.Host)
	}

	if entry.TLS.IssuerCN != "R3" {
		t.Errorf("Expected issuer_cn to be 'R3', got '%s'", entry.TLS.IssuerCN)
	}

	if len(entry.TLS.IssuerOrg) != 1 || entry.TLS.IssuerOrg[0] != "Let's Encrypt" {
		t.Errorf("Expected issuer_org to be ['Let's Encrypt'], got %v", entry.TLS.IssuerOrg)
	}

	if entry.TLS.SubjectCN != "example.com" {
		t.Errorf("Expected subject_cn to be 'example.com', got '%s'", entry.TLS.SubjectCN)
	}

	if len(entry.TLS.SubjectAN) != 2 {
		t.Errorf("Expected 2 subject alternative names, got %d", len(entry.TLS.SubjectAN))
	}

	if entry.TLS.NotAfter != "2024-04-01T00:00:00Z" {
		t.Errorf("Expected not_after to be '2024-04-01T00:00:00Z', got '%s'", entry.TLS.NotAfter)
	}
}

func TestParseOutputWithTLS(t *testing.T) {
	// Test full parseOutput with TLS data
	httpxOutput := `{"url":"https://example.com","status_code":200,"title":"Example","tls":{"issuer_cn":"R3","issuer_org":["Let's Encrypt"],"subject_cn":"example.com","not_after":"2024-04-01T00:00:00Z","subject_an":["example.com","www.example.com"]}}`

	output, err := parseOutput([]byte(httpxOutput))
	if err != nil {
		t.Fatalf("parseOutput failed: %v", err)
	}

	results, ok := output["results"].([]map[string]any)
	if !ok {
		t.Fatal("Expected results array")
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	result := results[0]

	// Check cert fields are present
	certIssuer, ok := result["cert_issuer"].(string)
	if !ok || certIssuer == "" {
		t.Error("Expected cert_issuer to be present and non-empty")
	}

	certSubject, ok := result["cert_subject"].(string)
	if !ok || certSubject == "" {
		t.Error("Expected cert_subject to be present and non-empty")
	}

	certExpiry, ok := result["cert_expiry"].(string)
	if !ok || certExpiry != "2024-04-01T00:00:00Z" {
		t.Errorf("Expected cert_expiry to be '2024-04-01T00:00:00Z', got '%s'", certExpiry)
	}

	certSANs, ok := result["cert_sans"].([]string)
	if !ok || len(certSANs) != 2 {
		t.Errorf("Expected cert_sans to have 2 entries, got %v", certSANs)
	}
}

func TestParseOutputWithoutTLS(t *testing.T) {
	// Test HTTP (non-HTTPS) output without TLS data
	httpxOutput := `{"url":"http://example.com","status_code":200,"title":"Example"}`

	output, err := parseOutput([]byte(httpxOutput))
	if err != nil {
		t.Fatalf("parseOutput failed: %v", err)
	}

	results, ok := output["results"].([]map[string]any)
	if !ok {
		t.Fatal("Expected results array")
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	result := results[0]

	// Check cert fields are NOT present for HTTP
	if _, ok := result["cert_issuer"]; ok {
		t.Error("cert_issuer should not be present for HTTP endpoints")
	}

	if _, ok := result["cert_subject"]; ok {
		t.Error("cert_subject should not be present for HTTP endpoints")
	}

	if _, ok := result["cert_expiry"]; ok {
		t.Error("cert_expiry should not be present for HTTP endpoints")
	}

	if _, ok := result["cert_sans"]; ok {
		t.Error("cert_sans should not be present for HTTP endpoints")
	}
}
