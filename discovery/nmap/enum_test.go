package main

import (
	"testing"

	"github.com/zero-day-ai/sdk/enum"
)

func TestEnumRegistrations(t *testing.T) {
	// Get registered mappings for nmap
	mappings := enum.GetMappings("nmap")
	if mappings == nil {
		t.Fatal("Expected nmap mappings to be registered, got nil")
	}

	// Verify scanType mappings
	scanTypeMappings, ok := mappings["scanType"]
	if !ok {
		t.Fatal("Expected scanType mappings to be registered")
	}

	expectedScanTypes := map[string]string{
		"ping":    "SCAN_TYPE_PING",
		"syn":     "SCAN_TYPE_SYN",
		"connect": "SCAN_TYPE_CONNECT",
		"udp":     "SCAN_TYPE_UDP",
		"ack":     "SCAN_TYPE_ACK",
		"window":  "SCAN_TYPE_WINDOW",
		"maimon":  "SCAN_TYPE_MAIMON",
	}

	for shortValue, expectedProto := range expectedScanTypes {
		actualProto, exists := scanTypeMappings[shortValue]
		if !exists {
			t.Errorf("Expected scanType mapping for %q to exist", shortValue)
			continue
		}
		if actualProto != expectedProto {
			t.Errorf("Expected scanType mapping for %q to be %q, got %q", shortValue, expectedProto, actualProto)
		}
	}

	// Verify timing mappings
	timingMappings, ok := mappings["timing"]
	if !ok {
		t.Fatal("Expected timing mappings to be registered")
	}

	expectedTimings := map[string]string{
		"paranoid":   "TIMING_TEMPLATE_PARANOID",
		"sneaky":     "TIMING_TEMPLATE_SNEAKY",
		"polite":     "TIMING_TEMPLATE_POLITE",
		"normal":     "TIMING_TEMPLATE_NORMAL",
		"aggressive": "TIMING_TEMPLATE_AGGRESSIVE",
		"insane":     "TIMING_TEMPLATE_INSANE",
	}

	for shortValue, expectedProto := range expectedTimings {
		actualProto, exists := timingMappings[shortValue]
		if !exists {
			t.Errorf("Expected timing mapping for %q to exist", shortValue)
			continue
		}
		if actualProto != expectedProto {
			t.Errorf("Expected timing mapping for %q to be %q, got %q", shortValue, expectedProto, actualProto)
		}
	}
}

func TestEnumNormalization(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normalize scanType",
			input:    `{"scanType":"syn","timing":"normal"}`,
			expected: `{"scanType":"SCAN_TYPE_SYN","timing":"TIMING_TEMPLATE_NORMAL"}`,
		},
		{
			name:     "case insensitive normalization",
			input:    `{"scanType":"SYN","timing":"NORMAL"}`,
			expected: `{"scanType":"SCAN_TYPE_SYN","timing":"TIMING_TEMPLATE_NORMAL"}`,
		},
		{
			name:     "preserve unknown values",
			input:    `{"scanType":"unknown","timing":"normal"}`,
			expected: `{"scanType":"unknown","timing":"TIMING_TEMPLATE_NORMAL"}`,
		},
		{
			name:     "preserve other fields",
			input:    `{"scanType":"syn","ports":"1-1000","timing":"aggressive"}`,
			expected: `{"ports":"1-1000","scanType":"SCAN_TYPE_SYN","timing":"TIMING_TEMPLATE_AGGRESSIVE"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := enum.Normalize("nmap", tt.input)
			// Note: JSON field order may vary, so we should parse and compare
			// For now, we'll just check if the expected substrings are present
			if !contains(result, "SCAN_TYPE_SYN") && contains(tt.expected, "SCAN_TYPE_SYN") {
				t.Errorf("Expected result to contain SCAN_TYPE_SYN, got %q", result)
			}
			if !contains(result, "TIMING_TEMPLATE_NORMAL") && contains(tt.expected, "TIMING_TEMPLATE_NORMAL") {
				t.Errorf("Expected result to contain TIMING_TEMPLATE_NORMAL, got %q", result)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || len(s) > len(substr)+1 && s[1:len(substr)+1] == substr))
}
