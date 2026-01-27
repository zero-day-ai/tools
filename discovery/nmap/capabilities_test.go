package main

import (
	"context"
	"testing"

	"github.com/zero-day-ai/sdk/types"
)

// TestNmapTool_Capabilities verifies that Capabilities() returns a non-nil struct
func TestNmapTool_Capabilities(t *testing.T) {
	tool := &ToolImpl{}
	ctx := context.Background()

	caps := tool.Capabilities(ctx)

	if caps == nil {
		t.Fatal("Capabilities() returned nil, expected non-nil *types.Capabilities")
	}

	// Verify the struct has initialized maps/slices
	if caps.Features == nil {
		t.Error("Features map is nil, expected initialized map")
	}

	// BlockedArgs and ArgAlternatives may be nil or empty depending on privilege level
	// but they should be properly handled by the types.Capabilities methods
}

// TestNmapTool_Capabilities_Features verifies that expected features are in the Features map
func TestNmapTool_Capabilities_Features(t *testing.T) {
	tool := &ToolImpl{}
	ctx := context.Background()

	caps := tool.Capabilities(ctx)

	// These features should always be present (regardless of privilege level)
	expectedFeatures := []string{
		"os_detection",
		"syn_scan",
		"udp_scan",
		"traceroute",
		"service_detect",
		"script_scan",
	}

	for _, feature := range expectedFeatures {
		if _, exists := caps.Features[feature]; !exists {
			t.Errorf("expected feature %q not found in Features map", feature)
		}
	}

	// Verify feature states are logical
	// If privileged, all features should be true
	if caps.HasPrivilegedAccess() {
		for _, feature := range expectedFeatures {
			if !caps.Features[feature] {
				t.Errorf("feature %q is false but tool has privileged access", feature)
			}
		}
	} else {
		// If unprivileged, service_detect and script_scan should be true
		// Others should be false
		if !caps.Features["service_detect"] {
			t.Error("service_detect should be true even without privileges")
		}
		if !caps.Features["script_scan"] {
			t.Error("script_scan should be true even without privileges")
		}

		privilegedFeatures := []string{"os_detection", "syn_scan", "udp_scan", "traceroute"}
		for _, feature := range privilegedFeatures {
			if caps.Features[feature] {
				t.Errorf("feature %q should be false without privileged access", feature)
			}
		}
	}
}

// TestNmapTool_Capabilities_BlockedArgs verifies that when unprivileged,
// blocked args are populated correctly
func TestNmapTool_Capabilities_BlockedArgs(t *testing.T) {
	tool := &ToolImpl{}
	ctx := context.Background()

	caps := tool.Capabilities(ctx)

	if caps.HasPrivilegedAccess() {
		// When privileged, BlockedArgs should be empty
		if len(caps.BlockedArgs) > 0 {
			t.Errorf("BlockedArgs should be empty when privileged, got %d items", len(caps.BlockedArgs))
		}
		t.Skip("skipping unprivileged tests: tool has privileged access")
		return
	}

	// When unprivileged, verify blocked args are populated
	if len(caps.BlockedArgs) == 0 {
		t.Error("BlockedArgs should be populated when unprivileged")
	}

	// Expected blocked flags from privilegedFlags variable
	expectedBlocked := []string{
		"-O",
		"-sS",
		"-sA",
		"-sW",
		"-sM",
		"-sN",
		"-sF",
		"-sX",
		"--traceroute",
		"-sU",
	}

	// Build a map of blocked args for easier lookup
	blockedMap := make(map[string]bool)
	for _, arg := range caps.BlockedArgs {
		blockedMap[arg] = true
	}

	// Verify all expected blocked flags are present
	for _, flag := range expectedBlocked {
		if !blockedMap[flag] {
			t.Errorf("expected blocked flag %q not found in BlockedArgs", flag)
		}
	}

	// Verify IsArgBlocked method works correctly
	for _, flag := range expectedBlocked {
		if !caps.IsArgBlocked(flag) {
			t.Errorf("IsArgBlocked(%q) returned false, expected true", flag)
		}
	}

	// Verify non-blocked args return false
	nonBlockedArgs := []string{"-sT", "-sV", "-sC", "-p", "-T4"}
	for _, arg := range nonBlockedArgs {
		if caps.IsArgBlocked(arg) {
			t.Errorf("IsArgBlocked(%q) returned true, expected false", arg)
		}
	}
}

// TestNmapTool_Capabilities_Alternatives verifies that alternatives map
// contains expected mappings for unprivileged mode
func TestNmapTool_Capabilities_Alternatives(t *testing.T) {
	tool := &ToolImpl{}
	ctx := context.Background()

	caps := tool.Capabilities(ctx)

	if caps.HasPrivilegedAccess() {
		// When privileged, ArgAlternatives should be empty
		if len(caps.ArgAlternatives) > 0 {
			t.Errorf("ArgAlternatives should be empty when privileged, got %d items", len(caps.ArgAlternatives))
		}
		t.Skip("skipping unprivileged tests: tool has privileged access")
		return
	}

	// When unprivileged, verify alternatives are populated
	if len(caps.ArgAlternatives) == 0 {
		t.Error("ArgAlternatives should be populated when unprivileged")
	}

	// Expected alternatives from flagAlternatives variable
	expectedAlternatives := map[string]string{
		"-sS": "-sT", // SYN stealth scan -> TCP connect scan
		"-sA": "-sT", // ACK scan -> TCP connect scan
	}

	// Verify all expected alternatives are present
	for blocked, alternative := range expectedAlternatives {
		gotAlt, exists := caps.ArgAlternatives[blocked]
		if !exists {
			t.Errorf("expected alternative for %q not found in ArgAlternatives", blocked)
			continue
		}
		if gotAlt != alternative {
			t.Errorf("alternative for %q: got %q, want %q", blocked, gotAlt, alternative)
		}
	}

	// Verify GetAlternative method works correctly
	for blocked, expected := range expectedAlternatives {
		alt, exists := caps.GetAlternative(blocked)
		if !exists {
			t.Errorf("GetAlternative(%q) returned exists=false, expected true", blocked)
			continue
		}
		if alt != expected {
			t.Errorf("GetAlternative(%q) = %q, want %q", blocked, alt, expected)
		}
	}

	// Verify GetAlternative returns false for non-existent mappings
	nonExistent := []string{"-O", "-sU", "--traceroute", "-sN"}
	for _, arg := range nonExistent {
		if alt, exists := caps.GetAlternative(arg); exists {
			t.Errorf("GetAlternative(%q) returned exists=true with alt=%q, expected false", arg, alt)
		}
	}
}

// TestNmapTool_Capabilities_PrivilegedAccess tests the HasPrivilegedAccess method
func TestNmapTool_Capabilities_PrivilegedAccess(t *testing.T) {
	tool := &ToolImpl{}
	ctx := context.Background()

	caps := tool.Capabilities(ctx)

	hasPriv := caps.HasPrivilegedAccess()

	// Verify consistency: if HasPrivilegedAccess is true, at least one privilege flag should be true
	if hasPriv && !caps.HasRoot && !caps.HasSudo && !caps.CanRawSocket {
		t.Error("HasPrivilegedAccess is true but no privilege flags are set")
	}

	// Verify inverse: if HasPrivilegedAccess is false, all privilege flags should be false
	if !hasPriv && (caps.HasRoot || caps.HasSudo || caps.CanRawSocket) {
		t.Error("HasPrivilegedAccess is false but at least one privilege flag is set")
	}

	// Log the privilege state for debugging (not an error, just informational)
	t.Logf("Privilege state: HasRoot=%v, HasSudo=%v, CanRawSocket=%v, HasPrivilegedAccess=%v",
		caps.HasRoot, caps.HasSudo, caps.CanRawSocket, hasPriv)
}

// TestNmapTool_Capabilities_HasFeature tests the HasFeature convenience method
func TestNmapTool_Capabilities_HasFeature(t *testing.T) {
	tool := &ToolImpl{}
	ctx := context.Background()

	caps := tool.Capabilities(ctx)

	tests := []struct {
		feature string
	}{
		{"os_detection"},
		{"syn_scan"},
		{"udp_scan"},
		{"traceroute"},
		{"service_detect"},
		{"script_scan"},
	}

	for _, tt := range tests {
		t.Run(tt.feature, func(t *testing.T) {
			hasFeature := caps.HasFeature(tt.feature)
			inMap, exists := caps.Features[tt.feature]

			if !exists {
				t.Errorf("feature %q not found in Features map", tt.feature)
				return
			}

			if hasFeature != inMap {
				t.Errorf("HasFeature(%q) = %v, but Features[%q] = %v",
					tt.feature, hasFeature, tt.feature, inMap)
			}
		})
	}

	// Test non-existent feature
	nonExistent := "non_existent_feature"
	if caps.HasFeature(nonExistent) {
		t.Errorf("HasFeature(%q) returned true for non-existent feature", nonExistent)
	}
}

// TestCapabilities_PrivilegedVsUnprivileged tests the overall behavior difference
// between privileged and unprivileged modes
func TestCapabilities_PrivilegedVsUnprivileged(t *testing.T) {
	tool := &ToolImpl{}
	ctx := context.Background()

	caps := tool.Capabilities(ctx)

	if caps.HasPrivilegedAccess() {
		t.Log("Testing in PRIVILEGED mode")

		// In privileged mode:
		// 1. All features should be enabled
		// 2. BlockedArgs should be empty
		// 3. ArgAlternatives should be empty

		for feature, enabled := range caps.Features {
			if !enabled {
				t.Errorf("in privileged mode, feature %q should be enabled", feature)
			}
		}

		if len(caps.BlockedArgs) > 0 {
			t.Errorf("in privileged mode, BlockedArgs should be empty, got %v", caps.BlockedArgs)
		}

		if len(caps.ArgAlternatives) > 0 {
			t.Errorf("in privileged mode, ArgAlternatives should be empty, got %v", caps.ArgAlternatives)
		}
	} else {
		t.Log("Testing in UNPRIVILEGED mode")

		// In unprivileged mode:
		// 1. Only service_detect and script_scan should be enabled
		// 2. BlockedArgs should contain privileged flags
		// 3. ArgAlternatives should contain mappings

		enabledCount := 0
		for feature, enabled := range caps.Features {
			if enabled {
				enabledCount++
				if feature != "service_detect" && feature != "script_scan" {
					t.Errorf("in unprivileged mode, only service_detect and script_scan should be enabled, but %q is enabled", feature)
				}
			}
		}

		if enabledCount != 2 {
			t.Errorf("in unprivileged mode, expected 2 enabled features, got %d", enabledCount)
		}

		if len(caps.BlockedArgs) == 0 {
			t.Error("in unprivileged mode, BlockedArgs should not be empty")
		}

		if len(caps.ArgAlternatives) == 0 {
			t.Error("in unprivileged mode, ArgAlternatives should not be empty")
		}
	}
}

// TestCapabilities_Consistency verifies internal consistency of the Capabilities struct
func TestCapabilities_Consistency(t *testing.T) {
	tool := &ToolImpl{}
	ctx := context.Background()

	caps := tool.Capabilities(ctx)

	// Verify that all blocked args with alternatives actually appear in BlockedArgs
	for blocked := range caps.ArgAlternatives {
		if !caps.IsArgBlocked(blocked) {
			t.Errorf("flag %q has alternative but is not in BlockedArgs", blocked)
		}
	}

	// Verify Features map is not nil
	if caps.Features == nil {
		t.Fatal("Features map should never be nil")
	}

	// If unprivileged, verify that disabled features correspond to blocked args
	if !caps.HasPrivilegedAccess() {
		featureToArgs := map[string][]string{
			"os_detection": {"-O"},
			"syn_scan":     {"-sS"},
			"udp_scan":     {"-sU"},
			"traceroute":   {"--traceroute"},
		}

		for feature, args := range featureToArgs {
			if caps.Features[feature] {
				// If feature is enabled, corresponding args should not be blocked
				for _, arg := range args {
					if caps.IsArgBlocked(arg) {
						t.Errorf("feature %q is enabled but arg %q is blocked", feature, arg)
					}
				}
			} else {
				// If feature is disabled, at least one corresponding arg should be blocked
				hasBlocked := false
				for _, arg := range args {
					if caps.IsArgBlocked(arg) {
						hasBlocked = true
						break
					}
				}
				if !hasBlocked {
					t.Errorf("feature %q is disabled but none of its args %v are blocked", feature, args)
				}
			}
		}
	}
}

// TestCapabilities_TypeInterface verifies the Capabilities struct satisfies expected interface contracts
func TestCapabilities_TypeInterface(t *testing.T) {
	tool := &ToolImpl{}
	ctx := context.Background()

	caps := tool.Capabilities(ctx)

	// Verify return type is correct
	var _ *types.Capabilities = caps

	// Verify all expected methods are available and work
	_ = caps.HasPrivilegedAccess()
	_ = caps.HasFeature("test")
	_ = caps.IsArgBlocked("-test")
	_, _ = caps.GetAlternative("-test")
}
