package main

import (
	"context"

	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

// privilegedFlags contains nmap flags that require root/sudo/raw socket privileges.
// These operations perform low-level network operations that require elevated access.
var privilegedFlags = []string{
	"-O",          // OS detection - requires raw packet access
	"-sS",         // SYN scan - requires raw socket for TCP SYN packets
	"-sA",         // ACK scan - requires raw socket for TCP ACK packets
	"-sW",         // Window scan - requires raw socket access
	"-sM",         // Maimon scan - requires raw socket access
	"-sN",         // Null scan - requires raw socket for crafted packets
	"-sF",         // FIN scan - requires raw socket for TCP FIN packets
	"-sX",         // Xmas scan - requires raw socket for crafted packets
	"--traceroute", // Traceroute - requires raw socket for ICMP/UDP
	"-sU",         // UDP scan - requires raw socket for UDP packets
}

// flagAlternatives maps privileged nmap flags to their unprivileged equivalents.
// These alternatives provide similar functionality without requiring raw socket access.
var flagAlternatives = map[string]string{
	"-sS": "-sT", // SYN stealth scan -> TCP connect scan
	"-sA": "-sT", // ACK scan -> TCP connect scan
}

// Capabilities reports the runtime privileges and features available to nmap.
// This method probes the execution environment to determine what scan types
// and operations are available based on privilege level.
//
// The returned Capabilities struct includes:
//   - HasRoot: true if running as uid 0
//   - HasSudo: true if passwordless sudo is available
//   - CanRawSocket: true if raw socket creation is possible (requires CAP_NET_RAW)
//   - Features: map of nmap features and their availability
//   - BlockedArgs: list of nmap flags that cannot be used (if unprivileged)
//   - ArgAlternatives: suggested replacements for blocked flags
//
// Feature flags:
//   - os_detection: OS fingerprinting (-O flag)
//   - syn_scan: SYN stealth scanning (-sS flag)
//   - udp_scan: UDP port scanning (-sU flag)
//   - traceroute: Network path tracing (--traceroute flag)
//   - service_detect: Service version detection (-sV flag) - always available
//   - script_scan: NSE script execution (-sC flag) - always available
func (t *ToolImpl) Capabilities(ctx context.Context) *types.Capabilities {
	caps := types.NewCapabilities()

	// Probe runtime environment for privilege levels
	caps.HasRoot = tool.ProbeRoot()
	caps.HasSudo = tool.ProbeSudo()
	caps.CanRawSocket = tool.ProbeRawSocket()

	// If we have any form of privileged access, all features are available
	if caps.HasPrivilegedAccess() {
		caps.Features["os_detection"] = true
		caps.Features["syn_scan"] = true
		caps.Features["udp_scan"] = true
		caps.Features["traceroute"] = true
		caps.Features["service_detect"] = true
		caps.Features["script_scan"] = true
		return caps
	}

	// Unprivileged mode - populate blocked args and alternatives
	caps.BlockedArgs = privilegedFlags
	caps.ArgAlternatives = flagAlternatives

	// Set feature availability for unprivileged execution
	caps.Features["os_detection"] = false   // -O requires raw socket
	caps.Features["syn_scan"] = false       // -sS requires raw socket
	caps.Features["udp_scan"] = false       // -sU requires raw socket
	caps.Features["traceroute"] = false     // --traceroute requires raw socket
	caps.Features["service_detect"] = true  // -sV works without privileges
	caps.Features["script_scan"] = true     // -sC works without privileges

	return caps
}
