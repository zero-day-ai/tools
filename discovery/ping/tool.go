package main

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zero-day-ai/sdk/health"
	sdkinput "github.com/zero-day-ai/sdk/input"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/toolerr"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "ping"
	ToolVersion     = "1.0.0"
	ToolDescription = "ICMP ping sweep tool for host discovery"
	BinaryName      = "ping"
)

// PingResult represents the result of pinging a single host
type PingResult struct {
	IP    string  `json:"ip"`
	Alive bool    `json:"alive"`
	RTT   float64 `json:"rtt_ms"`
	Error string  `json:"error,omitempty"`
}

// ToolImpl implements the ping tool
type ToolImpl struct{}

// NewTool creates a new ping tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"discovery",
			"network",
			"ping",
			"host-discovery",
			"T1018", // Remote System Discovery
			"T1046", // Network Service Discovery
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

// Execute runs the ping sweep with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	targets := sdkinput.GetStringSlice(input, "targets")
	if len(targets) == 0 {
		return nil, toolerr.New(ToolName, "validate", toolerr.ErrCodeInvalidInput, "targets is required")
	}

	count := sdkinput.GetInt(input, "count", 1)
	timeoutMs := sdkinput.GetInt(input, "timeout", 1000)
	concurrent := sdkinput.GetInt(input, "concurrent", 50)

	// Limit concurrency to reasonable bounds
	if concurrent < 1 {
		concurrent = 1
	}
	if concurrent > 100 {
		concurrent = 100
	}

	// Create result channel and semaphore
	results := make([]PingResult, len(targets))
	sem := make(chan struct{}, concurrent)
	var wg sync.WaitGroup

	// Ping all targets concurrently
	for i, target := range targets {
		wg.Add(1)
		go func(idx int, ip string) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			// Check context
			select {
			case <-ctx.Done():
				results[idx] = PingResult{IP: ip, Alive: false, Error: "context cancelled"}
				return
			default:
			}

			// Ping the target
			result := pingHost(ctx, ip, count, timeoutMs)
			results[idx] = result
		}(i, target)
	}

	// Wait for all pings to complete
	wg.Wait()

	// Count alive hosts
	alive := 0
	for _, r := range results {
		if r.Alive {
			alive++
		}
	}

	// Build output
	resultMaps := make([]map[string]any, len(results))
	for i, r := range results {
		resultMaps[i] = map[string]any{
			"ip":     r.IP,
			"alive":  r.Alive,
			"rtt_ms": r.RTT,
		}
		if r.Error != "" {
			resultMaps[i]["error"] = r.Error
		}
	}

	return map[string]any{
		"results":      resultMaps,
		"total":        len(targets),
		"alive":        alive,
		"dead":         len(targets) - alive,
		"scan_time_ms": int(time.Since(startTime).Milliseconds()),
	}, nil
}

// pingHost pings a single host and returns the result
func pingHost(ctx context.Context, ip string, count, timeoutMs int) PingResult {
	result := PingResult{IP: ip, Alive: false}

	// Validate IP address
	if net.ParseIP(ip) == nil {
		// Try to resolve hostname
		ips, err := net.LookupIP(ip)
		if err != nil || len(ips) == 0 {
			result.Error = fmt.Sprintf("invalid host: %s", ip)
			return result
		}
		ip = ips[0].String()
	}

	// Build ping command
	// Use -c for count, -W for timeout (in seconds on Linux, milliseconds varies by OS)
	timeoutSec := timeoutMs / 1000
	if timeoutSec < 1 {
		timeoutSec = 1
	}

	args := []string{"-c", strconv.Itoa(count), "-W", strconv.Itoa(timeoutSec), ip}

	// Create command with context
	cmd := exec.CommandContext(ctx, BinaryName, args...)

	// Run command
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if it's a timeout or unreachable
		if ctx.Err() != nil {
			result.Error = "timeout"
		} else if strings.Contains(string(output), "100% packet loss") ||
			strings.Contains(string(output), "Destination Host Unreachable") ||
			strings.Contains(string(output), "Request timeout") {
			// Host is down but ping executed successfully
			result.Alive = false
		} else {
			result.Error = fmt.Sprintf("ping failed: %v", err)
		}
		return result
	}

	// Parse output for RTT
	result.Alive = true
	result.RTT = parseRTT(string(output))

	return result
}

// parseRTT extracts the average RTT from ping output
func parseRTT(output string) float64 {
	// Linux format: rtt min/avg/max/mdev = 0.123/0.456/0.789/0.012 ms
	// macOS format: round-trip min/avg/max/stddev = 0.123/0.456/0.789/0.012 ms
	patterns := []string{
		`rtt min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms`,
		`round-trip min/avg/max/stddev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms`,
		`time=([\d.]+)\s*ms`, // Single ping response
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(output)
		if len(matches) >= 2 {
			rtt, err := strconv.ParseFloat(matches[1], 64)
			if err == nil {
				return rtt
			}
		}
	}

	return 0
}

// Health checks if the ping binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}
