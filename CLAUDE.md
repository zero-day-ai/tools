# Gibson Tools Development Guide

## Overview

Gibson tools are atomic, stateless wrappers around security utilities that provide structured, LLM-consumable I/O. Tools use **Protocol Buffers** for type-safe input/output, enabling reliable integration with the Gibson framework.

## Tool Interface

Every tool must implement the `Tool` interface:

```go
type Tool interface {
    // Identity
    Name() string
    Version() string
    Description() string
    Tags() []string

    // Proto-based execution (REQUIRED)
    InputMessageType() string   // e.g., "gibson.tools.NmapRequest"
    OutputMessageType() string  // e.g., "gibson.tools.NmapResponse"
    ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error)

    // Health monitoring
    Health(ctx context.Context) types.HealthStatus
}
```

## Directory Structure

```
tools/
├── discovery/           # Host/network discovery
│   └── nmap/           # Network mapper
├── reconnaissance/     # Information gathering
│   ├── httpx/          # HTTP probing
│   └── nuclei/         # Vulnerability scanning
├── fingerprinting/     # Technology detection
│   ├── wappalyzer/     # Web tech detection
│   ├── whatweb/        # Web fingerprinting
│   ├── sslyze/         # SSL/TLS analysis
│   └── testssl/        # SSL testing
└── bin/                # Compiled binaries
```

## Tool Categories (MITRE ATT&CK)

| Category | Tools | Purpose |
|----------|-------|---------|
| **Discovery** | nmap, masscan | Network/host discovery |
| **Reconnaissance** | httpx, nuclei, subfinder | Information gathering |
| **Fingerprinting** | wappalyzer, whatweb, sslyze, testssl | Technology detection |
| **Initial Access** | sqlmap, gobuster, hydra | Exploitation |
| **Credential Access** | responder, secretsdump | Credential harvesting |
| **Post-Exploitation** | linpeas, winpeas, hashcat | Privilege escalation |

## Building a Tool

### 1. Define Proto Messages

Create `proto/tool.proto`:

```protobuf
syntax = "proto3";

package gibson.tools;

option go_package = "github.com/zero-day-ai/tools/mytool/proto";

message MyToolRequest {
    string target = 1;
    repeated string options = 2;
    int32 timeout_seconds = 3;
}

message MyToolResponse {
    bool success = 1;
    string output = 2;
    repeated Finding findings = 3;
    ErrorInfo error = 4;
}

message Finding {
    string title = 1;
    string description = 2;
    string severity = 3;
}

message ErrorInfo {
    string code = 1;
    string message = 2;
}
```

### 2. Implement Tool Interface

```go
package mytool

import (
    "context"
    "os/exec"

    pb "github.com/zero-day-ai/tools/mytool/proto"
    "github.com/zero-day-ai/sdk/tool"
    "github.com/zero-day-ai/sdk/types"
    "google.golang.org/protobuf/proto"
)

type MyTool struct {
    binaryPath string
}

func New() *MyTool {
    return &MyTool{binaryPath: "/usr/bin/mytool"}
}

func (t *MyTool) Name() string        { return "mytool" }
func (t *MyTool) Version() string     { return "1.0.0" }
func (t *MyTool) Description() string { return "My security tool wrapper" }
func (t *MyTool) Tags() []string      { return []string{"reconnaissance", "scanning"} }

func (t *MyTool) InputMessageType() string  { return "gibson.tools.MyToolRequest" }
func (t *MyTool) OutputMessageType() string { return "gibson.tools.MyToolResponse" }

func (t *MyTool) ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error) {
    req, ok := input.(*pb.MyToolRequest)
    if !ok {
        return nil, fmt.Errorf("invalid input type")
    }

    // Build command
    args := []string{"-t", req.Target}
    args = append(args, req.Options...)

    // Execute with context (timeout support)
    cmd := exec.CommandContext(ctx, t.binaryPath, args...)
    output, err := cmd.Output()
    if err != nil {
        return &pb.MyToolResponse{
            Success: false,
            Error: &pb.ErrorInfo{
                Code:    "EXEC_ERROR",
                Message: err.Error(),
            },
        }, nil
    }

    // Parse output into structured response
    findings := parseOutput(output)

    return &pb.MyToolResponse{
        Success:  true,
        Output:   string(output),
        Findings: findings,
    }, nil
}

func (t *MyTool) Health(ctx context.Context) types.HealthStatus {
    // Check if binary exists and is executable
    if _, err := exec.LookPath(t.binaryPath); err != nil {
        return types.HealthStatus{
            Status:  types.HealthStatusUnhealthy,
            Message: fmt.Sprintf("binary not found: %s", t.binaryPath),
        }
    }
    return types.HealthStatus{Status: types.HealthStatusHealthy}
}
```

### 3. Create Main Entry Point

```go
package main

import (
    "github.com/zero-day-ai/tools/mytool"
    "github.com/zero-day-ai/sdk/serve"
)

func main() {
    tool := mytool.New()
    serve.Tool(tool, serve.WithPort(50052))
}
```

### 4. Define component.yaml

```yaml
name: mytool
version: 1.0.0
type: tool
description: My security tool wrapper

tags:
  - reconnaissance
  - scanning

mitre_attack:
  tactics:
    - TA0043  # Reconnaissance
  techniques:
    - T1595   # Active Scanning

dependencies:
  binaries:
    - name: mytool
      version: ">=2.0.0"
      install: "apt-get install mytool"

proto:
  input: gibson.tools.MyToolRequest
  output: gibson.tools.MyToolResponse
```

## Tool Output Standards

### Structured JSON

All tools must produce structured output that LLMs can parse:

```json
{
  "success": true,
  "target": "192.168.1.1",
  "findings": [
    {
      "port": 22,
      "service": "ssh",
      "version": "OpenSSH 8.2",
      "vulnerability": null
    },
    {
      "port": 80,
      "service": "http",
      "version": "nginx 1.18.0",
      "vulnerability": "CVE-2021-23017"
    }
  ],
  "metadata": {
    "scan_time": "12.5s",
    "host_up": true
  }
}
```

### MITRE ATT&CK Mappings

Include technique mappings in tool metadata:

```go
func (t *MyTool) MITREMappings() []MITREMapping {
    return []MITREMapping{
        {Tactic: "TA0043", Technique: "T1595", SubTechnique: "T1595.001"},
    }
}
```

## Health Monitoring

Tools must implement health checks that verify:

1. **Binary availability** - Required executables exist
2. **Version compatibility** - Binary version meets requirements
3. **Dependencies** - Required libraries/services available

```go
func (t *MyTool) Health(ctx context.Context) types.HealthStatus {
    // Check binary exists
    path, err := exec.LookPath("mytool")
    if err != nil {
        return types.HealthStatus{
            Status:  types.HealthStatusUnhealthy,
            Message: "mytool binary not found",
        }
    }

    // Check version
    cmd := exec.CommandContext(ctx, path, "--version")
    output, err := cmd.Output()
    if err != nil {
        return types.HealthStatus{
            Status:  types.HealthStatusDegraded,
            Message: "unable to check version",
        }
    }

    version := parseVersion(string(output))
    if !isCompatible(version, "2.0.0") {
        return types.HealthStatus{
            Status:  types.HealthStatusDegraded,
            Message: fmt.Sprintf("version %s < required 2.0.0", version),
        }
    }

    return types.HealthStatus{Status: types.HealthStatusHealthy}
}
```

## Existing Tools

### nmap (discovery/)

Network mapper for host discovery and port scanning.

```go
// Request
&pb.NmapRequest{
    Target: "192.168.1.0/24",
    Ports:  "1-65535",
    Flags:  []string{"-sV", "-sC", "-T4"},
}

// Response
&pb.NmapResponse{
    Hosts: []*pb.Host{
        {Address: "192.168.1.1", Ports: []*pb.Port{...}},
    },
}
```

### httpx (reconnaissance/)

HTTP probe for web server analysis.

```go
// Request
&pb.HttpxRequest{
    Targets: []string{"https://example.com"},
    Options: &pb.HttpxOptions{
        StatusCode: true,
        Title:      true,
        TechDetect: true,
    },
}
```

### nuclei (reconnaissance/)

Template-based vulnerability scanner.

```go
// Request
&pb.NucleiRequest{
    Target:    "https://example.com",
    Templates: []string{"cves/", "vulnerabilities/"},
    Severity:  []string{"critical", "high"},
}
```

### wappalyzer (fingerprinting/)

Web technology fingerprinting.

```go
// Request
&pb.WappalyzerRequest{
    Url: "https://example.com",
}

// Response
&pb.WappalyzerResponse{
    Technologies: []*pb.Technology{
        {Name: "nginx", Category: "Web servers", Version: "1.18.0"},
        {Name: "React", Category: "JavaScript frameworks"},
    },
}
```

### sslyze / testssl (fingerprinting/)

SSL/TLS security analysis.

```go
// Request
&pb.SSLyzeRequest{
    Target: "example.com:443",
    Checks: []string{"certinfo", "protocols", "ciphers"},
}
```

## Build System

### Building Individual Tools

```bash
cd tools/discovery/nmap
make build
```

### Building All Tools

```bash
cd tools/
make build-all
```

### Install to Gibson

```bash
gibson tool install ./bin/nmap
gibson tool install github.com/zero-day-ai/tools/discovery/nmap
```

## Testing

### Unit Tests

```go
func TestMyTool_Execute(t *testing.T) {
    tool := New()
    req := &pb.MyToolRequest{Target: "localhost"}

    resp, err := tool.ExecuteProto(context.Background(), req)
    require.NoError(t, err)

    result := resp.(*pb.MyToolResponse)
    assert.True(t, result.Success)
}
```

### Integration Tests

```bash
make test-integration
```

## Best Practices

1. **Always use Proto** - Never use raw JSON maps for tool I/O
2. **Structured output** - Parse tool output into meaningful structures
3. **Health checks** - Verify dependencies before execution
4. **Context respect** - Honor context cancellation and timeouts
5. **Error handling** - Return structured errors, not panics
6. **MITRE mappings** - Tag tools with ATT&CK techniques
7. **Idempotent** - Tools should be safe to retry
8. **Minimal permissions** - Request only necessary capabilities
