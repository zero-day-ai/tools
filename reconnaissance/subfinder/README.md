# Subfinder Tool

Subfinder is a subdomain enumeration tool that uses passive DNS and other data sources to discover subdomains for a target domain.

## Features

- Passive subdomain enumeration using multiple data sources
- JSON output with deduplicated subdomain list
- Configurable timeout and rate limiting
- Recursive subdomain discovery support
- Health check to verify subfinder binary availability

## Input Schema

```json
{
  "domain": "example.com",        // Required: Target domain
  "sources": ["crtsh", "anubis"], // Optional: Specific sources to use
  "timeout": 30,                   // Optional: Timeout in seconds
  "rate_limit": 10,                // Optional: Requests per second
  "recursive": false               // Optional: Enable recursive enumeration
}
```

## Output Schema

```json
{
  "domain": "example.com",
  "subdomains": [
    "www.example.com",
    "api.example.com",
    "mail.example.com"
  ],
  "count": 3,
  "sources_used": ["crtsh", "anubis"],
  "scan_time_ms": 2500
}
```

## Requirements

- `subfinder` binary must be installed and available in PATH
- Install via: `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`

## Building

```bash
# From the gibson-tools-official root directory
go build ./reconnaissance/subfinder

# Or with output to bin directory
go build -o reconnaissance/subfinder/bin/subfinder ./reconnaissance/subfinder
```

## Testing

Run integration tests (requires subfinder binary):

```bash
cd reconnaissance/subfinder
go test -v -tags=integration
```

## MITRE ATT&CK Mapping

- **T1595.002**: Active Scanning: Vulnerability Scanning
- **T1592**: Gather Victim Host Information

## Example Usage

Via gRPC tool interface:

```go
input := map[string]any{
    "domain": "example.com",
    "timeout": 60,
}

output, err := tool.Execute(ctx, input)
if err != nil {
    log.Fatal(err)
}

subdomains := output["subdomains"].([]string)
fmt.Printf("Found %d subdomains\n", len(subdomains))
```

## Implementation Details

- Uses `-json` and `-silent` flags for clean JSON output
- Parses JSON lines format (one result per line)
- Deduplicates subdomains automatically
- Tracks which data sources were used
- Returns both subdomain list and count for convenience
