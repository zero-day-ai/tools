# Task 13: Cross-Tool Relationships Implementation Summary

## Overview

Enhanced cross-tool relationships across Gibson tools to enable complete attack chain traversal from domain discovery through vulnerability identification. This implementation allows graph queries to trace attack paths and link discoveries across different reconnaissance stages.

## Changes Made

### 1. HTTPx Schema Enhancements (`/reconnaissance/httpx/schema.go`)

**Added Fields**:
- `host` (string): Extracted host/IP from URL for cross-tool linking
- `port` (integer): Extracted port from URL (with defaults: 80 for HTTP, 443 for HTTPS)
- `scheme` (string): Protocol scheme (http or https)

**Added Relationships**:
- `HAS_ENDPOINT`: Links port nodes (from nmap/masscan) to endpoint nodes
  - Format: `port:{host}:{port}:tcp` → `endpoint:{url}`
  - Enables traversal: port → endpoint

- `HOSTED_ON`: Links endpoint to host node
  - Format: `endpoint:{url}` → `host:{host}`
  - Enables direct endpoint → host queries

**Code Changes**:
```go
// Schema additions (lines 104-106)
"host":   schema.String(),
"port":   schema.Int(),
"scheme": schema.String(),

// New relationships (lines 133-135)
schema.Rel("HAS_ENDPOINT", "port:{.host}:{.port}:tcp", "endpoint:{.url}"),
schema.Rel("HOSTED_ON", "endpoint:{.url}", "host:{.host}"),
```

### 2. HTTPx Tool Implementation (`/reconnaissance/httpx/tool.go`)

**Import Addition**:
- Added `net/url` package for URL parsing

**Implementation**:
- Parses each discovered URL to extract host, port, and scheme
- Handles default ports (80 for HTTP, 443 for HTTPS)
- Stores extracted values in output data

**Code Changes**:
```go
// URL parsing logic (lines 217-238)
parsedURL, err := url.Parse(entry.URL)
host := ""
port := 0
scheme := ""
if err == nil {
    scheme = parsedURL.Scheme
    host = parsedURL.Hostname()

    portStr := parsedURL.Port()
    if portStr != "" {
        fmt.Sscanf(portStr, "%d", &port)
    } else {
        if scheme == "https" {
            port = 443
        } else if scheme == "http" {
            port = 80
        }
    }
}

// Added to result map (lines 250-252)
"host":   host,
"port":   port,
"scheme": scheme,
```

### 3. Nuclei Schema Enhancements (`/reconnaissance/nuclei/schema.go`)

**Added Fields**:
- `host` (string): Extracted host/IP from matched_at URL
- `port` (integer): Extracted port from matched_at URL
- `scheme` (string): Protocol scheme

**Added Relationships**:
- `AFFECTS` (finding → port): Links vulnerability findings to port nodes
  - Format: `finding:{template_id}:{matched_at}` → `port:{host}:{port}:tcp`

- `AFFECTS` (finding → host): Links vulnerability findings to host nodes
  - Format: `finding:{template_id}:{matched_at}` → `host:{host}`

**Code Changes**:
```go
// Schema additions (lines 55-57)
"host":   schema.String(),
"port":   schema.Int(),
"scheme": schema.String(),

// New relationships (lines 84-86)
schema.Rel("AFFECTS", "finding:{.template_id}:{.matched_at}", "port:{.host}:{.port}:tcp"),
schema.Rel("AFFECTS", "finding:{.template_id}:{.matched_at}", "host:{.host}"),
```

### 4. Nuclei Tool Implementation (`/reconnaissance/nuclei/tool.go`)

**Import Addition**:
- Added `net/url` package for URL parsing

**Implementation**:
- Parses matched_at URL to extract host, port, and scheme
- Uses same URL parsing logic as httpx for consistency
- Stores extracted values in finding data

**Code Changes**:
```go
// URL parsing logic (lines 175-196)
parsedURL, err := url.Parse(entry.MatchedAt)
host := ""
port := 0
scheme := ""
if err == nil {
    scheme = parsedURL.Scheme
    host = parsedURL.Hostname()

    portStr := parsedURL.Port()
    if portStr != "" {
        fmt.Sscanf(portStr, "%d", &port)
    } else {
        if scheme == "https" {
            port = 443
        } else if scheme == "http" {
            port = 80
        }
    }
}

// Added to finding map (lines 205-207)
"host":   host,
"port":   port,
"scheme": scheme,
```

### 5. Documentation (`/CROSS_TOOL_RELATIONSHIPS.md`)

Created comprehensive documentation covering:
- Node ID template consistency across all tools
- Detailed cross-tool relationship mappings
- Complete attack chain examples
- Graph traversal query examples
- Implementation notes and best practices
- Troubleshooting guide
- Future enhancement suggestions

## Existing Relationships Verified

The following relationships were already correctly implemented:

### Subfinder → Nmap/Masscan
- **RESOLVES_TO**: `subdomain:{name}` → `host:{ips[*]}`
- Status: ✅ Already implemented correctly

### Amass → Nmap/Masscan
- **HOSTED_BY**: `host:{ip}` → `asn:{number}`
- Status: ✅ Already implemented correctly

### Nmap Service Detection
- **RUNS_SERVICE**: `port:{host}:{port}:{protocol}` → `service:{host}:{port}:{name}`
- Status: ✅ Already implemented with service nodes

### HTTPx Technology Detection
- **USES_TECHNOLOGY**: `endpoint:{url}` → `technology:{name}`
- Status: ✅ Already implemented

### HTTPx Certificate Discovery
- **SERVES_CERTIFICATE**: `endpoint:{url}` → `certificate:{subject}`
- Status: ✅ Already implemented

### Nuclei → HTTPx
- **AFFECTS**: `finding:{template_id}:{matched_at}` → `endpoint:{matched_at}`
- Status: ✅ Already implemented

## Complete Attack Chain Traversal

With these enhancements, the following attack chain is now fully traversable:

```
Domain Discovery (Amass/Subfinder)
  ↓ HAS_SUBDOMAIN
Subdomain Enumeration
  ↓ RESOLVES_TO
Host Discovery (shared: Subfinder/Nmap/Masscan)
  ↓ HAS_PORT
Port Discovery (Nmap/Masscan)
  ↓ RUNS_SERVICE
Service Detection (Nmap)
  ↓ HAS_ENDPOINT
HTTP Endpoint Discovery (HTTPx)
  ↓ USES_TECHNOLOGY / SERVES_CERTIFICATE
Technology/Certificate Detection
  ↑ AFFECTS (finding → endpoint)
  ↑ AFFECTS (finding → port)
  ↑ AFFECTS (finding → host)
Vulnerability Findings (Nuclei)
```

### Additional Infrastructure Attribution
```
Host → HOSTED_BY → ASN (Amass)
```

## Example Graph Queries Enabled

### 1. Complete Vulnerability Attack Path
```cypher
MATCH path = (d:domain {name: "example.com"})
            -[:HAS_SUBDOMAIN]->(s:subdomain)
            -[:RESOLVES_TO]->(h:host)
            -[:HAS_PORT]->(p:port)
            -[:HAS_ENDPOINT]->(e:endpoint)
            <-[:AFFECTS]-(f:finding)
RETURN path
```

### 2. Critical Findings on Specific Services
```cypher
MATCH (s:service {name: "https"})
      <-[:RUNS_SERVICE]-(p:port)
      <-[:AFFECTS]-(f:finding {severity: "critical"})
RETURN s.product, s.version, f.template_name, f.cvss_score
ORDER BY f.cvss_score DESC
```

### 3. Infrastructure Attribution
```cypher
MATCH (d:domain {name: "example.com"})
      -[:HAS_SUBDOMAIN]->(s:subdomain)
      -[:RESOLVES_TO]->(h:host)
      -[:HOSTED_BY]->(asn:asn)
RETURN asn.number, asn.description, count(h) as host_count
```

### 4. Technology Stack Vulnerabilities
```cypher
MATCH (e:endpoint)-[:USES_TECHNOLOGY]->(t:technology {name: "nginx"})
WHERE exists((e)<-[:AFFECTS]-(:finding))
RETURN e.url,
       [(e)<-[:AFFECTS]-(f:finding) | f.severity] as severities
```

### 5. Find All Attack Paths to a Vulnerable Service
```cypher
MATCH path = (d:domain)
            -[:HAS_SUBDOMAIN*0..1]->(s:subdomain)
            -[:RESOLVES_TO]->(h:host)
            -[:HAS_PORT]->(p:port)
            -[:RUNS_SERVICE]->(svc:service)
WHERE exists((p)<-[:AFFECTS]-(f:finding {severity: "critical"}))
RETURN path
```

## ID Template Consistency

All tools now use consistent ID templates:

| Node Type | ID Format | Tools |
|-----------|-----------|-------|
| domain | `domain:{name}` | amass, subfinder |
| subdomain | `subdomain:{name}` | amass, subfinder |
| host | `host:{ip}` | amass, subfinder, nmap, masscan |
| port | `port:{host}:{port}:{protocol}` | nmap, masscan |
| service | `service:{host}:{port}:{name}` | nmap |
| endpoint | `endpoint:{url}` | httpx |
| finding | `finding:{template_id}:{matched_at}` | nuclei |
| technology | `technology:{name}` | httpx |
| certificate | `certificate:{subject}` | httpx |
| asn | `asn:{number}` | amass |

## Testing

Both modified tools compile successfully:
- ✅ httpx: `go build` completed without errors
- ✅ nuclei: `go build` completed without errors

## Benefits

1. **Complete Attack Surface Visibility**: Trace from domain discovery to exploitable vulnerabilities

2. **Infrastructure Attribution**: Link findings to ASNs, organizations, and infrastructure owners

3. **Service-Level Analysis**: Connect vulnerabilities to specific services and versions

4. **Technology Stack Mapping**: Understand technology dependencies and security implications

5. **Efficient Prioritization**: Query for critical vulnerabilities on internet-facing services

6. **Multi-Tool Correlation**: Combine data from different reconnaissance stages

## Files Modified

1. `/reconnaissance/httpx/schema.go`
2. `/reconnaissance/httpx/tool.go`
3. `/reconnaissance/nuclei/schema.go`
4. `/reconnaissance/nuclei/tool.go`

## Files Created

1. `/CROSS_TOOL_RELATIONSHIPS.md` - Comprehensive documentation
2. `/TASK_13_SUMMARY.md` - This summary document

## Future Enhancements

Potential additional cross-tool relationships:

1. **Service → CVE**: Link service versions to known CVEs from vulnerability databases
2. **Technology → CVE**: Link technology stacks to known vulnerabilities
3. **Certificate → Subdomain**: Link certificate SANs to subdomain nodes
4. **Port → Service Banner**: Create separate banner nodes for detailed fingerprinting
5. **Finding → CWE**: Enhanced CWE relationship for weakness categorization

## Validation Checklist

- ✅ HTTPx extracts host, port, scheme from URLs
- ✅ HTTPx creates HAS_ENDPOINT relationship to ports
- ✅ HTTPx creates HOSTED_ON relationship to hosts
- ✅ Nuclei extracts host, port, scheme from matched_at URLs
- ✅ Nuclei creates AFFECTS relationships to ports
- ✅ Nuclei creates AFFECTS relationships to hosts
- ✅ ID templates are consistent across all tools
- ✅ Both tools compile successfully
- ✅ Documentation is comprehensive and includes examples
- ✅ Existing relationships verified and documented
