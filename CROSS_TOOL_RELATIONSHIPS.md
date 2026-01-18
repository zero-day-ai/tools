# Cross-Tool Relationships for Attack Chain Traversal

This document describes the cross-tool relationships that enable complete attack chain traversal across Gibson tools. These relationships link nodes created by different tools, allowing graph queries to trace attack paths from initial reconnaissance through vulnerability identification.

## Overview

The Gibson tools create a unified knowledge graph where nodes and relationships from different tools are interconnected using consistent ID templates. This enables queries like:

- "Show me all vulnerabilities affecting services running on hosts discovered via subdomain enumeration"
- "Trace the attack path from domain → subdomain → host → port → endpoint → vulnerability"
- "Find all services vulnerable to CVE-X across all discovered infrastructure"

## Node ID Template Consistency

All tools use consistent ID templates to ensure proper cross-tool linking:

| Node Type | ID Template | Example |
|-----------|-------------|---------|
| Domain | `domain:{name}` | `domain:example.com` |
| Subdomain | `subdomain:{name}` | `subdomain:api.example.com` |
| Host | `host:{ip}` | `host:192.168.1.100` |
| Port | `port:{host}:{port}:{protocol}` | `port:192.168.1.100:443:tcp` |
| Service | `service:{host}:{port}:{name}` | `service:192.168.1.100:443:https` |
| Endpoint | `endpoint:{url}` | `endpoint:https://api.example.com/login` |
| Finding | `finding:{template_id}:{matched_at}` | `finding:CVE-2023-1234:https://api.example.com` |
| Technology | `technology:{name}` | `technology:nginx` |
| Certificate | `certificate:{subject}` | `certificate:*.example.com` |
| ASN | `asn:{number}` | `asn:15169` |

## Cross-Tool Relationship Mappings

### 1. Subfinder → Nmap/Masscan (DNS Resolution to Host Discovery)

**Relationship**: `RESOLVES_TO`

**From**: Subdomain nodes created by subfinder
**To**: Host nodes (shared with nmap/masscan)

**Schema Location**: `/reconnaissance/subfinder/schema.go`

```go
// Subdomain resolves to IP addresses
schema.Rel("RESOLVES_TO", "subdomain:{.name}", "host:{.ips[*]}")
```

**Attack Chain Example**:
```
domain:example.com → subdomain:api.example.com → host:192.168.1.100
```

This enables queries that start from domain enumeration and traverse to infrastructure discovered by port scanners.

### 2. Amass → Nmap/Masscan (ASN to Host Mapping)

**Relationship**: `HOSTED_BY`

**From**: Host nodes (shared across tools)
**To**: ASN nodes created by amass

**Schema Location**: `/reconnaissance/amass/schema.go`

```go
// Host is hosted by an ASN
schema.Rel("HOSTED_BY", "host:{.}", "asn:{_parent.number}")
```

**Attack Chain Example**:
```
host:192.168.1.100 → asn:15169 (Google LLC)
```

This enables infrastructure attribution queries like "Show all hosts in AS15169" or "Find all ASNs associated with target infrastructure".

### 3. HTTPx → Nmap/Masscan (Endpoint to Port Mapping)

**Relationships**:
- `HAS_ENDPOINT` (port → endpoint)
- `HOSTED_ON` (endpoint → host)

**From**: Endpoint nodes created by httpx
**To**: Port nodes created by nmap/masscan

**Schema Location**: `/reconnaissance/httpx/schema.go`

```go
// Port has an HTTP endpoint
schema.Rel("HAS_ENDPOINT", "port:{.host}:{.port}:tcp", "endpoint:{.url}")

// Endpoint is hosted on a host
schema.Rel("HOSTED_ON", "endpoint:{.url}", "host:{.host}")
```

**Implementation Details**:
- HTTPx extracts `host`, `port`, and `scheme` from each discovered URL
- These fields are stored in the endpoint node properties
- The relationships link to port nodes using the format: `port:{host}:{port}:tcp`

**Attack Chain Example**:
```
port:192.168.1.100:443:tcp → endpoint:https://api.example.com/login
endpoint:https://api.example.com/login → host:192.168.1.100
```

This enables queries like:
- "Show me all web endpoints running on ports discovered by nmap"
- "Find all endpoints hosted on vulnerable services"

### 4. Nuclei → HTTPx Endpoint (Vulnerability to Endpoint)

**Relationship**: `AFFECTS`

**From**: Finding nodes created by nuclei
**To**: Endpoint nodes created by httpx

**Schema Location**: `/reconnaissance/nuclei/schema.go`

```go
// Finding affects an endpoint
schema.Rel("AFFECTS", "finding:{.template_id}:{.matched_at}", "endpoint:{.matched_at}")
```

**Attack Chain Example**:
```
finding:CVE-2023-1234:https://api.example.com/login → endpoint:https://api.example.com/login
```

### 5. Nuclei → Nmap/Masscan Port (Vulnerability to Infrastructure)

**Relationships**:
- `AFFECTS` (finding → port)
- `AFFECTS` (finding → host)

**From**: Finding nodes created by nuclei
**To**: Port and Host nodes from nmap/masscan

**Schema Location**: `/reconnaissance/nuclei/schema.go`

```go
// Finding affects a port
schema.Rel("AFFECTS", "finding:{.template_id}:{.matched_at}", "port:{.host}:{.port}:tcp")

// Finding affects a host
schema.Rel("AFFECTS", "finding:{.template_id}:{.matched_at}", "host:{.host}")
```

**Implementation Details**:
- Nuclei extracts `host`, `port`, and `scheme` from the `matched_at` URL
- These fields enable direct relationships to infrastructure nodes

**Attack Chain Example**:
```
finding:CVE-2023-1234:https://api.example.com → port:192.168.1.100:443:tcp → host:192.168.1.100
```

This enables powerful queries like:
- "Show all vulnerabilities affecting this specific port/service"
- "Find all hosts with critical findings"
- "Trace vulnerability from finding → port → host → subdomain → domain"

### 6. HTTPx → Technology (Endpoint to Tech Stack)

**Relationship**: `USES_TECHNOLOGY`

**From**: Endpoint nodes
**To**: Technology nodes (created from detected technologies)

**Schema Location**: `/reconnaissance/httpx/schema.go`

```go
// Endpoint uses a technology
schema.Rel("USES_TECHNOLOGY", "endpoint:{_parent.url}", "technology:{.}")
```

**Attack Chain Example**:
```
endpoint:https://api.example.com → technology:nginx → technology:php
```

### 7. HTTPx → Certificate (Endpoint to TLS Certificate)

**Relationship**: `SERVES_CERTIFICATE`

**From**: Endpoint nodes (HTTPS only)
**To**: Certificate nodes

**Schema Location**: `/reconnaissance/httpx/schema.go`

```go
// Endpoint serves a TLS certificate
schema.Rel("SERVES_CERTIFICATE", "endpoint:{.url}", "certificate:{.certificate.subject}")
```

**Attack Chain Example**:
```
endpoint:https://api.example.com → certificate:*.example.com
```

### 8. Nmap Service → Port

**Relationship**: `RUNS_SERVICE`

**From**: Port nodes
**To**: Service nodes (detailed service information)

**Schema Location**: `/discovery/nmap/schema.go`

```go
// Port runs a service
schema.Rel("RUNS_SERVICE", "port:{_parent._parent.ip}:{_parent.port}:{_parent.protocol}", "service:{_parent._parent.ip}:{_parent.port}:{.name}")
```

**Attack Chain Example**:
```
port:192.168.1.100:443:tcp → service:192.168.1.100:443:https
```

## Complete Attack Chain Example

Here's a complete attack chain that demonstrates cross-tool traversal:

```
1. Domain Discovery (Amass/Subfinder)
   domain:example.com

2. Subdomain Enumeration (Amass/Subfinder)
   → subdomain:api.example.com

3. DNS Resolution (Subfinder)
   → host:192.168.1.100 [RESOLVES_TO]

4. ASN Attribution (Amass)
   → asn:15169 [HOSTED_BY]

5. Port Discovery (Nmap/Masscan)
   → port:192.168.1.100:443:tcp [HAS_PORT]

6. Service Detection (Nmap)
   → service:192.168.1.100:443:https [RUNS_SERVICE]

7. HTTP Probing (HTTPx)
   → endpoint:https://api.example.com/login [HAS_ENDPOINT]

8. Technology Detection (HTTPx)
   → technology:nginx [USES_TECHNOLOGY]
   → technology:php [USES_TECHNOLOGY]

9. Certificate Discovery (HTTPx)
   → certificate:*.example.com [SERVES_CERTIFICATE]

10. Vulnerability Scanning (Nuclei)
    → finding:CVE-2023-1234:https://api.example.com/login [AFFECTS endpoint]
    → finding:CVE-2023-1234:https://api.example.com/login [AFFECTS port]
    → finding:CVE-2023-1234:https://api.example.com/login [AFFECTS host]
```

## Graph Traversal Queries

### Query 1: Find All Vulnerabilities for a Domain

```cypher
MATCH path = (d:domain {name: "example.com"})-[:HAS_SUBDOMAIN]->(s:subdomain)
            -[:RESOLVES_TO]->(h:host)
            -[:HAS_PORT]->(p:port)
            -[:HAS_ENDPOINT]->(e:endpoint)
            <-[:AFFECTS]-(f:finding)
RETURN path
```

### Query 2: Find Critical Findings on Specific Services

```cypher
MATCH (s:service {name: "https"})<-[:RUNS_SERVICE]-(p:port)
      <-[:AFFECTS]-(f:finding {severity: "critical"})
RETURN s, p, f
```

### Query 3: Infrastructure Attribution

```cypher
MATCH (h:host)-[:HOSTED_BY]->(asn:asn)
WHERE h.ip IN ["192.168.1.100", "192.168.1.101"]
RETURN h, asn
```

### Query 4: Technology Stack Vulnerabilities

```cypher
MATCH (e:endpoint)-[:USES_TECHNOLOGY]->(t:technology {name: "nginx"})
      <-[:AFFECTS]-(f:finding)
RETURN e, t, f
```

## Implementation Notes

### Required Fields for Cross-Tool Linking

Each tool must extract and include specific fields to enable cross-tool relationships:

#### HTTPx Output Fields
```go
{
  "url": "https://api.example.com:8443/login",
  "host": "192.168.1.100",  // Extracted from URL
  "port": 8443,              // Extracted from URL (or default 80/443)
  "scheme": "https"          // Extracted from URL
}
```

#### Nuclei Output Fields
```go
{
  "matched_at": "https://api.example.com:8443/login",
  "host": "192.168.1.100",  // Extracted from matched_at
  "port": 8443,              // Extracted from matched_at
  "scheme": "https"          // Extracted from matched_at
}
```

### URL Parsing Logic

Both httpx and nuclei use the same URL parsing logic:

```go
parsedURL, err := url.Parse(urlString)
if err == nil {
    scheme = parsedURL.Scheme
    host = parsedURL.Hostname()

    portStr := parsedURL.Port()
    if portStr != "" {
        fmt.Sscanf(portStr, "%d", &port)
    } else {
        // Default ports
        if scheme == "https" {
            port = 443
        } else if scheme == "http" {
            port = 80
        }
    }
}
```

## Benefits of Cross-Tool Relationships

1. **Complete Attack Surface Visibility**: Trace from initial domain discovery through to exploitable vulnerabilities

2. **Infrastructure Attribution**: Link findings to ASNs, organizations, and infrastructure owners

3. **Service-Level Analysis**: Connect vulnerabilities to specific services and versions

4. **Technology Stack Mapping**: Understand technology dependencies and their security implications

5. **Efficient Prioritization**: Query for critical vulnerabilities on internet-facing services

6. **Automated Remediation Tracking**: Follow relationships to identify all affected systems

## Future Enhancements

Potential additional cross-tool relationships:

1. **Service → CVE**: Link service versions to known CVEs
2. **Technology → CVE**: Link technology stacks to vulnerabilities
3. **Certificate → Subdomain**: Link SANs to subdomain nodes
4. **Port → Service Banner**: Create separate banner nodes for fingerprinting
5. **Finding → CWE**: Link vulnerabilities to weakness categories

## Testing Cross-Tool Relationships

To verify cross-tool relationships are working:

1. Run a complete reconnaissance workflow:
   ```bash
   subfinder -d example.com → nmap → httpx → nuclei
   ```

2. Query the graph to verify relationships exist:
   ```cypher
   MATCH (s:subdomain)-[:RESOLVES_TO]->(h:host)-[:HAS_PORT]->(p:port)
   RETURN count(*) as cross_tool_links
   ```

3. Check for orphaned nodes (nodes without cross-tool links):
   ```cypher
   MATCH (e:endpoint)
   WHERE NOT (e)-[:HOSTED_ON]->(:host)
   RETURN e.url
   ```

## Troubleshooting

### Issue: Endpoints not linking to ports

**Symptom**: HTTPx endpoints exist but no `HAS_ENDPOINT` relationships

**Possible Causes**:
1. Port was not discovered by nmap/masscan first
2. Host/port extraction from URL failed
3. Port ID format mismatch

**Solution**: Verify port nodes exist with correct IDs:
```cypher
MATCH (p:port) WHERE p.number = 443 RETURN p
```

### Issue: Findings not linking to hosts

**Symptom**: Nuclei findings exist but no `AFFECTS` relationships to hosts

**Possible Causes**:
1. URL parsing failed in nuclei
2. Host was not discovered by nmap/masscan
3. Host ID format mismatch

**Solution**: Check finding host field:
```cypher
MATCH (f:finding) RETURN f.host, f.port, f.matched_at LIMIT 10
```

## Maintenance

When adding new tools or modifying schemas:

1. Ensure consistent ID templates across all tools
2. Document new relationships in this file
3. Add cross-tool relationship tests
4. Update graph traversal examples
5. Verify backward compatibility with existing graphs
