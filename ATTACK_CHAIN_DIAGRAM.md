# Gibson Attack Chain Visualization

This document provides visual representations of the complete attack chain enabled by cross-tool relationships in Gibson.

## Complete Attack Chain Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         RECONNAISSANCE PHASE                                  │
└──────────────────────────────────────────────────────────────────────────────┘

    ┌──────────────┐
    │    DOMAIN    │
    │ example.com  │
    └──────┬───────┘
           │ HAS_SUBDOMAIN (amass/subfinder)
           ↓
    ┌──────────────────┐
    │    SUBDOMAIN     │
    │ api.example.com  │
    └──────┬───────────┘
           │ RESOLVES_TO (subfinder)
           ↓
    ┌──────────────────┐
    │       HOST       │────────┐
    │  192.168.1.100   │        │ HOSTED_BY (amass)
    └──────┬───────────┘        │
           │ HAS_PORT           ↓
           │ (nmap/masscan)     ┌──────────────┐
           ↓                    │     ASN      │
    ┌──────────────────┐        │ AS15169      │
    │       PORT       │        │ (Google LLC) │
    │   443:tcp        │        └──────────────┘
    └──────┬───────────┘
           │ RUNS_SERVICE (nmap)
           ↓
    ┌──────────────────┐
    │     SERVICE      │
    │  https (nginx)   │
    │  version 1.21.0  │
    └──────┬───────────┘
           │
           │ HAS_ENDPOINT (httpx) 🔧 NEW
           ↓

┌──────────────────────────────────────────────────────────────────────────────┐
│                         WEB RECONNAISSANCE PHASE                              │
└──────────────────────────────────────────────────────────────────────────────┘

    ┌────────────────────────────┐
    │         ENDPOINT           │
    │ https://api.example.com/   │
    │         login              │
    └────┬───────────────┬───────┘
         │               │
         │ USES_         │ SERVES_CERTIFICATE
         │ TECHNOLOGY    │ (httpx)
         ↓               ↓
    ┌─────────────┐  ┌──────────────┐
    │ TECHNOLOGY  │  │ CERTIFICATE  │
    │    nginx    │  │ *.example.com│
    └─────────────┘  └──────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│                     VULNERABILITY IDENTIFICATION PHASE                        │
└──────────────────────────────────────────────────────────────────────────────┘

    ┌────────────────────────────┐
    │         FINDING            │
    │  CVE-2023-1234 (Critical)  │
    │  SQL Injection in login    │
    └────────────────────────────┘
           │
           │ AFFECTS (nuclei)
           ├──────────────────────┐
           │                      │
           ↓                      ↓
    ┌─────────────┐        ┌──────────────┐
    │  ENDPOINT   │        │     PORT     │ 🔧 NEW
    │ (httpx)     │        │ (nmap)       │
    └─────────────┘        └──────┬───────┘
                                  │
                                  ↓
                           ┌──────────────┐
                           │     HOST     │ 🔧 NEW
                           │ (discovery)  │
                           └──────────────┘
```

## Relationship Type Legend

| Symbol | Meaning |
|--------|---------|
| → | Relationship direction (from → to) |
| ✅ | Previously implemented |
| 🔧 | New in Task 13 |

## Tool Contribution Map

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TOOL CONTRIBUTION MAP                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────────┐
│  Amass/    │   │    Nmap/   │   │   HTTPx    │   │   Nuclei   │   │ Shared │
│ Subfinder  │   │  Masscan   │   │            │   │            │   │ Nodes  │
└────────────┘   └────────────┘   └────────────┘   └────────────┘   └────────┘
     │                │                │                │                │
     │                │                │                │                │
     ↓                ↓                ↓                ↓                ↓

 domain           host            endpoint         finding           host
 subdomain        port            technology                         port
 asn              service         certificate

 dns_record
```

## Attack Chain Scenarios

### Scenario 1: Web Application Attack Chain

```
START: Domain Discovery
  ↓
  domain:example.com
  ↓ [HAS_SUBDOMAIN]
  subdomain:api.example.com
  ↓ [RESOLVES_TO]
  host:192.168.1.100
  ↓ [HAS_PORT]
  port:192.168.1.100:443:tcp
  ↓ [RUNS_SERVICE]
  service:192.168.1.100:443:https (nginx 1.21.0)
  ↓ [HAS_ENDPOINT] 🔧 NEW
  endpoint:https://api.example.com/login
  ↓ [AFFECTS]
  finding:CVE-2023-1234:https://api.example.com/login
  ↓
END: Exploitable Vulnerability Identified

PIVOTS ENABLED:
  • finding → [AFFECTS] → port 🔧 NEW
  • finding → [AFFECTS] → host 🔧 NEW
  • endpoint → [HOSTED_ON] → host 🔧 NEW
  • host → [HOSTED_BY] → asn
```

### Scenario 2: Infrastructure Attribution Chain

```
START: Vulnerability Discovery
  ↓
  finding:CVE-2023-1234:https://api.example.com/login
  ↓ [AFFECTS] 🔧 NEW
  host:192.168.1.100
  ↓ [HOSTED_BY]
  asn:15169 (Google LLC)
  ↓
END: Infrastructure Owner Identified

QUERY: "All vulnerabilities in AS15169"
REVERSE CHAIN:
  asn:15169
  ↑ [HOSTED_BY]
  host:192.168.1.100
  ↑ [AFFECTS] 🔧 NEW
  finding:* (all findings affecting this host)
```

### Scenario 3: Service-Level Vulnerability Chain

```
START: Service Discovery
  ↓
  port:192.168.1.100:443:tcp
  ↓ [RUNS_SERVICE]
  service:192.168.1.100:443:https (nginx 1.21.0)
  ↑ [AFFECTS] (via port) 🔧 NEW
  finding:nginx-version-disclosure
  ↓
END: Service-Specific Vulnerability

CROSS-REFERENCE:
  port:192.168.1.100:443:tcp
  ↓ [HAS_ENDPOINT] 🔧 NEW
  endpoint:https://api.example.com/
  ↑ [AFFECTS]
  finding:CVE-2023-1234 (different vulnerability, same target)
```

### Scenario 4: Technology Stack Attack Chain

```
START: Endpoint Discovery
  ↓
  endpoint:https://api.example.com/
  ↓ [USES_TECHNOLOGY]
  technology:nginx
  technology:php
  technology:mysql
  ↑ [AFFECTS] (via endpoint)
  finding:php-info-disclosure
  finding:mysql-version-disclosure
  ↓
END: Technology-Specific Vulnerabilities

CORRELATION:
  All endpoints using "nginx" with critical findings
  ↓
  Remediation: Update nginx across all endpoints
```

## Multi-Tool Correlation Matrix

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     MULTI-TOOL CORRELATION MATRIX                            │
└─────────────────────────────────────────────────────────────────────────────┘

          ┌──────────┬──────────┬──────────┬──────────┬──────────┐
          │ Subfinder│  Amass   │   Nmap   │  HTTPx   │  Nuclei  │
┌─────────┼──────────┼──────────┼──────────┼──────────┼──────────┤
│Subfinder│    -     │  domain  │   host   │    -     │    -     │
│         │          │subdomain │          │          │          │
├─────────┼──────────┼──────────┼──────────┼──────────┼──────────┤
│ Amass   │  domain  │    -     │   host   │    -     │    -     │
│         │subdomain │          │   asn    │          │          │
├─────────┼──────────┼──────────┼──────────┼──────────┼──────────┤
│ Nmap    │   host   │   host   │    -     │   port   │   port   │
│         │          │   asn    │          │  host🔧  │  host🔧  │
├─────────┼──────────┼──────────┼──────────┼──────────┼──────────┤
│ HTTPx   │    -     │    -     │   port🔧 │    -     │ endpoint │
│         │          │          │  host🔧  │          │          │
├─────────┼──────────┼──────────┼──────────┼──────────┼──────────┤
│ Nuclei  │    -     │    -     │   port🔧 │ endpoint │    -     │
│         │          │          │  host🔧  │          │          │
└─────────┴──────────┴──────────┴──────────┴──────────┴──────────┘

Legend:
  - No direct relationship
  🔧 New relationship added in Task 13
  Other cells: Shared node types or existing relationships
```

## Query Pattern Examples

### Pattern 1: Full Forward Chain (Discovery → Vulnerability)

```cypher
// Start from a domain, traverse to all vulnerabilities
MATCH path = (d:domain {name: "example.com"})
            -[:HAS_SUBDOMAIN*0..1]->(s:subdomain)
            -[:RESOLVES_TO]->(h:host)
            -[:HAS_PORT]->(p:port)
            -[:HAS_ENDPOINT]->(e:endpoint)      // 🔧 NEW
            <-[:AFFECTS]-(f:finding)
WHERE f.severity IN ["critical", "high"]
RETURN path
ORDER BY f.cvss_score DESC
```

### Pattern 2: Backward Chain (Vulnerability → Infrastructure)

```cypher
// Start from critical findings, trace back to infrastructure
MATCH path = (f:finding {severity: "critical"})
            -[:AFFECTS]->(target)               // endpoint, port, or host
            <-[:HAS_PORT]-(h:host)
            -[:HOSTED_BY]->(asn:asn)
RETURN path, asn.description, count(f) as vuln_count
```

### Pattern 3: Lateral Movement (Service → All Affected)

```cypher
// Find all instances of a vulnerable service
MATCH (s:service {product: "nginx", version: "1.21.0"})
      <-[:RUNS_SERVICE]-(p:port)
      <-[:AFFECTS]-(f:finding)              // 🔧 NEW relationship
RETURN s, p, f
```

### Pattern 4: Technology Correlation

```cypher
// Find all endpoints using a technology with vulnerabilities
MATCH (e:endpoint)-[:USES_TECHNOLOGY]->(t:technology {name: "nginx"})
WHERE exists((e)<-[:AFFECTS]-(:finding))
OPTIONAL MATCH (e)-[:HOSTED_ON]->(h:host)   // 🔧 NEW
RETURN e.url, h.ip, [(e)<-[:AFFECTS]-(f:finding) | f.severity] as severities
```

### Pattern 5: ASN-Level Risk Assessment

```cypher
// Aggregate all risks by ASN
MATCH (asn:asn)<-[:HOSTED_BY]-(h:host)
      <-[:AFFECTS]-(f:finding)              // 🔧 NEW
RETURN asn.number,
       asn.description,
       count(DISTINCT h) as affected_hosts,
       count(f) as total_findings,
       collect(DISTINCT f.severity) as severities
ORDER BY total_findings DESC
```

## Node Relationship Density

```
HIGH CONNECTIVITY (Hub Nodes):
  ┌──────────────────────────────────────┐
  │           HOST NODE                  │
  │  • 6 relationship types              │
  │  • Connected by 4 different tools    │
  │  • Central to attack chain           │
  └──────────────────────────────────────┘
       ↑ RESOLVES_TO (subfinder)
       ↑ DISCOVERED (amass/nmap/masscan)
       ↑ HOSTED_ON (httpx) 🔧 NEW
       ↑ AFFECTS (nuclei) 🔧 NEW
       → HAS_PORT (nmap/masscan)
       → HOSTED_BY (amass)

MEDIUM CONNECTIVITY:
  ┌──────────────────────────────────────┐
  │           PORT NODE                  │
  │  • 4 relationship types              │
  │  • Connected by 3 different tools    │
  └──────────────────────────────────────┘
       ↑ HAS_PORT (from host)
       ↑ AFFECTS (nuclei) 🔧 NEW
       → RUNS_SERVICE (nmap)
       → HAS_ENDPOINT (httpx) 🔧 NEW

  ┌──────────────────────────────────────┐
  │         ENDPOINT NODE                │
  │  • 5 relationship types              │
  │  • Connected by 2 different tools    │
  └──────────────────────────────────────┘
       ↑ HAS_ENDPOINT (from port) 🔧 NEW
       ↑ AFFECTS (from finding)
       → USES_TECHNOLOGY (httpx)
       → SERVES_CERTIFICATE (httpx)
       → HOSTED_ON (httpx) 🔧 NEW

LOW CONNECTIVITY (Leaf Nodes):
  • TECHNOLOGY (1 relationship)
  • CERTIFICATE (1 relationship)
  • SERVICE (1 relationship)
  • ASN (1 relationship)
  • FINDING (3 relationships)
```

## Performance Considerations

### Optimal Query Paths

1. **Best Performance** (using indexes):
   ```
   domain → subdomain → host → port → endpoint → finding
   ```

2. **Good Performance** (hub node traversal):
   ```
   host → [port, subdomain, asn, finding]
   ```

3. **Requires Optimization** (multiple hops):
   ```
   technology → endpoint → port → service → port → host → asn
   ```

### Recommended Indexes

```cypher
// Primary node indexes
CREATE INDEX ON :domain(name)
CREATE INDEX ON :subdomain(name)
CREATE INDEX ON :host(ip)
CREATE INDEX ON :port(number)
CREATE INDEX ON :endpoint(url)
CREATE INDEX ON :finding(severity)
CREATE INDEX ON :finding(template_id)

// Composite indexes for common queries
CREATE INDEX ON :finding(severity, cvss_score)
CREATE INDEX ON :service(product, version)
```

## Summary

### Total Relationships Implemented

| Category | Count | Status |
|----------|-------|--------|
| Domain Relationships | 2 | ✅ Verified |
| Host Relationships | 4 | 2 ✅, 2 🔧 NEW |
| Port Relationships | 3 | 1 ✅, 2 🔧 NEW |
| Endpoint Relationships | 4 | 2 ✅, 2 🔧 NEW |
| Finding Relationships | 4 | 1 ✅, 3 🔧 NEW |
| Service Relationships | 1 | ✅ Verified |
| **TOTAL** | **18** | **10 ✅, 8 🔧** |

### Attack Chain Coverage

- ✅ **Full Forward Chain**: domain → subdomain → host → port → endpoint → finding
- ✅ **Full Backward Chain**: finding → endpoint/port/host → subdomain → domain
- ✅ **Infrastructure Attribution**: host → asn
- ✅ **Service Correlation**: port → service
- ✅ **Technology Mapping**: endpoint → technology
- ✅ **Certificate Tracking**: endpoint → certificate

### Key Achievements

1. **Complete Traversal**: Can traverse from domain discovery to exploitable vulnerabilities
2. **Bi-directional Queries**: Can query forward (discovery) or backward (impact analysis)
3. **Multi-Tool Correlation**: Findings from one tool link to discoveries from others
4. **Infrastructure Attribution**: Can attribute findings to ASNs and organizations
5. **Risk Aggregation**: Can aggregate risks at any level (domain, host, ASN, technology)
