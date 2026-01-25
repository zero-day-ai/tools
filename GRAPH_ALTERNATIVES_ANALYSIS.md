# Gibson Taxonomy-to-Graph Pipeline: Alternatives Analysis

**Date:** 2026-01-23
**Current System:** Custom YAML taxonomy → Code generator (900 LOC) → Proto + Go types (2929 LOC) → Graph storage
**Goal:** Simplify or replace the taxonomy-to-graph pipeline while maintaining schema-first development

---

## Executive Summary

The current Gibson system uses a custom taxonomy YAML format that generates:
1. **Protocol Buffers** definitions (taxonomy.proto)
2. **Go domain types** (domain_generated.go - 2929 lines)
3. **Validators** using CEL (validators_generated.go)
4. **Constants** for node/relationship types

This analysis evaluates 8 alternatives across 4 categories:
- **Schema-First Entity Frameworks** (ent, Prisma-like)
- **Graph Databases with Native Schema** (Neo4j, Dgraph, TypeDB)
- **Multi-Model Databases** (SurrealDB, ArangoDB)
- **Go-Native Graph Libraries** (Cayley)

---

## Current Implementation Analysis

### Strengths
✅ Type-safe Go code generation
✅ Single source of truth (YAML)
✅ CEL validation rules
✅ Protocol Buffer serialization
✅ No external database required (can use in-memory)

### Pain Points
❌ Custom code generator to maintain (900 LOC)
❌ Three-stage build process (YAML → Proto → Go)
❌ 2929 lines of generated boilerplate
❌ Manual relationship validation
❌ No built-in query language
❌ No schema migration tools

### Current Taxonomy Example

```yaml
node_types:
  - name: host
    category: asset
    properties:
      - name: ip
        type: string
        required: true
      - name: os
        type: string
    identifying_properties: [ip]
    validations:
      - rule: "has(self.ip) || has(self.hostname)"
        message: "host requires either ip or hostname"

relationship_types:
  - name: HAS_PORT
    from_types: [host]
    to_types: [port]
    cardinality: one_to_many
```

### Generated Code Pattern

```go
// domain_generated.go (excerpt)
type Host struct {
    proto  *taxonomypb.Host
    parent *NodeRef
}

func NewHost(ip string) *Host {
    return &Host{
        proto: &taxonomypb.Host{Ip: ip},
    }
}

func (n *Host) NodeType() string { return "host" }
func (n *Host) Properties() map[string]any { /* ... */ }
func (n *Host) Validate() error { return validation.ValidateHost(n.proto) }
```

---

## Option 1: ent (entgo.io) - Facebook's Entity Framework

**Category:** Schema-First Entity Framework
**Maturity:** Production (used at Meta, 15k+ GitHub stars)
**Go Support:** Excellent (written in Go)
**Embedded:** Yes (supports SQLite, in-memory)

### Overview

Ent is a code-generation-based entity framework that models database schemas as Go graphs. It provides type-safe APIs, automatic migrations, and graph traversal.

### How It Would Work

**Define Schema (ent/schema/host.go):**
```go
package schema

import (
    "entgo.io/ent"
    "entgo.io/ent/schema/edge"
    "entgo.io/ent/schema/field"
)

type Host struct {
    ent.Schema
}

func (Host) Fields() []ent.Field {
    return []ent.Field{
        field.String("ip").
            NotEmpty().
            Unique(),
        field.String("hostname").
            Optional(),
        field.String("os").
            Optional(),
        field.Enum("state").
            Values("up", "down", "unknown").
            Default("unknown"),
    }
}

func (Host) Edges() []ent.Edge {
    return []ent.Edge{
        edge.To("ports", Port.Type),
        edge.From("discovered_by", AgentRun.Type).
            Ref("discovered_hosts"),
    }
}

// Custom validation
func (Host) Hooks() []ent.Hook {
    return []ent.Hook{
        func(next ent.Mutator) ent.Mutator {
            return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
                hm := m.(*ent.HostMutation)
                ip, ipOK := hm.IP()
                hostname, hostnameOK := hm.Hostname()

                if !ipOK && !hostnameOK {
                    return nil, errors.New("host requires either ip or hostname")
                }
                return next.Mutate(ctx, m)
            })
        },
    }
}
```

**Generated Usage:**
```go
// Ent generates type-safe client code
client, _ := ent.Open("sqlite3", ":memory:")

// Create host
host, err := client.Host.
    Create().
    SetIP("10.0.0.1").
    SetOS("Linux").
    Save(ctx)

// Create related port
port, err := client.Port.
    Create().
    SetNumber(80).
    SetProtocol("tcp").
    SetHost(host).  // Type-safe relationship
    Save(ctx)

// Query with graph traversal
hosts, err := client.Host.
    Query().
    Where(host.StateEQ("up")).
    WithPorts().  // Eager load ports
    All(ctx)

// Complex graph query
findings, err := client.Finding.
    Query().
    Where(finding.SeverityIn("critical", "high")).
    QueryAffects().  // Traverse AFFECTS relationship
        Where(host.HasPortsWith(port.StateEQ("open"))).
    All(ctx)
```

### Comparison to Current System

| Feature | Current | Ent |
|---------|---------|-----|
| **Schema Definition** | YAML | Go code |
| **Type Safety** | Generated Go | Generated Go |
| **Validation** | CEL expressions | Go hooks |
| **Query Language** | Manual | Type-safe builder |
| **Migrations** | Manual | Automatic |
| **Graph Traversal** | Manual | Built-in |
| **Code Generation** | Custom (900 LOC) | Built-in |
| **Relationship Validation** | Manual | Automatic |

### Pros
✅ Eliminates custom code generator
✅ Automatic schema migrations
✅ Type-safe graph traversal
✅ Supports multiple backends (SQLite, Postgres, MySQL)
✅ Active development by Atlas team
✅ Built-in hooks for validation
✅ GraphQL integration available

### Cons
❌ Schema in Go, not YAML (less readable for non-developers)
❌ No CEL-style declarative validation
❌ Opinionated field naming (snake_case in DB)
❌ Steeper learning curve
❌ Less control over generated code structure

### Migration Effort
**Medium (3-4 weeks)**
- Convert 21 node types from YAML to ent schemas
- Implement validation hooks
- Update harness to use ent client
- Test graph traversal queries

### Recommendation
**Strong Candidate** - Best fit if you want to eliminate custom code generation while keeping Go-native type safety. The schema-as-code approach is more maintainable than YAML for developers.

---

## Option 2: TypeDB (formerly Grakn)

**Category:** Knowledge Graph Database
**Maturity:** Production (formerly Grakn, rebranded 2021)
**Go Support:** Limited (no official Go driver mentioned)
**Embedded:** No (requires TypeDB server)

### Overview

TypeDB is a knowledge graph database with a strong type system and declarative schema language (TypeQL). It supports type hierarchies, hyper-relationships, and logic rules.

### How It Would Work

**Define Schema (TypeQL):**
```typeql
define

# Entity types
host sub entity,
    owns ip @key,
    owns hostname,
    owns os,
    owns state,
    plays has-port:host,
    plays discovered:asset;

port sub entity,
    owns number @key,
    owns protocol @key,
    owns state,
    plays has-port:port,
    plays runs-service:port;

service sub entity,
    owns name,
    owns version,
    plays runs-service:service;

# Relation types
has-port sub relation,
    relates host,
    relates port;

runs-service sub relation,
    relates port,
    relates service;

discovered sub relation,
    relates agent-run,
    relates asset;

# Attribute types
ip sub attribute, value string;
hostname sub attribute, value string;
os sub attribute, value string;
state sub attribute, value string;
number sub attribute, value long;
protocol sub attribute, value string;
name sub attribute, value string;
version sub attribute, value string;

# Rules
rule host-must-have-identifier:
    when {
        $h isa host;
        not { $h has ip $ip; };
        not { $h has hostname $hn; };
    } then {
        $h has error "Host must have either IP or hostname";
    };
```

**Usage (TypeQL queries):**
```typeql
# Insert data
insert
    $h isa host, has ip "10.0.0.1", has os "Linux";
    $p isa port, has number 80, has protocol "tcp", has state "open";
    (host: $h, port: $p) isa has-port;

# Query
match
    $h isa host, has ip $ip;
    (host: $h, port: $p) isa has-port;
    $p has number $num, has state "open";
get $ip, $num;

# Graph pattern matching
match
    $f isa finding, has severity "critical";
    (finding: $f, asset: $h) isa affects;
    $h isa host;
    (host: $h, port: $p) isa has-port;
    $p has state "open";
get $f, $h, $p;
```

### Pros
✅ Powerful type system with inheritance
✅ Declarative schema language
✅ Built-in reasoning and rules
✅ Strong relationship modeling
✅ Pattern matching queries

### Cons
❌ No official Go driver (critical blocker)
❌ Requires external server (not embeddable)
❌ Steep learning curve for TypeQL
❌ Smaller community than Neo4j
❌ Enterprise features behind paywall
❌ Operational complexity

### Recommendation
**Not Recommended** - Lack of Go driver and embeddability are dealbreakers for Gibson's architecture. TypeDB is designed for enterprise knowledge graph use cases, not embedded security tool databases.

---

## Option 3: SurrealDB

**Category:** Multi-Model Database
**Maturity:** Beta/Production (v2.0+ stable)
**Go Support:** Excellent (official SDK)
**Embedded:** Yes (in-memory, on-disk, or server mode)

### Overview

SurrealDB is a Rust-based multi-model database supporting documents, graphs, and key-value. It can run embedded in Go applications via the SDK or as a standalone server.

### How It Would Work

**Define Schema (SurrealQL):**
```sql
-- Define tables with schema enforcement
DEFINE TABLE host SCHEMAFULL;
DEFINE FIELD ip ON TABLE host TYPE string ASSERT $value != NONE;
DEFINE FIELD hostname ON TABLE host TYPE option<string>;
DEFINE FIELD os ON TABLE host TYPE option<string>;
DEFINE FIELD state ON TABLE host TYPE string DEFAULT "unknown"
    ASSERT $value IN ["up", "down", "unknown"];
DEFINE INDEX idx_host_ip ON TABLE host COLUMNS ip UNIQUE;

-- Validation rule
DEFINE FIELD ip ON TABLE host TYPE string
    ASSERT $value != NONE OR parent.hostname != NONE;

DEFINE TABLE port SCHEMAFULL;
DEFINE FIELD number ON TABLE port TYPE int ASSERT $value >= 1 AND $value <= 65535;
DEFINE FIELD protocol ON TABLE port TYPE string ASSERT $value IN ["tcp", "udp", "sctp"];
DEFINE FIELD state ON TABLE port TYPE string DEFAULT "unknown";
DEFINE FIELD host ON TABLE port TYPE record<host>;

-- Graph relationships
DEFINE TABLE has_port TYPE RELATION FROM host TO port;
DEFINE TABLE runs_service TYPE RELATION FROM port TO service;
DEFINE TABLE affects TYPE RELATION FROM finding TO host | port | service;
```

**Usage (Go SDK):**
```go
package main

import (
    "github.com/surrealdb/surrealdb.go"
)

func main() {
    // Connect to embedded or server instance
    db, err := surrealdb.New("memory://")  // or "file://data.db" or "ws://localhost:8000/rpc"

    // Use namespace and database
    db.Use("gibson", "mission-123")

    // Create host (type-safe with Go structs)
    type Host struct {
        ID       string `json:"id,omitempty"`
        IP       string `json:"ip"`
        Hostname string `json:"hostname,omitempty"`
        OS       string `json:"os,omitempty"`
        State    string `json:"state"`
    }

    host := Host{
        IP:    "10.0.0.1",
        OS:    "Linux",
        State: "up",
    }

    created, err := surrealdb.Create[Host](db, "host", host)

    // Create port with relationship
    type Port struct {
        ID       string  `json:"id,omitempty"`
        Number   int     `json:"number"`
        Protocol string  `json:"protocol"`
        State    string  `json:"state"`
        Host     string  `json:"host"` // Reference to host ID
    }

    port := Port{
        Number:   80,
        Protocol: "tcp",
        State:    "open",
        Host:     created.ID,
    }

    db.Create("port", port)

    // Graph query (SurrealQL)
    results, err := db.Query(`
        SELECT * FROM host
        WHERE state = 'up'
        FETCH host->has_port->port;
    `, nil)

    // Complex graph traversal
    findings, err := db.Query(`
        SELECT * FROM finding
        WHERE severity IN ['critical', 'high']
        FETCH ->affects->host->has_port->port
        WHERE port.state = 'open';
    `, nil)
}
```

### Pros
✅ Excellent Go SDK with embedded support
✅ Schema-first with flexible schemaless option
✅ SQL-like query language (familiar)
✅ Native graph traversal (->)
✅ Single Rust binary (easy deployment)
✅ Real-time subscriptions via WebSocket
✅ Multi-tenancy (namespace/database isolation)
✅ Can run in-memory for testing

### Cons
❌ Relatively new (maturity concerns)
❌ Schema in SQL, not Go (less type-safe)
❌ Requires Rust runtime (via FFI)
❌ Limited validation compared to CEL
❌ Smaller ecosystem than established databases

### Migration Effort
**Medium (2-3 weeks)**
- Convert YAML to SurrealQL schema
- Integrate Go SDK into harness
- Rewrite queries to SurrealQL
- Test embedded mode performance

### Recommendation
**Strong Candidate** - Best embedded option with native graph support. The SQL-like syntax is approachable, and embedded mode fits Gibson's architecture. However, maturity is a concern for production security tools.

---

## Option 4: Dgraph

**Category:** Native GraphQL Graph Database
**Maturity:** Production (written in Go, 20k+ stars)
**Go Support:** Excellent (native)
**Embedded:** Partial (Badger embedded, but server required for GraphQL)

### Overview

Dgraph is a horizontally scalable graph database written in Go. It provides a GraphQL API and DQL (Dgraph Query Language) for graph operations.

### How It Would Work

**Define Schema (GraphQL):**
```graphql
type Host @dgraph(type: "host") {
    id: ID!
    ip: String! @search(by: [exact]) @id
    hostname: String @search(by: [term])
    os: String
    state: HostState
    ports: [Port] @hasInverse(field: host)
    discoveredBy: [AgentRun] @hasInverse(field: discoveredHosts)
}

enum HostState {
    UP
    DOWN
    UNKNOWN
}

type Port @dgraph(type: "port") {
    id: ID!
    number: Int! @search
    protocol: Protocol!
    state: PortState
    host: Host!
    services: [Service] @hasInverse(field: port)
}

enum Protocol {
    TCP
    UDP
    SCTP
}

type Finding @dgraph(type: "finding") {
    id: ID!
    title: String! @search(by: [fulltext])
    severity: Severity!
    affects: [Asset] @hasInverse(field: findings)
}

union Asset = Host | Port | Service

directive @custom(http: CustomHTTP) on FIELD_DEFINITION
directive @dgraph(type: String, pred: String) on OBJECT | INTERFACE | FIELD_DEFINITION
```

**Usage (DQL):**
```go
package main

import (
    "github.com/dgraph-io/dgo/v230"
    "google.golang.org/grpc"
)

func main() {
    // Connect to Dgraph
    conn, _ := grpc.Dial("localhost:9080", grpc.WithInsecure())
    defer conn.Close()

    client := dgo.NewDgraphClient(api.NewDgraphClient(conn))

    // Mutation (insert)
    mu := &api.Mutation{
        SetJson: []byte(`{
            "dgraph.type": "Host",
            "ip": "10.0.0.1",
            "os": "Linux",
            "state": "UP",
            "ports": [{
                "dgraph.type": "Port",
                "number": 80,
                "protocol": "TCP",
                "state": "OPEN"
            }]
        }`),
        CommitNow: true,
    }
    _, err := client.NewTxn().Mutate(ctx, mu)

    // Query with graph traversal
    query := `{
        hosts(func: eq(state, "UP")) {
            ip
            os
            ports @filter(eq(state, "OPEN")) {
                number
                protocol
                services {
                    name
                    version
                }
            }
        }
    }`

    resp, err := client.NewTxn().Query(ctx, query)
}
```

**GraphQL API:**
```graphql
# Auto-generated from schema
query {
  queryHost(filter: { state: { eq: UP } }) {
    ip
    os
    ports(filter: { state: { eq: OPEN } }) {
      number
      protocol
      services {
        name
        version
      }
    }
  }
}

# Complex graph query
query {
  queryFinding(filter: { severity: { in: [CRITICAL, HIGH] } }) {
    title
    severity
    affects {
      ... on Host {
        ip
        ports(filter: { state: { eq: OPEN } }) {
          number
        }
      }
    }
  }
}
```

### Pros
✅ Native Go implementation
✅ GraphQL schema (familiar to many developers)
✅ Automatic GraphQL API generation
✅ Powerful DQL for complex queries
✅ Horizontal scalability
✅ ACID transactions

### Cons
❌ Requires Dgraph server (not truly embedded)
❌ GraphQL schema less expressive than YAML for validation
❌ Operational complexity (cluster management)
❌ No built-in CEL-style validation
❌ Recent acquisition uncertainty (Istari Digital)

### Migration Effort
**High (4-6 weeks)**
- Convert YAML to GraphQL schema
- Set up Dgraph server/cluster
- Rewrite all queries to DQL/GraphQL
- Operational overhead for deployment

### Recommendation
**Not Recommended** - Requires external server, which contradicts Gibson's goal of being an embedded framework. Better suited for large-scale distributed systems than security tool data storage.

---

## Option 5: Neo4j

**Category:** Property Graph Database
**Maturity:** Industry Standard (20+ years)
**Go Support:** Good (official driver)
**Embedded:** No (requires Neo4j server)

### Overview

Neo4j is the world's leading graph database with Cypher query language. It excels at relationship queries but requires a server.

### How It Would Work

**Define Schema (Cypher):**
```cypher
// Create constraints (schema enforcement)
CREATE CONSTRAINT host_ip IF NOT EXISTS
FOR (h:Host) REQUIRE h.ip IS UNIQUE;

CREATE CONSTRAINT port_composite IF NOT EXISTS
FOR (p:Port) REQUIRE (p.number, p.protocol) IS NODE KEY;

// Property existence constraints
CREATE CONSTRAINT host_identifier IF NOT EXISTS
FOR (h:Host) REQUIRE h.ip IS NOT NULL OR h.hostname IS NOT NULL;

// Enum-like validation via application layer (Neo4j lacks native enums)
```

**Usage (Go Driver):**
```go
package main

import (
    "github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func main() {
    driver, _ := neo4j.NewDriverWithContext(
        "bolt://localhost:7687",
        neo4j.BasicAuth("neo4j", "password", ""),
    )
    defer driver.Close(ctx)

    session := driver.NewSession(ctx, neo4j.SessionConfig{})
    defer session.Close(ctx)

    // Create host and port
    result, err := session.Run(ctx, `
        CREATE (h:Host {ip: $ip, os: $os, state: $state})
        CREATE (p:Port {number: $port, protocol: $protocol, state: 'open'})
        CREATE (h)-[:HAS_PORT]->(p)
        RETURN h, p
    `, map[string]any{
        "ip":       "10.0.0.1",
        "os":       "Linux",
        "state":    "up",
        "port":     80,
        "protocol": "tcp",
    })

    // Complex graph query
    findings, err := session.Run(ctx, `
        MATCH (f:Finding)-[:AFFECTS]->(h:Host)-[:HAS_PORT]->(p:Port)
        WHERE f.severity IN ['critical', 'high']
          AND p.state = 'open'
        RETURN f, h, p
    `, nil)

    // Type-safe result parsing
    for findings.Next(ctx) {
        record := findings.Record()
        finding := neo4j.GetRecordValue[neo4j.Node](record, "f")
        host := neo4j.GetRecordValue[neo4j.Node](record, "h")
        port := neo4j.GetRecordValue[neo4j.Node](record, "p")
    }
}
```

### Pros
✅ Industry-standard graph database
✅ Powerful Cypher query language
✅ Excellent visualization (Neo4j Browser)
✅ Mature ecosystem
✅ Strong ACID guarantees

### Cons
❌ Requires Neo4j server (not embeddable)
❌ No native schema definition (constraints only)
❌ No code generation
❌ No type-safe queries in Go
❌ Enterprise features expensive
❌ Operational overhead

### Recommendation
**Not Recommended** - Excellent for production graph analytics, but the server requirement and lack of embedded mode make it unsuitable for Gibson's use case.

---

## Option 6: ArangoDB

**Category:** Multi-Model Database
**Maturity:** Production (15+ years)
**Go Support:** Excellent (official driver v2)
**Embedded:** No (requires ArangoDB server)

### Overview

ArangoDB is a multi-model database supporting documents, graphs, and key-values with a flexible schema.

### How It Would Work

**Define Schema (AQL + Collections):**
```go
// Create collections with schema validation
db.CreateCollection(ctx, "hosts", &arangodb.CreateCollectionOptions{
    Schema: &arangodb.CollectionSchema{
        Rule: map[string]interface{}{
            "properties": map[string]interface{}{
                "ip": map[string]interface{}{
                    "type": "string",
                },
                "os": map[string]interface{}{
                    "type": "string",
                },
                "state": map[string]interface{}{
                    "type": "string",
                    "enum": []string{"up", "down", "unknown"},
                },
            },
            "required": []string{"ip"},
        },
        Level: "strict",
    },
})

// Create edge collection for relationships
db.CreateCollection(ctx, "has_port", &arangodb.CreateCollectionOptions{
    Type: arangodb.CollectionTypeEdge,
})
```

**Usage (AQL queries):**
```go
query := `
    FOR h IN hosts
        FILTER h.state == 'up'
        FOR p IN 1..1 OUTBOUND h has_port
            FILTER p.state == 'open'
            RETURN {host: h, port: p}
`

cursor, err := db.Query(ctx, query, nil)
```

### Pros
✅ Multi-model flexibility
✅ AQL query language
✅ JSON schema validation
✅ Good Go driver

### Cons
❌ Requires server (not embedded)
❌ Schema validation less powerful than CEL
❌ No code generation
❌ Operational complexity

### Recommendation
**Not Recommended** - Server requirement is a dealbreaker for embedded use.

---

## Option 7: Cayley

**Category:** Go-Native Graph Library
**Maturity:** Stable (Google-inspired, 15k stars)
**Go Support:** Native
**Embedded:** Yes (Bolt/LevelDB/in-memory)

### Overview

Cayley is a pure Go graph database inspired by Google's Knowledge Graph (Freebase). It can run embedded with Bolt or in-memory.

### How It Would Work

**Schema (RDF-based):**
```go
// Cayley uses quads (subject, predicate, object, label)
store, _ := cayley.NewMemoryGraph()

// Add nodes
store.AddQuad(quad.Make(
    "host:10.0.0.1",      // Subject
    "rdf:type",           // Predicate
    "Host",               // Object
    "mission-123",        // Label (context)
))

store.AddQuad(quad.Make("host:10.0.0.1", "ip", "10.0.0.1", "mission-123"))
store.AddQuad(quad.Make("host:10.0.0.1", "os", "Linux", "mission-123"))

// Add relationship
store.AddQuad(quad.Make("host:10.0.0.1", "has_port", "port:80", "mission-123"))
```

**Query (Gizmo JavaScript):**
```javascript
g.V("host:10.0.0.1")
  .Out("has_port")
  .Has("state", "open")
  .All()

// Complex graph query
g.V()
  .Has("rdf:type", "Finding")
  .Has("severity", "critical")
  .Out("affects")
  .Out("has_port")
  .Has("state", "open")
  .All()
```

### Pros
✅ Pure Go (no CGO dependencies)
✅ Embeddable (Bolt backend)
✅ RDF/Linked Data support
✅ Multiple backends

### Cons
❌ No schema definition (schema-less)
❌ No type generation
❌ JavaScript query language (not Go-native)
❌ RDF quad model more complex
❌ Less active development recently
❌ No validation framework

### Recommendation
**Not Recommended** - Lacks schema enforcement and type generation, which are core requirements for Gibson.

---

## Option 8: Hybrid Approach - Enhance Current System

**Category:** Incremental Improvement
**Effort:** Low to Medium

### Proposed Enhancements

Instead of replacing the entire system, enhance the current generator:

1. **Add Query Builder Generation**
```go
// Auto-generate from taxonomy YAML
func (h *Harness) FindOpenPorts() *PortQuery {
    return &PortQuery{
        harness: h,
        filters: []Filter{
            {"state", "=", "open"},
        },
    }
}

// Usage
ports := harness.FindOpenPorts().
    WithHost(host).
    WithProtocol("tcp").
    Execute(ctx)
```

2. **Add Migration Support**
```yaml
# taxonomy/migrations/001_add_hostname.yaml
migration:
  version: "3.0.0"
  from: "2.9.0"
  changes:
    - add_field:
        node_type: host
        field:
          name: hostname
          type: string
          default: null
```

3. **Add Schema Validation CLI**
```bash
gibson taxonomy validate taxonomy/core.yaml
gibson taxonomy diff taxonomy/v2.yaml taxonomy/v3.yaml
gibson taxonomy migrate --from v2 --to v3
```

4. **Improve Generator**
- Use `text/template` for cleaner code generation
- Add custom template support
- Generate GraphQL schema alongside Proto

### Pros
✅ Minimal disruption
✅ Keep full control
✅ Incremental improvements
✅ No new dependencies

### Cons
❌ Still maintain custom generator
❌ No built-in graph traversal
❌ Manual query building

---

## Final Recommendations

### Tier 1: Best Fit for Gibson

**1. ent (entgo.io)** - Primary Recommendation
- Eliminates 900 LOC of custom code generation
- Type-safe graph traversal out of the box
- Automatic migrations
- Production-proven at Meta
- **Action:** Prototype with 3-5 node types to validate

**2. SurrealDB** - Alternative if embedded + SQL syntax preferred
- Best embedded graph database option
- Familiar SQL-like syntax
- Real-time subscriptions
- **Risk:** Maturity concerns for production security tools
- **Action:** Benchmark embedded performance

### Tier 2: Situational

**3. Hybrid Enhancement** - If minimizing change is priority
- Incremental improvements to current system
- Add query builder generation
- Add migration tooling
- **When to use:** If switching costs are too high

### Tier 3: Not Recommended

- **Dgraph:** Requires server (not embedded)
- **Neo4j:** Requires server, expensive
- **TypeDB:** No Go driver
- **ArangoDB:** Requires server
- **Cayley:** No schema/validation

---

## Migration Decision Matrix

| Criteria | Weight | Current | ent | SurrealDB | Hybrid |
|----------|--------|---------|-----|-----------|--------|
| Embedded support | 30% | ✅ | ✅ | ✅ | ✅ |
| Schema-first | 25% | ✅ | ✅ | ⚠️ | ✅ |
| Type safety | 20% | ✅ | ✅ | ⚠️ | ✅ |
| Graph traversal | 15% | ❌ | ✅ | ✅ | ❌ |
| Maintenance burden | 10% | ❌ | ✅ | ✅ | ⚠️ |
| **Total Score** | | **65%** | **95%** | **80%** | **70%** |

**Legend:** ✅ Excellent | ⚠️ Acceptable | ❌ Poor

---

## Next Steps

1. **Prototype with ent** (1 week)
   - Convert Host, Port, Service node types
   - Test graph traversal performance
   - Evaluate developer experience

2. **Performance Benchmark** (3 days)
   - Compare query performance: Current vs ent vs SurrealDB
   - Test with 100k nodes, 500k relationships
   - Measure memory footprint

3. **Decision Checkpoint**
   - Review prototype results
   - Get team feedback on schema-as-code approach
   - Make final architecture decision

4. **Full Migration** (if approved)
   - Convert all 21 node types
   - Update harness integration
   - Migrate existing data (if any)
   - Update documentation

---

## Code Examples: Side-by-Side Comparison

### Creating a Host + Port

**Current (Gibson):**
```go
host := domain.NewHost("10.0.0.1").
    SetOS("Linux").
    SetState("up")

port := domain.NewPort(80, "tcp").
    SetState("open")

// Manual relationship management
harness.StoreNode(ctx, host)
harness.StoreNode(ctx, port)
harness.CreateRelationship(ctx, host.ID(), port.ID(), "HAS_PORT")
```

**With ent:**
```go
host, _ := client.Host.
    Create().
    SetIP("10.0.0.1").
    SetOS("Linux").
    SetState(host.StateUp).
    Save(ctx)

port, _ := client.Port.
    Create().
    SetNumber(80).
    SetProtocol("tcp").
    SetState(port.StateOpen).
    SetHost(host).  // Automatic relationship
    Save(ctx)
```

**With SurrealDB:**
```go
host := Host{IP: "10.0.0.1", OS: "Linux", State: "up"}
createdHost, _ := surrealdb.Create[Host](db, "host", host)

port := Port{Number: 80, Protocol: "tcp", State: "open", Host: createdHost.ID}
db.Create("port", port)

// Relationship created automatically via port.Host field
```

### Querying Critical Findings on Open Ports

**Current (Gibson):**
```go
findings, _ := harness.Query(ctx, `
    MATCH (f:Finding)-[:AFFECTS]->(h:Host)-[:HAS_PORT]->(p:Port)
    WHERE f.severity IN ['critical', 'high'] AND p.state = 'open'
    RETURN f, h, p
`)
// Manual query string, no type safety
```

**With ent:**
```go
findings, _ := client.Finding.
    Query().
    Where(finding.SeverityIn("critical", "high")).
    QueryAffects().
        QueryPorts().
            Where(port.StateEQ(port.StateOpen)).
    All(ctx)
// Type-safe, auto-complete in IDE
```

**With SurrealDB:**
```go
findings, _ := db.Query(`
    SELECT * FROM finding
    WHERE severity IN ['critical', 'high']
    FETCH ->affects->host->has_port->port
    WHERE port.state = 'open'
`, nil)
```

---

## Sources

- [ent (entgo.io) Quick Introduction](https://entgo.io/docs/getting-started/)
- [ent GitHub Repository](https://github.com/ent/ent)
- [TypeDB Official Website](https://typedb.com)
- [TypeDB Documentation](https://www.edgedb.com/docs/intro)
- [SurrealDB Embedded Database Blog](https://surrealdb.com/blog/the-power-of-surrealdb-embedded)
- [SurrealDB Go SDK Documentation](https://surrealdb.com/docs/sdk/golang)
- [Dgraph GitHub Repository](https://github.com/dgraph-io/dgraph)
- [Dgraph Documentation](https://docs.dgraph.io/)
- [Neo4j Go Driver Manual](https://neo4j.com/docs/go-manual/current/)
- [ArangoDB Go Driver](https://docs.arangodb.com/3.12/develop/drivers/go/)
- [Cayley Graph Database](https://cayley.io/)
- [EdgeDB/Gel Graph-Relational Database](https://www.geldata.com)
