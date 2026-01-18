# Gibson Tools Ecosystem

The Gibson Tools Ecosystem provides AI-automation-ready security tools with embedded GraphRAG taxonomy for knowledge graph integration. Each tool outputs structured JSON with taxonomy mappings that enable automatic knowledge graph population.

[![Go Version](https://img.shields.io/badge/go-1.24.4-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Current Tools

All tools include embedded GraphRAG taxonomy using `schema.TaxonomyMapping` for automatic knowledge graph integration.

### Reconnaissance (TA0043)

| Tool | Description | Node Types |
|------|-------------|------------|
| **subfinder** | Fast passive subdomain enumeration | domain, subdomain |
| **httpx** | HTTP toolkit for probing web services | endpoint, technology |
| **amass** | In-depth attack surface mapping | domain, subdomain, host, asn, dns_record |
| **nuclei** | Template-based vulnerability scanner | finding |

### Discovery (TA0007)

| Tool | Description | Node Types |
|------|-------------|------------|
| **nmap** | Network exploration and port scanning | host, port |
| **masscan** | Fast TCP port scanner | host, port |

## Installation

```bash
# Clone the repository
git clone https://github.com/zero-day-ai/tools.git
cd tools

# Build all tools
make build

# Tools are built to bin/
ls bin/
```

## Usage

Each tool supports the `--schema` flag to output its JSON schema with embedded taxonomy:

```bash
# View tool schema with taxonomy
./bin/nmap --schema

# Run tool with JSON input
echo '{"targets": "192.168.1.0/24", "ports": "22,80,443"}' | ./bin/nmap

# Run tool with specific input
./bin/subfinder --input '{"domain": "example.com"}'
```

## GraphRAG Taxonomy

Each tool embeds taxonomy mappings in its schema. When Gibson executes a tool with `--schema`, it extracts these mappings to understand how to populate the knowledge graph.

Example taxonomy from nmap's schema:

```json
{
  "taxonomy": {
    "node_type": "host",
    "id_template": "host:{.ip}",
    "properties": [
      {"source": "ip", "target": "ip"},
      {"source": "hostname", "target": "hostname"}
    ],
    "relationships": [
      {
        "type": "DISCOVERED",
        "from_template": "agent_run:{_context.agent_run_id}",
        "to_template": "host:{.ip}"
      }
    ]
  }
}
```

## Development

### Building

```bash
make build          # Build all tools
make build-recon    # Build reconnaissance tools only
make build-discovery # Build discovery tools only
make test           # Run tests
make clean          # Clean build artifacts
```

### Adding a New Tool

New tools must include embedded GraphRAG taxonomy. See the SDK documentation at `~/Code/zero-day.ai/opensource/sdk/docs/TOOLS.md` for the complete tool development guide.

## Requirements

- Go 1.24.4+
- Underlying tools must be installed on the host system (nmap, masscan, subfinder, httpx, amass, nuclei)

## License

MIT License - see LICENSE file for details.
