# Nmap Network Scanner Tool

Gibson SDK tool wrapper for the Nmap network scanner.

## Overview

This tool provides a structured interface to Nmap for network scanning, port discovery, service detection, and OS fingerprinting. It wraps the nmap binary and returns structured JSON output parsed from nmap's XML format.

## MITRE ATT&CK Techniques

- **T1046**: Network Service Scanning
- **T1595.001**: Scanning IP Blocks
- **T1592.002**: Gather Victim Host Information: Software

## Requirements

- **nmap** binary must be installed and available in PATH
- For SYN scans (-sS), nmap requires either:
  - CAP_NET_RAW capability: `sudo setcap cap_net_raw+eip /usr/bin/nmap`
  - Root privileges

## Input Parameters

### Required
- `targets` (string): IP address, CIDR range, or hostname to scan

### Optional
- `ports` (string): Port specification (e.g., "22,80,443" or "1-1000")
- `scan_type` (enum): Scan type - syn, connect, udp, ack, fin, xmas, null (default: syn)
- `timing` (enum): Timing template - paranoid, sneaky, polite, normal, aggressive, insane (default: normal)
- `service_detection` (bool): Enable service/version detection (-sV)
- `os_detection` (bool): Enable OS detection (-O)
- `script_scan` (bool): Enable default NSE scripts (-sC)
- `scripts` (array): Specific NSE scripts to run
- `script_args` (object): Arguments for NSE scripts
- `aggressive` (bool): Enable aggressive scan (-A)
- `ping_scan` (bool): Ping scan only (-sn)
- `no_ping` (bool): Skip host discovery (-Pn)
- `top_ports` (int): Scan top N most common ports
- `exclude_hosts` (string): Hosts to exclude from scan
- `interface` (string): Network interface to use
- `source_port` (int): Source port for scans
- `max_retries` (int): Maximum retries for port scanning
- `host_timeout` (string): Timeout per host
- `min_rate` (int): Minimum packets per second
- `max_rate` (int): Maximum packets per second

## Output Structure

```json
{
  "scan_info": {
    "scanner": "nmap",
    "args": "nmap -oX - -sT -T4 -p 22,80,443 192.168.1.1",
    "start_time": "Mon Dec 29 17:52:44 2025",
    "end_time": "Mon Dec 29 17:52:44 2025",
    "elapsed_seconds": 0.03
  },
  "hosts": [
    {
      "ip": "192.168.1.1",
      "hostnames": ["router.local"],
      "status": "up",
      "ports": [
        {
          "port": 22,
          "protocol": "tcp",
          "state": "open",
          "service": {
            "name": "ssh",
            "product": "OpenSSH",
            "version": "8.2p1",
            "extrainfo": "Ubuntu",
            "cpe": ["cpe:/o:linux:linux_kernel"]
          },
          "scripts": [
            {
              "id": "ssh-hostkey",
              "output": "..."
            }
          ]
        }
      ],
      "os": {
        "name": "Linux 5.4",
        "accuracy": 95,
        "family": "Linux",
        "vendor": "Linux"
      },
      "uptime": {
        "seconds": 3600,
        "lastboot": "Mon Dec 29 16:52:44 2025"
      },
      "distance": 1,
      "mac_address": "00:11:22:33:44:55",
      "vendor": "Vendor Name"
    }
  ],
  "run_stats": {
    "hosts_up": 1,
    "hosts_down": 0,
    "hosts_total": 1
  },
  "warnings": [],
  "scan_time_ms": 50
}
```

## Usage Examples

### Basic Port Scan
```json
{
  "targets": "192.168.1.1",
  "ports": "22,80,443,8080"
}
```

### Service Version Detection
```json
{
  "targets": "192.168.1.0/24",
  "ports": "1-1000",
  "scan_type": "syn",
  "service_detection": true,
  "timing": "aggressive"
}
```

### OS Detection with NSE Scripts
```json
{
  "targets": "10.0.0.0/8",
  "top_ports": 100,
  "os_detection": true,
  "script_scan": true,
  "timing": "polite"
}
```

### Stealth Scan with Custom Scripts
```json
{
  "targets": "target.example.com",
  "ports": "1-65535",
  "scan_type": "syn",
  "scripts": ["http-title", "ssl-cert", "ssh-hostkey"],
  "timing": "sneaky",
  "max_rate": 100
}
```

## Health Check

The tool performs the following health checks:

1. Verifies nmap binary exists in PATH
2. Checks for CAP_NET_RAW capability (for SYN scans)
3. Falls back to checking if running as root

Health status will be:
- **healthy**: nmap is available with required capabilities
- **degraded**: nmap is available but lacks CAP_NET_RAW (SYN scans may fail)
- **unhealthy**: nmap binary not found

## Building

```bash
cd discovery/nmap
go build -o nmap-tool .
```

## Notes

- Uses `-oX -` to output XML to stdout
- Parses all nmap XML elements including hosts, ports, services, OS detection, and NSE scripts
- Supports all major nmap scan types and options
- Default timeout is 5 minutes
- Connect scans (-sT) don't require special privileges
- SYN scans (-sS) are faster but require CAP_NET_RAW or root
