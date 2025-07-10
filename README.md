# SCAPalyzer-MCP

[![smithery badge](https://smithery.ai/badge/@darryk10/scapalyzer-mcp)](https://smithery.ai/server/@darryk10/scapalyzer-mcp)

## Overview

**SCAPalyzer-MCP** is a Model Context Protocol (MCP) server for automated behavioral analysis of Sysdig capture (SCAP) files. It integrates threat intelligence from VirusTotal and OTX, and exposes a suite of tools for extracting, analyzing, and interpreting security-relevant events from system captures. The server is designed for security analysts, incident responders, and researchers who need to automate the detection of suspicious or malicious activity in system traces.

---

## Features

- **Behavioral Extraction:** Detects cryptomining, fileless execution, botnet activity, suspicious file and network operations, and more from SCAP files.
- **Threat Intelligence Enrichment:** Integrates with VirusTotal and OTX to provide context and reputation for files, domains, and IPs.
- **Falco Integration:** Runs Falco in Docker to extract security alerts from SCAP files using custom rules.
- **LLM-Powered Interpretation:** Uses language models to interpret findings, highlight risks, and suggest mitigations.

---

## Requirements

- Python 3.7+
- [sysdig](https://github.com/draios/sysdig) (for SCAP parsing)
- [Docker](https://www.docker.com/) (for Falco integration)
- VirusTotal and OTX API keys (for threat intelligence enrichment)
- Python dependencies: `mcp`, `requests`, `otx`, and others (see `requirements.txt`)

### Environment Variables

- `VT_API_KEY`: Your VirusTotal API key
- `OTX_API_KEY`: Your AlienVault OTX API key

---

## Installation

### Installing via Smithery

To install SCAPalyzer for Claude Desktop automatically via [Smithery](https://smithery.ai/server/@darryk10/scapalyzer-mcp):

```bash
npx -y @smithery/cli install @darryk10/scapalyzer-mcp --client claude
```

1. **Clone the repository:**
   ```bash
   git clone https://github.com/darryk10/SCAPalyzer-MCP.git
   cd SCAPalyzer-MCP
   ```

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install sysdig:**
   - On Ubuntu: `sudo apt-get install -y sysdig`
   - On macOS: `brew install sysdig`

4. **Install Docker:**  
   [Get Docker](https://docs.docker.com/get-docker/)

5. **Set API keys:**
   ```bash
   export VT_API_KEY=your_virustotal_key
   export OTX_API_KEY=your_otx_key
   ```

---

## Usage

Start the MCP server:
```bash
python server.py
```
The server will start and listen for MCP requests.

You can interact with the tools via an MCP client or HTTP API, depending on your integration.

---

## Method Reference

### Behavioral Extraction Tools

#### `extract_malicious_behaviors(scap_file_path: str) -> dict`
Detects:
- Cryptomining
- Fileless execution
- IRC botnet communication
- Suspicious curl/wget usage

**Returns:** Structured JSON with findings for each category.

---

#### `extract_files_written(scap_file_path: str) -> dict`
Extracts files read/written by processes, flags suspicious file access.

**Returns:** JSON with file access details (timestamp, process, file, args, action).

---

#### `extract_network_connections(scap_file_path: str) -> dict`
Extracts inbound/outbound/listening network connections, checks IP reputation with VirusTotal/OTX.

**Returns:** JSON with connection metadata and threat intelligence.

---

#### `extract_dns_connections(scap_file_path: str) -> dict`
Extracts DNS-related events, invokes threat intelligence checks on domains.

**Returns:** JSON with DNS connection events.

---

#### `extract_file_deletions(scap_file_path: str) -> dict`
Extracts file deletion events (unlink, rmdir), flags anti-forensics.

**Returns:** JSON with deletion event details.

---

#### `extract_process_executed(scap_file_path: str) -> dict`
Builds a process execution tree from execve/execveat events.

**Returns:** JSON with process lineage.

---

#### `extract_mmap_libraries(scap_file_path: str) -> dict`
Extracts memory-mapped shared libraries (.so files) from mmap events.

**Returns:** JSON with mapped library details.

---

### Threat Intelligence Tools

#### `analyze_domain_TIC(domain: str) -> dict`
Analyzes a domain with VirusTotal and OTX.

**Returns:** JSON with threat intelligence results.

---

#### `analyze_file_TIC(file_path: str) -> dict`
Analyzes a file with VirusTotal.

**Returns:** JSON with threat intelligence results.

---

### Falco Integration

#### `analyze_with_falco(scap_file_path: str, falco_rules_path: str) -> dict`
Runs Falco in Docker on a SCAP file with custom rules, extracts security alerts.

**Returns:** JSON with Falco output.

---

### LLM-Powered Prompts

#### `interpret_file_deletions(findings: str) -> str`
Interprets file deletion events for suspicious behavior.

#### `interpret_scap_behavior(finding_json: str) -> str`
Interprets general SCAP findings for IOCs and risks.

#### `interpret_network_connections(connections_json: str) -> str`
Interprets network connection logs for malicious activity.

#### `interpret_malicious_findings(findings_json: str) -> str`
Interprets suspicious behaviors for IOCs and threats.

#### `explain_dns_connections(connections: str) -> str`
Interprets DNS connection events for tunneling/exfiltration.

---

## Example

```python
# Example: Extract malicious behaviors from a SCAP file
result = extract_malicious_behaviors("/path/to/capture.scap")
print(result)
```

---

## Credits

- Built on [MCP](https://github.com/modelcontextprotocol/mcp)
- Uses [Sysdig](https://github.com/draios/sysdig) and [Falco](https://falco.org/)
- Integrates [VirusTotal](https://www.virustotal.com/) and [AlienVault OTX](https://otx.alienvault.com/)

---

## License

See [LICENSE](LICENSE) for details.
