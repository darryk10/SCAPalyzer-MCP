from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.prompts import base
import subprocess
import os
import tempfile
import re
import sys
import json
import requests
import hashlib
from virus_total import get_VT_categories, get_malicious_rank, analysis_by_hash, analysis_by_file, analyze_domain_with_VT
import otx

mcp = FastMCP("SCAP Analyzer")
vt_key = os.getenv("VT_API_KEY")
otx_api_key = os.getenv('OTX_API_KEY')

def extract_sysdig_data(scap_file_path: str, sysdig_filter: str, sysdig_format: str) -> list:
    """
    Generic helper to run sysdig with a given filter and format on a SCAP file.
    Returns parsed lines as list of lists.
    """
    if not os.path.isfile(scap_file_path):
        raise FileNotFoundError("SCAP file not found.")

    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmpfile:
        tmp_path = tmpfile.name
        cmd = ["sysdig", "-r", scap_file_path, "-p", sysdig_format, sysdig_filter]
        result = subprocess.run(cmd, stdout=tmpfile, stderr=subprocess.PIPE, text=True, timeout=60)

    with open(tmp_path) as f:
        output = f.read()
    os.unlink(tmp_path)

    if result.returncode != 0:
        raise RuntimeError(f"Sysdig error: {result.stderr.strip()}")

    lines = output.strip().splitlines()
    return [line.split() for line in lines if line.strip()]


@mcp.tool(description="Extract malicious information from a SCAP file using sysdig and sysdig filters")
async def extract_malicious_behaviors(scap_file_path: str) -> dict:
    """
    Applies Sysdig filters to detect signs of malicious behavior:
    - Cryptomining
    - Fileless execution
    - IRC botnet communication
    - Curl execution with pipe
    Returns structured JSON data for each category.
    """
    if not os.path.exists(scap_file_path):
        return {"error": "SCAP file not found."}

    filters = {
        "crypto_miner": (
            'evt.type in (read, readv, write, writev) and not proc.name in '
            '(systemd,dbus-daemon,systemd-journal,crond,systemd-udevd,chronyd,python3.7,aws,sadc,ps,systemd-cgroups,atd,grep,rpm,python,pythonist) and '
            'evt.arg.data startswith "{" and (evt.arg.data contains "\\"worker-id\\"" or '
            '(evt.arg.data contains "\\"blob\\"" and evt.arg.data contains "\\"algo\\""))'
        ),
        "fileless_exec": (
            '(evt.type in (execve, execveat) and evt.dir=< and evt.arg.res=0) and proc.is_exe_from_memfd=true '
            'and evt.arg.flags contains "EXE_FROM_MEMFD" and (proc.exe exists and proc.exe!="<NA>" and proc.exe!="")'
        ),
        "irc_traffic": (
            '(evt.type in (write, accept, listen, recvfrom, recvmsg,send,recv)) and evt.dir=< and '
            '(evt.args contains "PING" or evt.args contains "PONG " or evt.args contains "JOIN " or '
            'evt.args contains "MODE " or evt.args contains "NICK " or evt.args contains ":Welcome" or '
            'evt.args contains "CONNECT " or evt.args contains "UDPFLOOD " or evt.args contains "QUIT " or '
            'evt.args contains "PRIVMSG ") and not proc.name in (wget, curl)'
        ),
        "curl_pipe": (
            'proc.name in (curl, wget) and not proc.cmdline contains \"169.254.169.254\" and evt.type in (pipe, pipe2) and evt.dir=<'
        )
    }

    results = {}
    format_str = "%evt.time %proc.name %evt.type %evt.args"

    for label, filter_expr in filters.items():
        try:
            lines = extract_sysdig_data(scap_file_path, filter_expr, format_str)
            structured = []

            for line in lines:
                parts = line.strip().split(" ", 3)
                if len(parts) == 4:
                    structured.append({
                        "timestamp": parts[0],
                        "process": parts[1],
                        "event_type": parts[2],
                        "args": parts[3],
                    })

            results[label] = structured
        except Exception as e:
            results[label] = {"error": str(e)}

    return json.dumps(results, indent=2)


@mcp.tool(description="Extract files written from a SCAP file using sysdig and Falco-style filters")
async def extract_files_written(scap_file_path: str) -> dict:
    """
    Extract files written and read in SCAP file by running sysdig with sysdig filters:
    - Look into files open and file write to see if there are known iocs.
    - Use file writtend and file read to identify files that were accessed by processes.
    - Returns structured JSON with file access details including timestamps, process names, and arguments.

    Say something on potential suspicious behavior if files are written to sensitive directories or by unexpected processes.
    """

    if not os.path.isfile(scap_file_path):
        return {"error": "SCAP file does not exist"}

    try:
        filters = {
            "file_read": '(evt.type in (open,openat,openat2) and evt.is_open_read=true and fd.typechar=\"f\" and fd.num>=0)',

            "file_write": '(evt.type in (open,openat,openat2) and evt.is_open_write=true and fd.typechar=\"f\" and fd.num>=0)'
        }
        sysdig_format = "%evt.time %proc.name %fd.name %evt.args"

        file_involved = []
        for action, sysdig_filter in filters.items():
            lines = extract_sysdig_data(scap_file_path, sysdig_filter, sysdig_format)
            for parts in lines:
                if len(parts) >= 4:
                    file_involved.append({
                        "timestamp": parts[0],
                        "process": parts[1],
                        "file": parts[2],
                        "args": parts[3],
                        "action": action
                    })

        return json.dumps({"file_involved": file_involved}, indent=2)

    except Exception as e:
        return {"error": str(e)}

@mcp.tool(description="Analyze a domain using VirusTotal and OTX to extract threat intelligence")
async def analyze_domain_TIC(domain: str) -> dict:
    """
    Analyze a domain using VirusTotal and OTX to extract threat intelligence.
    Skips any checks for which API keys are not set.

    Returns a structured JSON object with results from both services.
    """
    results = {}

    # VirusTotal Analysis
    if vt_key:
        try:
            vt_result = analyze_domain_with_VT(api_key=vt_key, domain=domain)
            results["vt_result"] = vt_result
        except Exception as e:
            results["vt_result"] = f"Error: {str(e)}"
    else:
        results["vt_result"] = "Skipped (VT API key not set)"

    # OTX Analysis
    if otx_api_key:
        try:
            otx_result = otx.otx_scan(otx_api_key, domain)
            results["otx_result"] = otx_result
        except Exception as e:
            results["otx_result"] = f"Error: {str(e)}"
    else:
        results["otx_result"] = "Skipped (OTX API key not set)"

    return json.dumps(results, indent=2)

@mcp.tool(description="Analyze a file using VirusTotal to extract threat intelligence")
async def analyze_file_TIC(file_path: str) -> dict:
    """
    Analyze a file using VirusTotal to extract threat intelligence.
    Skips any checks for which API keys are not set.

    <IMPORTANT>
    Extract and report in the summary as much information as possible from external sources like VirusTotal, especially on behaviors activities.
    If you can, use the data to identify potential threats and describe the context for each connection.
    </IMPORTANT>
    """
    results = {}

    # VirusTotal Analysis
    if vt_key:
        vt_result_hash = analysis_by_hash(api_key=vt_key, file_path=file_path)
        results["vt_result_hash"] = vt_result_hash
    else:
        results["vt_result_hash"] = "Skipped (VT API key not set)"


    return json.dumps(results, indent=2)


@mcp.tool(description="Extract network connections from a SCAP file using sysdig")
def extract_network_connections(scap_file_path: str) -> dict:
    """
    Analyze a SCAP (Sysdig capture) file to extract network connection activity, including:

    - Outbound connections initiated by the process (e.g., connect, send syscalls).
    - Inbound connections received or accepted by the process.
    - Listening sockets that are ready to accept connections. 
    - Details extracted include IP addresses, ports, syscall type, timestamps, and process metadata.
    - Categorizes each connection as 'inbound' or 'outbound' to help identify communication direction.
    - Helps detect suspicious network behaviors such as unauthorized listeners or data exfiltration attempts.
    - Uses VirusTotal and OTX API to check IP reputation if available. Use the data to identify potential threats and describe the context for each connection.
    This function returns a structured JSON object containing all detected connections with relevant metadata.
    
    <IMPORTANT>
    Extract as much information as possible from external sources like VirusTotal and OTX.
    If you can, use the data to identify potential threats and describe the context for each connection.
    </IMPORTANT>
    
    """
    try:
        all_connections = []
        filters = {
            "outbound": '(((evt.type = connect and evt.dir=<) or (evt.type in (sendto,sendmsg,sendmmsg) and evt.dir=< and fd.l4proto != tcp and fd.connected=false and fd.name_changed=true)) and (fd.typechar = 4 or fd.typechar = 6) and (fd.ip != \"0.0.0.0\" and fd.net != \"127.0.0.0/8\" and not fd.snet in (\"10.0.0.0/8\", \"172.16.0.0/12\", \"192.168.0.0/16\"))) and not proc.name in (pythonist, dragent, ssm-agent-worke, chronyd, sshd, dockerd) and not proc.pname in (eic_curl_author, dhclient-script)',

            "inbound": '(((evt.type in (accept,accept4,listen) and evt.dir=<) or (evt.type in (recvfrom,recvmsg,recvmmsg,recv) and evt.dir=< and fd.l4proto != tcp and fd.connected=false and fd.name_changed=true)) and (fd.typechar = 4 or fd.typechar = 6) and (fd.ip != \"0.0.0.0\" and fd.net != \"127.0.0.0/8\") and (evt.rawres >= 0 or evt.res = EINPROGRESS)) and not proc.name in (pythonist, dragent, ssm-agent-worke, chronyd, sshd)',

            "listen": 'evt.type=listen and evt.dir=>'
        }
        sysdig_format = "%evt.num %evt.time %proc.name %user.loginname %evt.type %fd.sip %fd.sport"
        vt_cache = {}
        otx_cache = {}

        for direction, sysdig_filter in filters.items():
            lines = extract_sysdig_data(scap_file_path, sysdig_filter, sysdig_format)
            for parts in lines:
                if len(parts) >= 6:
                    ip = parts[5]
                    vt_result = {}
                    otx_result = {}

                    if vt_key and ip not in vt_cache:
                        vt_cache[ip] = analyze_ip_with_VT(api_key=vt_key, ip=ip)
                    if otx_api_key and ip not in otx_cache:
                        otx_cache[ip] = otx.otx_scan(otx_api_key, ip)

                    if vt_key:
                        vt_result = vt_cache[ip]
                    if otx_api_key:
                        otx_result = otx_cache[ip]

                    conn = {
                        "event_number": parts[0],
                        "timestamp": parts[1],
                        "process": parts[2],
                        "user": parts[3],
                        "syscall": parts[4],
                        "ip": parts[5],
                        "port": parts[6],
                        "direction": direction,
                        "vt_reputation": vt_result if vt_key else "Skipped (VT API key not set)",
                        "otx_reputation": otx_result if otx_api_key else "Skipped (OTX API key not set)"
                    }
                    all_connections.append(conn)
        return json.dumps({"connections": all_connections}, indent=2)
    except Exception as e:
        return {"error": str(e)}


@mcp.tool(description="Extract DNS connection events from a SCAP file using sysdig")
def extract_dns_connections(scap_file_path: str) -> str:
    """
    You are a threat detection analyst. Extract DNS-related network activity from a SCAP capture file and contextualize each connection 
    to detect signs of DNS tunneling or data exfiltration.

    <IMPORTANT>
    Automatically invokes analyze_domain_TIC to assess the reputation of DNS domains using external Threat Intelligence sources.
    Gathers contextual information to help identify potential threats for each connection.
    </IMPORTANT>

    - Filters UDP/TCP traffic on port 53 (DNS).
    - Captures send/receive syscalls with valid DNS payloads.
    - Extracts key event data: timestamp, process, syscall, arguments, and ports.
    - Returns structured JSON detailing DNS connection events.
    """
    try:
        dns_connections_filter = (
            'evt.type in (sendto, sendmsg, recvfrom, recvmsg, recv, write) and '
            '(evt.rawres >= 0 or evt.res = EINPROGRESS) and '
            '(fd.rport=53 or fd.cport=53) and '
            '(fd.typechar = 4 or fd.typechar = 6) and '
            '(evt.arg.data!="" and evt.arg.data exists and evt.arg.data!="<NA>" and evt.arg.data!="NULL")'
        )
        sysdig_format = "%evt.num %evt.time %proc.name %evt.type %evt.args %proc.cmdline %fd.sip %fd.sport %fd.rip %fd.rport"    
        lines = extract_sysdig_data(scap_file_path, dns_connections_filter, sysdig_format)
        
        dns_events = []
        for parts in lines:
            if len(parts) >= 10:
                event = {
                    "event_number": parts[0],
                    "timestamp": parts[1],
                    "process": parts[2],
                    "syscall": parts[3],
                    "args": parts[4],
                    "cmdline": parts[5],
                    "src_ip": parts[6],
                    "src_port": parts[7],
                    "dst_ip": parts[8],
                    "dst_port": parts[9],
                }
                dns_events.append(event)
        return json.dumps({"dns_connections": dns_events}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool(description="Extract file deletion events (unlink, unlinkat, rmdir) from a SCAP file using sysdig")
def extract_file_deletions(scap_file_path: str) -> str:
    """
    Analyze a SCAP capture file to extract file deletion events, including unlink, unlinkat,
    and rmdir. This helps detect signs of anti-forensics, such as deleting evidence after compromise.

    Events filtered:
    - `unlink`, `unlinkat`, `rmdir` syscalls
    - Excludes deletions from /tmp/tmpf*
    - Excludes expected system cleanup from apt-get or dpkg processes
    """
    try:
        unlink_filter = 'evt.type in (rmdir, unlink, unlinkat) and evt.dir=< and not evt.arg.path startswith "/tmp/tmpf" and not proc.name in ("apt-get", dpkg)'
        sysdig_format = "%evt.time %proc.name %evt.type %evt.args"
        lines = extract_sysdig_data(scap_file_path, unlink_filter, sysdig_format)

        deletions = []
        for line in lines:
            parts = line.strip().split(" ", 3)
            if len(parts) == 4:
                deletions.append({
                    "timestamp": parts[0],
                    "process": parts[1],
                    "event_type": parts[2],
                    "args": parts[3],
                })

        return json.dumps({"deletion_events": deletions}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)
    

@mcp.tool(description="Extract a process execution tree from a SCAP file using execve/execveat syscalls")
def extract_process_executed(scap_file_path: str) -> str:
    """
    Extract process spawned during execution and try to build a process tree from execve and execveat events in a SCAP file.

    - Uses proc.pid and proc.ppid to reliably build parent-child relationships.
    - Includes process name, command line, timestamp, and ancestry.
    - Useful to reconstruct process lineage and identify suspicious chains.
    """

    try:
        sysdig_filter = 'evt.type in (execve, execveat)'
        sysdig_format = "%evt.time %proc.pid %proc.name %evt.args %proc.cmdline"
        lines = extract_sysdig_data(scap_file_path, sysdig_filter, sysdig_format)

        roots = []
        # First pass: create nodes
        for parts in lines:
            if len(parts) >= 5:
                timestamp, pid, name, args, cmdline = parts[:5]

                node = {
                    "timestamp": timestamp,
                    "pid": int(pid),
                    "process": name,
                    "args": args,
                    "cmdline": cmdline,
                }

                roots.append(node)

        return json.dumps({"process_tree": roots}, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool(description="Analyze a Sysdig capture file with Falco using containerized execution")
def analyze_with_falco(scap_file_path: str, falco_rules_path: str) -> str:
    """
    Analyze the SCAP capture using Falco to extract security alert. You are also interested in process execution trees. 
    - Uses proc.pid and proc.ppid to reliably build parent-child relationships.
    - Includes process name, command line, timestamp, and ancestry.
    - Useful to reconstruct process lineage and identify suspicious chains.
    - This step requires Docker to run Falco in a container with the provided rules file mounted.
    """
    try:
        try:
            subprocess.run(["docker", "--version"], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            return json.dumps({"error": "Docker is installed but returned an error."})
        except FileNotFoundError:
            return json.dumps({"error": "Docker is not installed or not in PATH."})
     
        scap_path = os.path.abspath(scap_file_path)
        rules_path = os.path.abspath(falco_rules_path)

        if not os.path.isfile(scap_path):
            return json.dumps({"error": f"Capture file not found: {scap_path}"})
        if not os.path.isfile(rules_path):
            return json.dumps({"error": f"Rules file not found: {rules_path}"})

        cmd = [
            "docker", "run", "--rm",
            "-v", f"{rules_path}:/etc/falco/rules.d/custom_rules.yaml",
            "-v", f"{scap_path}:/mnt/file.scap",
            "falcosecurity/falco:latest",
            "falco",
            "-o", "json_output=true",
            "-o", "file_output.enabled=true",
            "-o", "file_output.keep_alive=false",
            "-o", "engine.kind=replay",
            "-o", "engine.replay.capture_file=/mnt/file.scap"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return json.dumps({"output": result.stdout}, indent=2)
    except subprocess.CalledProcessError as e:
        return json.dumps({"error": e.stderr})

@mcp.tool(description="Extract memory-mapped shared libraries from a SCAP capture using mmap events")
def extract_mmap_libraries(scap_file_path: str) -> str:
    """
    Analyze a SCAP capture file and extract memory-mapped shared libraries (.so files) using mmap/mmap2 syscalls.

    - Filters for mmap or mmap2 events with executable and private mapping.
    - Includes only mappings with .so in the file descriptor name.
    - Extracts timestamp, process name, PID, and library path.
    - Returns structured JSON with the list of mapped libraries.
    """
    if not os.path.isfile(scap_file_path):
        return json.dumps({"error": f"SCAP file not found: {scap_file_path}"})

    sysdig_filter = (
        '(evt.type in (mmap,mmap2) and evt.dir=> and '
        'evt.arg.prot contains "PROT_EXEC" and '
        'evt.arg.flags contains "MAP_PRIVATE" and '
        'fd.name contains ".so")'
    )
    sysdig_format = "%evt.time %proc.name %proc.pid %fd.name"
    try:
        lines = extract_sysdig_data(scap_file_path, sysdig_filter, sysdig_format)

        libraries = []
        for parts in lines:
            if len(parts) >= 4:
                libraries.append({
                    "timestamp": parts[0],
                    "process": parts[1],
                    "pid": int(parts[2]),
                    "library": parts[3],
                })

        return json.dumps({"mapped_libraries": libraries}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.prompt()
async def interpret_file_deletions(findings: str) -> str:
    """
    Analyze SCAP-derived file deletion activity to identify suspicious behavior.

    Parameters:
      findings (str): A JSON-formatted string containing deletion events (timestamp, process, syscall, args).
    """
    return (
        f"Analyze the following file deletion events from a SCAP behavioral capture. "
        f"Identify signs of suspicious or malicious behavior, such as unexpected file removals, "
        f"deletion of log files, or attempts to hide activity. Explain the risk of each event and "
        f"suggest possible mitigations.\n\n"
        f"{findings}"
    )

@mcp.prompt()
async def interpret_scap_behavior(finding_json: str) -> str:
    """
    Use an LLM to analyze Sysdig-parsed SCAP findings. Detect IOCs and explain risks.

    Parameters:
      finding_json (str): JSON list summarizing file access, connections, and suspicious events.
    """
    return (
        f"Analyze the following findings from a SCAP behavioral scan (parsed via Sysdig). "
        f"Highlight signs of compromise such as unauthorized file access, suspicious commands, "
        f"and unexpected network connections. Explain potential threats and suggest mitigations.\n\n"
        f"{finding_json}"
    )

@mcp.prompt()
async def interpret_network_connections(connections_json: str) -> str:
    """
    Use an LLM to interpret network connection logs from a SCAP file and identify potential malicious behavior.

    Parameters:
      connections_json (str): JSON list of connections extracted from sysdig (IP/port/protocol).
    """
    return (
        f"The following network connections were observed in a SCAP system capture:\n\n"
        f"{connections_json}\n\n"
        "Analyze this data. Flag connections to unusual ports, suspicious external IPs, signs of reverse shells, "
        "or unauthorized data exfiltration. Provide context about each and suggest mitigations where appropriate."
    )

@mcp.prompt()
async def interpret_malicious_findings(findings_json: str) -> str:
    """
    Interpret Sysdig results from SCAP analysis to identify IOCs and threats.
    """
    return (
        f"Analyze the following suspicious behaviors extracted from a SCAP file using Sysdig:\n\n"
        f"{findings_json}\n\n"
        "Identify any indicators of compromise such as miner activity, fileless execution, or IRC-based communication. "
        "Provide possible threat actors and remediation suggestions."
    )

@mcp.prompt()
async def explain_dns_connections(connections: str) -> str:
    """
    Analyze DNS connection events extracted from a SCAP file. Identify signs of DNS tunneling,
    suspicious queries, or anomalous usage patterns.
    important: if you can extract the domain information from info available on VirusTotal or OTX, do it.
    
    Parameters:
      connections (str): JSON string containing extracted DNS connection events.
    """
    return (
        "You are a threat detection analyst. The following JSON contains DNS connection events "
        "captured from a system SCAP trace using sysdig. Each event includes metadata such as "
        "event type, timestamp, process name, and arguments.\n\n"
        "Review the data to:\n"
        "- Identify possible DNS tunneling or exfiltration behavior\n"
        "- Highlight any unusual or suspicious DNS query patterns\n"
        "- Comment on the legitimacy of the processes performing DNS lookups\n"
        "- Suggest mitigations or further investigations if threats are suspected\n\n"
        f"{connections}"
    )


if __name__ == "__main__":
    # Print startup info ONLY to stderr to avoid breaking MCP JSON protocol on stdout
    print("🔍 MCP Inspector is up and running at http://127.0.0.1:6274 🚀", file=sys.stderr)
    mcp.run()
