#!/usr/bin/env python3
"""
WSAAF-NG: Windows Security Self-Audit Framework (Next Generation)
HTML-Only Version: Processes, Sigcheck, Filtered Network Connections,
Autoruns (-ms), AV/Firewall Status, and Clean Filters
"""

import os
import sys
import csv
import io
import ctypes
import logging
import subprocess
from datetime import datetime
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
from pathlib import Path

try:
    import psutil
except ImportError:
    sys.exit("[FATAL] Required dependency 'psutil' is not installed. Install via: pip install psutil")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("WSAAF-NG")

SYSINTERNALS_DIR = r"C:\Tools\SysinternalsSuite"
SUBPROCESS_TIMEOUT = 120
EXCLUDED_IPS = {"127.0.0.1", "0.0.0.0", "192.168.1.9"}

# ============================================================================
# SIMPLIFIED ENUMS & MODELS
# ============================================================================

class SignatureStatus:
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    UNKNOWN = "UNKNOWN"

class Severity:
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

@dataclass
class ProcessRecord:
    pid: int
    ppid: int
    name: str
    path: str
    cmdline: str
    user: str
    create_time: str
    parent_name: str
    signature_status: str = SignatureStatus.UNKNOWN
    signer: str = "N/A"
    sha256: str = "N/A"
    risk_score: int = 0

@dataclass
class PersistenceRecord:
    location: str
    entry: str
    image_path: str
    launch_string: str
    category: str
    publisher: str
    signature_status: str = SignatureStatus.UNKNOWN
    risk_score: int = 0

@dataclass
class NetworkRecord:
    protocol: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    pid: int
    process_name: str
    signature_status: str = SignatureStatus.UNKNOWN

@dataclass
class Finding:
    finding_id: str
    rule_id: str
    severity: str
    risk_score: int
    entity: str
    evidence: List[str]
    reasons: List[str]
    recommendation: str

@dataclass
class SystemMetadata:
    audit_time: str
    hostname: str
    os_version: str
    is_admin: bool
    sysinternals_dir: str
    tools_available: Dict[str, str]
    av_status: str = "Unknown"
    firewall_status: str = "Unknown"

# ============================================================================
# SYSINTERNALS EXECUTION LAYER
# ============================================================================

class SysinternalsManager:
    def __init__(self, base_dir: str = SYSINTERNALS_DIR):
        self.base_dir = Path(base_dir)
        self.discovered_tools: Dict[str, Optional[str]] = {}
        self._discover_tools()

    def _discover_tools(self):
        tool_names = ["sigcheck", "autorunsc", "tcpvcon"]
        for tool in tool_names:
            resolved = self.find_tool(tool)
            self.discovered_tools[tool] = resolved
            if resolved:
                logger.info(f"Discovered '{tool}' -> {resolved}")
            else:
                logger.warning(f"Tool '{tool}' NOT found in {self.base_dir}")

    def find_tool(self, name: str) -> Optional[str]:
        if not self.base_dir.exists(): return None
        for candidate in [self.base_dir / f"{name}64.exe", self.base_dir / f"{name}.exe"]:
            if candidate.is_file(): return str(candidate)
        return None

    def execute(self, tool_key: str, args: List[str], timeout: int = SUBPROCESS_TIMEOUT) -> Tuple[bool, str, str]:
        tool_path = self.discovered_tools.get(tool_key)
        if not tool_path:
            return False, "", "Tool not available"

        cmd = [tool_path, "-accepteula"] + args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=timeout)
            return True, result.stdout, result.stderr
        except Exception as e:
            logger.error(f"Error executing {tool_key}: {e}")
            return False, "", str(e)

# ============================================================================
# UTILITIES & STATUS CHECKERS
# ============================================================================

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def get_security_statuses() -> Dict[str, str]:
    av_status = "OFF"
    fw_status = "OFF"
    try:
        cmd = ["powershell", "-NoProfile", "-Command", "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if res.returncode == 0 and "true" in res.stdout.strip().lower():
            av_status = "ON"
    except:
        pass
    
    try:
        cmd = ["powershell", "-NoProfile", "-Command", "(Get-NetFirewallProfile).Enabled -contains $true"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if res.returncode == 0 and "true" in res.stdout.strip().lower():
            fw_status = "ON"
    except:
        pass
    
    return {"av": av_status, "firewall": fw_status}

def clean_image_path(raw_path: str) -> str:
    """Cleans Windows service/autorun paths, translates NT prefixes, and normalizes format."""
    if not raw_path or raw_path == "N/A":
        return "N/A"
    
    path = raw_path.strip()
    
    if path.startswith('"'):
        end_quote = path.find('"', 1)
        if end_quote != -1:
            path = path[1:end_quote]
    else:
        for flag in [" -", " /"]:
            if flag in path:
                path = path.split(flag)[0].strip()

    path_lower = path.lower()
    if path_lower.startswith(r"\systemroot\\") or path_lower.startswith(r"\systemroot/"):
        path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), path[12:])
    elif path_lower.startswith(r"\??\\"):
        path = path[4:]

    path = os.path.expandvars(path)

    if ":" in path or path.startswith("\\"):
        abs_path = os.path.abspath(path)
    else:
        abs_path = path

    return abs_path

# ============================================================================
# AUDIT COLLECTORS
# ============================================================================

class ProcessCollector:
    @staticmethod
    def collect() -> List[ProcessRecord]:
        records = []
        for p in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'username', 'create_time']):
            try:
                info = p.info
                exe = info['exe'] or ""
                if exe: exe = os.path.abspath(exe)
                
                parent_name = "N/A"
                if info['ppid'] and info['ppid'] > 0:
                    try:
                        parent_name = psutil.Process(info['ppid']).name()
                    except:
                        pass

                records.append(ProcessRecord(
                    pid=info['pid'] or 0,
                    ppid=info['ppid'] or 0,
                    name=info['name'] or "Unknown",
                    path=exe if exe else "N/A",
                    cmdline=" ".join(info['cmdline']) if info['cmdline'] else "",
                    user=info['username'] or "N/A",
                    create_time=datetime.fromtimestamp(info['create_time']).isoformat() if info['create_time'] else "",
                    parent_name=parent_name
                ))
            except:
                continue
        return records

class SignatureVerifier:
    """Performs executable signature verification using Sysinternals Sigcheck."""

    def __init__(self, sys_mgr: SysinternalsManager):
        self.sys_mgr = sys_mgr

    def verify_paths(self, file_paths: List[str]) -> Dict[str, Dict[str, str]]:
        results: Dict[str, Dict[str, str]] = {}

        unique_paths = list(set([
            os.path.abspath(p) for p in file_paths 
            if p and p != "N/A" and os.path.isfile(p)
        ]))

        if not unique_paths or not self.sys_mgr.discovered_tools.get("sigcheck"):
            logger.warning("Sigcheck tool not found or no valid executable paths to scan.")
            return results

        logger.info(f"Running Sigcheck on {len(unique_paths)} files one by one...")
        
        for original_path in unique_paths:
            args = ["-nobanner", "-c", "-q", original_path]
            success, stdout, stderr = self.sys_mgr.execute("sigcheck", args)

            if not success or not stdout.strip():
                continue

            clean_output = stdout.replace('\0', '').replace('\ufeff', '').strip()
            lines = [line.strip() for line in clean_output.splitlines() if line.strip()]

            header_idx = -1
            for idx, line in enumerate(lines):
                line_lower = line.lower()
                if line_lower.startswith("path,") or line_lower.startswith('"path",'):
                    header_idx = idx
                    break

            if header_idx == -1:
                continue

            csv_payload = "\n".join(lines[header_idx:])

            try:
                reader = csv.DictReader(io.StringIO(csv_payload))
                for row in reader:
                    path_key = row.get("Path") or row.get("path")
                    if not path_key:
                        continue

                    verified_val = row.get("Verified", "").strip().lower()
                    status = SignatureStatus.VERIFIED if verified_val == "signed" else SignatureStatus.UNVERIFIED
                    publisher = row.get("Publisher", "").strip() or row.get("Company", "").strip() or "Unsigned"

                    results[os.path.normpath(path_key).lower()] = {
                        "status": status,
                        "signer": publisher,
                        "sha256": "N/A"
                    }
            except Exception as e:
                logger.error(f"Error parsing Sigcheck output for {original_path}: {e}")

        final_mapping: Dict[str, Dict[str, str]] = {}
        for original_path in unique_paths:
            norm_p = os.path.normpath(original_path).lower()
            if norm_p in results:
                final_mapping[original_path] = results[norm_p]
            else:
                final_mapping[original_path] = {
                    "status": SignatureStatus.UNKNOWN,
                    "signer": "N/A",
                    "sha256": "N/A"
                }

        return final_mapping

class PersistenceCollector:
    """Collects system persistence using autorunsc with -ms to hide verified MS entries."""
    def __init__(self, sys_mgr: SysinternalsManager):
        self.sys_mgr = sys_mgr

    def collect(self) -> List[PersistenceRecord]:
        records = []
        tool_path = self.sys_mgr.discovered_tools.get("autorunsc")
        if not tool_path:
            logger.warning("Autorunsc not available. Persistence collection skipped.")
            return records

        success, stdout, stderr = self.sys_mgr.execute("autorunsc", ["-a", "*", "-c", "-nobanner", "-ms"], timeout=180)
        
        if success and stdout.strip():
            try:
                clean_output = stdout.replace('\0', '').replace('\ufeff', '').strip()
                lines = [line.strip() for line in clean_output.splitlines() if line.strip()]
                
                header_idx = -1
                for idx, line in enumerate(lines):
                    line_lower = line.lower()
                    if "entry location" in line_lower or "image path" in line_lower or "imagepath" in line_lower:
                        header_idx = idx
                        break
                
                if header_idx != -1:
                    csv_payload = "\n".join(lines[header_idx:])
                    reader = csv.DictReader(io.StringIO(csv_payload))
                    
                    for row in reader:
                        raw_image = (
                            row.get("Image Path") or 
                            row.get("ImagePath") or 
                            row.get("Path") or 
                            ""
                        ).strip()
                        
                        if "file not found" in raw_image.lower():
                            continue

                        cleaned_path = clean_image_path(raw_image)
                        sig_raw = row.get("Signer", "").strip().lower()
                        publisher = row.get("Publisher", "").strip()
                        
                        if "verified" in sig_raw and "not" not in sig_raw:
                            status = SignatureStatus.VERIFIED
                        else:
                            status = SignatureStatus.UNVERIFIED

                        records.append(PersistenceRecord(
                            location=row.get("Entry Location", "Unknown"),
                            entry=row.get("Entry", "Unknown"),
                            image_path=cleaned_path if cleaned_path else "N/A",
                            launch_string=row.get("Launch String", "").strip(),
                            category=row.get("Category", "General").strip(),
                            publisher=publisher if publisher else "Unsigned/Unknown",
                            signature_status=status
                        ))
            except Exception as e:
                logger.error(f"Error parsing Autorunsc output: {e}")
        else:
            logger.error(f"Autorunsc execution failed. Ensure script is run as Administrator. Stderr: {stderr}")
            
        return records

class NetworkCollector:
    """Collects and filters active network connections (ESTABLISHED, external IPs only)."""
    def __init__(self, sys_mgr: SysinternalsManager):
        self.sys_mgr = sys_mgr

    def collect(self) -> List[NetworkRecord]:
        records = []
        if self.sys_mgr.discovered_tools.get("tcpvcon"):
            success, stdout, _ = self.sys_mgr.execute("tcpvcon", ["-a", "-n", "-c", "-nobanner"])
            if success and stdout.strip():
                try:
                    reader = csv.reader(io.StringIO(stdout))
                    for row in reader:
                        if len(row) < 6: continue
                        
                        state = row[3].strip().upper()
                        if state != "ESTABLISHED":
                            continue

                        try: pid = int(row[2].strip())
                        except: continue
                        
                        loc_addr, loc_port = self._split_addr_port(row[4].strip() if len(row) > 4 else "")
                        rem_addr, rem_port = self._split_addr_port(row[5].strip() if len(row) > 5 else "")
                        
                        if rem_addr in EXCLUDED_IPS:
                            continue

                        records.append(NetworkRecord(
                            protocol=row[0].strip(),
                            local_addr=loc_addr, local_port=loc_port,
                            remote_addr=rem_addr, remote_port=rem_port,
                            state=state,
                            pid=pid, process_name=row[1].strip()
                        ))
                    return records
                except Exception as e:
                    logger.error(f"Error parsing tcpvcon output: {e}")
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
                    continue
                
                rem_addr = conn.raddr.ip
                if rem_addr in EXCLUDED_IPS:
                    continue

                try:
                    p_name = psutil.Process(conn.pid).name() if conn.pid else "Unknown"
                except:
                    p_name = "Unknown"

                records.append(NetworkRecord(
                    protocol="TCP",
                    local_addr=conn.laddr.ip if conn.laddr else "",
                    local_port=conn.laddr.port if conn.laddr else 0,
                    remote_addr=rem_addr,
                    remote_port=conn.raddr.port if conn.raddr else 0,
                    state="ESTABLISHED",
                    pid=conn.pid or 0,
                    process_name=p_name
                ))
        except Exception as e:
            logger.error(f"Fallback psutil network collection failed: {e}")

        return records

    @staticmethod
    def _split_addr_port(addr_str: str) -> Tuple[str, int]:
        if ":" in addr_str:
            parts = addr_str.rsplit(":", 1)
            try: return parts[0], int(parts[1])
            except: return parts[0], 0
        return addr_str, 0

# ============================================================================
# CORRELATION ENGINE
# ============================================================================

class AuditEngine:
    def __init__(self, sys_mgr: SysinternalsManager):
        self.sys_mgr = sys_mgr

    def run_audit(self):
        logger.info("Collecting System Metadata & Security Statuses...")
        sec = get_security_statuses()
        meta = SystemMetadata(
            audit_time=datetime.now().isoformat(),
            hostname=os.getenv("COMPUTERNAME", "Unknown"),
            os_version=f"Windows {sys.getwindowsversion().major}.{sys.getwindowsversion().minor}",
            is_admin=is_admin(),
            sysinternals_dir=SYSINTERNALS_DIR,
            tools_available={k: (v if v else "NOT_AVAILABLE") for k, v in self.sys_mgr.discovered_tools.items()},
            av_status=sec["av"],
            firewall_status=sec["firewall"]
        )

        logger.info("Collecting Processes...")
        processes = ProcessCollector.collect()

        logger.info("Verifying Signatures via Sigcheck...")
        verifier = SignatureVerifier(self.sys_mgr)
        sig_map = verifier.verify_paths([p.path for p in processes if p.path != "N/A"])

        for p in processes:
            if p.path in sig_map:
                p.signature_status = sig_map[p.path]["status"]
                p.signer = sig_map[p.path]["signer"]
                p.sha256 = sig_map[p.path]["sha256"]

        logger.info("Collecting Persistence (Autoruns)...")
        persistence = PersistenceCollector(self.sys_mgr).collect()
        persist_sig_map = verifier.verify_paths([p.image_path for p in persistence if p.image_path != "N/A"])
        
        for p in persistence:
            if p.image_path in persist_sig_map:
                p.signature_status = persist_sig_map[p.image_path]["status"]
                p.publisher = persist_sig_map[p.image_path]["signer"]

        logger.info("Collecting Filtered External Network Connections...")
        network = NetworkCollector(self.sys_mgr).collect()
        pid_to_sig = {p.pid: p.signature_status for p in processes}
        for n in network:
            n.signature_status = pid_to_sig.get(n.pid, SignatureStatus.UNKNOWN)

        findings = self._correlate(processes, persistence, network)
        return meta, processes, persistence, network, findings

    def _correlate(self, processes, persistence, network):
        findings = []
        pids_net = {n.pid for n in network}
        paths_pers = {p.image_path.lower() for p in persistence if p.image_path != "N/A"}

        for p in processes:
            score, evidence = 0, []
            if p.signature_status == SignatureStatus.UNVERIFIED:
                score += 30; evidence.append("Executable is UNVERIFIED/Unsigned")
            if p.path.lower() in paths_pers:
                score += 20; evidence.append("Binary configured for persistence")
            if p.pid in pids_net:
                score += 25; evidence.append("Active external established network connection")
            
            p.risk_score = score
            if score >= 45:
                findings.append(Finding(
                    finding_id=f"FIND-PROC-{p.pid}",
                    rule_id="SUSPICIOUS_PROCESS",
                    severity=Severity.HIGH,
                    risk_score=score,
                    entity=f"{p.name} (PID {p.pid})",
                    evidence=evidence,
                    reasons=["Process exhibits unverified binary attributes or active unauthorized external communication."],
                    recommendation="Investigate process binary."
                ))

        for idx, pers in enumerate(persistence):
            if not pers.entry or not pers.entry.strip() or not pers.image_path or pers.image_path == "N/A":
                continue
            if "file not found" in pers.image_path.lower():
                continue
            
            score, evidence = 0, []
            if pers.signature_status == SignatureStatus.UNVERIFIED:
                score += 50; evidence.append("Persistence binary is UNVERIFIED / Unsigned (Potential Payload)")
            
            pers.risk_score = score
            if score >= 30:
                findings.append(Finding(
                    finding_id=f"FIND-PERS-{idx}",
                    rule_id="UNVERIFIED_PERSISTENCE_PAYLOAD",
                    severity=Severity.HIGH if score >= 50 else Severity.MEDIUM,
                    risk_score=score,
                    entity=f"Service/Autorun: {pers.entry} ({pers.category})",
                    evidence=evidence,
                    reasons=["Configured to auto-start with operating system execution chain."],
                    recommendation="High priority threat check. Inspect target executable path and verify service authenticity."
                ))
        
        return findings

# ============================================================================
# REPORT GENERATION & MAIN
# ============================================================================

def generate_reports(meta, processes, persistence, network, findings):
    verified_procs = [p for p in processes if p.signature_status == SignatureStatus.VERIFIED]
    unverified_procs = [p for p in processes if p.signature_status == SignatureStatus.UNVERIFIED]
    unknown_procs = [p for p in processes if p.signature_status == SignatureStatus.UNKNOWN]
    
    unverified_pers = [
        p for p in persistence 
        if p.signature_status == SignatureStatus.UNVERIFIED 
        and p.entry and p.entry.strip() 
        and p.image_path and p.image_path != "N/A"
        and "file not found" not in p.image_path.lower()
    ]

    av_class = "text-green" if meta.av_status == "ON" else "text-red"
    fw_class = "text-green" if meta.firewall_status == "ON" else "text-red"

    html = f"""<!DOCTYPE html>
    <html>
    <head>
        <title>WSAAF Security Audit Report</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 20px; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 30px; background: #1e293b; }}
            th, td {{ border: 1px solid #334155; padding: 10px; text-align: left; font-size: 0.9rem; word-break: break-all; }}
            th {{ background-color: #0f172a; color: #94a3b8; }}
            h2 {{ border-bottom: 1px solid #334155; padding-bottom: 8px; margin-top: 40px; }}
            .text-green {{ color: #22c55e; font-weight: bold; }}
            .text-red {{ color: #ef4444; font-weight: bold; }}
            .text-yellow {{ color: #eab308; }}
            .badge-danger {{ background: #ef4444; color: white; padding: 2px 6px; border-radius: 4px; font-weight: bold; }}
            .status-box {{ background: #1e293b; border: 1px solid #334155; padding: 12px; margin-bottom: 25px; border-radius: 6px; }}
        </style>
    </head>
    <body>
        <h1>Security Report: {meta.hostname}</h1>
        <p>Audit Time: {meta.audit_time} | Administrator Mode: {meta.is_admin}</p>

        <div class="status-box">
            <p><strong>Antivirus Status:</strong> <span class="{av_class}">{meta.av_status}</span> &nbsp;|&nbsp; <strong>Firewall Status:</strong> <span class="{fw_class}">{meta.firewall_status}</span></p>
        </div>

        <h2 class="text-red">Detected Persistence Payloads / Unverified Autoruns ({len(unverified_pers)})</h2>
        <table>
            <tr><th>Location</th><th>Entry Name</th><th>Payload Image Path</th><th>Publisher / Status</th></tr>
            {''.join([f"<tr><td>{p.location}</td><td><strong>{p.entry}</strong></td><td>{p.image_path}</td><td><span class='badge-danger'>{p.signature_status}</span> ({p.publisher})</td></tr>" for p in unverified_pers])}
        </table>
        {"<p style='color: #94a3b8;'>No unverified persistence items found.</p>" if not unverified_pers else ""}

        <h2 class="text-red">Active Established External Connections ({len(network)})</h2>
        <table>
            <tr><th>Protocol</th><th>Process Name (PID)</th><th>Local Address</th><th>Remote Address</th><th>State</th></tr>
            {''.join([f"<tr><td>{n.protocol}</td><td><strong>{n.process_name}</strong> (PID {n.pid})</td><td>{n.local_addr}:{n.local_port}</td><td><span class='badge-danger'>{n.remote_addr}:{n.remote_port}</span></td><td>{n.state}</td></tr>" for n in network])}
        </table>
        {"<p style='color: #94a3b8;'>No active external established connections found.</p>" if not network else ""}

        <h2 class="text-red">Unverified / Unsigned Processes ({len(unverified_procs)})</h2>
        <table>
            <tr><th>PID</th><th>Name</th><th>Path</th><th>Status</th></tr>
            {''.join([f"<tr><td>{p.pid}</td><td>{p.name}</td><td>{p.path}</td><td><strong class='text-red'>{p.signature_status}</strong></td></tr>" for p in unverified_procs])}
        </table>

        <h2 class="text-yellow">Unknown / Failed to Check Processes ({len(unknown_procs)})</h2>
        <table>
            <tr><th>PID</th><th>Name</th><th>Path</th><th>Status</th></tr>
            {''.join([f"<tr><td>{p.pid}</td><td>{p.name}</td><td>{p.path}</td><td><strong class='text-yellow'>{p.signature_status}</strong></td></tr>" for p in unknown_procs])}
        </table>

        <h2 class="text-green">Successfully Verified Processes ({len(verified_procs)})</h2>
        <table>
            <tr><th>PID</th><th>Name</th><th>Path</th><th>Signer</th></tr>
            {''.join([f"<tr><td>{p.pid}</td><td>{p.name}</td><td>{p.path}</td><td>{p.signer}</td></tr>" for p in verified_procs])}
        </table>
    </body>
    </html>"""
    
    with open("wsaaf_report.html", "w", encoding="utf-8") as f:
        f.write(html)
    logger.info("Report generated successfully: wsaaf_report.html")

def main():
    logger.info("Starting WSAAF-NG...")
    sys_mgr = SysinternalsManager(SYSINTERNALS_DIR)
    meta, procs, pers, net, findings = AuditEngine(sys_mgr).run_audit()
    generate_reports(meta, procs, pers, net, findings)

if __name__ == "__main__":
    main()
