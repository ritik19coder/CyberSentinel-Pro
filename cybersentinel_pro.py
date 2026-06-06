# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════╗
║        CYBERSENTINEL PRO — Blue Team SOC Analyst Tool        ║
║        MSc Cybersecurity Project — Full Working Version      ║
╚══════════════════════════════════════════════════════════════╝

# ══════════════════════════════════════════════════════════════
# CELL 1 — INSTALL  (run this cell first, every new session)
# ══════════════════════════════════════════════════════════════
"""
#

import subprocess, sys, os, importlib.util

try:
    # Prevent Windows cp1252 console crashes when printing Unicode symbols.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

PKGS = ["flask","pyngrok","openai","pandas","plotly",
        "scikit-learn","reportlab","kaleido","nest_asyncio","matplotlib"]

# pip names do not always match import names
IMPORT_NAME = {
    "scikit-learn": "sklearn",
}

def _is_installed(pkg_name):
    mod_name = IMPORT_NAME.get(pkg_name, pkg_name.replace("-", "_"))
    return importlib.util.find_spec(mod_name) is not None

print("📦 Checking packages...")
missing = [p for p in PKGS if not _is_installed(p)]
if not missing:
    print("✅ All required packages already installed.\n")
else:
    print(f"Installing missing packages: {', '.join(missing)}")
    for p in missing:
        r = subprocess.run([sys.executable, "-m", "pip", "install", p, "--quiet"],
                           capture_output=True, text=True)
        print(f"  {'✅' if r.returncode == 0 else '❌'} {p}")
    print("\n✅ Package check/install complete.\n")

# ══════════════════════════════════════════════════════════════
# CELL 2 — TOKENS  (paste your keys here)
# ══════════════════════════════════════════════════════════════

NGROK_AUTHTOKEN = os.getenv("NGROK_AUTHTOKEN", "")   
OPENAI_KEY      = os.getenv("OPENAI_API_KEY", "")    

# ══════════════════════════════════════════════════════════════
# CELL 3 — IMPORTS & INIT
# ══════════════════════════════════════════════════════════════

import os, re, json, random , io
from datetime import datetime
from collections import Counter

import nest_asyncio
nest_asyncio.apply()

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from sklearn.metrics import confusion_matrix
import matplotlib
matplotlib.use('Agg')

from flask import Flask, request, render_template_string, send_file, jsonify, make_response
from pyngrok import ngrok
from openai import OpenAI

from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                 Table, TableStyle, PageBreak,
                                 Image as RLImage)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors as rl_colors
from reportlab.lib.units import inch

try:
    ngrok.kill()
except Exception:
    pass
if NGROK_AUTHTOKEN:
    ngrok.set_auth_token(NGROK_AUTHTOKEN)
if OPENAI_KEY:
    os.environ["OPENAI_API_KEY"] = OPENAI_KEY
client = OpenAI(api_key=OPENAI_KEY) if OPENAI_KEY else None

# Global session state
alerts          = []   # one entry per analysis run
all_log_entries = []

print("✅ Imports complete.")

# ══════════════════════════════════════════════════════════════
# CELL 4 — LOG PARSER & MITRE MAPPING
# ══════════════════════════════════════════════════════════════

MITRE_MAP = {
    "brute force":       ("TA0006","T1110","Credential Access","Brute Force"),
    "failed login":      ("TA0006","T1110","Credential Access","Brute Force"),
    "ssh":               ("TA0006","T1110","Credential Access","Brute Force"),
    "port scan":         ("TA0007","T1046","Discovery","Network Service Scanning"),
    "nmap":              ("TA0007","T1046","Discovery","Network Service Scanning"),
    "sql injection":     ("TA0009","T1190","Initial Access","Exploit Public App"),
    "sqli":              ("TA0009","T1190","Initial Access","Exploit Public App"),
    "xss":               ("TA0009","T1189","Initial Access","Drive-by Compromise"),
    "ddos":              ("TA0040","T1498","Impact","Network DoS"),
    "flood":             ("TA0040","T1498","Impact","Network DoS"),
    "malware":           ("TA0011","T1071","Command & Control","App Layer Protocol"),
    "c2":                ("TA0011","T1071","Command & Control","App Layer Protocol"),
    "ransomware":        ("TA0040","T1486","Impact","Data Encrypted for Impact"),
    "privilege":         ("TA0004","T1068","Privilege Escalation","Exploit for Priv Esc"),
    "lateral":           ("TA0008","T1021","Lateral Movement","Remote Services"),
    "exfil":             ("TA0010","T1041","Exfiltration","Exfil Over C2 Channel"),
    "phish":             ("TA0001","T1566","Initial Access","Phishing"),
    "unauthorized":      ("TA0001","T1078","Initial Access","Valid Accounts"),
    "path traversal":    ("TA0005","T1055","Defense Evasion","Path Traversal"),
    "command injection": ("TA0002","T1059","Execution","Command & Scripting Interp."),
    "powershell":        ("TA0002","T1059.001","Execution","PowerShell"),
    "persistence":       ("TA0003","T1053","Persistence","Scheduled Task/Job"),
}

SEV_KW = {
    "critical": ["sql injection","ransomware","malware","c2","exfil",
                 "ddos","flood","root access","path traversal","command injection"],
    "high":     ["brute force","privilege","lateral","phish","unauthorized",
                 "failed login","ssh attack","powershell","persistence"],
    "medium":   ["port scan","nmap","xss","suspicious","anomaly","unusual","scan"],
    "low":      ["info","notice","debug","warning","timeout","connection refused"],
}

def fake_country(ip):
    if not ip: return "Unknown"
    parts = ip.split('.')
    if not parts[0].isdigit(): return "Unknown"
    first = int(parts[0])
    mapping = [
        (range(1,50),   "United States"),
        (range(50,80),  "Russia"),
        (range(80,110), "China"),
        (range(110,130),"Germany"),
        (range(130,150),"Brazil"),
        (range(150,170),"India"),
        (range(170,190),"Iran"),
        (range(190,210),"Nigeria"),
        (range(210,230),"Ukraine"),
        (range(230,256),"Netherlands"),
    ]
    for rng, country in mapping:
        if first in rng: return country
    return "Unknown"

def parse_log_content(content):
    entries = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'): continue

        e = {
            "raw": line, "time"
            "tamp": "", "source_ip": "", "dest_ip": "",
            "dest_port": "", "protocol": "", "severity": "low",
            "severity_score": 10, "attack_type": "Informational",
            "mitre_tactic_id": "", "mitre_technique_id": "",
            "mitre_tactic": "Unknown", "mitre_technique": "Unknown",
            "country": "Unknown", "suspicious": False, "flags": [],
            "ai_explanation": ""
        }

        # Timestamp
        for pat in [r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}',
                    r'\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}',
                    r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}']:
            m = re.search(pat, line)
            if m: e["timestamp"] = m.group(0); break
        if not e["timestamp"]:
            e["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # IPs
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        priv = ('10.','192.168.','172.','127.')
        pub = [ip for ip in ips if not any(ip.startswith(p) for p in priv)]
        if pub:
            e["source_ip"] = pub[0]
            e["country"]   = fake_country(pub[0])
        elif ips:
            e["source_ip"] = ips[0]
        if len(ips) > 1: e["dest_ip"] = ips[1]

        # Port
        pm = re.search(r'(?:port|dpt|DPT|dst_port)[=:\s]+(\d+)', line, re.I)
        if not pm: pm = re.search(r':(\d{2,5})\b', line)
        if pm: e["dest_port"] = pm.group(1)

        # Protocol
        prot = re.search(r'\b(TCP|UDP|ICMP|HTTP|HTTPS|SSH|FTP|DNS|SMTP)\b', line, re.I)
        if prot: e["protocol"] = prot.group(1).upper()

        # Severity & MITRE
        ll = line.lower()
        sev, attack, mitre = "low", "Informational", ("","","Unknown","Unknown")

        for s in ["critical","high","medium","low"]:
            for kw in SEV_KW[s]:
                if kw in ll:
                    sev, attack = s, kw.title()
                    e["flags"].append(f"Keyword: '{kw}'")
                    break
            if sev in ["critical","high"]: break

        for kw, m in MITRE_MAP.items():
            if kw in ll:
                mitre = m
                attack = kw.replace("-"," ").title()
                break

        # Regex heuristics
        if re.search(r"select.{0,40}from|union.{0,20}select|or\s+1=1|drop\s+table", ll):
            sev, attack, mitre = "critical","SQL Injection", MITRE_MAP["sql injection"]
            e["flags"].append("SQL injection pattern")
        if re.search(r"<script|javascript:|onerror=|onload=", ll):
            sev, attack, mitre = "high","XSS Attempt", MITRE_MAP["xss"]
            e["flags"].append("XSS payload")
        if re.search(r"\.\.\/|\.\.\\|/etc/passwd|cmd\.exe|powershell.*-enc", ll):
            sev, attack, mitre = "critical","Command/Path Injection", MITRE_MAP["command injection"]
            e["flags"].append("Path traversal / command injection")

        fails = len(re.findall(r'fail|invalid|denied|reject|error', ll))
        if fails >= 3 and sev == "low":
            sev = "medium"
            e["flags"].append(f"Multiple failure keywords ({fails}x)")

        score_map = {"critical": random.randint(87,100), "high": random.randint(65,86),
                     "medium": random.randint(35,64),    "low":  random.randint(5,34)}

        e.update(severity=sev, severity_score=score_map[sev], attack_type=attack,
                 mitre_tactic_id=mitre[0], mitre_technique_id=mitre[1],
                 mitre_tactic=mitre[2],    mitre_technique=mitre[3],
                 suspicious=(sev in ["critical","high","medium"]))
        entries.append(e)
    return entries

print("✅ Parser ready.")

# ══════════════════════════════════════════════════════════════
# CELL 5 — AI ANALYSIS (GPT-4o-mini)
# ══════════════════════════════════════════════════════════════

# ── CVE reference database (built-in, no API needed) ──────────
CVE_DB = {
    "sql injection":     [
        ("CVE-2023-23397","Critical","SQL injection via mail client auth bypass"),
        ("CVE-2022-22965","Critical","Spring4Shell – RCE via SQL-injectable endpoint"),
        ("CVE-2021-44228","Critical","Log4Shell – injectable JNDI lookup strings"),
    ],
    "xss":               [
        ("CVE-2022-24086","Critical","Adobe Commerce stored XSS pre-auth"),
        ("CVE-2021-26855","Critical","Exchange SSRF leading to reflected XSS"),
        ("CVE-2023-44487","High",   "HTTP/2 Rapid Reset used post-XSS pivot"),
    ],
    "brute force":       [
        ("CVE-2023-20198","Critical","Cisco IOS privilege escalation via cred brute"),
        ("CVE-2022-40684","Critical","Fortinet FortiOS auth bypass via brute force"),
        ("CVE-2021-20021","Critical","SonicWall admin credential brute attack"),
    ],
    "ssh":               [
        ("CVE-2023-38408","Critical","OpenSSH remote code execution – pre-auth"),
        ("CVE-2023-25136","High",   "OpenSSH pre-auth double free memory bug"),
        ("CVE-2018-10933","Critical","libssh authentication bypass via SSH2_MSG"),
    ],
    "port scan":         [
        ("CVE-2022-32548","Critical","BIG-IP recon post network scan"),
        ("CVE-2021-22986","Critical","F5 unauthenticated RCE discovered via scan"),
    ],
    "ransomware":        [
        ("CVE-2023-34362","Critical","MOVEit Transfer SQLi used by Cl0p ransomware"),
        ("CVE-2021-34527","Critical","PrintNightmare used in ransomware deployment"),
        ("CVE-2020-1472", "Critical","Zerologon – ransomware privilege escalation"),
    ],
    "malware":           [
        ("CVE-2023-23397","Critical","Outlook zero-click malware delivery"),
        ("CVE-2022-30190","Critical","Follina – Word document malware dropper"),
        ("CVE-2021-40444","High",   "MSHTML remote code execution malware loader"),
    ],
    "ddos":              [
        ("CVE-2023-44487","High",   "HTTP/2 Rapid Reset DDoS amplification"),
        ("CVE-2022-26134","Critical","Confluence unauthenticated DDoS vector"),
    ],
    "privilege":         [
        ("CVE-2023-21674","Critical","Windows ALPC local privilege escalation"),
        ("CVE-2022-37969","Critical","Windows CLFS driver privilege escalation"),
        ("CVE-2021-4034", "Critical","Polkit pkexec LPE – major Linux systems"),
    ],
    "lateral":           [
        ("CVE-2020-1472", "Critical","Zerologon – domain lateral movement"),
        ("CVE-2017-0144", "Critical","EternalBlue – SMB lateral spread"),
        ("CVE-2021-34527","Critical","PrintNightmare – lateral movement via spooler"),
    ],
    "exfil":             [
        ("CVE-2023-34362","Critical","MOVEit Transfer mass data exfiltration"),
        ("CVE-2022-41040","High",   "ProxyNotShell – Exchange data exfil chain"),
        ("CVE-2021-26855","Critical","Exchange SSRF enabling data exfiltration"),
    ],
    "path traversal":    [
        ("CVE-2021-41773","Critical","Apache HTTP Server path traversal + RCE"),
        ("CVE-2021-42013","Critical","Apache path traversal auth bypass"),
        ("CVE-2019-18935","Critical","Telerik UI path traversal to RCE"),
    ],
    "command injection": [
        ("CVE-2023-46604","Critical","Apache ActiveMQ remote code execution"),
        ("CVE-2022-1388", "Critical","F5 BIG-IP iControl REST command injection"),
        ("CVE-2021-21985","Critical","VMware vCenter command injection RCE"),
    ],
    "phish":             [
        ("CVE-2023-23397","Critical","Outlook zero-click phishing – NTLM hash leak"),
        ("CVE-2022-30190","Critical","Follina – phishing via malicious Word doc"),
    ],
    "powershell":        [
        ("CVE-2022-41082","Critical","ProxyNotShell – PowerShell RCE via Exchange"),
        ("CVE-2021-34527","Critical","PrintNightmare via PowerShell spooler abuse"),
    ],
    "c2":                [
        ("CVE-2021-44228","Critical","Log4Shell – C2 callback via JNDI injection"),
        ("CVE-2021-26855","Critical","Exchange SSRF as C2 relay channel"),
    ],
    "unauthorized":      [
        ("CVE-2022-40684","Critical","Fortinet FortiOS unauthorized admin access"),
        ("CVE-2021-20016","Critical","SonicWall unauthorized access pre-auth"),
    ],
}

def get_cve_context(log_text, attack_type=""):
    """Return relevant CVEs from built-in DB based on log content / attack type."""
    ll = (log_text + " " + attack_type).lower()
    for kw, cves in CVE_DB.items():
        if kw in ll:
            return cves
    # Generic fallback
    return [
        ("CVE-2023-44487","High",   "HTTP/2 Rapid Reset – common web attack vector"),
        ("CVE-2021-44228","Critical","Log4Shell – opportunistic exploitation"),
        ("CVE-2022-40684","Critical","Fortinet auth bypass – widespread scanning"),
    ]


def ai_analyze_log(log_text, api_key=""):
    key = api_key or OPENAI_KEY
    if not key or key == "YOUR_OPENAI_KEY":
        # Template fallback with CVE data
        cves = get_cve_context(log_text)
        cve_lines = "\n".join([f"  • {c[0]} [{c[1]}] — {c[2]}\n    🔗 https://nvd.nist.gov/vuln/detail/{c[0]}" for c in cves])
        return (
            "Attack Type: [No API key — manual review required]\n"
            "Severity: Unknown\nConfidence %: N/A\nRisk Score: N/A\n"
            "MITRE Tactic ID: N/A\nMITRE Technique ID: N/A\n"
            "MITRE Tactic: Unknown\nMITRE Technique: Unknown\n"
            "Indicators of Compromise:\n  - Manual IOC extraction required\n"
            "Recommended Analyst Actions:\n  - Review log manually\n  - Check against threat intel\n"
            f"\n─── CVE DATABASE MATCHES ───\n{cve_lines}\n\n"
            "Reasoning:\n  No OpenAI key configured. Set OPENAI_KEY to enable full AI analysis."
        )

    prompt = f"""You are a senior Blue Team SOC analyst (CISSP, CEH certified).

Analyze the security log below and return EXACTLY this structure — do not skip any field:

Attack Type:
Severity (Low/Medium/High/Critical):
Confidence %:
Risk Score (0-100):
MITRE Tactic ID:
MITRE Technique ID:
MITRE Tactic:
MITRE Technique:
Indicators of Compromise:
  - (list each IOC: IP, hash, domain, pattern)
Recommended Analyst Actions:
  - (list concrete remediation steps)
CVE References:
  - (list CVE IDs with severity and description, e.g. CVE-2021-44228 [Critical] — Log4Shell RCE)
Threat Actor Profile:
  - Likely actor type (nation-state / cybercriminal / hacktivist / insider threat)
  - Known TTPs matching this attack pattern
Reasoning:
  (2-3 paragraph detailed analysis of the threat, attack chain, and business impact)

Log Data:
{log_text[:3000]}"""

    try:
        active_client = OpenAI(api_key=key)
        resp = active_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2
        )
        raw = resp.choices[0].message.content

        # Always append local CVE DB as supplementary intel
        cves = get_cve_context(log_text)
        cve_block = "\n\n─── SUPPLEMENTARY CVE DATABASE MATCHES ───\n"
        for cve_id, sev, desc in cves:
            cve_block += f"  • {cve_id} [{sev}] — {desc}\n    🔗 https://nvd.nist.gov/vuln/detail/{cve_id}\n"
        return raw + cve_block

    except Exception as ex:
        cves = get_cve_context(log_text)
        cve_lines = "\n".join([f"  • {c[0]} [{c[1]}] — {c[2]}" for c in cves])
        return (f"[AI Error: {ex}]\n\n"
                f"CVE References (from local DB):\n{cve_lines}")


def ai_executive_summary(stats, api_key=""):
    key = api_key or OPENAI_KEY
    if not key or key == "YOUR_OPENAI_KEY":
        top_a = stats["top_attacks"][0][0]  if stats.get("top_attacks")  else "Unknown"
        top_c = stats["top_countries"][0][0] if stats.get("top_countries") else "Unknown"
        return (f"Threat Overview\nAnalysis of {stats['total']} log entries identified "
                f"{stats['suspicious']} suspicious events. Most prevalent: {top_a} from {top_c}. "
                f"{stats['critical']} critical and {stats['high']} high-severity events recorded.\n\n"
                f"Key Findings\nCritical alerts indicate active exploitation. "
                f"MITRE tactics detected: {', '.join([t[0] for t in stats.get('top_tactics',[])][:3])}.\n\n"
                f"Recommended Actions\n"
                f"1. Block source IPs at perimeter firewall.\n"
                f"2. Isolate affected endpoints.\n"
                f"3. Escalate critical findings to senior analysts.\n"
                f"4. Preserve log evidence for forensic review.")
    prompt = f"""Senior Blue Team SOC analyst. Write a 3-paragraph professional executive summary.
Stats: {stats['total']} logs, {stats['suspicious']} suspicious, {stats['critical']} critical,
{stats['high']} high. Top attack: {stats['top_attacks'][0][0] if stats.get('top_attacks') else 'N/A'}.
Top country: {stats['top_countries'][0][0] if stats.get('top_countries') else 'N/A'}.
MITRE tactics: {', '.join([t[0] for t in stats.get('top_tactics',[])][:4])}.
Paragraphs: 1) Threat Overview 2) Key Findings 3) Recommended Actions. British English, formal."""
    try:
        active_client = OpenAI(api_key=key)
        resp = active_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role":"user","content":prompt}],
            temperature=0.3
        )
        return resp.choices[0].message.content
    except Exception as ex:
        return f"[Summary error: {ex}]"


def ai_explain_entry(entry, api_key=""):
    key = api_key or OPENAI_KEY
    if not key or key == "YOUR_OPENAI_KEY":
        return (f"Explanation: {entry.get('attack_type','Unknown')} detected from "
                f"{entry.get('source_ip','unknown')} ({entry.get('country','?')}). "
                f"| Action: {'Block IP immediately and escalate.' if entry.get('severity') in ['critical','high'] else 'Monitor and log for review.'}")
    prompt = (f"SOC analyst. One sentence explanation + one action for this log.\n"
              f"Log: {entry['raw'][:200]}\n"
              f"Detected: {entry['attack_type']} | {entry['severity']} | {entry['mitre_tactic']}\n"
              f"Format exactly: Explanation: <text> | Action: <text>")
    try:
        active_client = OpenAI(api_key=key)
        resp = active_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role":"user","content":prompt}],
            max_tokens=130
        )
        return resp.choices[0].message.content
    except:
        return (f"Explanation: {entry.get('attack_type','Event')} from {entry.get('source_ip','unknown')}. "
                f"| Action: Review and escalate if confirmed malicious.")


def parse_ai_output(text):
    def grab(label):
        m = re.search(rf"{label}[:\s]+(.+?)(?=\n[A-Z]|\Z)", text, re.S|re.I)
        return m.group(1).strip() if m else "N/A"
    def grab_list(label):
        m = re.search(rf"{label}[:\s]*((?:\s*[-•]\s*.+\n?)+)", text, re.I)
        if not m: return []
        return [re.sub(r'^[-•]\s*','',l).strip() for l in m.group(1).splitlines() if l.strip()]
    return {
        "attack_type":     grab("Attack Type"),
        "severity":        grab("Severity"),
        "confidence":      grab("Confidence %").replace('%','').strip(),
        "risk_score":      grab("Risk Score"),
        "mitre_tactic_id": grab("MITRE Tactic ID"),
        "mitre_tech_id":   grab("MITRE Technique ID"),
        "mitre_tactic":    grab("MITRE Tactic"),
        "mitre_tech":      grab("MITRE Technique"),
        "iocs":            grab_list("Indicators of Compromise"),
        "actions":         grab_list("Recommended Analyst Actions"),
        "reasoning":       grab("Reasoning"),
    }

print("✅ AI functions ready.")

# ══════════════════════════════════════════════════════════════
# CELL 6 — STATS BUILDER
# ══════════════════════════════════════════════════════════════

def build_stats(entries):
    if not entries: return {}
    sev  = Counter(e["severity"]     for e in entries)
    atk  = Counter(e["attack_type"]  for e in entries)
    cnt  = Counter(e["country"]      for e in entries if e["country"] != "Unknown")
    ips  = Counter(e["source_ip"]    for e in entries if e["source_ip"])
    tact = Counter(e["mitre_tactic"] for e in entries if e["mitre_tactic"] != "Unknown")
    susp = [e for e in entries if e["suspicious"]]
    return {
        "total":       len(entries),
        "suspicious":  len(susp),
        "critical":    sev.get("critical",0),
        "high":        sev.get("high",0),
        "medium":      sev.get("medium",0),
        "low":         sev.get("low",0),
        "top_attacks":   atk.most_common(8),
        "top_countries": cnt.most_common(8),
        "top_ips":       ips.most_common(8),
        "top_tactics":   tact.most_common(6),
        "severity_dist": dict(sev),
        "suspicious_entries": susp[:50],
        "all_entries":   entries[:300],
    }

print("✅ Stats builder ready.")

# ══════════════════════════════════════════════════════════════
# CELL 7 — CHART BUILDER  (returns JSON for safe JS rendering)
# ══════════════════════════════════════════════════════════════

BASE_LAYOUT = dict(
    paper_bgcolor='rgba(0,0,0,0)',
    plot_bgcolor='rgba(8,18,30,0.7)',
    font=dict(color='#00f5ff', family='Consolas, monospace'),
    margin=dict(t=30, b=45, l=50, r=15),
)
SEV_COLORS = {"critical":"#ff2244","high":"#ff6b00","medium":"#ffd000","low":"#00cc66"}
FILL_COLORS = {"#ff2244":"rgba(255,34,68,0.13)","#ff6b00":"rgba(255,107,0,0.13)",
               "#ffd000":"rgba(255,208,0,0.13)","#00ff88":"rgba(0,255,136,0.1)"}
ATK_PAL  = ['#00d4ff','#00aadd','#0088bb','#006699','#004477','#003355','#002244','#001133']
CTR_PAL  = ['#ff4444','#ff7700','#ffaa00','#ffdd00','#aaff00','#00ff88','#00ffcc','#00ccff']


def make_charts(stats):
    """Returns list of Plotly JSON strings. JS renders via Plotly.newPlot()."""
    charts = []

    # Shared axis style
    AX = dict(
        color='#4a8a9a',
        gridcolor='rgba(0,245,255,0.06)',
        zerolinecolor='rgba(0,245,255,0.12)',
        tickfont=dict(size=9, color='#4a8a9a'),
        linecolor='rgba(0,245,255,0.15)',
    )
    def ax_title(text):
        return dict(text=text, font=dict(size=10, color='#6aaabb'), standoff=8)

    # ── 1. Severity Donut ─────────────────────────────────
    sev = stats["severity_dist"]
    fig = go.Figure(go.Pie(
        labels=list(sev.keys()), values=list(sev.values()), hole=0.6,
        marker_colors=[SEV_COLORS.get(k, "#888") for k in sev],
        textinfo='label+percent', textfont_size=11,
        hovertemplate='<b>%{label}</b>: %{value} alerts (%{percent})<extra></extra>'
    ))
    fig.add_annotation(
        text=f"<b>{stats['total']}</b><br><span style='font-size:11px'>Total</span>",
        x=0.5, y=0.5, font=dict(size=17, color='#00d4ff'), showarrow=False
    )
    fig.update_layout(
        **BASE_LAYOUT, height=310, showlegend=True,
        title=dict(text="Alert Severity Breakdown", font=dict(size=12, color='#5ab0c0'), x=0),
        legend=dict(orientation='h', x=0, y=-0.18, font=dict(size=10, color='#6aaabb'))
    )
    charts.append(fig.to_json())

    # ── 2. Attack Type Bar ────────────────────────────────
    a_lbl = [a[0] for a in stats["top_attacks"]]
    a_val = [a[1] for a in stats["top_attacks"]]
    fig2 = go.Figure(go.Bar(
        x=a_val, y=a_lbl, orientation='h',
        marker=dict(color=ATK_PAL[:len(a_lbl)], line=dict(color='rgba(0,212,255,0.3)', width=1)),
        hovertemplate='<b>%{y}</b><br>Events: <b>%{x}</b><extra></extra>'
    ))
    fig2.update_layout(
        **BASE_LAYOUT, height=310,
        title=dict(text="Top Attack Types Detected", font=dict(size=12, color='#5ab0c0'), x=0),
        xaxis=dict(**AX, title=ax_title("Number of Events")),
        yaxis=dict(**AX, categoryorder='total ascending', automargin=True,
                   title=ax_title("Attack Type"))
    )
    charts.append(fig2.to_json())

    # ── 3. Alert Timeline ─────────────────────────────────
    # ── 3. Alert Timeline (minute-level stacked bars) ─────
    tmap = {}
    for e in stats["all_entries"]:
        ts = e["timestamp"] or ""
        # Use minute-level bucketing [:16] → "2024-01-15 08:12"
        # Falls back to hour [:13] if timestamp is shorter
        b = ts[:16] if len(ts) >= 16 else (ts[:13] if len(ts) >= 13 else "Unknown")
        if not b: b = "Unknown"
        tmap.setdefault(b, {"critical": 0, "high": 0, "medium": 0, "low": 0})
        tmap[b][e["severity"]] = tmap[b].get(e["severity"], 0) + 1

    times = sorted(tmap.keys())
    if not times:
        times = ["No data"]

    fig3 = go.Figure()
    # Draw low→critical so critical is always on top (most visible)
    for sname, bar_col, border_col in [
        ("low",      "rgba(0,204,102,0.75)",  "#00cc66"),
        ("medium",   "rgba(255,208,0,0.80)",   "#ffd000"),
        ("high",     "rgba(255,107,0,0.85)",   "#ff6b00"),
        ("critical", "rgba(255,34,68,0.90)",   "#ff2244"),
    ]:
        y_vals = [tmap[t].get(sname, 0) for t in times]
        fig3.add_trace(go.Bar(
            name=sname.capitalize(),
            x=times,
            y=y_vals,
            marker=dict(
                color=bar_col,
                line=dict(color=border_col, width=1),
            ),
            hovertemplate=(
                f"<b>{sname.capitalize()}</b><br>"
                "Time: %{x}<br>"
                "Count: <b>%{y}</b><extra></extra>"
            ),
        ))

    fig3.update_layout(
        **{k: v for k, v in BASE_LAYOUT.items() if k != "margin"},
        height=350,
        barmode="stack",
        bargap=0.15,
        hovermode="x unified",
        showlegend=True,
        title=dict(
            text="Alert Volume Over Time",
            font=dict(size=12, color="#5ab0c0"), x=0,
        ),
        legend=dict(
            orientation="h", x=0, y=1.06,
            font=dict(size=10, color="#aaccdd"),
            bgcolor="rgba(0,0,0,0)",
            traceorder="reversed",   # show Critical first in legend
        ),
        xaxis=dict(
            gridcolor="rgba(0,245,255,0.06)",
            tickfont=dict(size=9, color="#4a8a9a"),
            title=dict(text="Timestamp", font=dict(size=10, color="#6aaabb")),
            tickangle=30,
            automargin=True,
        ),
        yaxis=dict(
            gridcolor="rgba(0,245,255,0.06)",
            tickfont=dict(size=9, color="#4a8a9a"),
            title=dict(text="Alert Count", font=dict(size=10, color="#6aaabb")),
        ),
        margin=dict(t=55, b=65, l=60, r=15),
    )
    charts.append(fig3.to_json())

    # ── 4. Countries Bar ──────────────────────────────────
    c_lbl = [c[0] for c in stats["top_countries"]]
    c_val = [c[1] for c in stats["top_countries"]]
    fig4 = go.Figure(go.Bar(
        x=c_lbl, y=c_val,
        marker=dict(color=CTR_PAL[:len(c_lbl)], line=dict(color='rgba(255,100,100,0.3)', width=1)),
        hovertemplate='<b>%{x}</b><br>Attacks: <b>%{y}</b><extra></extra>'
    ))
    fig4.update_layout(
        **BASE_LAYOUT, height=310,
        title=dict(text="Top Attacking Countries", font=dict(size=12, color='#5ab0c0'), x=0),
        xaxis=dict(**AX, tickangle=30, automargin=True, title=ax_title("Country of Origin")),
        yaxis=dict(**AX, title=ax_title("Number of Attacks"))
    )
    charts.append(fig4.to_json())

    # ── 5. MITRE Tactics ──────────────────────────────────
    m_lbl = [t[0] for t in stats["top_tactics"]]
    m_val = [t[1] for t in stats["top_tactics"]]
    fig5 = go.Figure(go.Bar(
        x=m_val, y=m_lbl, orientation='h',
        marker=dict(color='rgba(0,245,255,0.75)', line=dict(color='#00f5ff', width=1)),
        hovertemplate='<b>%{y}</b><br>Events: <b>%{x}</b><extra></extra>'
    ))
    fig5.update_layout(
        **BASE_LAYOUT, height=310,
        title=dict(text="MITRE ATT&CK Tactics Detected", font=dict(size=12, color='#5ab0c0'), x=0),
        xaxis=dict(**AX, title=ax_title("Event Count")),
        yaxis=dict(**AX, automargin=True, title=ax_title("MITRE ATT&CK Tactic"))
    )
    charts.append(fig5.to_json())

    # ── 6. Confusion Matrix ───────────────────────────────
    if len(alerts) > 1:
        try:
            df_a = pd.DataFrame(alerts)
            if "manual" in df_a and "ai_severity" in df_a:
                lbls = ["Low", "Medium", "High", "Critical"]
                cm = confusion_matrix(df_a["manual"], df_a["ai_severity"], labels=lbls)
                fig6 = px.imshow(
                    cm, x=lbls, y=lbls, color_continuous_scale='Blues',
                    labels=dict(x="AI Predicted Severity", y="Analyst Manual Severity", color="Count"),
                    title="AI vs Manual Severity Agreement Matrix"
                )
                fig6.update_layout(**BASE_LAYOUT, height=310)
                charts.append(fig6.to_json())
            else:
                charts.append(None)
        except:
            charts.append(None)
    else:
        charts.append(None)

    # ── 7. Threat Gauge ───────────────────────────────────
    # ── 7. Threat Gauge (no overlapping text) ────────────
    high_c = stats["high"] + stats["critical"]
    total  = max(stats["total"], 1)
    t30    = max(int(total * 0.3), 1)
    t60    = max(int(total * 0.6), 2)
    pct    = round((high_c / total) * 100, 1)

    if pct > 60:
        risk_label = "CRITICAL RISK"
        risk_color = "#ff2244"
    elif pct > 30:
        risk_label = "HIGH RISK"
        risk_color = "#ff6b00"
    elif pct > 10:
        risk_label = "MODERATE"
        risk_color = "#ffd000"
    else:
        risk_label = "LOW RISK"
        risk_color = "#00cc66"

    fig7 = go.Figure(go.Indicator(
        mode="gauge+number",
        value=high_c,
        number={
            "font":   {"color": "#00f5ff", "size": 38, "family": "Consolas"},
            "suffix": f" / {total}",
        },
        # Use title ONLY for the top label — keep it short, no HTML span
        title={
            "text": "HIGH + CRITICAL",
            "font": {"color": "#00f5ff", "size": 11, "family": "Consolas"},
        },
        gauge={
            "axis": {
                "range":     [0, total],
                "tickcolor": "#4a8a9a",
                "tickfont":  {"size": 9, "color": "#4a8a9a"},
                "nticks":    6,
            },
            "bar":       {"color": "#ff2244", "thickness": 0.22},
            "bgcolor":   "#0a1a2a",
            "borderwidth": 0,
            "steps": [
                {"range": [0,      t30],  "color": "#0d2e0d"},
                {"range": [t30,    t60],  "color": "#2a2a08"},
                {"range": [t60,  total],  "color": "#2e0d0d"},
            ],
            "threshold": {
                "line":      {"color": "#ffffff", "width": 2},
                "thickness": 0.75,
                "value":     high_c,
            },
        },
        # Shrink domain vertically so number sits inside arc, not below it
        domain={"x": [0.05, 0.95], "y": [0.12, 1.0]},
    ))

    # Risk label goes in the space BELOW the gauge (y=0.02, safely below number)
    fig7.add_annotation(
        text=f"● {risk_label}  —  {pct}% of {total} logs",
        x=0.5, y=0.04,
        xref="paper", yref="paper",
        showarrow=False,
        font=dict(size=10, color=risk_color, family="Consolas"),
        align="center",
        bgcolor="rgba(0,0,0,0.4)",
        borderpad=3,
    )

    fig7.update_layout(
        **{k: v for k, v in BASE_LAYOUT.items() if k != "margin"},
        height=340,
        margin=dict(t=20, b=40, l=20, r=20),
    )
    charts.append(fig7.to_json())

    # ── 8. Source IPs ─────────────────────────────────────
    i_lbl = [i[0] for i in stats["top_ips"]]
    i_val = [i[1] for i in stats["top_ips"]]
    fig8 = go.Figure(go.Bar(
        x=i_val, y=i_lbl, orientation='h',
        marker=dict(color='rgba(170,102,255,0.78)', line=dict(color='#aa66ff', width=1)),
        hovertemplate='<b>%{y}</b><br>Events: <b>%{x}</b><extra></extra>'
    ))
    fig8.update_layout(
        **BASE_LAYOUT, height=310,
        title=dict(text="Top Attacking Source IPs", font=dict(size=12, color='#5ab0c0'), x=0),
        xaxis=dict(**AX, title=ax_title("Number of Events")),
        yaxis=dict(**AX, automargin=True, title=ax_title("Source IP Address"))
    )
    charts.append(fig8.to_json())

    return charts

print("✅ Chart builder ready.")

# ══════════════════════════════════════════════════════════════
# CELL 8 — PDF REPORT GENERATOR
# ══════════════════════════════════════════════════════════════

def generate_pdf(stats, ai_text, summary_text, manual_severity, override, entries):
    ai_data   = parse_ai_output(ai_text) if ai_text else {}
    final_sev = override if override != "None" else ai_data.get("severity","Unknown")
    case_id   = f"SOC-{datetime.now().strftime('%Y%m%d')}-{random.randint(100,999)}"
    timestamp = datetime.now().strftime("%d %B %Y — %H:%M:%S UTC")
    buffer = io.BytesIO()

    doc = SimpleDocTemplate(buffer,
                            pagesize=(8.5*inch, 11*inch),
                            leftMargin=0.75*inch, rightMargin=0.75*inch,
                            topMargin=0.75*inch,  bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()
    elems  = []

    # ── Helpers ───────────────────────────────────────────
    def h1(t):
        return Paragraph(t, ParagraphStyle('H1', parent=styles['Heading1'],
                                           fontSize=13, spaceAfter=8, spaceBefore=12))
    def body(t):
        return Paragraph(str(t)[:1000],
                         ParagraphStyle('BD', parent=styles['Normal'],
                                        fontSize=9, leading=14, spaceAfter=5))
    def gap(n=10): return Spacer(1, n)
    def sc(v, n=55): return str(v)[:n] if v and v != "N/A" else "N/A"

    def pdf_table(data, widths=None):
        t = Table(data, colWidths=widths or [2.2*inch, 4.3*inch], repeatRows=1)
        t.setStyle(TableStyle([
            ('GRID',         (0,0),(-1,-1), 0.4, rl_colors.HexColor('#bbbbbb')),
            ('BACKGROUND',   (0,0),(-1,0),  rl_colors.HexColor('#1a3a5c')),
            ('TEXTCOLOR',    (0,0),(-1,0),  rl_colors.white),
            ('FONTNAME',     (0,0),(-1,0),  'Helvetica-Bold'),
            ('FONTNAME',     (0,1),(-1,-1), 'Helvetica'),
            ('FONTSIZE',     (0,0),(-1,-1), 8),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[rl_colors.HexColor('#f0f5ff'),
                                             rl_colors.white]),
            ('VALIGN',       (0,0),(-1,-1), 'TOP'),
            ('PADDING',      (0,0),(-1,-1), 5),
        ]))
        return t

    # ── Cover Page ────────────────────────────────────────
    elems += [
        gap(30),
        Paragraph("CYBERSENTINEL PRO",
                  ParagraphStyle('brand', parent=styles['Title'],
                                 fontSize=24, textColor=rl_colors.HexColor('#003366'),
                                 spaceAfter=5)),
        Paragraph("Blue Team SOC — Incident Investigation Report",
                  ParagraphStyle('sub', parent=styles['Normal'],
                                 fontSize=12, textColor=rl_colors.HexColor('#555'),
                                 spaceAfter=22)),
        gap(12),
        pdf_table([
            ["Case ID",        case_id],
            ["Generated",      timestamp],
            ["Classification", "CONFIDENTIAL — Authorised Personnel Only"],
            ["Tool",           "CyberSentinel Pro v2.0 | MSc Cybersecurity Project"],
            ["Final Severity", final_sev.upper()],
            ["Manual Review",  manual_severity],
            ["Total Logs",     str(stats.get("total",0))],
            ["Suspicious",     str(stats.get("suspicious",0))],
        ]),
        gap(20),
        PageBreak(),
    ]

    # ── 1. Executive Summary ──────────────────────────────
    elems += [h1("1. Executive Summary"), gap(6)]
    for para in summary_text.split('\n\n'):
        if para.strip(): elems += [body(para.strip()), gap(4)]
    elems.append(gap(12))

    # ── 2. AI Threat Analysis ─────────────────────────────
    mitre_cell = (sc(ai_data.get("mitre_tech_id"),12) + " — " +
                  sc(ai_data.get("mitre_tech"),38))
    elems += [h1("2. AI Threat Analysis"), gap(6),
              pdf_table([
                  ["Field",           "AI Assessment"],
                  ["Attack Type",     sc(ai_data.get("attack_type"),55)],
                  ["Severity",        sc(ai_data.get("severity"),20)],
                  ["Confidence",      sc(ai_data.get("confidence"),10) + " %"],
                  ["Risk Score",      sc(ai_data.get("risk_score"),10) + " / 100"],
                  ["MITRE Tactic ID", sc(ai_data.get("mitre_tactic_id"),15)],
                  ["MITRE Tactic",    sc(ai_data.get("mitre_tactic"),40)],
                  ["MITRE Technique", mitre_cell],
                  ["Manual Severity", sc(manual_severity,20)],
                  ["Final Severity",  final_sev.upper()],
              ]),
              gap(14)]

    # ── 3. IOCs ───────────────────────────────────────────
    elems += [h1("3. Indicators of Compromise"), gap(6)]
    iocs = ai_data.get("iocs",[])
    if iocs:
        rows = [["#","Indicator"]] + [[str(i+1), sc(ioc,80)] for i,ioc in enumerate(iocs[:12])]
        elems.append(pdf_table(rows, widths=[0.4*inch, 6.1*inch]))
    else:
        elems.append(body("No specific IOCs extracted. Perform manual identification."))
    elems.append(gap(14))

    # ── 4. Recommended Actions ────────────────────────────
    elems += [h1("4. Recommended Analyst Actions"), gap(6)]
    actions = ai_data.get("actions",[])
    if actions:
        rows2 = [["#","Action"]] + [[f"#{i+1}", sc(a,95)] for i,a in enumerate(actions[:10])]
        elems.append(pdf_table(rows2, widths=[0.4*inch, 6.1*inch]))
    else:
        elems.append(body("Perform manual triage based on detected severity."))
    elems.append(gap(14))

    # ── 5. Risk Reasoning ────────────────────────────────
    elems += [h1("5. Risk Assessment & Reasoning"), gap(6),
              body(ai_data.get("reasoning","No AI reasoning available.")), gap(14)]

    # ── 6. Log Statistics ─────────────────────────────────
    top_a = stats["top_attacks"][0][0]   if stats.get("top_attacks")   else "N/A"
    top_c = stats["top_countries"][0][0] if stats.get("top_countries") else "N/A"
    elems += [h1("6. Log Statistics"), gap(6),
              pdf_table([
                  ["Metric","Value"],
                  ["Total Entries",   str(stats.get("total",0))],
                  ["Suspicious",      str(stats.get("suspicious",0))],
                  ["Critical",        str(stats.get("critical",0))],
                  ["High",            str(stats.get("high",0))],
                  ["Medium",          str(stats.get("medium",0))],
                  ["Low",             str(stats.get("low",0))],
                  ["Countries",       str(len(stats.get("top_countries",[])))],
                  ["Unique IPs",      str(len(stats.get("top_ips",[])))],
                  ["Top Attack",      sc(top_a,45)],
                  ["Top Country",     sc(top_c,30)],
              ]),
              gap(14)]

    # ── 7. Top Suspicious Entries ─────────────────────────
    if entries:
        elems += [h1("7. Top Suspicious Log Entries"), gap(6)]
        rows3 = [["Time","Source IP","Country","Attack Type","Sev","Score"]]
        for e in sorted(entries, key=lambda x: x.get("severity_score",0), reverse=True)[:12]:
            rows3.append([
                sc(e.get("timestamp","")[-8:],10),
                sc(e.get("source_ip",""),16),
                sc(e.get("country",""),14),
                sc(e.get("attack_type",""),22),
                sc(e.get("severity","").upper(),8),
                str(e.get("severity_score",""))[:5],
            ])
        t3 = Table(rows3,
                   colWidths=[0.7*inch,1.2*inch,1.05*inch,1.65*inch,0.7*inch,0.5*inch],
                   repeatRows=1)
        t3.setStyle(TableStyle([
            ('GRID',         (0,0),(-1,-1), 0.4, rl_colors.HexColor('#bbbbbb')),
            ('BACKGROUND',   (0,0),(-1,0),  rl_colors.HexColor('#1a3a5c')),
            ('TEXTCOLOR',    (0,0),(-1,0),  rl_colors.white),
            ('FONTNAME',     (0,0),(-1,-1), 'Helvetica'),
            ('FONTSIZE',     (0,0),(-1,-1), 7.5),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[rl_colors.HexColor('#f0f5ff'),
                                             rl_colors.white]),
            ('VALIGN',       (0,0),(-1,-1), 'MIDDLE'),
            ('PADDING',      (0,0),(-1,-1), 4),
        ]))
        elems += [t3, gap(14)]

    # ── 8. Charts Page ────────────────────────────────────
    elems += [PageBreak(), h1("8. Analytics Charts"), gap(8)]

    chart_defs = [
        ("Severity Distribution",
         lambda: go.Figure(go.Pie(
             labels=list(stats["severity_dist"].keys()),
             values=list(stats["severity_dist"].values()),
             hole=0.45,
             marker_colors=[SEV_COLORS.get(k,"#888") for k in stats["severity_dist"]]
         ))),
        ("Top Attack Types",
         lambda: go.Figure(go.Bar(
             x=[a[1] for a in stats["top_attacks"]],
             y=[a[0] for a in stats["top_attacks"]],
             orientation='h', marker_color='steelblue'
         ))),
        ("Top Attacking Countries",
         lambda: go.Figure(go.Bar(
             x=[c[0] for c in stats["top_countries"]],
             y=[c[1] for c in stats["top_countries"]],
             marker_color='tomato'
         ))),
    ]

    for title, fig_fn in chart_defs:
        try:
            fig = fig_fn()
            fig.update_layout(title=title, paper_bgcolor='white',
                              plot_bgcolor='white', font=dict(color='#111'),
                              margin=dict(t=40,b=30,l=20,r=20),
                              yaxis=dict(automargin=True))
            chart_bytes = fig.to_image(format="png", width=640, height=310, scale=2)
            chart_buffer = io.BytesIO(chart_bytes)
            elems += [RLImage(chart_buffer, width=5.0*inch, height=2.4*inch), gap(10)]
        except Exception as ce:
            elems.append(body(f"[{title} unavailable: {ce}]"))

    # ── Footer ────────────────────────────────────────────
    elems += [
        PageBreak(), gap(50),
        Paragraph("CLASSIFICATION: CONFIDENTIAL",
                  ParagraphStyle('clf', parent=styles['Normal'],
                                 fontSize=11, textColor=rl_colors.HexColor('#cc0000'),
                                 spaceAfter=8)),
        body(f"Generated by CyberSentinel Pro v2.0 on {timestamp}."),
        body("All AI analysis is advisory. Final decisions rest with the authorised analyst."),
        body("Human-in-the-loop confirmation mandatory before any remediation action."),
        gap(16),
        pdf_table([
            ["Analyst Signature","________________________"],
            ["Date",             datetime.now().strftime("%d / %m / %Y")],
            ["Case ID",          case_id],
        ]),
    ]

    doc.build(elems)
    buffer.seek(0)
    return buffer, case_id

print("✅ PDF generator ready.")

# ══════════════════════════════════════════════════════════════
# CELL 9 — FLASK APP + HTML
# ══════════════════════════════════════════════════════════════

app = Flask(__name__)

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>CyberSentinel Pro — Blue Team SOC</title>
<script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
<script src="https://unpkg.com/three@0.150.1/build/three.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/topojson-client@3"></script>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@400;600;700;900&display=swap" rel="stylesheet"/>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#050a0f;--bg2:#090f17;--panel:#0b1e30;
  --border:#1a3350;--border2:#0f2035;
  --accent:#00f5ff;--accent2:#0099cc;
  --red:#ff2244;--orange:#ff6b00;--yellow:#ffd000;--green:#00ff88;
  --text:#c8dff0;--muted:#4a6a80;
  --mono:'Share Tech Mono',monospace;
  --main:'Exo 2',sans-serif;
}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--main);min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,245,255,0.012) 2px,rgba(0,245,255,0.012) 4px);
  pointer-events:none;z-index:9999}
body::after{content:'';position:fixed;inset:0;
  background-image:linear-gradient(rgba(0,245,255,0.022) 1px,transparent 1px),
    linear-gradient(90deg,rgba(0,245,255,0.022) 1px,transparent 1px);
  background-size:40px 40px;pointer-events:none;z-index:0}

/* SIDEBAR */
.sidebar{position:fixed;left:-270px;top:0;width:260px;height:100%;
  background:linear-gradient(180deg,#071a33,#031020);
  transition:.35s ease;padding:30px 22px;z-index:1000;
  box-shadow:0 0 40px rgba(0,245,255,.1)}
.sidebar.open{left:0}
.sidebar h2{font-family:var(--mono);color:var(--accent);font-size:15px;
  letter-spacing:2px;margin-bottom:28px;border-bottom:1px solid var(--border);padding-bottom:12px}
.sidebar a{display:block;padding:10px 0;color:var(--text);text-decoration:none;
  font-size:13px;border-bottom:1px solid var(--border2);transition:.2s;font-family:var(--mono)}
.sidebar a:hover{color:var(--accent);padding-left:8px}
.sb-stats{margin-top:20px;font-family:var(--mono);font-size:11px;color:var(--muted);line-height:2.1}
.nav-toggle{position:fixed;left:16px;top:16px;font-size:21px;cursor:pointer;
  z-index:1100;color:var(--accent);background:rgba(0,0,0,.45);padding:6px 10px;
  border-radius:6px;border:1px solid var(--border)}

/* HEADER */
header{position:relative;z-index:10;
  background:linear-gradient(180deg,rgba(0,20,40,.98),rgba(5,10,15,.95));
  border-bottom:1px solid var(--border);padding:0 50px 0 70px;
  display:flex;align-items:center;justify-content:space-between;height:66px;
  box-shadow:0 0 40px rgba(0,245,255,.06)}
.logo{display:flex;align-items:center;gap:14px}
.logo-icon{width:40px;height:40px;border:2px solid var(--accent);border-radius:8px;
  display:flex;align-items:center;justify-content:center;font-size:18px;
  background:rgba(0,245,255,.07);box-shadow:0 0 15px rgba(0,245,255,.3)}
.logo-text{font-family:var(--mono);font-size:17px;letter-spacing:3px;
  color:var(--accent);text-shadow:0 0 20px rgba(0,245,255,.5)}
.logo-sub{font-size:10px;color:var(--muted);letter-spacing:2px;margin-top:2px}
.hdr-right{display:flex;gap:16px;align-items:center}
.pulse{width:8px;height:8px;border-radius:50%;background:var(--green);
  box-shadow:0 0 8px var(--green);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.hdr-txt{font-family:var(--mono);font-size:12px;color:var(--muted)}

/* BANNER */
.banner{background:linear-gradient(90deg,#8b0000,#cc0000,#8b0000);
  text-align:center;padding:10px;font-weight:bold;font-family:var(--mono);
  letter-spacing:2px;font-size:13px;animation:blink 1.2s infinite;
  position:relative;z-index:5}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.45}}

/* MAIN */
main{position:relative;z-index:1;max-width:1500px;margin:0 auto;padding:26px 28px}

/* KPI */
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(135px,1fr));
  gap:12px;margin-bottom:22px}
.kpi{background:var(--panel);border:1px solid var(--border2);border-radius:10px;
  padding:16px 12px;text-align:center;position:relative;overflow:hidden;
  transition:transform .2s,box-shadow .2s;cursor:default}
.kpi:hover{transform:translateY(-4px);box-shadow:0 8px 24px rgba(0,0,0,.4)}
.kpi::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:var(--kc,var(--accent))}
.kpi-val{font-family:var(--mono);font-size:28px;font-weight:700;
  color:var(--kc,var(--accent));line-height:1}
.kpi-lbl{font-size:10px;color:var(--muted);letter-spacing:2px;
  text-transform:uppercase;margin-top:5px}
.kpi-ico{font-size:17px;margin-bottom:5px}

/* GLOBE + MAP */
#globeViz{position:relative;width:100%;height:500px;border-radius:12px;
  overflow:hidden;margin-bottom:22px;border:1px solid #2a3c52;background:#000;
  box-shadow:0 0 40px rgba(40,70,100,.15)}
#extGlobe{position:absolute;inset:0;width:100%;height:100%;border:0;z-index:45;background:#000}
#gCanvas{position:absolute;top:0;left:0;width:100%;height:100%;display:block}
#mDiv{position:absolute;top:0;left:0;width:100%;height:100%;opacity:0;pointer-events:none;transition:opacity .5s}
#mDiv.mshow{opacity:1;pointer-events:all}
#gCanvas.mhide{opacity:0;pointer-events:none;transition:opacity .5s}
#mapCtrls{position:absolute;top:12px;right:12px;z-index:50;display:none;flex-direction:column;gap:4px}
.mcb{width:32px;height:32px;background:rgba(6,10,16,.9);border:1px solid rgba(85,170,220,.35);
  border-radius:5px;color:#78d5ff;font-size:13px;cursor:pointer;
  display:flex;align-items:center;justify-content:center;transition:all .2s;font-family:monospace;user-select:none}
.mcb:hover{background:rgba(95,165,220,.16);border-color:rgba(135,205,255,.8)}
.mcb.mon{background:rgba(95,165,220,.22);border-color:#7fd4ff;box-shadow:0 0 10px rgba(90,170,230,.28)}
.mcsep{height:1px;background:rgba(110,170,220,.28);margin:2px 4px}
#globeViz.light-map{border-color:#3d6b67;box-shadow:0 0 40px rgba(90,130,150,.14)}
#globeViz.light-map .mcb{background:rgba(220,250,248,.8);border-color:rgba(46,108,104,.45);color:#176b67}
#globeViz.light-map .mcb:hover{background:rgba(180,235,230,.95);border-color:rgba(34,112,103,.8)}
#globeViz.light-map .mcb.mon{background:rgba(60,168,151,.2);border-color:#228e82;box-shadow:0 0 10px rgba(26,114,106,.25)}

/* SECTION TITLE */
.stitle{font-family:var(--mono);font-size:11px;letter-spacing:3px;
  color:var(--accent);text-transform:uppercase;
  display:flex;align-items:center;gap:8px;margin-bottom:13px}
.stitle::before{content:'// ';opacity:.5}

/* PANELS */
.panel{background:var(--panel);border:1px solid var(--border2);border-radius:10px;
  padding:20px;margin-bottom:20px;box-shadow:0 4px 18px rgba(0,0,0,.3)}

/* UPLOAD */
.upload-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:860px){.upload-grid{grid-template-columns:1fr}}
.drop-zone{border:2px dashed var(--border);border-radius:10px;
  padding:34px 14px;text-align:center;cursor:pointer;
  transition:all .3s;background:var(--bg2);position:relative;overflow:hidden}
.drop-zone:hover,.drop-zone.drag{border-color:var(--accent);
  background:rgba(0,245,255,.04);box-shadow:0 0 20px rgba(0,245,255,.1)}
.drop-zone input{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
.drop-ico{font-size:36px;margin-bottom:10px}
.drop-title{font-size:15px;font-weight:600;color:var(--accent);margin-bottom:5px}
.drop-sub{font-size:11px;color:var(--muted);font-family:var(--mono)}
.paste-area{display:flex;flex-direction:column;gap:8px}
.paste-area label{font-family:var(--mono);font-size:11px;color:var(--muted);letter-spacing:1px}
textarea{width:100%;background:var(--bg2);border:1px solid var(--border);
  border-radius:8px;color:var(--text);font-family:var(--mono);font-size:11px;
  padding:12px;resize:vertical;min-height:128px;transition:border-color .3s;line-height:1.5}
textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 10px rgba(0,245,255,.08)}
textarea::placeholder{color:var(--muted)}
.form-row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin-top:14px}
.form-row input,.form-row select{background:var(--bg2);border:1px solid var(--border);
  border-radius:8px;color:var(--text);font-family:var(--mono);font-size:12px;padding:10px 12px;
  transition:border-color .3s}
.form-row input{flex:1;min-width:190px}
.form-row select{min-width:120px}
.form-row input:focus,.form-row select:focus{outline:none;border-color:var(--accent)}
.form-row select option{background:#0b1e30}
.btn-go{background:linear-gradient(135deg,var(--accent),var(--accent2));
  color:#000;font-family:var(--mono);font-weight:700;font-size:12px;letter-spacing:2px;
  text-transform:uppercase;border:none;border-radius:8px;padding:12px 26px;
  cursor:pointer;transition:all .3s;white-space:nowrap;
  box-shadow:0 0 20px rgba(0,245,255,.25)}
.btn-go:hover{transform:translateY(-2px);box-shadow:0 0 30px rgba(0,245,255,.45)}
.btn-go:disabled{opacity:.4;cursor:not-allowed;transform:none}

/* LOADING */
#loading{display:none;text-align:center;padding:48px}
.spinner{width:46px;height:46px;border:3px solid var(--border);
  border-top-color:var(--accent);border-radius:50%;
  animation:spin 1s linear infinite;margin:0 auto 16px}
@keyframes spin{to{transform:rotate(360deg)}}
.load-txt{font-family:var(--mono);font-size:13px;color:var(--accent);
  letter-spacing:2px;animation:blink 1s step-end infinite}

/* CHARTS */
.chart-2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:18px}
@media(max-width:800px){.chart-2{grid-template-columns:1fr}}
.chart-box{background:var(--panel);border:1px solid var(--border2);
  border-radius:10px;padding:16px;min-height:350px;overflow:hidden}

/* AI OUTPUT */
.ai-out{background:var(--bg2);border:1px solid var(--border);border-radius:8px;
  padding:16px;max-height:400px;overflow-y:auto;
  white-space:pre-wrap;font-family:var(--mono);font-size:11.5px;
  color:var(--green);line-height:1.7;border-left:3px solid var(--green)}

/* TABLE */
.tbl-wrap{overflow-x:auto}
.filter-row{display:flex;gap:8px;margin-bottom:11px;flex-wrap:wrap;align-items:center}
.fbtn{background:var(--bg2);border:1px solid var(--border);border-radius:6px;
  color:var(--muted);font-family:var(--mono);font-size:11px;
  padding:5px 13px;cursor:pointer;transition:all .2s;letter-spacing:1px}
.fbtn.on,.fbtn:hover{border-color:var(--accent);color:var(--accent);background:rgba(0,245,255,.06)}
.fbtn.cr.on{border-color:var(--red);color:var(--red);background:rgba(255,34,68,.06)}
.fbtn.hi.on{border-color:var(--orange);color:var(--orange)}
.fbtn.me.on{border-color:var(--yellow);color:var(--yellow)}
table{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:11.5px}
thead th{background:rgba(0,245,255,.05);color:var(--accent);padding:9px 11px;
  text-align:left;border-bottom:1px solid var(--border);
  font-size:10px;letter-spacing:2px;text-transform:uppercase;white-space:nowrap}
tbody tr{border-bottom:1px solid var(--border2);transition:background .14s;cursor:pointer}
tbody tr:hover{background:rgba(0,245,255,.034)}
tbody td{padding:8px 11px;vertical-align:middle;max-width:200px;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sb{display:inline-block;padding:2px 9px;border-radius:20px;font-size:10px;
  font-weight:700;letter-spacing:1px;text-transform:uppercase;border:1px solid}
.s-cr{color:var(--red);border-color:var(--red);background:rgba(255,34,68,.1)}
.s-hi{color:var(--orange);border-color:var(--orange);background:rgba(255,107,0,.1)}
.s-me{color:var(--yellow);border-color:var(--yellow);background:rgba(255,208,0,.1)}
.s-lo{color:var(--green);border-color:var(--green);background:rgba(0,255,136,.07)}
.sc-bg{width:50px;height:5px;background:var(--bg2);border-radius:3px;
  display:inline-block;vertical-align:middle;margin-right:5px;overflow:hidden}
.sc-fill{height:100%;border-radius:3px}

/* INCIDENT CARDS */
.cards-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));
  gap:13px;margin-bottom:20px}
.ic{background:var(--panel);border:1px solid var(--border2);border-radius:10px;
  padding:16px;transition:transform .2s,box-shadow .2s;
  border-left:3px solid var(--cc,var(--accent))}
.ic:hover{transform:translateY(-3px);box-shadow:0 10px 28px rgba(0,0,0,.4)}
.ic-head{display:flex;justify-content:space-between;align-items:flex-start;
  margin-bottom:10px;gap:8px}
.ic-title{font-size:13px;font-weight:700;color:#fff;flex:1}
.ic-meta{font-family:var(--mono);font-size:11px;color:var(--muted);
  margin-bottom:9px;line-height:1.85}
.ic-ex{font-size:12px;color:var(--text);background:var(--bg2);
  padding:9px 11px;border-radius:6px;border-left:2px solid var(--border);
  margin-bottom:8px;line-height:1.6}
.ic-ac{font-size:12px;color:var(--text);background:rgba(255,107,0,.05);
  padding:9px 11px;border-radius:6px;border-left:2px solid var(--orange);
  margin-bottom:10px;line-height:1.6}
.mt-tags{display:flex;flex-wrap:wrap;gap:5px;margin-bottom:10px}
.mt{background:rgba(0,245,255,.06);border:1px solid var(--border);
  color:var(--accent);font-family:var(--mono);font-size:10px;
  padding:2px 7px;border-radius:4px}
.card-btns{display:flex;gap:7px;flex-wrap:wrap}
.cbtn{font-family:var(--mono);font-size:10px;letter-spacing:1px;border:1px solid;
  border-radius:5px;padding:5px 13px;cursor:pointer;transition:all .2s;
  text-transform:uppercase;background:transparent}
.c-ok{color:var(--green);border-color:var(--green)}
.c-ok:hover{background:rgba(0,255,136,.08)}
.c-esc{color:var(--orange);border-color:var(--orange)}
.c-esc:hover{background:rgba(255,107,0,.08)}
.c-dis{color:var(--muted);border-color:var(--muted)}
.c-dis:hover{background:rgba(255,255,255,.04)}

/* ── Escalation / Confirm modal ─────────────────────────── */
.esc-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.88);
  z-index:2000;align-items:center;justify-content:center;backdrop-filter:blur(5px)}
.esc-overlay.open{display:flex}
.esc-modal{background:var(--panel);border:1px solid var(--orange);border-radius:12px;
  padding:26px;max-width:620px;width:94%;font-family:var(--mono);font-size:12px;
  box-shadow:0 0 40px rgba(255,107,0,.2)}
.esc-modal.confirm{border-color:var(--green);box-shadow:0 0 40px rgba(0,255,136,.15)}
.esc-modal h3{font-size:14px;letter-spacing:2px;margin-bottom:16px}
.esc-modal h3.esc-h{color:var(--orange)}
.esc-modal h3.con-h{color:var(--green)}
.esc-field{margin-bottom:12px}
.esc-field label{display:block;font-size:10px;color:var(--muted);
  letter-spacing:1px;text-transform:uppercase;margin-bottom:4px}
.esc-field input,.esc-field textarea,.esc-field select{
  width:100%;background:var(--bg2);border:1px solid var(--border);
  border-radius:6px;color:var(--text);font-family:var(--mono);
  font-size:11px;padding:9px 11px;transition:border-color .2s}
.esc-field input:focus,.esc-field textarea:focus{
  outline:none;border-color:var(--accent)}
.esc-field textarea{min-height:100px;resize:vertical;line-height:1.6}
.esc-btns{display:flex;gap:10px;justify-content:flex-end;margin-top:16px}
.esc-send{background:linear-gradient(135deg,#ff6b00,#cc4400);color:#fff;
  border:none;border-radius:6px;padding:9px 22px;font-family:var(--mono);
  font-size:11px;letter-spacing:1px;cursor:pointer;transition:all .2s}
.esc-send:hover{transform:translateY(-1px);box-shadow:0 4px 16px rgba(255,107,0,.4)}
.esc-send.green{background:linear-gradient(135deg,#00aa44,#006622)}
.esc-send.green:hover{box-shadow:0 4px 16px rgba(0,255,136,.3)}
.esc-cancel{background:transparent;border:1px solid var(--border);color:var(--muted);
  border-radius:6px;padding:9px 16px;font-family:var(--mono);font-size:11px;cursor:pointer}
.esc-cancel:hover{border-color:var(--red);color:var(--red)}
.email-preview{background:var(--bg2);border:1px solid var(--border);
  border-left:3px solid var(--orange);border-radius:6px;padding:12px;
  font-size:11px;color:var(--text);white-space:pre-wrap;
  max-height:180px;overflow-y:auto;line-height:1.7;margin-bottom:12px}
.email-preview.green{border-left-color:var(--green)}
.badge-sent{display:inline-block;background:rgba(0,255,136,.12);
  border:1px solid var(--green);color:var(--green);font-size:10px;
  padding:2px 9px;border-radius:20px;margin-left:8px;letter-spacing:1px}

/* MODAL */
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.82);
  z-index:1000;align-items:center;justify-content:center;backdrop-filter:blur(4px)}
.overlay.open{display:flex}
.modal{background:var(--panel);border:1px solid var(--border);border-radius:12px;
  padding:24px;max-width:670px;width:92%;max-height:80vh;overflow-y:auto;
  font-family:var(--mono);font-size:12px}
.modal h3{color:var(--accent);font-size:14px;margin-bottom:13px;letter-spacing:2px}
.modal pre{background:var(--bg2);padding:12px;border-radius:6px;overflow-x:auto;
  color:var(--text);font-size:10.5px;line-height:1.6;white-space:pre-wrap;word-break:break-all}
.mclose{float:right;background:none;border:1px solid var(--border);color:var(--muted);
  padding:3px 10px;border-radius:4px;cursor:pointer;font-family:var(--mono);font-size:11px}
.mclose:hover{color:var(--red);border-color:var(--red)}
.mf{margin-bottom:9px}
.mf .ml{color:var(--muted);font-size:10px;letter-spacing:1px;text-transform:uppercase;margin-bottom:2px}
.mf .mv{color:var(--text);font-size:12px}

/* TOAST */
.toast{position:fixed;bottom:26px;right:26px;z-index:2000;
  background:var(--panel);border:1px solid var(--border);border-radius:8px;
  padding:12px 18px;font-family:var(--mono);font-size:12px;
  transform:translateX(220%);transition:transform .3s;
  box-shadow:0 10px 28px rgba(0,0,0,.5)}
.toast.show{transform:translateX(0)}
.toast.ok{border-left:3px solid var(--green);color:var(--green)}
.toast.err{border-left:3px solid var(--red);color:var(--red)}

/* EXPORT */
.exp-row{display:flex;gap:10px;flex-wrap:wrap;justify-content:center;margin-bottom:26px}
.exp-btn{background:transparent;border:1px solid var(--border);border-radius:6px;
  color:var(--muted);font-family:var(--mono);font-size:11px;letter-spacing:1px;
  padding:8px 18px;cursor:pointer;transition:all .2s;text-decoration:none;display:inline-block}
.exp-btn:hover{border-color:var(--accent);color:var(--accent)}

footer{position:relative;z-index:1;text-align:center;padding:20px;
  border-top:1px solid var(--border2);font-family:var(--mono);font-size:11px;
  color:var(--muted);letter-spacing:1px}
</style>
</head>
<body>

<div class="nav-toggle" onclick="document.getElementById('sb').classList.toggle('open')">☰</div>
<div class="sidebar" id="sb">
  <h2>🛡️ SOC NAVIGATOR</h2>
  <a href="#">📊 Dashboard</a>
  <a href="#upload-panel">📁 Log Analysis</a>
  <a href="#dash-section">📈 Analytics</a>
  <a href="#tbl-section">📋 Alert Feed</a>
  <a href="#cards-section">📝 Report Cards</a>
  <a href="#" onclick="downloadPDF();return false;">⬇️ Export PDF</a>
  <div class="sb-stats">
    Cases: <span id="sb-total">0</span><br>
    Critical: <span id="sb-crit" style="color:var(--red)">0</span><br>
    High: <span id="sb-high" style="color:var(--orange)">0</span><br>
    Status: <span style="color:var(--green);font-weight:bold">● ONLINE</span>
  </div>
</div>

<header>
  <div class="logo">
    <div class="logo-icon">🛡️</div>
    <div>
      <div class="logo-text">CYBERSENTINEL PRO</div>
      <div class="logo-sub">Blue Team SOC Decision-Support Tool</div>
    </div>
  </div>
  <div class="hdr-right">
    <div class="pulse"></div>
    <div class="hdr-txt" id="clock"></div>
  </div>
</header>

{% if show_banner %}
<div class="banner">🚨 CRITICAL / HIGH THREAT DETECTED — IMMEDIATE ANALYST REVIEW REQUIRED 🚨</div>
{% endif %}

<main>
  <!-- KPI Cards -->
  <div class="kpi-grid">
    <div class="kpi" style="--kc:var(--accent)"><div class="kpi-ico">📋</div><div class="kpi-val" id="kv-total">{{ total }}</div><div class="kpi-lbl">Total Logs</div></div>
    <div class="kpi" style="--kc:var(--orange)"><div class="kpi-ico">⚠️</div><div class="kpi-val" id="kv-susp">{{ suspicious }}</div><div class="kpi-lbl">Suspicious</div></div>
    <div class="kpi" style="--kc:var(--red)"><div class="kpi-ico">🚨</div><div class="kpi-val" id="kv-crit">{{ critical }}</div><div class="kpi-lbl">Critical</div></div>
    <div class="kpi" style="--kc:var(--orange)"><div class="kpi-ico">🟠</div><div class="kpi-val" id="kv-high">{{ high }}</div><div class="kpi-lbl">High</div></div>
    <div class="kpi" style="--kc:var(--yellow)"><div class="kpi-ico">🟡</div><div class="kpi-val" id="kv-med">{{ medium }}</div><div class="kpi-lbl">Medium</div></div>
    <div class="kpi" style="--kc:var(--green)"><div class="kpi-ico">🟢</div><div class="kpi-val" id="kv-low">{{ low }}</div><div class="kpi-lbl">Low</div></div>
    <div class="kpi" style="--kc:#aa66ff"><div class="kpi-ico">🌍</div><div class="kpi-val" id="kv-ctr">{{ countries }}</div><div class="kpi-lbl">Countries</div></div>
    <div class="kpi" style="--kc:#00ccaa"><div class="kpi-ico">📡</div><div class="kpi-val" id="kv-ips">{{ unique_ips }}</div><div class="kpi-lbl">Unique IPs</div></div>
  </div>

  <!-- Globe / Map -->
  <div id="globeViz">
    <canvas id="gCanvas"></canvas>
    <div id="mDiv"><div id="mapPlot" style="width:100%;height:100%"></div></div>
    <iframe id="extGlobe" src="/globe_flatmap_final?v=20260326-flatfix1" title="Integrated Globe Map"></iframe>
    <div id="mapCtrls">
      <div class="mcb mon" id="btnGlobe" onclick="switchView('globe')" title="Globe">◯</div>
      <div class="mcb" id="btnMap" onclick="switchView('map')" title="Map">⊞</div>
      <div class="mcb" id="btnTheme" onclick="toggleTheme()" title="Toggle Theme">◐</div>
      <div class="mcsep"></div>
      <div class="mcb" onclick="mapZoom(1)" title="Zoom In">+</div>
      <div class="mcb" onclick="mapZoom(-1)" title="Zoom Out">−</div>
      <div class="mcb" onclick="mapReset()" title="Reset" style="font-size:10px">⌂</div>
    </div>
  </div>

  <!-- Upload Panel -->
  <div class="panel" id="upload-panel">
    <div class="stitle">Upload Security Logs for Analysis</div>
    <form id="upForm" enctype="multipart/form-data">
      <div class="upload-grid">
        <div>
          <div class="drop-zone" id="dz">
            <input type="file" name="logfile" id="fi" accept=".log,.txt,.csv,.json"/>
            <div class="drop-ico">📁</div>
            <div class="drop-title">Drop Log File Here</div>
            <div class="drop-sub">Supports .log .txt .csv .json — Max 16 MB</div>
            <div id="fname" style="margin-top:8px;font-family:var(--mono);font-size:11px;color:var(--accent)"></div>
          </div>
        </div>
        <div class="paste-area">
          <label>— OR PASTE RAW LOG DATA —</label>
          <textarea name="logtext" id="lt" placeholder="2024-01-15 08:12:34 FAILED SSH login from 185.220.101.45 port 22 user=root&#10;2024-01-15 08:17:45 SQL injection: SELECT * FROM users WHERE id=1 OR 1=1&#10;2024-01-15 08:25:33 Malware C2 callback detected to 185.234.218.75 port=4444&#10;2024-01-15 08:52:00 Ransomware behavior detected rapid file encryption host 10.0.0.30"></textarea>
        </div>
      </div>
      <div class="form-row">
        <input type="password" name="api_key" id="ak" placeholder="OpenAI API Key (sk-proj-...) — leave blank to use default"/>
        <div style="display:flex;flex-direction:column;gap:4px">
          <label style="font-family:var(--mono);font-size:10px;color:var(--muted)">MANUAL SEVERITY</label>
          <select name="manual">
            <option>Low</option><option>Medium</option>
            <option selected>High</option><option>Critical</option>
          </select>
        </div>
        <div style="display:flex;flex-direction:column;gap:4px">
          <label style="font-family:var(--mono);font-size:10px;color:var(--muted)">OVERRIDE AI</label>
          <select name="override">
            <option>None</option><option>Low</option>
            <option>Medium</option><option>High</option><option>Critical</option>
          </select>
        </div>
        <button type="button" class="btn-go" id="goBtn" onclick="doAnalyze()">⚡ ANALYZE</button>
      </div>
    </form>
  </div>

  <!-- Loading indicator -->
  <div id="loading">
    <div class="spinner"></div>
    <div class="load-txt">ANALYZING LOGS...</div>
    <div style="font-family:var(--mono);font-size:11px;color:var(--muted);margin-top:8px">
      Running AI threat detection &amp; MITRE mapping
    </div>
  </div>

  <!-- Dynamic sections injected here -->
  <div id="dash-section"></div>
  <div id="tbl-section"></div>
  <div id="cards-section"></div>
  <div id="exp-row"></div>
</main>

<!-- Modal -->
<div class="overlay" id="ov" onclick="if(event.target===this)closeMod()">
  <div class="modal">
    <button class="mclose" onclick="closeMod()">CLOSE ✕</button>
    <h3 id="mod-title">Log Entry Detail</h3>
    <div id="mod-body"></div>
  </div>
</div>

<div class="toast" id="toast"></div>

<footer>
  CYBERSENTINEL PRO v2.0 &nbsp;|&nbsp; Blue Team SOC Decision-Support Tool &nbsp;|&nbsp; MSc Cybersecurity Project<br>
  <span style="color:rgba(74,106,128,.6)">AI is advisory only — all decisions require analyst confirmation</span>
</footer>

<script>
// ── Clock ──────────────────────────────────────────────────
setInterval(()=>{
  document.getElementById('clock').textContent=
    new Date().toLocaleTimeString('en-GB',{hour12:false});
},1000);

// ── Drag & Drop ────────────────────────────────────────────
const dz=document.getElementById('dz');
dz.addEventListener('dragover',e=>{e.preventDefault();dz.classList.add('drag')});
dz.addEventListener('dragleave',()=>dz.classList.remove('drag'));
dz.addEventListener('drop',e=>{
  e.preventDefault();dz.classList.remove('drag');
  const f=e.dataTransfer.files[0];
  if(f){const dt=new DataTransfer();dt.items.add(f);
    document.getElementById('fi').files=dt.files;
    document.getElementById('fname').textContent='📄 '+f.name;}
});
document.getElementById('fi').addEventListener('change',e=>{
  if(e.target.files[0]) document.getElementById('fname').textContent='📄 '+e.target.files[0].name;
});

// ── State ──────────────────────────────────────────────────
let allEntries=[], lastStats={};

// ── Analyze ────────────────────────────────────────────────
async function doAnalyze(){
  const fd=new FormData(document.getElementById('upForm'));
  const lt=document.getElementById('lt').value.trim();
  const fi=document.getElementById('fi');
  if(!fi.files.length && !lt){showToast('Upload a file or paste log data','err');return;}

  document.getElementById('loading').style.display='block';
  document.getElementById('goBtn').disabled=true;
  ['dash-section','tbl-section','cards-section','exp-row'].forEach(id=>{
    document.getElementById(id).innerHTML='';
  });

  try{
    const res=await fetch('/analyze_ajax',{method:'POST',body:fd});
    const d=await res.json();
    if(d.error) throw new Error(d.error);
    allEntries=d.stats.all_entries||[];
    lastStats=d.stats;
    updateKPIs(d.stats);
    renderDashboard(d);
    showToast('✅ Analyzed '+d.stats.total+' log entries','ok');
  } catch(e){
    showToast('❌ Error: '+e.message,'err');
    console.error(e);
  }
  document.getElementById('loading').style.display='none';
  document.getElementById('goBtn').disabled=false;
}

// ── KPIs ───────────────────────────────────────────────────
function updateKPIs(s){
  const ids=['kv-total','kv-susp','kv-crit','kv-high','kv-med','kv-low'];
  const vals=[s.total,s.suspicious,s.critical,s.high,s.medium,s.low];
  ids.forEach((id,i)=>{const el=document.getElementById(id);if(el)el.textContent=vals[i]||0;});
  document.getElementById('kv-ctr').textContent=(s.top_countries||[]).length;
  document.getElementById('kv-ips').textContent=(s.top_ips||[]).length;
  document.getElementById('sb-total').textContent=s.total||0;
  document.getElementById('sb-crit').textContent=s.critical||0;
  document.getElementById('sb-high').textContent=s.high||0;
}

// ── Render Dashboard ───────────────────────────────────────
function renderDashboard(d){
  const s=d.stats, charts=d.charts||[], summary=d.summary||'', ai_raw=d.ai_raw||'';

  let html=`<div class="panel"><div class="stitle">AI Executive Summary</div>
    <div style="font-size:13px;line-height:1.9;color:var(--text);white-space:pre-wrap">${escH(summary)}</div></div>`;

  if(ai_raw){
    html+=`<div class="panel"><div class="stitle">Full AI Threat Analysis</div>
      <div class="ai-out">${escH(ai_raw)}</div></div>`;
  }

  // Chart containers — Plotly renders into these divs after DOM update
  html+=`
  <div class="chart-2">
    <div class="chart-box"><div class="stitle">Severity Distribution</div><div id="ch0" style="height:300px"></div></div>
    <div class="chart-box"><div class="stitle">Attack Types</div><div id="ch1" style="height:300px"></div></div>
  </div>
  <div class="panel"><div class="stitle">Alert Timeline</div><div id="ch2" style="height:300px"></div></div>
  <div class="chart-2">
    <div class="chart-box"><div class="stitle">Countries</div><div id="ch3" style="height:300px"></div></div>
    <div class="chart-box"><div class="stitle">MITRE Tactics</div><div id="ch4" style="height:300px"></div></div>
  </div>
  <div class="chart-2">
    <div class="chart-box"><div class="stitle">Threat Gauge</div><div id="ch6" style="height:300px"></div></div>
    <div class="chart-box"><div class="stitle">Source IPs</div><div id="ch7" style="height:300px"></div></div>
  </div>`;

  if(charts[5]){
    html+=`<div class="panel"><div class="stitle">AI vs Manual Severity Matrix</div><div id="ch5" style="height:300px"></div></div>`;
  }

  document.getElementById('dash-section').innerHTML=html;

  // Render charts via Plotly.newPlot() after DOM settles
  setTimeout(()=>{
    charts.forEach((cjson,i)=>{
      if(!cjson) return;
      const el=document.getElementById('ch'+i);
      if(!el) return;
      try{
        const fig=JSON.parse(cjson);
        // Merge dark theme but preserve each chart's own margin/annotations
        const base={paper_bgcolor:'rgba(0,0,0,0)',plot_bgcolor:'rgba(8,18,30,0.7)',
          font:{color:'#00f5ff',family:'Consolas,monospace'}};
        fig.layout=Object.assign({},base,fig.layout||{});
        Plotly.newPlot(el,fig.data,fig.layout,{responsive:true,displayModeBar:false});
      } catch(err){
        console.warn('Chart',i,'error:',err);
        el.innerHTML='<div style="color:var(--muted);padding:20px;font-family:var(--mono);font-size:11px">Chart unavailable</div>';
      }
    });
  }, 120);

  renderTable(allEntries,'all');
  renderCards(s.suspicious_entries||[]);

  document.getElementById('exp-row').innerHTML=`
    <div class="exp-row">
      <button class="exp-btn" onclick="exportCSV()">⬇ Export CSV</button>
      <button class="exp-btn" onclick="exportJSON()">⬇ Export JSON</button>
      <button class="exp-btn" type="button" onclick="downloadPDF()">📄 Download PDF Report</button>
    </div>`;
}

// ── Table ──────────────────────────────────────────────────
function renderTable(entries, flt){
  const filtered=flt==='all'?entries:entries.filter(e=>e.severity===flt);
  const sbC={critical:'s-cr',high:'s-hi',medium:'s-me',low:'s-lo'};
  const stArr=['BLOCKED','DETECTED','INVESTIGATING','RESOLVED'];
  const stCol={BLOCKED:'var(--green)',DETECTED:'var(--orange)',INVESTIGATING:'var(--accent)',RESOLVED:'var(--muted)'};

  const rows=filtered.slice(0,120).map((e,i)=>{
    const sc=e.severity_score||0;
    const bc=sc>=85?'#ff2244':sc>=65?'#ff6b00':sc>=35?'#ffd000':'#00ff88';
    const st=stArr[Math.abs(simpleHash((e.source_ip||'')+(e.timestamp||'')))%4];
    const cls=sbC[e.severity]||'s-lo';
    return `<tr onclick="showMod(${allEntries.indexOf(e)})">
      <td style="color:var(--muted)">${i+1}</td>
      <td style="color:var(--muted);font-size:10px">${(e.timestamp||'-').slice(-8)}</td>
      <td style="color:var(--accent)">${e.source_ip||'-'}</td>
      <td>🌍 ${e.country||'?'}</td>
      <td>${e.attack_type||'-'}</td>
      <td><span class="sb ${cls}">${e.severity||'-'}</span></td>
      <td><span class="sc-bg"><span class="sc-fill" style="width:${sc}%;background:${bc}"></span></span>${sc}</td>
      <td style="font-size:10px;color:var(--muted)">${e.mitre_tactic||'-'}</td>
      <td style="color:var(--muted)">${e.dest_port||'-'}</td>
      <td style="font-size:10px;color:${stCol[st]||'var(--muted)'}">${st}</td>
    </tr>`;
  }).join('');

  const btns=['all','critical','high','medium','low'];
  const bhtml=btns.map(b=>{
    const extra=b==='all'?'':` ${b.slice(0,2)}`;
    const ico=b==='all'?'ALL':{'critical':'🔴 CRITICAL','high':'🟠 HIGH','medium':'🟡 MEDIUM','low':'🟢 LOW'}[b];
    return `<button class="fbtn${extra}${flt===b?' on':''}" onclick="renderTable(allEntries,'${b}')">${ico}</button>`;
  }).join('');

  document.getElementById('tbl-section').innerHTML=`
    <div class="panel">
      <div class="stitle">Suspicious Alert Log</div>
      <div class="filter-row">
        ${bhtml}
        <span style="margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--muted)">${filtered.length} entries</span>
      </div>
      <div class="tbl-wrap"><table>
        <thead><tr>
          <th>#</th><th>Time</th><th>Source IP</th><th>Country</th><th>Attack</th>
          <th>Severity</th><th>Score</th><th>MITRE Tactic</th><th>Port</th><th>Status</th>
        </tr></thead>
        <tbody>${rows||'<tr><td colspan="10" style="text-align:center;color:var(--muted);padding:20px">No entries match this filter</td></tr>'}</tbody>
      </table></div>
    </div>`;
}

// ── Incident Cards ─────────────────────────────────────────
// ── Escalation / Confirmation system ──────────────────────

// Store card data for modal use
let cardDataStore=[];

function renderCards(entries){
  const top=entries.filter(e=>['critical','high'].includes(e.severity)).slice(0,8);
  if(!top.length){ document.getElementById('cards-section').innerHTML=''; return; }
  const cc={critical:'var(--red)',high:'var(--orange)',medium:'var(--yellow)',low:'var(--green)'};

  // Store entries globally for modal access
  cardDataStore=top;

  const cards=top.map((e,i)=>{
    const ai=e.ai_explanation||'';
    const [ex,ac]=ai.includes('| Action:') ? ai.split('| Action:') : [ai,''];
    const exT=ex.replace('Explanation:','').trim();
    const acT=ac.trim();
    const col=cc[e.severity]||'var(--accent)';
    return `<div class="ic" style="--cc:${col}" id="ic-${i}">
      <div class="ic-head">
        <div class="ic-title">⚠️ ${escH(e.attack_type)}</div>
        <span class="sb s-${e.severity?e.severity[0]:'-'}${e.severity?e.severity[1]:'-'}">${e.severity}</span>
      </div>
      <div class="ic-meta">
        🕐 ${e.timestamp||'?'}<br>
        🌐 ${e.source_ip||'?'} &nbsp;|&nbsp; 🌍 ${e.country||'?'}<br>
        🎯 Port: ${e.dest_port||'N/A'} &nbsp;|&nbsp; 📡 ${e.protocol||'N/A'}
        &nbsp;|&nbsp; Score: <span style="color:${col}">${e.severity_score}/100</span>
      </div>
      ${exT?`<div style="font-size:10px;color:var(--muted);margin-bottom:3px">🤖 AI ANALYSIS:</div><div class="ic-ex">${escH(exT)}</div>`:''}
      ${acT?`<div style="font-size:10px;color:var(--muted);margin-bottom:3px">💡 RECOMMENDED ACTION:</div><div class="ic-ac">${escH(acT)}</div>`:''}
      <div class="mt-tags">
        ${e.mitre_tactic_id?`<span class="mt">${e.mitre_tactic_id}</span>`:''}
        ${e.mitre_technique_id?`<span class="mt">${e.mitre_technique_id}</span>`:''}
        ${e.mitre_tactic&&e.mitre_tactic!='Unknown'?`<span class="mt">${e.mitre_tactic}</span>`:''}
      </div>
      <div class="card-btns" id="cb-${i}">
        <button class="cbtn c-ok"  onclick="openConfirmModal(${i})">✅ CONFIRM</button>
        <button class="cbtn c-esc" onclick="openEscalateModal(${i})">🚨 ESCALATE</button>
        <button class="cbtn c-dis" onclick="dismissCard(${i})">❌ DISMISS</button>
      </div>
      <div id="card-status-${i}"></div>
    </div>`;
  }).join('');

  document.getElementById('cards-section').innerHTML=`
    <div class="panel">
      <div class="stitle">AI Incident Report Cards — Critical &amp; High</div>
      <div class="cards-grid">${cards}</div>
    </div>`;

  // Inject modals into page (only once)
  if(!document.getElementById('esc-overlay')){
    document.body.insertAdjacentHTML('beforeend',`
      <!-- ESCALATE MODAL -->
      <div class="esc-overlay" id="esc-overlay">
        <div class="esc-modal" id="esc-modal">
          <h3 class="esc-h">🚨 ESCALATE ALERT — Notify SOC Analyst</h3>
          <div class="esc-field">
            <label>Recipient Analyst Email</label>
            <input type="email" id="esc-email" placeholder="analyst@soc.company.com" value="soc-team@cybersentinel.local"/>
          </div>
          <div class="esc-field">
            <label>Recipient Name</label>
            <input type="text" id="esc-name" placeholder="Senior Analyst / Team Lead" value="SOC Team Lead"/>
          </div>
          <div class="esc-field">
            <label>Priority Level</label>
            <select id="esc-priority">
              <option value="P1 — CRITICAL">P1 — CRITICAL (respond within 15 mins)</option>
              <option value="P2 — HIGH">P2 — HIGH (respond within 1 hour)</option>
              <option value="P3 — MEDIUM">P3 — MEDIUM (respond within 4 hours)</option>
            </select>
          </div>
          <div class="esc-field">
            <label>Additional Notes for Analyst</label>
            <textarea id="esc-notes" placeholder="Add context, suspected attack chain, affected systems..."></textarea>
          </div>
          <div class="esc-field">
            <label>Generated Email Preview</label>
            <div class="email-preview" id="esc-preview">Click "Generate Email" to preview...</div>
          </div>
          <div class="esc-btns">
            <button class="esc-cancel" onclick="closeEscModal()">Cancel</button>
            <button class="esc-send" onclick="generateEscEmail()">📧 Generate Email</button>
            <button class="esc-send" id="esc-send-btn" onclick="sendEscalation()" style="display:none">🚨 Send Escalation</button>
          </div>
        </div>
      </div>

      <!-- CONFIRM MODAL -->
      <div class="esc-overlay" id="con-overlay">
        <div class="esc-modal confirm" id="con-modal">
          <h3 class="con-h">✅ CONFIRM ALERT — Log & Notify</h3>
          <div class="esc-field">
            <label>Your Analyst Name</label>
            <input type="text" id="con-analyst" placeholder="Your name" value="SOC Analyst L1"/>
          </div>
          <div class="esc-field">
            <label>Notify Manager / Team (email)</label>
            <input type="email" id="con-email" placeholder="manager@soc.company.com" value="soc-manager@cybersentinel.local"/>
          </div>
          <div class="esc-field">
            <label>Resolution Action Taken</label>
            <select id="con-action">
              <option>Blocked source IP at firewall</option>
              <option>Isolated affected endpoint</option>
              <option>Reset compromised credentials</option>
              <option>Patched vulnerable service</option>
              <option>Logged for monitoring — no immediate action</option>
              <option>Handed off to IR team</option>
            </select>
          </div>
          <div class="esc-field">
            <label>Analyst Notes</label>
            <textarea id="con-notes" placeholder="Document your findings and actions taken..."></textarea>
          </div>
          <div class="esc-field">
            <label>Generated Notification Email Preview</label>
            <div class="email-preview green" id="con-preview">Click "Generate Email" to preview...</div>
          </div>
          <div class="esc-btns">
            <button class="esc-cancel" onclick="closeConModal()">Cancel</button>
            <button class="esc-send green" onclick="generateConEmail()">📧 Generate Email</button>
            <button class="esc-send green" id="con-send-btn" onclick="sendConfirmation()" style="display:none">✅ Confirm & Notify</button>
          </div>
        </div>
      </div>
    `);
  }
}

// Current card index being acted on
let activeCardIdx=-1;

function openEscalateModal(i){
  activeCardIdx=i;
  const e=cardDataStore[i]||{};
  document.getElementById('esc-notes').value=
    `Threat: ${e.attack_type||'Unknown'}\nSource IP: ${e.source_ip||'?'} (${e.country||'?'})\nMITRE: ${e.mitre_tactic||'?'} ${e.mitre_technique||''}\nSeverity Score: ${e.severity_score||'?'}/100`;
  document.getElementById('esc-preview').textContent='Click "Generate Email" to preview...';
  document.getElementById('esc-send-btn').style.display='none';
  document.getElementById('esc-overlay').classList.add('open');
}

function openConfirmModal(i){
  activeCardIdx=i;
  const e=cardDataStore[i]||{};
  document.getElementById('con-notes').value=
    `Alert reviewed: ${e.attack_type||'Unknown'}\nIP: ${e.source_ip||'?'} | Severity: ${e.severity||'?'}\nTimestamp: ${e.timestamp||'?'}`;
  document.getElementById('con-preview').textContent='Click "Generate Email" to preview...';
  document.getElementById('con-send-btn').style.display='none';
  document.getElementById('con-overlay').classList.add('open');
}

function closeEscModal(){ document.getElementById('esc-overlay').classList.remove('open'); }
function closeConModal(){ document.getElementById('con-overlay').classList.remove('open'); }

function generateEscEmail(){
  const e=cardDataStore[activeCardIdx]||{};
  const to=document.getElementById('esc-email').value||'analyst@soc.team';
  const name=document.getElementById('esc-name').value||'Analyst';
  const priority=document.getElementById('esc-priority').value;
  const notes=document.getElementById('esc-notes').value;
  const ts=new Date().toUTCString();
  const caseId=`ESC-${Date.now().toString().slice(-6)}`;

  const email=
`TO: ${to}
FROM: cybersentinel-soc@auto-alert.local
SUBJECT: [${priority}] ESCALATED ALERT — ${e.attack_type||'Security Event'} — Case ${caseId}
DATE: ${ts}

Dear ${name},

This is an automated escalation notification from CyberSentinel Pro SOC Platform.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
INCIDENT SUMMARY — Case ${caseId}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Attack Type   : ${e.attack_type||'Unknown'}
Severity      : ${(e.severity||'?').toUpperCase()}  (Score: ${e.severity_score||'?'}/100)
Priority      : ${priority}
Source IP     : ${e.source_ip||'Unknown'}
Country       : ${e.country||'Unknown'}
Timestamp     : ${e.timestamp||'Unknown'}
Port          : ${e.dest_port||'N/A'}
Protocol      : ${e.protocol||'N/A'}

MITRE ATT&CK  : ${e.mitre_tactic_id||'?'} — ${e.mitre_tactic||'?'}
               ${e.mitre_technique_id||'?'} — ${e.mitre_technique||'?'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ANALYST NOTES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
${notes}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ACTION REQUIRED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Log into CyberSentinel Pro and review Case ${caseId}
2. Confirm or override severity classification
3. Execute recommended remediation actions
4. Update case status within SLA window

This is an automated alert. Do not reply to this email.
Human-in-the-loop confirmation required before remediation.

— CyberSentinel Pro v2.0 | Blue Team SOC Platform
  MSc Cybersecurity Project`;

  document.getElementById('esc-preview').textContent=email;
  document.getElementById('esc-send-btn').style.display='inline-block';
}

function generateConEmail(){
  const e=cardDataStore[activeCardIdx]||{};
  const to=document.getElementById('con-email').value||'manager@soc.team';
  const analyst=document.getElementById('con-analyst').value||'Analyst';
  const action=document.getElementById('con-action').value;
  const notes=document.getElementById('con-notes').value;
  const ts=new Date().toUTCString();
  const caseId=`CON-${Date.now().toString().slice(-6)}`;

  const email=
`TO: ${to}
FROM: cybersentinel-soc@auto-alert.local
SUBJECT: [CONFIRMED] Alert Resolved — ${e.attack_type||'Security Event'} — Case ${caseId}
DATE: ${ts}

Dear Manager,

Analyst ${analyst} has confirmed and resolved the following security alert.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RESOLUTION SUMMARY — Case ${caseId}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Attack Type   : ${e.attack_type||'Unknown'}
Severity      : ${(e.severity||'?').toUpperCase()}  (Score: ${e.severity_score||'?'}/100)
Source IP     : ${e.source_ip||'Unknown'} (${e.country||'?'})
Timestamp     : ${e.timestamp||'Unknown'}
Resolved By   : ${analyst}
Resolution    : ${action}

MITRE ATT&CK  : ${e.mitre_tactic_id||'?'} — ${e.mitre_tactic||'?'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ANALYST NOTES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
${notes}

This alert has been marked CONFIRMED and logged in the incident register.
No further action required unless the threat re-emerges.

— CyberSentinel Pro v2.0 | Blue Team SOC Platform`;

  document.getElementById('con-preview').textContent=email;
  document.getElementById('con-send-btn').style.display='inline-block';
}

function sendEscalation(){
  const e=cardDataStore[activeCardIdx]||{};
  const email=document.getElementById('esc-email').value;
  const priority=document.getElementById('esc-priority').value;

  // Open mailto with pre-filled content (works in browser)
  const subject=encodeURIComponent(`[${priority}] ESCALATED — ${e.attack_type||'Alert'}`);
  const body=encodeURIComponent(document.getElementById('esc-preview').textContent);
  window.open(`mailto:${email}?subject=${subject}&body=${body}`,'_blank');

  // Update card UI
  const cb=document.getElementById('cb-'+activeCardIdx);
  const st=document.getElementById('card-status-'+activeCardIdx);
  if(cb) cb.style.display='none';
  if(st) st.innerHTML=`<div style="font-family:var(--mono);font-size:10px;color:var(--orange);margin-top:6px">🚨 ESCALATED <span class="badge-sent">NOTIFIED</span> — ${email}</div>`;
  closeEscModal();
  showToast(`🚨 Escalation sent to ${email}`,'ok');
}

function sendConfirmation(){
  const e=cardDataStore[activeCardIdx]||{};
  const email=document.getElementById('con-email').value;
  const analyst=document.getElementById('con-analyst').value;

  // Open mailto
  const subject=encodeURIComponent(`[CONFIRMED] Resolved — ${e.attack_type||'Alert'}`);
  const body=encodeURIComponent(document.getElementById('con-preview').textContent);
  window.open(`mailto:${email}?subject=${subject}&body=${body}`,'_blank');

  // Update card UI
  const c=document.getElementById('ic-'+activeCardIdx);
  const cb=document.getElementById('cb-'+activeCardIdx);
  const st=document.getElementById('card-status-'+activeCardIdx);
  if(c){ c.style.opacity='.5'; c.style.borderLeftColor='var(--green)'; }
  if(cb) cb.style.display='none';
  if(st) st.innerHTML=`<div style="font-family:var(--mono);font-size:10px;color:var(--green);margin-top:6px">✅ CONFIRMED by ${analyst} <span class="badge-sent" style="border-color:var(--green);color:var(--green)">LOGGED</span></div>`;
  closeConModal();
  showToast(`✅ Confirmation logged & notified`,'ok');
}

function dismissCard(i){
  const c=document.getElementById('ic-'+i);
  const cb=document.getElementById('cb-'+i);
  const st=document.getElementById('card-status-'+i);
  if(c){ c.style.opacity='.35'; }
  if(cb) cb.style.display='none';
  if(st) st.innerHTML=`<div style="font-family:var(--mono);font-size:10px;color:var(--muted);margin-top:6px">❌ DISMISSED — logged as false positive</div>`;
  showToast('Alert dismissed — logged as false positive','ok');
}

function showMod(idx){
  const e=allEntries[idx]; if(!e) return;
  document.getElementById('mod-title').textContent=`⚠️ ${e.attack_type}`;
  document.getElementById('mod-body').innerHTML=`
    <div class="mf"><div class="ml">Raw Log</div><pre>${escH(e.raw||'—')}</pre></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px">
      <div class="mf"><div class="ml">Timestamp</div><div class="mv">${e.timestamp||'—'}</div></div>
      <div class="mf"><div class="ml">Severity</div><div class="mv">
        <span class="sb s-${e.severity?e.severity[0]:'l'}${e.severity?e.severity[1]:'o'}">${e.severity} (${e.severity_score}/100)</span>
      </div></div>
      <div class="mf"><div class="ml">Source IP</div><div class="mv" style="color:var(--accent)">${e.source_ip||'—'}</div></div>
      <div class="mf"><div class="ml">Country</div><div class="mv">🌍 ${e.country||'?'}</div></div>
      <div class="mf"><div class="ml">MITRE Tactic</div><div class="mv">${e.mitre_tactic_id} ${e.mitre_tactic}</div></div>
      <div class="mf"><div class="ml">MITRE Technique</div><div class="mv">${e.mitre_technique_id} ${e.mitre_technique}</div></div>
      <div class="mf"><div class="ml">Dest Port</div><div class="mv">${e.dest_port||'—'}</div></div>
      <div class="mf"><div class="ml">Protocol</div><div class="mv">${e.protocol||'—'}</div></div>
    </div>
    ${e.flags&&e.flags.length?`<div class="mf" style="margin-top:10px"><div class="ml">Detection Flags</div>
      ${e.flags.map(f=>`<div style="color:var(--orange);margin-top:3px;font-size:11px">⚑ ${escH(f)}</div>`).join('')}</div>`:''}
    ${e.ai_explanation?`<div class="mf" style="margin-top:10px"><div class="ml">AI Explanation</div>
      <div class="ic-ex" style="margin-top:5px">${escH(e.ai_explanation)}</div></div>`:''}`;
  document.getElementById('ov').classList.add('open');
}
function closeMod(){document.getElementById('ov').classList.remove('open');}
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeMod();});

// ── Utilities ──────────────────────────────────────────────
function simpleHash(s){let h=0;for(let i=0;i<s.length;i++)h=(Math.imul(31,h)+s.charCodeAt(i))|0;return h;}
function escH(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function showToast(msg,type){
  const t=document.getElementById('toast');
  t.textContent=msg; t.className=`toast ${type} show`;
  setTimeout(()=>t.classList.remove('show'),3500);
}

// ── Export ─────────────────────────────────────────────────
function exportCSV(){
  if(!allEntries.length){showToast('No data to export','err');return;}
  const h=['timestamp','source_ip','country','attack_type','severity',
           'severity_score','mitre_tactic','mitre_technique','dest_port','protocol'];
  const rows=allEntries.map(e=>h.map(k=>`"${(e[k]||'').toString().replace(/"/g,'""')}"`).join(','));
  dl('soc_report.csv',[h.join(','),...rows].join('\n'),'text/csv');
  showToast('✅ CSV exported','ok');
}
function exportJSON(){
  if(!lastStats.total){showToast('No data','err');return;}
  dl('soc_report.json',JSON.stringify({generated:new Date().toISOString(),
    stats:lastStats,entries:allEntries},null,2),'application/json');
  showToast('✅ JSON exported','ok');
}
async function downloadPDF(){
  if(!lastStats.total){showToast('Run analysis first','err');return;}
  // Most reliable in restricted browser contexts: let browser handle attachment response directly.
  window.location.href='/export_pdf?t='+Date.now();
  showToast('📄 Preparing PDF download...','ok');
}
function dl(name,content,type){
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([content],{type}));
  a.download=name; a.click();
}

// ══════════════════════════════════════════════════════════
//  GLOBE + MAP
// ══════════════════════════════════════════════════════════
var curMapView='globe';
var _globeRenderer=null,_globeCamera=null,_earthGroup=null;
var _earthRoot=null,_earthMat=null,_gridMat=null,_starMat=null;
var _sunLight=null,_rimLight=null,_ambLight=null;
var _activeArcs=[],_beacons=[],_socRings=[];
var _arcGrp=null;
var _fLines=[],_fDots=[],_fLabels=[],_fZoom=0,_fLA={};
var _tScore=0,_tLevel=1,_actCnt={},_lineCount=0;
var _autoRot=false,_camZTarget=270;
var _mapTheme='dark';

var _THEME={
  dark:{
    clear:0x070c12,land:'#1a242f',ocean:'#0c131d',lake:'#101a26',
    country:'rgba(120,175,220,0.56)',coast:'rgba(135,205,255,0.68)',
    subunit:'rgba(100,155,205,0.26)',river:'rgba(120,170,220,0.22)',
    font:'#9bcdf5',hoverBg:'#121c29',hoverBorder:'#79b9eb',hoverFont:'#d4ebff'
  },
  light:{
    clear:0xeaf2fa,land:'#d3e2f1',ocean:'#f4f8fd',lake:'#dfebf8',
    country:'rgba(48,116,170,0.55)',coast:'rgba(58,128,186,0.72)',
    subunit:'rgba(64,134,188,0.34)',river:'rgba(90,150,205,0.35)',
    font:'#285f8e',hoverBg:'#dfeaf7',hoverBorder:'#4c94cf',hoverFont:'#184b77'
  }
};

function _ll2v(lat,lon,r){
  var phi=(90-lat)*Math.PI/180,th=(lon+180)*Math.PI/180;
  return new THREE.Vector3(-r*Math.sin(phi)*Math.cos(th),r*Math.cos(phi),r*Math.sin(phi)*Math.sin(th));
}
function _hx(h){return{r:parseInt(h.slice(1,3),16),g:parseInt(h.slice(3,5),16),b:parseInt(h.slice(5,7),16)};}

function _buildFallbackGlobeTex(){
  var sz=3072,c=document.createElement('canvas');
  c.width=sz;c.height=sz/2;var h=sz/2,x=c.getContext('2d');
  var bg=x.createLinearGradient(0,0,0,h);
  bg.addColorStop(0,'#080d13');bg.addColorStop(.5,'#0d1622');bg.addColorStop(1,'#060a10');
  x.fillStyle=bg;x.fillRect(0,0,sz,h);

  // Scan-lines + stars for cyber look
  x.fillStyle='rgba(120,195,255,0.016)';
  for(var y=0;y<h;y+=4) x.fillRect(0,y,sz,1);
  for(var s=0;s<2600;s++){
    var sx=Math.random()*sz,sy=Math.random()*h,a=Math.random()*.17+.03;
    x.fillStyle='rgba(140,205,255,'+a.toFixed(3)+')';
    x.fillRect(sx,sy,1,1);
  }

  // Graticules
  x.strokeStyle='rgba(70,110,150,0.22)';x.lineWidth=1;
  for(var la=-80;la<=80;la+=10){
    var gy=((90-la)/180)*h;x.beginPath();x.moveTo(0,gy);x.lineTo(sz,gy);x.stroke();
  }
  for(var lo=-180;lo<=180;lo+=10){
    var gx=((lo+180)/360)*sz;x.beginPath();x.moveTo(gx,0);x.lineTo(gx,h);x.stroke();
  }

  function ptx(px){return px*sz;}
  function pty(py){return py*h;}
  function drawPoly(poly,fill,stroke,sw){
    x.beginPath();
    x.moveTo(ptx(poly[0][0]),pty(poly[0][1]));
    for(var i=1;i<poly.length;i++) x.lineTo(ptx(poly[i][0]),pty(poly[i][1]));
    x.closePath();
    x.fillStyle=fill;x.fill();
    x.strokeStyle=stroke;x.lineWidth=sw;x.stroke();
  }
  function drawLine(line,stroke,sw){
    x.beginPath();
    x.moveTo(ptx(line[0][0]),pty(line[0][1]));
    for(var i=1;i<line.length;i++) x.lineTo(ptx(line[i][0]),pty(line[i][1]));
    x.strokeStyle=stroke;x.lineWidth=sw;x.stroke();
  }

  var coast='rgba(140,205,255,0.42)';
  var land='rgba(34,48,62,0.96)';
  var land2='rgba(24,36,48,0.92)';
  var polys=[
    // North America
    [[.06,.12],[.12,.08],[.20,.09],[.26,.14],[.30,.22],[.30,.30],[.27,.36],[.21,.39],[.16,.37],[.11,.30],[.08,.22]],
    // Greenland
    [[.24,.06],[.27,.05],[.30,.08],[.28,.13],[.24,.12],[.22,.09]],
    // South America
    [[.22,.40],[.27,.41],[.30,.47],[.30,.56],[.28,.66],[.25,.74],[.22,.71],[.20,.62],[.19,.53]],
    // Europe
    [[.43,.14],[.47,.11],[.53,.12],[.56,.16],[.55,.21],[.50,.25],[.45,.24],[.42,.20]],
    // Africa
    [[.45,.26],[.50,.25],[.56,.29],[.58,.37],[.57,.49],[.54,.60],[.49,.66],[.45,.60],[.43,.49],[.43,.38]],
    // Asia
    [[.54,.11],[.62,.08],[.75,.08],[.86,.11],[.94,.16],[.95,.24],[.91,.30],[.84,.33],[.76,.36],[.67,.33],[.62,.29],[.57,.23],[.54,.17]],
    // India
    [[.67,.30],[.70,.31],[.72,.37],[.69,.42],[.66,.38]],
    // SE Asia
    [[.74,.34],[.78,.35],[.82,.39],[.80,.44],[.75,.42],[.73,.38]],
    // Australia
    [[.78,.58],[.84,.56],[.89,.58],[.91,.64],[.88,.70],[.82,.72],[.77,.67],[.76,.62]],
    // Japan
    [[.86,.24],[.87,.21],[.88,.24],[.88,.29],[.87,.31],[.86,.28]],
    // UK / Ireland
    [[.40,.15],[.41,.14],[.42,.16],[.41,.18],[.40,.17]],
    // Madagascar
    [[.57,.55],[.58,.57],[.58,.62],[.57,.64],[.56,.61],[.56,.57]],
    // Antarctica
    [[.03,.91],[.15,.88],[.28,.89],[.42,.87],[.58,.88],[.70,.87],[.84,.88],[.97,.90],[.98,.98],[.02,.98]]
  ];
  for(var p=0;p<polys.length;p++) drawPoly(polys[p],p<3?land:land2,coast,2);

  // Pseudo country borders (to improve detail readability)
  var borders=[
    [[.12,.15],[.18,.14],[.23,.17],[.24,.23],[.22,.30],[.17,.34],[.12,.32]],
    [[.24,.44],[.27,.50],[.26,.58],[.24,.65],[.22,.62]],
    [[.46,.15],[.49,.18],[.50,.24]],
    [[.47,.31],[.53,.31],[.55,.38],[.54,.47],[.50,.57],[.46,.55],[.45,.44]],
    [[.60,.12],[.68,.14],[.77,.16],[.86,.18],[.90,.24],[.86,.30],[.78,.31],[.70,.30],[.63,.26],[.59,.20]],
    [[.68,.31],[.70,.36],[.69,.40]],
    [[.79,.59],[.85,.59],[.88,.64],[.84,.69],[.79,.67]]
  ];
  for(var b=0;b<borders.length;b++) drawLine(borders[b],'rgba(140,205,255,0.24)',1.25);

  // Polar glow
  var glow=x.createRadialGradient(sz*.5,h*.08,10,sz*.5,h*.08,sz*.22);
  glow.addColorStop(0,'rgba(150,210,255,0.14)');glow.addColorStop(1,'rgba(150,210,255,0)');
  x.fillStyle=glow;x.fillRect(0,0,sz,h);

  var tex=new THREE.CanvasTexture(c);
  tex.anisotropy=8;
  return tex;
}

async function _buildGlobeTex(){
  if(typeof topojson==='undefined') return _buildFallbackGlobeTex();
  try{
    var res=await fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json',{cache:'force-cache'});
    if(!res.ok) throw new Error('topology unavailable');
    var top=await res.json();
    var countries=topojson.feature(top,top.objects.countries);
    var borders=topojson.mesh(top,top.objects.countries,function(a,b){return a!==b;});

    var sz=4096,c=document.createElement('canvas');
    c.width=sz;c.height=sz/2;var h=sz/2,x=c.getContext('2d');
    var bg=x.createLinearGradient(0,0,0,h);
    bg.addColorStop(0,'#080d13');bg.addColorStop(.5,'#0d1622');bg.addColorStop(1,'#060a10');
    x.fillStyle=bg;x.fillRect(0,0,sz,h);

    x.fillStyle='rgba(120,195,255,0.016)';
    for(var y=0;y<h;y+=4) x.fillRect(0,y,sz,1);
    for(var s=0;s<3200;s++){
      var sx=Math.random()*sz,sy=Math.random()*h,a=Math.random()*.15+.02;
      x.fillStyle='rgba(140,205,255,'+a.toFixed(3)+')';x.fillRect(sx,sy,1,1);
    }

    x.strokeStyle='rgba(70,110,150,0.22)';x.lineWidth=1;
    for(var la=-80;la<=80;la+=10){var gy=((90-la)/180)*h;x.beginPath();x.moveTo(0,gy);x.lineTo(sz,gy);x.stroke();}
    for(var lo=-180;lo<=180;lo+=10){var gx=((lo+180)/360)*sz;x.beginPath();x.moveTo(gx,0);x.lineTo(gx,h);x.stroke();}

    function ll2xy(ll){return [((ll[0]+180)/360)*sz,((90-ll[1])/180)*h];}
    function drawRings(rings,fill,stroke,width){
      x.beginPath();
      for(var r=0;r<rings.length;r++){
        var ring=rings[r],first=true,px=0;
        for(var i=0;i<ring.length;i++){
          var p=ll2xy(ring[i]),cx=p[0],cy=p[1];
          if(first){x.moveTo(cx,cy);first=false;px=cx;continue;}
          if(Math.abs(cx-px)>sz*.45){x.moveTo(cx,cy);}else{x.lineTo(cx,cy);}
          px=cx;
        }
      }
      x.fillStyle=fill;x.fill('evenodd');
      x.strokeStyle=stroke;x.lineWidth=width;x.stroke();
    }
    function drawMesh(mesh,stroke,width){
      x.beginPath();
      for(var m=0;m<mesh.coordinates.length;m++){
        var line=mesh.coordinates[m],start=true,px=0;
        for(var i=0;i<line.length;i++){
          var p=ll2xy(line[i]),cx=p[0],cy=p[1];
          if(start){x.moveTo(cx,cy);start=false;px=cx;continue;}
          if(Math.abs(cx-px)>sz*.45){x.moveTo(cx,cy);}else{x.lineTo(cx,cy);}
          px=cx;
        }
      }
      x.strokeStyle=stroke;x.lineWidth=width;x.stroke();
    }

    var fill='rgba(27,39,52,0.95)',shore='rgba(140,205,255,0.52)';
    for(var f=0;f<countries.features.length;f++){
      var g=countries.features[f].geometry;
      if(!g) continue;
      if(g.type==='Polygon') drawRings(g.coordinates,fill,shore,1.35);
      if(g.type==='MultiPolygon'){
        for(var mp=0;mp<g.coordinates.length;mp++) drawRings(g.coordinates[mp],fill,shore,1.35);
      }
    }

    drawMesh(borders,'rgba(140,205,255,0.24)',.75);

    var glow=x.createRadialGradient(sz*.5,h*.42,40,sz*.5,h*.42,sz*.34);
    glow.addColorStop(0,'rgba(150,210,255,0.12)');glow.addColorStop(1,'rgba(150,210,255,0)');
    x.fillStyle=glow;x.fillRect(0,0,sz,h);

    var tex=new THREE.CanvasTexture(c);
    tex.anisotropy=8;
    return tex;
  }catch(e){
    console.warn('Globe topology load failed; using fallback texture.',e);
    return _buildFallbackGlobeTex();
  }
}

async function _initGlobe(){
  var cv=document.getElementById('gCanvas');
  var wrap=document.getElementById('globeViz');
  var W=wrap.offsetWidth||800, H=500;
  cv.width=W;cv.height=H;

  var renderer=new THREE.WebGLRenderer({canvas:cv,antialias:true});
  renderer.setPixelRatio(Math.min(devicePixelRatio,2));
  renderer.setClearColor(_THEME[_mapTheme].clear,1);
  renderer.setSize(W,H);
  _globeRenderer=renderer;

  var scene=new THREE.Scene();
  var camera=new THREE.PerspectiveCamera(42,W/H,0.1,2000);
  camera.position.z=270;
  _globeCamera=camera;

  // Stars
  var sg=new THREE.BufferGeometry(),sv=[];
  for(var i=0;i<14000;i++) sv.push((Math.random()-.5)*3000,(Math.random()-.5)*3000,(Math.random()-.5)*3000);
  sg.setAttribute('position',new THREE.Float32BufferAttribute(sv,3));
  _starMat=new THREE.PointsMaterial({color:0x6f93b8,size:0.45,transparent:true,opacity:.55});
  scene.add(new THREE.Points(sg,_starMat));

  // Lights
  _ambLight=new THREE.AmbientLight(0x1f2731,4.5);scene.add(_ambLight);
  _sunLight=new THREE.DirectionalLight(0x9ec8ff,1.1);_sunLight.position.set(250,120,200);scene.add(_sunLight);
  _rimLight=new THREE.DirectionalLight(0x3a5f86,0.35);_rimLight.position.set(-200,-100,-150);scene.add(_rimLight);

  var R=100;
  var eg=new THREE.Group();scene.add(eg);_earthGroup=eg;_earthRoot=eg;

  // Earth
  var tex=await _buildGlobeTex();
  _earthMat=new THREE.MeshPhongMaterial({
    map:tex,specular:0x3d5f85,shininess:18,emissive:0x141e2b,emissiveIntensity:.22
  });
  eg.add(new THREE.Mesh(new THREE.SphereGeometry(R,96,96),_earthMat));

  // Grid
  _gridMat=new THREE.LineBasicMaterial({color:0x486b8f,transparent:true,opacity:.2});
  for(var la=-80;la<=80;la+=20){var pp=[];for(var lo2=-180;lo2<=180;lo2+=3)pp.push(_ll2v(la,lo2,R+.2));eg.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pp),_gridMat));}
  for(var lo3=-180;lo3<180;lo3+=20){var pp2=[];for(var la2=-90;la2<=90;la2+=3)pp2.push(_ll2v(la2,lo3,R+.2));eg.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pp2),_gridMat));}

  // Atmosphere glow
  eg.add(new THREE.Mesh(new THREE.SphereGeometry(R*1.07,64,64),
    new THREE.ShaderMaterial({
      vertexShader:'varying vec3 vN;void main(){vN=normalize(normalMatrix*normal);gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.);}',
      fragmentShader:'varying vec3 vN;void main(){float d=dot(vN,vec3(0,0,1));float r=pow(1.-clamp(d,0.,1.),3.);gl_FragColor=vec4(.42,.70,.95,r*.18);}',
      transparent:true,side:THREE.BackSide,depthWrite:false})));

  // Outer shell
  eg.add(new THREE.Mesh(new THREE.SphereGeometry(R*1.18,64,64),
    new THREE.MeshBasicMaterial({color:0x6aa8de,transparent:true,opacity:.07,side:THREE.DoubleSide})));

  // SOC dot (London)
  var socPos=_ll2v(51.5074,-0.1278,R).normalize().multiplyScalar(R+.5);
  var socDot=new THREE.Mesh(new THREE.SphereGeometry(1.6,12,12),new THREE.MeshBasicMaterial({color:0x7fd4ff}));
  socDot.position.copy(socPos);eg.add(socDot);
  setInterval(function(){
    var rm=new THREE.Mesh(new THREE.RingGeometry(1.4,2,32),new THREE.MeshBasicMaterial({color:0x7fd4ff,transparent:true,opacity:.8,side:THREE.DoubleSide}));
    var up=socPos.clone().normalize();rm.position.copy(up.multiplyScalar(R+.5));rm.quaternion.setFromUnitVectors(new THREE.Vector3(0,0,1),up.normalize());
    eg.add(rm);_socRings.push({mesh:rm,age:0,maxAge:65});
  },1100);

  var ag=new THREE.Group();eg.add(ag);_arcGrp=ag;

  // Drag rotate
  var isDrag=false,px=0,py=0;
  cv.addEventListener('mousedown',function(e){isDrag=true;px=e.clientX;py=e.clientY;_autoRot=false;});
  window.addEventListener('mouseup',function(){isDrag=false;});
  window.addEventListener('mousemove',function(e){
    if(!isDrag||curMapView!=='globe') return;
    var dx=e.clientX-px,dy=e.clientY-py;
    eg.quaternion.premultiply(new THREE.Quaternion().setFromEuler(new THREE.Euler(dy*.003,dx*.003,0)));
    px=e.clientX;py=e.clientY;
  });

  // Render loop
  (function loop(){
    requestAnimationFrame(loop);
    if(_camZTarget!=null&&Math.abs(camera.position.z-_camZTarget)>.05){
      camera.position.z+=(_camZTarget-camera.position.z)*.09;
    }
    if(_autoRot&&curMapView==='globe') eg.quaternion.premultiply(new THREE.Quaternion().setFromAxisAngle(new THREE.Vector3(0,1,0),.0007));
    // Update SOC rings
    for(var i=_socRings.length-1;i>=0;i--){var s=_socRings[i];s.age++;var t=s.age/s.maxAge;s.mesh.scale.setScalar(1+t*2.4);s.mesh.material.opacity=(1-t)*.72;if(t>=1){eg.remove(s.mesh);_socRings.splice(i,1);}}
    // Update beacons
    for(var i=_beacons.length-1;i>=0;i--){var b=_beacons[i];b.age++;if(b.age<0) continue;var t=b.age/b.maxAge;b.mesh.scale.setScalar(1+t*b.maxR);b.mesh.material.opacity=(1-t)*.78;if(t>=1){eg.remove(b.mesh);_beacons.splice(i,1);}}
    // Update arcs
    for(var i=_activeArcs.length-1;i>=0;i--){
      var a=_activeArcs[i];a.age++;a.progress=Math.min(1,a.progress+a.speed);
      var head=Math.min(a.pts.length-1,Math.floor(a.progress*a.pts.length));
      var tail=Math.max(0,head-24);
      if(a.lM){ag.remove(a.lM);a.lM=null;}
      if(a.gM){ag.remove(a.gM);a.gM=null;}
      if(a.hM){ag.remove(a.hM);a.hM=null;}
      if(head>1){
        var fade=a.age<20?a.age/20:a.age>a.maxAge-20?(a.maxAge-a.age)/20:1;
        var seg=a.pts.slice(tail,head+1);
        a.lM=new THREE.Line(new THREE.BufferGeometry().setFromPoints(seg),new THREE.LineBasicMaterial({
          color:a.col,transparent:true,opacity:fade*.95,blending:THREE.AdditiveBlending
        }));
        ag.add(a.lM);
        a.gM=new THREE.Line(new THREE.BufferGeometry().setFromPoints(seg),new THREE.LineBasicMaterial({
          color:a.col,transparent:true,opacity:fade*.28,blending:THREE.AdditiveBlending
        }));
        a.gM.scale.setScalar(1.0015);
        ag.add(a.gM);
        var hd=new THREE.Mesh(new THREE.SphereGeometry(1.3,8,8),new THREE.MeshBasicMaterial({color:a.col,transparent:true,opacity:fade*.95}));
        hd.position.copy(a.pts[head]);ag.add(hd);a.hM=hd;
      }
      if(a.age>=a.maxAge){
        if(a.lM)ag.remove(a.lM);
        if(a.gM)ag.remove(a.gM);
        if(a.hM)ag.remove(a.hM);
        _activeArcs.splice(i,1);
      }
    }
    renderer.render(scene,camera);
  })();

  window.addEventListener('resize',function(){
    var nw=wrap.offsetWidth||800;
    renderer.setSize(nw,H);camera.aspect=nw/H;camera.updateProjectionMatrix();
  });

  _applyTheme();
}

function _spawnArc(lat,lon,hexCol){
  if(!_arcGrp) return;
  var R=100;
  var A=_ll2v(lat,lon,R),B=_ll2v(51.5074,-0.1278,R);
  var mid=A.clone().add(B).multiplyScalar(.5).normalize();
  var ctrl=mid.multiplyScalar(R*(1.45+Math.random()*.3));
  var pts=[];
  for(var t=0;t<=1;t+=1/60){var p=new THREE.Vector3();p.addScaledVector(A,(1-t)*(1-t));p.addScaledVector(ctrl,2*t*(1-t));p.addScaledVector(B,t*t);pts.push(p.clone());}
  var rgb=_hx(hexCol);var col=new THREE.Color(rgb.r/255,rgb.g/255,rgb.b/255);
  _activeArcs.push({pts:pts,progress:0,speed:.013+Math.random()*.009,col:col,age:0,maxAge:220,lM:null,gM:null,hM:null});
}

function _spawnBeacon(lat,lon,hexCol,sev){
  if(!_earthGroup) return;
  var R=100;
  var pos=_ll2v(lat,lon,R).normalize().multiplyScalar(R);
  var rgb=_hx(hexCol);var col=new THREE.Color(rgb.r/255,rgb.g/255,rgb.b/255);
  var cnt=sev==='Critical'?3:2;var maxR=sev==='Critical'?5.5:sev==='High'?4:3;
  for(var i=0;i<cnt;i++){
    var rm=new THREE.Mesh(new THREE.RingGeometry(.5,1,32),new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:.82,side:THREE.DoubleSide}));
    var up=pos.clone().normalize();rm.position.copy(up.clone().multiplyScalar(R+.4));rm.quaternion.setFromUnitVectors(new THREE.Vector3(0,0,1),up.normalize());
    _earthGroup.add(rm);_beacons.push({mesh:rm,age:-i*15,maxAge:80,maxR:maxR});
  }
  var dot=new THREE.Mesh(new THREE.SphereGeometry(sev==='Critical'?2.2:1.5,10,10),new THREE.MeshBasicMaterial({color:col}));
  dot.position.copy(pos.normalize().multiplyScalar(R+.4));
  _earthGroup.add(dot);setTimeout(function(){_earthGroup.remove(dot);},3500);
}

// FLAT MAP
var WLD=[
  {n:"RUSSIA",lat:61,lon:90},{n:"CHINA",lat:35,lon:104},{n:"UNITED STATES",lat:39,lon:-97},
  {n:"CANADA",lat:58,lon:-95},{n:"BRAZIL",lat:-10,lon:-52},{n:"AUSTRALIA",lat:-25,lon:133},
  {n:"INDIA",lat:22,lon:78},{n:"GREENLAND",lat:72,lon:-42},{n:"MEXICO",lat:24,lon:-102},
  {n:"MONGOLIA",lat:46,lon:104},{n:"NIGERIA",lat:10,lon:7},{n:"IRAN",lat:32,lon:53},
  {n:"GERMANY",lat:51,lon:10},{n:"UKRAINE",lat:49,lon:31},{n:"JAPAN",lat:37,lon:137},
  {n:"N.KOREA",lat:40,lon:127},{n:"INDONESIA",lat:-2,lon:117},{n:"S.AFRICA",lat:-29,lon:24},
  {n:"PAKISTAN",lat:30,lon:69},{n:"TURKEY",lat:39,lon:35},{n:"ARGENTINA",lat:-35,lon:-64},
];

function _buildFlatMap(){
  var tp=_THEME[_mapTheme]||_THEME.dark;
  var s=_fZoom*14;
  var traces=[
    {type:'scattergeo',mode:'text',lat:WLD.map(function(c){return c.lat;}),lon:WLD.map(function(c){return c.lon;}),text:WLD.map(function(c){return c.n;}),
     textfont:{color:_mapTheme==='dark'?'rgba(135,190,240,0.62)':'rgba(40,120,160,0.65)',size:11,family:'Exo 2'},hoverinfo:'skip'},
    {type:'scattergeo',mode:'markers+text',lat:[51.5074],lon:[-0.1278],
     marker:{size:11,color:_mapTheme==='dark'?'#82d4ff':'#2f9fb8',symbol:'star',line:{width:2,color:'#fff'},opacity:.95},
     text:['◈ SOC'],textposition:'top center',textfont:{color:_mapTheme==='dark'?'#82d4ff':'#2f9fb8',size:11,family:'Share Tech Mono'},
     hovertemplate:'<b>London SOC HQ</b><extra></extra>'}
  ].concat(_fLines).concat(_fDots).concat(_fLabels);
  var layout={
    paper_bgcolor:'rgba(0,0,0,0)',plot_bgcolor:'rgba(0,0,0,0)',
    margin:{t:0,b:0,l:0,r:0},showlegend:false,
    font:{color:tp.font,family:'Share Tech Mono',size:10},
    hoverlabel:{bgcolor:tp.hoverBg,bordercolor:tp.hoverBorder,font:{family:'Share Tech Mono',size:11,color:tp.hoverFont}},
    geo:{projection:{type:'natural earth'},
      showland:true,landcolor:tp.land,showocean:true,oceancolor:tp.ocean,
      showlakes:true,lakecolor:tp.lake,
      countrycolor:tp.country,countrywidth:0.9,
      showcoastlines:true,coastlinecolor:tp.coast,coastlinewidth:1.1,
      showcountries:true,showsubunits:true,subunitcolor:tp.subunit,subunitwidth:0.6,
      showrivers:true,rivercolor:tp.river,riverwidth:0.6,
      showframe:false,bgcolor:'rgba(0,0,0,0)',
      lataxis:{range:[-65+s,82-s]},lonaxis:{range:[-170+s,175-s]}}
  };
  Plotly.react('mapPlot',traces,layout,{responsive:true,displayModeBar:false,scrollZoom:false});
}

function _applyTheme(){
  var t=_THEME[_mapTheme]||_THEME.dark;
  var gv=document.getElementById('globeViz');
  if(gv) gv.classList.toggle('light-map',_mapTheme==='light');
  var bt=document.getElementById('btnTheme');
  if(bt){bt.classList.toggle('mon',_mapTheme==='dark');bt.title='Theme: '+(_mapTheme==='dark'?'Dark':'Light');}
  if(_globeRenderer) _globeRenderer.setClearColor(t.clear,1);
  if(_earthMat){
    if(_mapTheme==='dark'){_earthMat.emissive.setHex(0x141e2b);_earthMat.emissiveIntensity=.22;_earthMat.specular.setHex(0x3d5f85);}
    else{_earthMat.emissive.setHex(0x2b4f43);_earthMat.emissiveIntensity=.16;_earthMat.specular.setHex(0x4c8c7a);}
  }
  if(_gridMat){_gridMat.color.setHex(_mapTheme==='dark'?0x486b8f:0x4d8e84);_gridMat.opacity=_mapTheme==='dark'?.2:.18;}
  if(_starMat){_starMat.color.setHex(_mapTheme==='dark'?0x6f93b8:0x7aaea3);_starMat.opacity=_mapTheme==='dark'?.55:.35;}
  if(_sunLight) _sunLight.intensity=_mapTheme==='dark'?1.1:1.1;
  if(_rimLight) _rimLight.intensity=_mapTheme==='dark'?.35:.22;
  if(_ambLight) _ambLight.intensity=_mapTheme==='dark'?4.5:4.3;
  if(curMapView==='map') _buildFlatMap();
}
function toggleTheme(){_mapTheme=(_mapTheme==='dark'?'light':'dark');_applyTheme();}

function switchView(v){
  curMapView=v;
  document.getElementById('btnGlobe').classList.toggle('mon',v==='globe');
  document.getElementById('btnMap').classList.toggle('mon',v==='map');
  document.getElementById('gCanvas').classList.toggle('mhide',v==='map');
  document.getElementById('mDiv').classList.toggle('mshow',v==='map');
  if(v==='map') _buildFlatMap();
}
function mapZoom(d){
  if(curMapView==='globe'&&_globeCamera) _camZTarget=Math.max(140,Math.min(480,(_camZTarget||_globeCamera.position.z)-d*30));
  else{_fZoom=Math.max(0,Math.min(4,_fZoom+d));_buildFlatMap();}
}
function mapReset(){
  _camZTarget=270;
  if(_earthGroup) _earthGroup.quaternion.set(0,0,0,1);
  _fZoom=0;if(curMapView==='map') _buildFlatMap();
}

// ATTACK GENERATOR
var _CTRY={
  Russia:{lat:55.75,lon:37.62,col:'#ff5544',apt:'APT-28/Sandworm'},
  China:{lat:39.91,lon:116.39,col:'#ff8800',apt:'APT-41'},
  Iran:{lat:35.69,lon:51.39,col:'#cc44ff',apt:'Charming Kitten'},
  'North Korea':{lat:39.02,lon:125.75,col:'#ee88ff',apt:'Lazarus Group'},
  Nigeria:{lat:9.07,lon:7.40,col:'#ff6600',apt:'TA505'},
  Brazil:{lat:-15.78,lon:-47.93,col:'#00ee77',apt:'LAPSUS$'},
  India:{lat:28.61,lon:77.21,col:'#ffaa33',apt:'SideWinder'},
  Ukraine:{lat:50.45,lon:30.52,col:'#44aaff',apt:'Various'},
  'United States':{lat:38.90,lon:-77.04,col:'#ffcc00',apt:'Various'},
  Pakistan:{lat:33.69,lon:73.06,col:'#ffbb44',apt:'Transparent Tribe'}
};
var _ACTORS=[
  {n:'APT-28',c:'Russia'},{n:'APT-41',c:'China'},{n:'Lazarus',c:'North Korea'},
  {n:'Charming Kitten',c:'Iran'},{n:'TA505',c:'Nigeria'},{n:'Sandworm',c:'Russia'},
  {n:'APT-34',c:'Iran'},{n:'SideWinder',c:'India'}
];
var _SEV={Critical:'#ff2244',High:'#ff6b00',Medium:'#ffd000',Low:'#00cc66'};

function genAtk(){
  var actor=_ACTORS[Math.floor(Math.random()*_ACTORS.length)];
  var cd=_CTRY[actor.c];if(!cd) return;
  var jLat=cd.lat+(Math.random()-.5)*4,jLon=cd.lon+(Math.random()-.5)*4;
  var r=Math.random();
  var sev=r>.72?'Critical':r>.44?'High':r>.2?'Medium':'Low';
  var sc=_SEV[sev],w=sev==='Critical'?2.2:sev==='High'?1.6:1.0;
  _spawnArc(jLat,jLon,sc);
  _spawnBeacon(cd.lat,cd.lon,cd.col,sev);
  // Flat map
  _fLines.push({type:'scattergeo',mode:'lines',lat:[jLat,51.5074],lon:[jLon,-0.1278],
    line:{width:w+1.6,color:'rgba(255,255,255,0.08)'},opacity:sev==='Critical'?.95:sev==='High'?.78:.55,hoverinfo:'skip'});
  _fLines.push({type:'scattergeo',mode:'lines',lat:[jLat,51.5074],lon:[jLon,-0.1278],
    line:{width:w,color:sc},opacity:sev==='Critical'?.88:sev==='High'?.74:.50,hoverinfo:'skip'});
  _fDots.push({type:'scattergeo',mode:'markers',lat:[cd.lat],lon:[cd.lon],
    marker:{size:sev==='Critical'?14:sev==='High'?10:7,color:sc,opacity:.88,symbol:'circle',line:{width:1.5,color:'rgba(255,255,255,0.3)'}},
    hovertemplate:'<b style="color:'+sc+'">⚠ '+actor.n+'</b><br>From: <b>'+actor.c+'</b><br>Sev: <b>'+sev+'</b><extra></extra>'});
  if(!_fLA[actor.c]){_fLA[actor.c]=true;
    _fLabels.push({type:'scattergeo',mode:'text',lat:[cd.lat+3.5],lon:[cd.lon],text:[actor.c.toUpperCase()],
      textfont:{color:cd.col,size:11,family:'Exo 2'},hoverinfo:'skip'});}
  if(_fLines.length>60) _fLines.splice(0,_fLines.length-50);
  if(_fDots.length>120) _fDots.splice(0,_fDots.length-90);
  if(curMapView==='map') _buildFlatMap();
  // HUD
  _tScore+=sev==='Critical'?10:sev==='High'?6:sev==='Medium'?3:1;_lineCount++;
  if(_tScore>40)_tLevel=2;if(_tScore>90)_tLevel=3;if(_tScore>160)_tLevel=4;
  var e1=document.getElementById('tSc'),e2=document.getElementById('tLv'),e3=document.getElementById('tCa');
  if(e1)e1.textContent=_tScore;if(e2)e2.textContent=_tLevel;if(e3)e3.textContent=_lineCount;
}
setInterval(genAtk,3000);

var _advice=['Recommend traffic sinkhole isolation.','Deploy deception network nodes.',
  'Initiate cross-border intel sharing.','Activate Tier-2 incident response.',
  'Monitor actor persistence patterns.','Enforce zero-trust segmentation.',
  'Review firewall egress rules immediately.','Correlate with threat intel feeds.'];
setInterval(function(){
  var p=document.getElementById('aiAdvisory');
  if(p){p.innerHTML+=_advice[Math.floor(Math.random()*_advice.length)]+'<br>';p.scrollTop=p.scrollHeight;}
},6000);

// INIT — use requestAnimationFrame to guarantee DOM is painted
requestAnimationFrame(function(){
  requestAnimationFrame(function(){
    if(document.getElementById('extGlobe')) return;
    _initGlobe().then(function(){ for(var i=0;i<5;i++) setTimeout(genAtk, i*500); });
  });
});
</script>
</body>
</html>"""

# ══════════════════════════════════════════════════════════════
# CELL 10 — FLASK ROUTES
# ══════════════════════════════════════════════════════════════

@app.route('/')
def home():
    total     = sum(a.get('total',0)      for a in alerts)
    suspicious= sum(a.get('suspicious',0) for a in alerts)
    critical  = sum(a.get('critical',0)   for a in alerts)
    high      = sum(a.get('high',0)       for a in alerts)
    medium    = sum(a.get('medium',0)     for a in alerts)
    low       = sum(a.get('low',0)        for a in alerts)
    countries = len(set(c for a in alerts for c in a.get('countries',[])))
    unique_ips= len(set(ip for a in alerts for ip in a.get('ips',[])))
    return render_template_string(HTML,
        total=total, suspicious=suspicious, critical=critical,
        high=high, medium=medium, low=low,
        countries=countries, unique_ips=unique_ips,
        show_banner=(critical+high)>0)

@app.route('/globe_flatmap_final')
def globe_flatmap_final():
    return send_file('globe_flatmap_final.html', max_age=0)


@app.route('/analyze_ajax', methods=['POST'])
def analyze_ajax():
    try:
        api_key  = request.form.get('api_key','').strip()
        manual   = request.form.get('manual','High')
        override = request.form.get('override','None')
        log_text = ''

        if 'logfile' in request.files and request.files['logfile'].filename:
            log_text = request.files['logfile'].read().decode('utf-8', errors='replace')
        elif request.form.get('logtext','').strip():
            log_text = request.form['logtext']
        else:
            return jsonify({'error':'No log data provided.'}), 400

        entries = parse_log_content(log_text)
        if not entries:
            return jsonify({'error':'No parseable log entries found.'}), 400

        stats   = build_stats(entries)
        key     = api_key or OPENAI_KEY
        ai_raw  = ai_analyze_log(log_text[:4000], key)
        summary = ai_executive_summary(stats, key)

        # Explain top suspicious entries
        for i, e in enumerate(stats['suspicious_entries'][:8]):
            stats['suspicious_entries'][i]['ai_explanation'] = ai_explain_entry(e, key)

        ai_data   = parse_ai_output(ai_raw)
        final_sev = override if override != 'None' else ai_data.get('severity','Unknown')

        alerts.append({
            'total':       stats['total'],
            'suspicious':  stats['suspicious'],
            'critical':    stats['critical'],
            'high':        stats['high'],
            'medium':      stats['medium'],
            'low':         stats['low'],
            'manual':      manual,
            'ai_severity': final_sev,
            'countries':   [c[0] for c in stats['top_countries']],
            'ips':         [ip[0] for ip in stats['top_ips']],
            # Preserved for PDF
            '_stats':    stats,
            '_ai_raw':   ai_raw,
            '_summary':  summary,
            '_manual':   manual,
            '_override': override,
            '_entries':  entries,
        })

        charts = make_charts(stats)
        return jsonify({'success':True, 'stats':stats,
                        'charts':charts, 'summary':summary, 'ai_raw':ai_raw})

    except Exception as ex:
        import traceback
        return jsonify({'error':str(ex), 'trace':traceback.format_exc()}), 500


@app.route('/export_pdf')
def export_pdf():
    if not alerts:
        return "No analysis data yet. Run an analysis first.", 400
    last = alerts[-1]
    try:
        fname, case_id = generate_pdf(
            stats           = last['_stats'],
            ai_text         = last['_ai_raw'],
            summary_text    = last['_summary'],
            manual_severity = last['_manual'],
            override        = last['_override'],
            entries         = last['_entries']
        )
        pdf_bytes = fname.getvalue()
        resp = make_response(pdf_bytes)
        resp.headers['Content-Type'] = 'application/pdf'
        resp.headers['Content-Disposition'] = f'attachment; filename="{case_id}_SOC_Report.pdf"'
        resp.headers['Content-Length'] = str(len(pdf_bytes))
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
        return resp
    except Exception as ex:
        import traceback
        return f"PDF generation error: {ex}\n\n{traceback.format_exc()}", 500


# ══════════════════════════════════════════════════════════════
# CELL 11 — LAUNCH
# ══════════════════════════════════════════════════════════════

public_url = None
try:
    public_url = ngrok.connect(5000)
except Exception as ex:
    print(f"Ngrok unavailable: {ex}")
print("=" * 60)
print("🛡️  CYBERSENTINEL PRO — BLUE TEAM SOC TOOL")
print("=" * 60)
print(f"✅  Public URL :  {public_url if public_url else 'Not available'}")
print(f"🌐  Local URL  :  http://localhost:5000")
print("=" * 60)
print("📁  Upload .log .txt .csv .json  |  Or paste raw logs")
print("🤖  GPT-4o-mini analysis + MITRE mapping")
print("🌍  3D live globe  |  📊 8 interactive charts")
print("📄  Professional PDF report export")
print("=" * 60)

app.run(port=5000)
