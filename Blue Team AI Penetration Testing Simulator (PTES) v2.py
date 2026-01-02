#!/usr/bin/env python3
"""
PTES AI Penetration Testing Simulator (ETHICAL / DEFENSIVE)

- Full PTES phase simulation (1–12)
- Recon-driven (TXT input)
- LLaMA reasoning only (NO exploits)
- SOC Playbooks for every phase
- MITRE ATT&CK mapping per phase
- OWASP ASVS scoring
- Executive summary auto-generator
- TXT report output
"""

import os
import re
import json
import streamlit as st
from huggingface_hub import InferenceClient

# =====================================================
# PROXY CONTROL (RESET)
# =====================================================
os.environ.pop("HTTP_PROXY", None)
os.environ.pop("HTTPS_PROXY", None)
os.environ.pop("ALL_PROXY", None)

# =====================================================
# HUGGING FACE CONFIG
# =====================================================
HF_TOKEN = "HF_TOKEN"
MODEL_ID = "meta-llama/Llama-3.1-8B-Instruct"
llm = InferenceClient(MODEL_ID, token=HF_TOKEN)

# =====================================================
# EXPANDED RECON SIGNAL EXTRACTION
# =====================================================
def extract_signals(text):
    t = text.lower()
    return {
        "network": {
            "open_ports": sorted(set(re.findall(r"(\d+)/tcp\s+open", t))),
            "admin_ports": any(p in t for p in ["22/tcp open", "3389/tcp open", "5900/tcp open"]),
            "cdn": any(x in t for x in ["cloudflare", "akamai", "fastly"]),
            "load_balancer": any(x in t for x in ["elb", "nginx", "haproxy"]),
            "waf_headers": any(h in t for h in [
                "content-security-policy",
                "x-frame-options",
                "x-xss-protection"
            ])
        },
        "web": {
            "http": "80/tcp open" in t,
            "https": "443/tcp open" in t,
            "redirects": t.count("302"),
            "error_pages": t.count("404") + t.count("500"),
            "upload_forms": "upload" in t,
            "api_paths": any(x in t for x in ["/api", "graphql", "swagger"]),
            "debug_keywords": any(x in t for x in ["debug", "trace", "stack trace"])
        },
        "auth": {
            "login_pages": any(x in t for x in ["login", "signin", "auth"]),
            "password_reset": "reset password" in t,
            "mfa_present": any(x in t for x in ["mfa", "2fa", "otp"]),
            "weak_cookie_flags": "secure" not in t or "httponly" not in t
        },
        "tls_crypto": {
            "hsts": "strict-transport-security" in t,
            "legacy_tls": any(x in t for x in ["tls 1.0", "tls 1.1"]),
            "expired_cert": "expired" in t,
            "self_signed": "self-signed" in t
        },
        "dns_email": {
            "dnssec": "dnssec" in t,
            "spf": "spf" in t,
            "dmarc": "dmarc" in t,
            "mx_records": "mail exchanger" in t,
            "email_leak": any(x in t for x in ["@", "email"])
        },
        "cloud_saas": {
            "aws": "amazonaws" in t,
            "azure": "azure" in t,
            "gcp": "google cloud" in t,
            "storage_buckets": any(x in t for x in ["s3", "blob", "bucket"])
        },
        "devops": {
            "ci_cd": any(x in t for x in ["jenkins", "gitlab", "github actions"]),
            "exposed_repos": "git" in t,
            "env_files": ".env" in t
        },
        "monitoring": {
            "ids_present": any(x in t for x in ["snort", "suricata"]),
            "edr_present": any(x in t for x in ["crowdstrike", "sentinelone"]),
            "logging_headers": "x-request-id" in t
        }
    }

# =====================================================
# PTES PHASE DEFINITIONS
# =====================================================
PTES_PHASES = [
    (1, "PRE_ENGAGEMENT", "Pre-Engagement & Scope"),
    (2, "RECON", "Reconnaissance"),
    (3, "ENUMERATION", "Enumeration"),
    (4, "VULN_ANALYSIS", "Vulnerability Analysis"),
    (5, "ATTACK_SIM", "Attack Path Simulation (Awareness)"),
    (6, "POST_EXPLOIT", "Post-Exploitation Impact"),
    (7, "LATERAL", "Lateral Movement Risk"),
    (8, "PRIV_ESC", "Privilege Escalation Indicators"),
    (9, "PERSISTENCE", "Persistence & Detection Gaps"),
    (10, "C2", "Command & Control Awareness"),
    (11, "IMPACT", "Business Impact"),
    (12, "REPORTING", "Reporting & Remediation"),
]

# =====================================================
# SOC PLAYBOOKS
# =====================================================
SOC_PLAYBOOKS = {
    "PRE_ENGAGEMENT": ["Confirm scope", "Approve ROE"],
    "RECON": ["Detect scanning behavior", "Rate-limit sources"],
    "ENUMERATION": ["Alert on enumeration patterns", "Tune IDS"],
    "VULN_ANALYSIS": ["Prioritize patching", "Threat modeling"],
    "ATTACK_SIM": ["Block suspicious paths", "WAF rule tuning"],
    "POST_EXPLOIT": ["Audit sensitive data access", "Enable DLP"],
    "LATERAL": ["Monitor auth anomalies", "Segment networks"],
    "PRIV_ESC": ["Audit privilege changes", "Harden IAM"],
    "PERSISTENCE": ["Detect config drift", "EDR rule review"],
    "C2": ["Monitor outbound traffic", "DNS filtering"],
    "IMPACT": ["Assess business impact", "Notify leadership"],
    "REPORTING": ["Executive summary", "Track remediation"]
}

# =====================================================
# MITRE ATT&CK MAPPING
# =====================================================
MITRE_ATTACK_MAP = {
    "RECON": [
        ("TA0043", "Reconnaissance"), ("T1595", "Active Scanning"),
        ("T1592", "Gather Victim Host Info"), ("T1589", "Gather Victim Identity Info")
    ],
    "ENUMERATION": [
        ("TA0007", "Discovery"), ("T1087", "Account Discovery"),
        ("T1046", "Network Service Discovery"), ("T1135", "Network Share Discovery")
    ],
    "VULN_ANALYSIS": [
        ("TA0001", "Initial Access"), ("T1190", "Exploit Public-Facing App (Awareness)"),
        ("T1133", "External Remote Services")
    ],
    "ATTACK_SIM": [
        ("TA0001", "Initial Access"), ("T1078", "Valid Accounts (Credential Risk)"),
        ("T1059", "Command/Scripting Interpreter Awareness")
    ],
    "POST_EXPLOIT": [
        ("TA0009", "Collection"), ("T1005", "Data from Local System"),
        ("T1213", "Data from Repositories")
    ],
    "LATERAL": [
        ("TA0008", "Lateral Movement"), ("T1021", "Remote Services"),
        ("T1080", "Taint Shared Content")
    ],
    "PRIV_ESC": [
        ("TA0004", "Privilege Escalation"), ("T1068", "Exploitation Awareness"),
        ("T1078", "Valid Accounts")
    ],
    "PERSISTENCE": [
        ("TA0003", "Persistence"), ("T1098", "Account Manipulation"),
        ("T1547", "Boot/Logon Autostart Execution")
    ],
    "C2": [
        ("TA0011", "Command & Control"), ("T1071", "Application Layer Protocol"),
        ("T1095", "Non-App Layer Protocol"), ("T1568", "Dynamic Resolution")
    ],
    "IMPACT": [
        ("TA0040", "Impact"), ("T1486", "Data Encrypted for Impact Awareness"),
        ("T1499", "Endpoint Denial of Service")
    ]
}

# =====================================================
# OWASP ASVS + Top 10
# =====================================================
def owasp_assessment(signals):
    findings = []
    # Auth / MFA
    if signals["auth"]["login_pages"] and not signals["auth"]["mfa_present"]:
        findings.append({
            "asvs": "V2: Authentication",
            "top10": "A07: Identification & Authentication Failures",
            "severity": "HIGH",
            "note": "Login functionality without visible MFA"
        })
    # Session
    if signals["auth"]["weak_cookie_flags"]:
        findings.append({
            "asvs": "V3: Session Management",
            "top10": "A02: Cryptographic Failures",
            "severity": "MEDIUM",
            "note": "Cookies missing Secure/HttpOnly"
        })
    # TLS
    if signals["tls_crypto"]["legacy_tls"]:
        findings.append({
            "asvs": "V7: Cryptography",
            "top10": "A02: Cryptographic Failures",
            "severity": "HIGH",
            "note": "Legacy TLS versions supported"
        })
    if signals["tls_crypto"]["expired_cert"]:
        findings.append({
            "asvs": "V7: Cryptography",
            "top10": "A02: Cryptographic Failures",
            "severity": "HIGH",
            "note": "Expired TLS certificate"
        })
    # API
    if signals["web"]["api_paths"]:
        findings.append({
            "asvs": "V13: API Security",
            "top10": "A04: Insecure Design",
            "severity": "MEDIUM",
            "note": "Public API endpoints detected"
        })
    # File upload
    if signals["web"]["upload_forms"]:
        findings.append({
            "asvs": "V12: File Upload",
            "top10": "A05: Security Misconfiguration",
            "severity": "MEDIUM",
            "note": "File upload functionality exposed"
        })
    # Monitoring
    if not signals["monitoring"]["ids_present"]:
        findings.append({
            "asvs": "V14: Configuration",
            "top10": "A09: Security Logging & Monitoring Failures",
            "severity": "MEDIUM",
            "note": "No visible IDS/EDR"
        })
    # Cloud storage
    if signals["cloud_saas"]["storage_buckets"]:
        findings.append({
            "asvs": "V1: Architecture",
            "top10": "A05: Security Misconfiguration",
            "severity": "HIGH",
            "note": "Cloud storage references detected"
        })
    if not findings:
        findings.append({"asvs": "General","top10": "N/A","severity":"LOW","note":"No OWASP gaps from recon"})
    return findings

# =====================================================
# LLM SIMULATION FUNCTION
# =====================================================
def simulate_phase(phase_name, phase_title, signals, temperature):
    prompt = f"""
You are a defensive PTES analyst.

PTES Phase: {phase_title}

Recon Signals:
{json.dumps(signals, indent=2)}

Create a STRUCTURED defensive report including:
1. Attacker intent & feasibility
2. Defensive controls & mitigations
3. Business & operational risk
4. SOC recommendations

Rules:
- NO exploits
- NO payloads
- NO commands
"""
    response = llm.chat.completions.create(
        model=MODEL_ID,
        messages=[{"role": "system", "content": "You are a defensive PTES analyst."},
                  {"role": "user", "content": prompt}],
        temperature=temperature,
        max_tokens=450
    )
    return response.choices[0].message.content.strip()

# =====================================================
# STREAMLIT UI
# =====================================================
st.set_page_config(page_title="PTES AI Simulator", layout="wide")
st.title("🧠 PTES AI Penetration Testing Simulator (Defensive)")
st.caption("Full 1–12 PTES Simulation | Ethical | SOC-Oriented")

uploaded = st.file_uploader("Upload Recon TXT", type=["txt"])
temperature = st.slider("LLM Temperature", 0.0, 1.0, 0.3)

if uploaded:
    recon_text = uploaded.read().decode(errors="ignore")
    signals = extract_signals(recon_text)

    st.subheader("🔍 Extracted Recon Signals")
    st.json(signals)

    # OWASP ASVS
    st.subheader("🛡️ OWASP ASVS & Top 10 Assessment")
    owasp_findings = owasp_assessment(signals)
    for f in owasp_findings:
        st.write(f"- **{f['asvs']}** | **{f['top10']}** → `{f['severity']}` — {f['note']}")

    # Report storage
    report = ["PTES AI PENETRATION TESTING SIMULATION REPORT","="*60]

    for phase_id, phase_key, phase_title in PTES_PHASES:
        with st.expander(f"Phase {phase_id}: {phase_title}"):
            # AI Simulation
            result = simulate_phase(phase_key, phase_title, signals, temperature)
            st.markdown("### 🧠 AI Simulation")
            st.write(result)

            # SOC Playbook
            st.markdown("### 🛡️ SOC Playbook")
            for step in SOC_PLAYBOOKS[phase_key]:
                st.write(f"- {step}")

            # MITRE ATT&CK
            if phase_key in MITRE_ATTACK_MAP:
                st.markdown("### 🧩 MITRE ATT&CK (Awareness)")
                for tid, name in MITRE_ATTACK_MAP[phase_key]:
                    st.write(f"- **{tid}**: {name}")

            # Append to TXT report
            report.append(f"\nPHASE {phase_id}: {phase_title}")
            report.append(result)
            report.append("SOC PLAYBOOK:")
            for step in SOC_PLAYBOOKS[phase_key]:
                report.append(f"- {step}")
            if phase_key in MITRE_ATTACK_MAP:
                report.append("MITRE ATT&CK:")
                for tid, name in MITRE_ATTACK_MAP[phase_key]:
                    report.append(f"- {tid}: {name}")

    # Download button
    st.download_button(
        "📄 Download PTES Simulation Report (TXT)",
        "\n".join(report),
        file_name="ptes_ai_simulation_report.txt"
    )
else:
    st.info("Upload recon TXT to begin PTES simulation.")
