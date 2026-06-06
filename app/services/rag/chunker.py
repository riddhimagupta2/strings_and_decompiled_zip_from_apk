
"""
APK JSON ko behavior-focused chunks mein todta hai.
Framework-agnostic: Flutter, Java, Kotlin, React Native sab same treatment.
"""

from typing import Any
import re

FRAMEWORK_NOISE_APIS = {
    "loadClass",         
    "registerReceiver",   
    "loadUrl",            
    "Runtime",            
    "reflection",         
    "ContentResolver",    
    "sendBroadcast",      
    "openFileOutput",     
    "rawQuery",           
    "execSQL",            
    "getAccounts",        
}

HIGH_RISK_PERMISSIONS = {
    "READ_SMS",
    "RECEIVE_SMS",
    "SEND_SMS",
    "BIND_ACCESSIBILITY_SERVICE",
    "BIND_DEVICE_ADMIN",
    "REQUEST_INSTALL_PACKAGES",
    "SYSTEM_ALERT_WINDOW",
    "PROCESS_OUTGOING_CALLS",
    "BIND_NOTIFICATION_LISTENER_SERVICE",
    "MANAGE_EXTERNAL_STORAGE",
    "DISABLE_KEYGUARD",
    "QUERY_ALL_PACKAGES",
}

MEDIUM_RISK_PERMISSIONS = {
    "RECORD_AUDIO",
    "CAMERA",
    "ACCESS_FINE_LOCATION",
    "READ_CONTACTS",
    "READ_CALL_LOG",
    "READ_PHONE_STATE",
    "USE_BIOMETRIC",
    "USE_FINGERPRINT",
}

HIGH_RISK_APIS = {
    "getDeviceId", "getImei", "getSubscriberId",
    "getSimSerialNumber", "sendTextMessage",
    "onAccessibilityEvent", "setAccessibilityDelegate",
    "DexClassLoader", "PathClassLoader", "loadDex",   
    "Runtime.exec", "ProcessBuilder",                  
    "getPassword",
}

BEHAVIOR_CLUSTERS = [
    
    {
        "id": "sms_exfiltration",
        "name": "SMS/OTP Exfiltration",
        "severity": "CRITICAL",
        "base_score": 8.0,
        "perm_triggers": {"READ_SMS", "RECEIVE_SMS", "SEND_SMS"},
        "api_triggers":  {"sendTextMessage", "getSubscriberId"},
        "min_perm_hits": 1,
        "min_api_hits":  0,
        "amplifiers":    {"BIND_NOTIFICATION_LISTENER_SERVICE", "INTERNET"},
        "amplification_bonus": 1.5,
        "description":   "Reads/sends SMS — banking OTP theft capability",
    },
    {
        "id": "accessibility_abuse",
        "name": "Accessibility Service Abuse",
        "severity": "CRITICAL",
        "base_score": 7.5,
        "perm_triggers": {"BIND_ACCESSIBILITY_SERVICE"},
        "api_triggers":  {"onAccessibilityEvent", "setAccessibilityDelegate"},
        "min_perm_hits": 1,
        "min_api_hits":  0,
        "amplifiers":    {"SYSTEM_ALERT_WINDOW", "READ_SMS"},
        "amplification_bonus": 2.0,
        "description":   "Reads screen content, simulates taps — keylogger possible",
    },
    {
        "id": "device_admin_abuse",
        "name": "Device Admin Abuse",
        "severity": "CRITICAL",
        "base_score": 7.0,
        "perm_triggers": {"BIND_DEVICE_ADMIN"},
        "api_triggers":  set(),
        "min_perm_hits": 1,
        "min_api_hits":  0,
        "amplifiers":    set(),
        "amplification_bonus": 0,
        "description":   "Can prevent uninstall, wipe device remotely",
    },
    {
        "id": "dynamic_code_exec",
        "name": "Dynamic Code Execution",
        "severity": "CRITICAL",
        "base_score": 6.5,
        "perm_triggers": set(),
        "api_triggers":  {"DexClassLoader", "PathClassLoader", "loadDex"},
        "min_perm_hits": 0,
        "min_api_hits":  1,
        "amplifiers":    {"INTERNET", "RECEIVE_BOOT_COMPLETED"},
        "amplification_bonus": 2.0,
        "description":   "Loads DEX code at runtime — dropper/evasion technique",
    },
    {
        "id": "shell_execution",
        "name": "Shell Command Execution",
        "severity": "CRITICAL",
        "base_score": 6.0,
        "perm_triggers": set(),
        "api_triggers":  {"Runtime.exec", "ProcessBuilder"},
        "min_perm_hits": 0,
        "min_api_hits":  1,
        "amplifiers":    set(),
        "amplification_bonus": 0,
        "description":   "Executes shell commands — privilege escalation risk",
    },

    {
        "id": "overlay_attack",
        "name": "Overlay / Phishing UI",
        "severity": "HIGH",
        "base_score": 5.0,
        "perm_triggers": {"SYSTEM_ALERT_WINDOW"},
        "api_triggers":  set(),
        "min_perm_hits": 1,
        "min_api_hits":  0,
        "amplifiers":    {"BIND_ACCESSIBILITY_SERVICE", "READ_SMS"},
        "amplification_bonus": 3.0,
        "description":   "Draw-over-other-apps — credential overlay attack possible",
    },
    {
        "id": "package_dropper",
        "name": "APK Dropper / Installer",
        "severity": "HIGH",
        "base_score": 4.5,
        "perm_triggers": {"REQUEST_INSTALL_PACKAGES"},
        "api_triggers":  set(),
        "min_perm_hits": 1,
        "min_api_hits":  0,
        "amplifiers":    {"INTERNET", "RECEIVE_BOOT_COMPLETED", "DexClassLoader"},
        "amplification_bonus": 2.5,
        "description":   "Can install other APKs — dropper malware pattern",
    },
    {
        "id": "notification_spy",
        "name": "Notification / OTP Spy",
        "severity": "HIGH",
        "base_score": 4.5,
        "perm_triggers": {"BIND_NOTIFICATION_LISTENER_SERVICE"},
        "api_triggers":  set(),
        "min_perm_hits": 1,
        "min_api_hits":  0,
        "amplifiers":    {"READ_SMS", "INTERNET"},
        "amplification_bonus": 2.5,
        "description":   "Reads all notifications — OTP interception possible",
    },

    {
        "id": "device_fingerprint",
        "name": "Device Fingerprinting",
        "severity": "MEDIUM",
        "base_score": 3.5,
        "perm_triggers": {"READ_PHONE_STATE"},
        "api_triggers":  {"getDeviceId", "getImei", "getSubscriberId", "getSimSerialNumber"},
        "min_perm_hits": 0,
        "min_api_hits":  1,
        "amplifiers":    {"INTERNET"},
        "amplification_bonus": 1.0,
        "description":   "Collects unique hardware/SIM identifiers",
    },
    {
        "id": "persistent_surveillance",
        "name": "Persistent Background Surveillance",
        "severity": "MEDIUM",
        "base_score": 3.0,
        "perm_triggers": {"RECEIVE_BOOT_COMPLETED", "FOREGROUND_SERVICE"},
        "api_triggers":  set(),
        "min_perm_hits": 2,      
        "min_api_hits":  0,
        "amplifiers":    {"RECORD_AUDIO", "ACCESS_FINE_LOCATION", "CAMERA"},
        "amplification_bonus": 2.0,
        "description":   "Survives reboot + persistent service + sensor access",
    },
    {
        "id": "contact_exfil",
        "name": "Contact / Call Log Exfiltration",
        "severity": "MEDIUM",
        "base_score": 2.5,
        "perm_triggers": {"READ_CONTACTS"},
        "api_triggers":  set(),
        "min_perm_hits": 1,
        "min_api_hits":  0,
        "amplifiers":    {"READ_CALL_LOG", "INTERNET"},
        "amplification_bonus": 1.5,
        "description":   "Can read and upload contact list",
    },
]

SAFE_URL_DOMAINS = [
    "schemas.android.com", "developer.android.com",
    "google.com", "googleapis.com", "firebase.google.com",
    "gstatic.com", "googleusercontent.com", "firebaseapp.com",
    "flutter.dev", "dart.dev", "pub.dev", "docs.flutter.dev",
    "microsoft.com", "live.com", "office.com",
    "github.com", "raw.githubusercontent.com/flutter",
    "fastlane.tools", "issuetracker.google.com",
    "stackoverflow.com", "w3.org", "schema.org",
    "amazon.com", "amazonaws.com", "cloudfront.net",
    "apple.com", "icloud.com",
    "facebook.com", "fbcdn.net",
    "twitter.com", "t.co",
    "example.com",   
]

SUSPICIOUS_URL_PATTERNS = [
    r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  
    r"\.tk/?(\?.*)?$",                          
    r"\.xyz/?(\?.*)?$",
    r"\.top/?(\?.*)?$",
    r"ngrok\.io",                               
    r"\.onion",                                 
    r"pastebin\.com",                           
]


def _is_safe_url(url: str) -> bool:
    url_lower = url.lower()
    return any(domain in url_lower for domain in SAFE_URL_DOMAINS)


def _is_suspicious_url(url: str) -> bool:
    return any(re.search(p, url, re.IGNORECASE) for p in SUSPICIOUS_URL_PATTERNS)


def _evaluate_behavior_clusters(
    permissions: list[str],
    api_calls: list[str],
) -> tuple[list[dict], float]:
    
    perm_set = {p.split(".")[-1] for p in permissions}
    api_set  = set(api_calls)

    api_set -= FRAMEWORK_NOISE_APIS

    triggered   = []
    total_score = 0.0

    for cluster in BEHAVIOR_CLUSTERS:
        perm_hits = perm_set & cluster["perm_triggers"]
        api_hits  = api_set  & cluster["api_triggers"]

        perm_count = len(perm_hits)
        api_count  = len(api_hits)

        if (perm_count >= cluster["min_perm_hits"] and
                api_count  >= cluster["min_api_hits"] and
                (perm_count + api_count) > 0):

            score = cluster["base_score"]

            amp_hits = perm_set & cluster.get("amplifiers", set())
 
            amp_api_hits = api_set & cluster.get("amplifiers", set())
            if amp_hits or amp_api_hits:
                score += cluster.get("amplification_bonus", 0)
                score  = min(score, 10.0)

            triggered.append({
                "cluster_id":    cluster["id"],
                "cluster_name":  cluster["name"],
                "severity":      cluster["severity"],
                "score":         round(score, 1),
                "perm_evidence": list(perm_hits),
                "api_evidence":  list(api_hits),
                "amplified_by":  list(amp_hits | amp_api_hits),
                "description":   cluster["description"],
            })
            total_score += score

    return triggered, min(total_score, 10.0)


def _score_certificate(cert: dict) -> tuple[float, str]:
    """Certificate score calculate karo."""
    subject        = cert.get("subject", "")
    is_self_signed = cert.get("is_self_signed", False)

    if "CN=Android Debug" in subject or "Android Debug" in subject:
        return 0.0, "Android Debug certificate — development build, NOT suspicious"

    if is_self_signed:
        suspicious_names = ["test", "example", "admin", "root", "user", "cn=android"]
        if any(s in subject.lower() for s in suspicious_names):
            return 3.0, f"Self-signed with suspicious subject: {subject}"
        return 1.5, f"Self-signed production certificate: {subject}"

    return 0.0, f"Properly signed: {subject}"


def _score_iocs(hardcoded: dict, strings: dict) -> tuple[float, list[str]]:

    score    = 0.0
    findings = []

    public_ips = [
        ip for ip in hardcoded.get("ips", [])
        if not any(ip.startswith(p) for p in ("192.168.", "10.", "127.", "172.", "0."))
    ]
    if public_ips:
        score += min(len(public_ips) * 2.0, 4.0)
        findings.append(f"Hardcoded public IPs: {public_ips}")

    
    all_urls = list(set(hardcoded.get("urls", []) + strings.get("urls", [])))
    sus_urls = [u for u in all_urls if not _is_safe_url(u) and _is_suspicious_url(u)]
    if sus_urls:
        score += min(len(sus_urls) * 2.5, 5.0)
        findings.append(f"Suspicious URLs: {sus_urls}")

    
    commands     = strings.get("commands", [])
    danger_cmds  = [
        c for c in commands
        if any(kw in c for kw in ["chmod 777", "su ", "mount -o rw", "rm -rf", "wget ", "curl "])
    ]
    if danger_cmds:
        score += min(len(danger_cmds) * 2.0, 4.0)
        findings.append(f"Dangerous shell commands: {danger_cmds}")

    return min(score, 10.0), findings






def chunk_apk_json(apk_json: dict[str, Any]) -> list[dict[str, Any]]:
    """
    APK JSON ko behavior-focused chunks mein todta hai.
    Framework-agnostic. Behavior correlation based.
    
    Returns 4 chunks:
      1. identity      — package info + cert
      2. behavior      — cluster analysis (PRIMARY signal)
      3. iocs          — hardcoded IPs, suspicious URLs, commands
      4. risk_summary  — composite score + pre-verdict
    """
    job_id       = apk_json.get("job_id", "unknown")
    package_name = apk_json.get("package_name", "unknown")

    permissions = apk_json.get("permissions", [])
    api_calls   = apk_json.get("api_calls", [])
    hardcoded   = apk_json.get("hardcoded", {})
    strings_d   = apk_json.get("strings", {})
    cert        = apk_json.get("certificate", {})
    risk_flags  = apk_json.get("risk_flags", [])

    
    triggered_clusters, behavior_score = _evaluate_behavior_clusters(permissions, api_calls)
    cert_score, cert_reason            = _score_certificate(cert)
    ioc_score, ioc_findings            = _score_iocs(hardcoded, strings_d)
    existing_score                     = float(apk_json.get("risk_score", 0))

    
    composite = round(
        behavior_score * 0.55 +
        ioc_score      * 0.25 +
        existing_score * 0.15 +
        cert_score     * 0.05,
        2
    )

    critical_count = sum(1 for c in triggered_clusters if c["severity"] == "CRITICAL")
    high_count     = sum(1 for c in triggered_clusters if c["severity"] == "HIGH")

    
    if composite >= 6.5 or (critical_count > 0 and composite >= 4.0):
        pre_verdict = "MALICIOUS"
    elif composite >= 3.5 or critical_count > 0:
        pre_verdict = "SUSPICIOUS"
    else:
        pre_verdict = "SAFE"

    chunks = []

    
    identity_text = f"""APK Identity for {package_name}:
  Package:     {package_name}
  Version:     {apk_json.get('version_name', 'unknown')}
  SHA256:      {apk_json.get('sha256', '')}
  Min SDK:     {apk_json.get('min_sdk', '')}
  Target SDK:  {apk_json.get('target_sdk', '')}

Certificate:
  Subject:     {cert.get('subject', '')}
  Issuer:      {cert.get('issuer', '')}
  Self-Signed: {cert.get('is_self_signed', False)}
  Valid:       {cert.get('not_before', '')} to {cert.get('not_after', '')}
  Risk Note:   {cert_reason}
  Cert Score:  {cert_score}/10"""

    chunks.append({
        "chunk_id":   f"{job_id}_identity",
        "chunk_type": "identity",
        "text":       identity_text,
        "metadata": {
            "job_id":        job_id,
            "package_name":  package_name,
            "chunk_type":    "identity",
            "is_self_signed": str(cert.get("is_self_signed", False)),
            "cert_score":    str(cert_score),
        }
    })

    
    high_risk_perms   = [p for p in permissions if p.split(".")[-1] in HIGH_RISK_PERMISSIONS]
    medium_risk_perms = [p for p in permissions if p.split(".")[-1] in MEDIUM_RISK_PERMISSIONS]

    cluster_lines = []
    for c in triggered_clusters:
        cluster_lines.append(
            f"  [{c['severity']}] {c['cluster_name']} | Score: {c['score']}"
        )
        if c["perm_evidence"]:
            cluster_lines.append(f"    Perm Evidence: {c['perm_evidence']}")
        if c["api_evidence"]:
            cluster_lines.append(f"    API Evidence:  {c['api_evidence']}")
        if c["amplified_by"]:
            cluster_lines.append(f"    Amplified By:  {c['amplified_by']}")
        cluster_lines.append(f"    Meaning: {c['description']}")

    behavior_text = f"""Behavior Analysis for {package_name}:
  Behavior Score: {behavior_score:.1f}/10

  Triggered Behavior Clusters ({len(triggered_clusters)}):
{chr(10).join(cluster_lines) if cluster_lines else '  NONE — no malicious behavior patterns detected'}

  High-Risk Permissions ({len(high_risk_perms)}):
{chr(10).join(f'    - {p}' for p in high_risk_perms) if high_risk_perms else '    None'}

  Medium-Risk Permissions ({len(medium_risk_perms)}):
{chr(10).join(f'    - {p}' for p in medium_risk_perms) if medium_risk_perms else '    None'}

  Total Permissions: {len(permissions)}
  NOTE: Framework APIs (loadClass, registerReceiver, loadUrl, Runtime) filtered — not scored."""

    chunks.append({
        "chunk_id":   f"{job_id}_behavior",
        "chunk_type": "behavior",
        "text":       behavior_text,
        "metadata": {
            "job_id":            job_id,
            "package_name":      package_name,
            "chunk_type":        "behavior",
            "behavior_score":    str(round(behavior_score, 1)),
            "critical_clusters": str(critical_count),
            "high_clusters":     str(high_count),
            "cluster_ids":       ",".join(c["cluster_id"] for c in triggered_clusters),
        }
    })

    
    all_urls       = list(set(hardcoded.get("urls", []) + strings_d.get("urls", [])))
    suspicious_urls = [u for u in all_urls if not _is_safe_url(u) and _is_suspicious_url(u)]
    unknown_urls    = [u for u in all_urls if not _is_safe_url(u) and not _is_suspicious_url(u)]
    public_ips      = [
        ip for ip in hardcoded.get("ips", [])
        if not any(ip.startswith(p) for p in ("192.168.", "10.", "127.", "172.", "0."))
    ]
    danger_cmds = [
        c for c in strings_d.get("commands", [])
        if any(kw in c for kw in ["chmod 777", "su ", "mount -o rw", "rm -rf", "wget ", "curl "])
    ]

    ioc_text = f"""IOC Analysis for {package_name}:
  IOC Score: {ioc_score:.1f}/10

  Hardcoded Public IPs ({len(public_ips)}):
{chr(10).join(f'    - {ip}' for ip in public_ips) if public_ips else '    None'}

  Suspicious URLs ({len(suspicious_urls)}):
{chr(10).join(f'    - {u}' for u in suspicious_urls) if suspicious_urls else '    None'}

  Unknown URLs ({len(unknown_urls[:5])} shown of {len(unknown_urls)}):
{chr(10).join(f'    - {u}' for u in unknown_urls[:5]) if unknown_urls else '    None'}

  Dangerous Shell Commands ({len(danger_cmds)}):
{chr(10).join(f'    - {c}' for c in danger_cmds) if danger_cmds else '    None'}

  Crypto Keys Found: {len(hardcoded.get('crypto_keys', []))}"""

    chunks.append({
        "chunk_id":   f"{job_id}_iocs",
        "chunk_type": "iocs",
        "text":       ioc_text,
        "metadata": {
            "job_id":             job_id,
            "package_name":       package_name,
            "chunk_type":         "iocs",
            "ioc_score":          str(round(ioc_score, 1)),
            "has_public_ips":     str(len(public_ips) > 0),
            "suspicious_urls":    str(len(suspicious_urls)),
            "dangerous_commands": str(len(danger_cmds)),
        }
    })

    
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for flag in risk_flags:
        sev = flag.get("severity", "LOW").upper()
        if sev in sev_counts:
            sev_counts[sev] += 1

    risk_text = f"""Risk Summary for {package_name}:
  Composite Score:    {composite}/10
  Behavior Score:     {behavior_score:.1f}/10  (weight 55%)
  IOC Score:          {ioc_score:.1f}/10       (weight 25%)
  Static Tool Score:  {existing_score}/10      (weight 15%)
  Certificate Score:  {cert_score}/10          (weight  5%)

  Pre-computed Verdict:    {pre_verdict}
  Critical Clusters:       {critical_count}
  High Clusters:           {high_count}

  Static Tool Risk Flags ({len(risk_flags)}):
    Critical: {sev_counts['CRITICAL']}
    High:     {sev_counts['HIGH']}
    Medium:   {sev_counts['MEDIUM']}
    Low:      {sev_counts['LOW']}"""

    chunks.append({
        "chunk_id":   f"{job_id}_risk",
        "chunk_type": "risk_summary",
        "text":       risk_text,
        "metadata": {
            "job_id":            job_id,
            "package_name":      package_name,
            "chunk_type":        "risk_summary",
            "composite_score":   str(composite),
            "behavior_score":    str(round(behavior_score, 1)),
            "pre_verdict":       pre_verdict,
            "critical_clusters": str(critical_count),
            "high_clusters":     str(high_count),
        }
    })

    return chunks