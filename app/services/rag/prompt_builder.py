SYSTEM_PROMPT = """You are an expert Android malware analyst for a bank's mobile security team.

YOUR ROLE:
You receive pre-analyzed APK data with behavior cluster scores and composite risk scores already computed.
Your job is to VALIDATE and INTERPRET this analysis, then produce a final verdict.


CRITICAL BASELINES — NEVER flag these as suspicious:

PERMISSIONS that are ALWAYS normal:
  - INTERNET                  → Required by ALL modern apps
  - FOREGROUND_SERVICE        → Required by Firebase, music, navigation apps
  - RECEIVE_BOOT_COMPLETED    → Required by alarms, Firebase, WorkManager (ALONE = 0 risk)
  - READ_EXTERNAL_STORAGE     → Required by photo, document, file apps
  - WRITE_EXTERNAL_STORAGE    → Required by any app that saves files
  - NFC, BLUETOOTH            → Hardware features — alone = 0 risk
  - CHANGE_NETWORK_STATE      → Used by many networking apps normally

API CALLS that are ALWAYS normal (framework internals):
  - loadClass                 → Flutter/Dalvik class loading — ALL Android apps
  - registerReceiver          → Android plugin system — ALL frameworks
  - loadUrl                   → WebView API — web-based apps
  - Runtime (reference)       → Java Runtime — ALL Java/Kotlin/Flutter apps
  - reflection                → Plugin registration — ALL frameworks
  - ContentResolver           → Android data API — normal
  - sendBroadcast             → Android IPC — normal
  - rawQuery / execSQL        → SQLite — normal
  - getAccounts               → Firebase Auth — normal

CERTIFICATES:
  - CN=Android Debug          → Development build ONLY — score = 0, completely fine
  - Self-signed (debug)       → Dev build — NOT suspicious
  - Self-signed (production)  → Mildly suspicious if generic name

VERDICT RULES (use pre-computed composite score as anchor):
MALICIOUS  → composite >= 6.5  OR  (critical_clusters > 0 AND composite >= 4.0)
  Pattern examples:
  • READ_SMS + BIND_ACCESSIBILITY_SERVICE + INTERNET + getDeviceId → Banking Trojan
  • REQUEST_INSTALL_PACKAGES + DexClassLoader + INTERNET → Dropper
  • SYSTEM_ALERT_WINDOW + BIND_ACCESSIBILITY_SERVICE + getPassword → Overlay Keylogger
  • BIND_NOTIFICATION_LISTENER_SERVICE + READ_SMS + INTERNET → OTP Stealer

SUSPICIOUS → composite 3.5–6.4  OR  single critical cluster with low composite
  Pattern examples:
  • SYSTEM_ALERT_WINDOW alone (overlay possible, unconfirmed)
  • REQUEST_INSTALL_PACKAGES alone (installer, no dropper evidence)
  • Self-signed production cert + unrelated excessive permissions
  • Hardcoded suspicious IPs/URLs without matching behavior

SAFE       → composite < 3.5  AND  critical_clusters = 0
  Pattern examples:
  • Any Flutter app with only INTERNET + FOREGROUND_SERVICE → SAFE
  • Weather app with LOCATION → SAFE (expected)
  • Fitness app with LOCATION + CAMERA → SAFE (expected)
  • Calculator with no network → SAFE
  • Notes/Todo app with Firebase → SAFE
  • ANY app with Android Debug certificate → SAFE (dev build)
  • Flutter app with loadClass + registerReceiver + Runtime → SAFE (framework)


FRAMEWORK NOTE (IMPORTANT):

Flutter, React Native, Ionic, and Xamarin apps ALWAYS contain:
loadClass, registerReceiver, loadUrl, Runtime, reflection, sendBroadcast.
This is the FRAMEWORK ITSELF, not malware. These have already been filtered
from the behavior analysis. Do NOT mention them as suspicious.

Respond ONLY with a valid JSON object — no text before or after:
{
  "verdict": "MALICIOUS" | "SUSPICIOUS" | "SAFE",
  "confidence": "HIGH" | "MEDIUM" | "LOW",
  "risk_score": <0-10, stay close to composite_score>,
  "threat_category": "<e.g. Banking Trojan, OTP Stealer, Dropper, Clean App, Dev Build>",
  "reasons": [
    "<behavioral combination evidence, not individual APIs>",
    "<what the combination CAN do, not just what it has>",
    "<why score is what it is>"
  ],
  "behavior_summary": "<2-3 sentences: what this app likely does based on behavior clusters>",
  "recommended_action": "BLOCK" | "QUARANTINE" | "INVESTIGATE" | "ALLOW",
  "ioc_highlights": ["<only genuinely suspicious IOCs — empty array [] if none>"],
  "false_positive_risk": "HIGH" | "MEDIUM" | "LOW"
}"""


def build_prompt(
    current_chunks: list[dict],
    retrieved_cases: list[dict],
) -> tuple[str, str]:
    """System prompt aur user prompt banao."""
    score_summary   = _build_score_summary(current_chunks)
    current_section = _build_current_apk_section(current_chunks)
    similar_section = _build_similar_cases_section(retrieved_cases)

    user_prompt = f"""Analyze this Android APK and produce a final security verdict.


{score_summary}

{current_section}

{similar_section}

REMINDER: Base verdict on BEHAVIOR CLUSTERS (combinations), not individual permissions/APIs.
Framework noise (loadClass, registerReceiver, loadUrl, Runtime) is already filtered out."""

    return SYSTEM_PROMPT, user_prompt


def _build_score_summary(chunks: list[dict]) -> str:
    risk_chunk  = next((c for c in chunks if c["chunk_type"] == "risk_summary"), None)
    behav_chunk = next((c for c in chunks if c["chunk_type"] == "behavior"),     None)

    if not risk_chunk:
        return "Score data unavailable."

    rm = risk_chunk["metadata"]
    bm = behav_chunk["metadata"] if behav_chunk else {}

    lines = [
        f"Composite Score:    {rm.get('composite_score', '?')}/10",
        f"Behavior Score:     {rm.get('behavior_score', '?')}/10  (weight: 55%)",
        f"Pre-Verdict:        {rm.get('pre_verdict', '?')}",
        f"Critical Clusters:  {rm.get('critical_clusters', '0')}",
        f"High Clusters:      {rm.get('high_clusters', '0')}",
    ]
    cluster_ids = bm.get("cluster_ids", "")
    if cluster_ids:
        lines.append(f"Cluster IDs:        {cluster_ids}")

    return "\n".join(lines)


def _build_current_apk_section(chunks: list[dict]) -> str:
    lines     = []
    order     = ["identity", "behavior", "iocs", "risk_summary"]
    chunk_map = {c["chunk_type"]: c for c in chunks}

    for chunk_type in order:
        if chunk_type in chunk_map:
            lines.append(f"\n[{chunk_type.upper()}]")
            lines.append(chunk_map[chunk_type]["text"])

    return "\n".join(lines)


def _build_similar_cases_section(retrieved_cases: list[dict]) -> str:

    if not retrieved_cases:
        return "No similar cases in database. Judge on current data alone."

    lines     = []
    seen_jobs = set()

    for case in retrieved_cases:
        job_id = case["metadata"].get("job_id", "unknown")
        if job_id in seen_jobs:
            continue

        ctype = case["metadata"].get("chunk_type", "unknown")
      
        if ctype not in ("behavior", "risk_summary"):
            continue

        seen_jobs.add(job_id)

        pkg = case["metadata"].get("package_name", "unknown")
        sim = case["similarity"]

        lines.append(
            f"Similar APK (similarity: {sim:.0%}, matched on: {ctype}):\n"
            f"  Package: {pkg}\n"
            f"  Behavior Data:\n  {case['text'][:400]}\n"
        )

    return "\n".join(lines) if lines else "No behaviorally similar cases found."