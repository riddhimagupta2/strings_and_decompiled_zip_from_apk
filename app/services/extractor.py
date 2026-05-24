"""
APK Extraction Service
Handles: hashing, manifest, permissions, strings, hardcoded IOCs,
         API calls, certificate/signature, risk scoring, zip artifact.
Uses androguard 4.x API.
"""

import hashlib
import io
import os
import re
import zipfile
import logging
from pathlib import Path
from typing import Any

from androguard.core.apk import APK
from androguard.misc import AnalyzeAPK

logger = logging.getLogger(__name__)

# ── Regex patterns for IOC extraction ────────────────────────────────────────

RE_URL          = re.compile(r'https?://[^\s"\'<>\x00-\x1F\x7F]{4,200}', re.I)
RE_IP           = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
RE_EMAIL        = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
RE_BASE64       = re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})')
RE_PHONE        = re.compile(r'\+?[0-9]{7,15}')
RE_FILEPATH     = re.compile(r'(?:/(?:data|sdcard|proc|sys|system|storage)/[^\s"\'\x00-\x1F\x7F]{3,100})')
RE_HEX_KEY      = re.compile(r'\b[0-9a-fA-F]{32,64}\b')
RE_PACKAGE      = re.compile(r'\b(?:com|org|net|io)\.[a-z][a-z0-9_]+(?:\.[a-z][a-z0-9_]+)+\b')

# Interesting Android API calls to flag
SENSITIVE_APIS = {
    "getDeviceId", "getSubscriberId", "getImei", "getLine1Number",
    "getSimSerialNumber", "getLastKnownLocation", "requestLocationUpdates",
    "sendTextMessage", "sendDataMessage", "getMessageBody",
    "getRunningTasks", "getRunningAppProcesses",
    "loadUrl", "addJavascriptInterface", "evaluateJavascript",
    "exec", "Runtime.getRuntime", "ProcessBuilder",
    "createSocket", "HttpURLConnection", "OkHttpClient",
    "getSystemService", "setWifiEnabled", "getCellLocation",
    "startActivity", "bindService", "setComponentEnabledSetting",
    "getAccounts", "getPassword", "BlockedNumberContract",
    "setAccessibilityDelegate", "performGlobalAction",
    "DexClassLoader", "PathClassLoader", "loadClass",
    "Cipher.getInstance", "SecretKeySpec", "KeyStore",
    "getContentResolver", "query", "rawQuery",
    "openFileOutput", "getSharedPreferences",
    "registerReceiver", "sendBroadcast",
    "NotificationManager", "createNotificationChannel",
    "PackageInstaller", "installPackage",
}

# High-risk permissions and their severity
DANGEROUS_PERMS = {
    "android.permission.READ_SMS":                    ("critical", "Can read SMS messages — OTP theft vector"),
    "android.permission.RECEIVE_SMS":                 ("critical", "Can intercept incoming SMS"),
    "android.permission.SEND_SMS":                    ("critical", "Can send SMS without user"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE":  ("critical", "Full accessibility control — overlay/keylog risk"),
    "android.permission.READ_CALL_LOG":               ("high",     "Access to call history"),
    "android.permission.PROCESS_OUTGOING_CALLS":      ("high",     "Can intercept calls"),
    "android.permission.READ_CONTACTS":               ("high",     "Access to contacts"),
    "android.permission.CAMERA":                      ("high",     "Camera access"),
    "android.permission.RECORD_AUDIO":                ("high",     "Microphone access"),
    "android.permission.ACCESS_FINE_LOCATION":        ("high",     "Precise location tracking"),
    "android.permission.READ_EXTERNAL_STORAGE":       ("medium",   "File system read"),
    "android.permission.WRITE_EXTERNAL_STORAGE":      ("medium",   "File system write"),
    "android.permission.REQUEST_INSTALL_PACKAGES":    ("high",     "Can install other APKs"),
    "android.permission.GET_ACCOUNTS":                ("medium",   "Access to device accounts"),
    "android.permission.USE_BIOMETRIC":               ("medium",   "Biometric data access"),
    "android.permission.READ_PHONE_STATE":            ("medium",   "Device identifiers (IMEI, etc.)"),
    "android.permission.INTERNET":                    ("low",      "Network access"),
    "android.permission.RECEIVE_BOOT_COMPLETED":      ("medium",   "Starts on device boot"),
    "android.permission.SYSTEM_ALERT_WINDOW":         ("high",     "Draw over other apps — overlay attack vector"),
    "android.permission.FOREGROUND_SERVICE":          ("low",      "Can run persistent foreground service"),
}


def compute_hashes(data: bytes) -> dict[str, str]:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def extract_certificate(apk: APK) -> dict[str, Any]:
    result: dict[str, Any] = {}
    try:
        # androguard 4.x: get_certificates_der_v2/v1 returns list of DER bytes
        certs = (apk.get_certificates_der_v2() or
                 apk.get_certificates_der_v1() or [])

        if not certs:
            return result

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.backends import default_backend

        cert_der = certs[0] if isinstance(certs[0], bytes) else certs[0][0]
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        result["subject"]    = cert.subject.rfc4514_string()
        result["issuer"]     = cert.issuer.rfc4514_string()
        result["serial"]     = str(cert.serial_number)
        result["not_before"] = cert.not_valid_before_utc.isoformat()
        result["not_after"]  = cert.not_valid_after_utc.isoformat()
        result["sha1"]       = cert.fingerprint(hashes.SHA1()).hex()
        result["sha256"]     = cert.fingerprint(hashes.SHA256()).hex()
        result["is_self_signed"] = cert.subject == cert.issuer
    except Exception as e:
        logger.warning(f"Certificate extraction failed: {e}")
    return result


def categorize_strings(raw: list[str]) -> dict[str, list[str]]:
    cats: dict[str, list[str]] = {
        "urls": [], "ips": [], "emails": [], "file_paths": [],
        "package_refs": [], "crypto_keys": [], "base64_blobs": [],
        "phone_numbers": [], "commands": [], "other": [],
    }
    for s in raw:
        s = s.strip()
        if not s:
            continue
        if RE_URL.fullmatch(s):
            cats["urls"].append(s)
        elif RE_EMAIL.fullmatch(s):
            cats["emails"].append(s)
        elif RE_FILEPATH.fullmatch(s):
            cats["file_paths"].append(s)
        elif RE_PACKAGE.fullmatch(s):
            cats["package_refs"].append(s)
        elif RE_HEX_KEY.fullmatch(s):
            cats["crypto_keys"].append(s)
        elif RE_BASE64.fullmatch(s) and len(s) >= 40:
            cats["base64_blobs"].append(s)
        elif any(cmd in s for cmd in ["sh ", "bash", "chmod", "su ", "mount", "kill"]):
            cats["commands"].append(s)
        elif RE_PHONE.fullmatch(s):
            cats["phone_numbers"].append(s)
        else:
            cats["other"].append(s)

    # Deduplicate all categories
    for k in cats:
        cats[k] = list(dict.fromkeys(cats[k]))[:500]
    return cats


def extract_hardcoded_iocs(dex_corpus: str, res_corpus: str) -> dict[str, list[str]]:
    corpus = dex_corpus + "\n" + res_corpus
    return {
        "urls":         list(dict.fromkeys(RE_URL.findall(corpus)))[:300],
        "ips":          [ip for ip in dict.fromkeys(RE_IP.findall(corpus))
                         if not ip.startswith("0.") and ip not in ("127.0.0.1",)][:200],
        "emails":       list(dict.fromkeys(RE_EMAIL.findall(corpus)))[:200],
        "crypto_keys":  list(dict.fromkeys(RE_HEX_KEY.findall(corpus)))[:100],
        "base64_blobs": list(dict.fromkeys(RE_BASE64.findall(corpus)))[:100],
        "package_refs": list(dict.fromkeys(RE_PACKAGE.findall(corpus)))[:200],
        "file_paths":   list(dict.fromkeys(RE_FILEPATH.findall(corpus)))[:200],
        "phone_numbers": list(dict.fromkeys(RE_PHONE.findall(corpus)))[:100],
    }


def score_risk(permissions: list[str], risk_flags: list[dict],
               api_calls: list[str], cert: dict) -> float:
    score = 0.0
    weights = {"critical": 2.5, "high": 1.5, "medium": 0.8, "low": 0.2}
    for flag in risk_flags:
        score += weights.get(flag.get("severity", "low"), 0.2)
    # Extra bump for specific combos
    p = set(permissions)
    if {"android.permission.READ_SMS", "android.permission.BIND_ACCESSIBILITY_SERVICE"} <= p:
        score += 3.0    # OTP-theft pattern
    if "android.permission.SYSTEM_ALERT_WINDOW" in p and "android.permission.BIND_ACCESSIBILITY_SERVICE" in p:
        score += 2.5    # overlay attack
    if cert.get("is_self_signed"):
        score += 1.0
    return min(round(score, 2), 10.0)


def build_risk_flags(permissions: list[str], api_calls: list[str],
                     iocs: dict, cert: dict, obf_ratio: float) -> list[dict]:
    flags = []

    for perm in permissions:
        if perm in DANGEROUS_PERMS:
            sev, detail = DANGEROUS_PERMS[perm]
            flags.append({"flag": f"PERM:{perm.split('.')[-1]}", "severity": sev, "detail": detail})

    for api in api_calls:
        for sensitive in SENSITIVE_APIS:
            if sensitive in api:
                flags.append({"flag": f"API:{sensitive}", "severity": "medium",
                               "detail": f"Detected sensitive API call: {api}"})
                break

    if iocs.get("urls"):
        flags.append({"flag": "HARDCODED_URLS", "severity": "medium",
                      "detail": f"{len(iocs['urls'])} hardcoded URL(s) found"})
    if iocs.get("ips"):
        flags.append({"flag": "HARDCODED_IPS", "severity": "high",
                      "detail": f"{len(iocs['ips'])} hardcoded IP address(es) found"})
    if iocs.get("crypto_keys"):
        flags.append({"flag": "HARDCODED_KEYS", "severity": "high",
                      "detail": f"{len(iocs['crypto_keys'])} potential hardcoded key(s) found"})
    if cert.get("is_self_signed"):
        flags.append({"flag": "SELF_SIGNED_CERT", "severity": "medium",
                      "detail": "APK signed with a self-signed certificate"})
    if obf_ratio > 0.5:
        flags.append({"flag": "HIGH_OBFUSCATION", "severity": "high",
                      "detail": f"High obfuscation ratio detected ({obf_ratio:.0%} suspicious class names)"})

    # Deduplicate by flag key
    seen = set()
    deduped = []
    for f in flags:
        if f["flag"] not in seen:
            seen.add(f["flag"])
            deduped.append(f)
    return deduped


def measure_obfuscation(class_names: list[str]) -> float:
    """Ratio of class names that look obfuscated (short, single-char, or high-entropy)."""
    if not class_names:
        return 0.0
    obf = sum(1 for n in class_names
              if len(n.split(".")[-1]) <= 2 or re.fullmatch(r'[a-z]{1,3}[0-9]*', n.split(".")[-1]))
    return obf / len(class_names)


def create_decompiled_zip(apk_path: str, artifact_dir: str, job_id: str) -> str:
    """
    Create a zip containing:
    - META/ (manifest, permissions JSON)
    - smali/  (raw smali files from APK classes.dex)
    - res/    (resources)
    - lib/    (native .so files)
    - assets/
    """
    out_path = os.path.join(artifact_dir, f"{job_id}_decompiled.zip")
    apk_zip = zipfile.ZipFile(apk_path, "r")

    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zout:
        for name in apk_zip.namelist():
            if (name.startswith("smali") or
                name.startswith("res/") or
                name.startswith("assets/") or
                name.startswith("lib/") or
                name in ("AndroidManifest.xml", "classes.dex", "classes2.dex",
                         "classes3.dex", "resources.arsc")):
                try:
                    data = apk_zip.read(name)
                    zout.writestr(name, data)
                except Exception:
                    pass
    apk_zip.close()
    return out_path


def analyze_apk(apk_path: str, artifact_dir: str, job_id: str) -> dict[str, Any]:
    """
    Full static analysis. Returns a flat dict matching AnalysisJob columns.
    """
    apk_data = Path(apk_path).read_bytes()
    hashes = compute_hashes(apk_data)

    # ── Androguard full analysis ──────────────────────────────────────────────
    try:
        apk_obj, dex_list, analysis = AnalyzeAPK(apk_path)
    except Exception as e:
        raise RuntimeError(f"Androguard AnalyzeAPK failed: {e}")

    # ── Manifest ──────────────────────────────────────────────────────────────
    package_name  = apk_obj.get_package()
    version_name  = apk_obj.get_androidversion_name()
    version_code_s = apk_obj.get_androidversion_code()
    version_code  = int(version_code_s) if version_code_s and str(version_code_s).isdigit() else None
    min_sdk_s     = apk_obj.get_min_sdk_version()
    target_sdk_s  = apk_obj.get_target_sdk_version()
    min_sdk       = int(min_sdk_s)    if min_sdk_s    and str(min_sdk_s).isdigit()    else None
    target_sdk    = int(target_sdk_s) if target_sdk_s and str(target_sdk_s).isdigit() else None

    permissions   = list(apk_obj.get_permissions())
    activities    = list(apk_obj.get_activities())
    services      = list(apk_obj.get_services())
    receivers     = list(apk_obj.get_receivers())
    providers     = list(apk_obj.get_providers())
    intent_filters: list[str] = []
    try:
        for item in (activities + services + receivers):
            for action in apk_obj.get_intent_filters("activity", item).get("action", []):
                intent_filters.append(action)
    except Exception:
        pass
    intent_filters = list(dict.fromkeys(intent_filters))

    # ── Class / method stats ──────────────────────────────────────────────────
    all_classes  = list(analysis.get_classes())
    class_names  = [c.name for c in all_classes]
    classes_count = len(class_names)
    methods_count = sum(1 for _ in analysis.get_methods())
    obf_ratio    = measure_obfuscation(class_names)

    # ── API call extraction ───────────────────────────────────────────────────
    found_apis: list[str] = []
    for method in analysis.get_methods():
        for _, call, _ in method.get_xref_to():
            call_name = call.name
            for sensitive in SENSITIVE_APIS:
                if sensitive in call_name:
                    sig = f"{call.class_name}->{call_name}"
                    found_apis.append(sig)
    found_apis = list(dict.fromkeys(found_apis))[:500]

    # ── String extraction from DEX and Resources ──────────────────────────────
    dex_strings = []
    # Pattern to filter out binary/Kotlin metadata containing control chars
    re_control = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
    for d in dex_list:
        for s in d.get_strings():
            if isinstance(s, bytes):
                s = s.decode("utf-8", errors="ignore")
            # Keep only strings that don't contain binary control chars
            if s and len(s) >= 3 and not re_control.search(s):
                dex_strings.append(s)
                
    str_cats   = categorize_strings(dex_strings)
    dex_corpus = "\n".join(dex_strings)

    res_corpus   = ""
    apk_raw_zip  = zipfile.ZipFile(apk_path, "r")
    for fname in apk_raw_zip.namelist():
        try:
            if fname.startswith("res/") and fname.endswith((".xml", ".json", ".html", ".js")):
                content = apk_raw_zip.read(fname).decode("utf-8", errors="ignore")
                # Strip binary control characters from compiled AXML
                content = re_control.sub(" ", content)
                res_corpus += content + "\n"
        except Exception:
            pass
    apk_raw_zip.close()

    iocs = extract_hardcoded_iocs(dex_corpus, res_corpus)

    # ── Certificate ───────────────────────────────────────────────────────────
    cert = extract_certificate(apk_obj)

    # ── Risk ──────────────────────────────────────────────────────────────────
    risk_flags = build_risk_flags(permissions, found_apis, iocs, cert, obf_ratio)
    risk_score = score_risk(permissions, risk_flags, found_apis, cert)

    # ── Native libs ───────────────────────────────────────────────────────────
    native_libs = list(apk_obj.get_libraries()) or []

    # ── Zip artifact ─────────────────────────────────────────────────────────
    zip_path = create_decompiled_zip(apk_path, artifact_dir, job_id)

    return {
        **hashes,
        "package_name":   package_name,
        "version_name":   version_name,
        "version_code":   version_code,
        "min_sdk":        min_sdk,
        "target_sdk":     target_sdk,
        "permissions":    permissions,
        "activities":     activities,
        "services":       services,
        "receivers":      receivers,
        "providers":      providers,
        "intent_filters": intent_filters,
        "strings":        str_cats,
        "hardcoded":      iocs,
        "api_calls":      found_apis,
        "native_libs":    native_libs,
        "classes_count":  classes_count,
        "methods_count":  methods_count,
        "cert_subject":   cert.get("subject"),
        "cert_issuer":    cert.get("issuer"),
        "cert_serial":    cert.get("serial"),
        "cert_not_before": cert.get("not_before"),
        "cert_not_after":  cert.get("not_after"),
        "cert_sha1":      cert.get("sha1"),
        "cert_sha256":    cert.get("sha256"),
        "is_self_signed": int(cert.get("is_self_signed", False)),
        "risk_score":     risk_score,
        "risk_flags":     risk_flags,
        "zip_artifact":   zip_path,
    }
