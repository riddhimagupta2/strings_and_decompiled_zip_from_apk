# APK Extraction Service

Static analysis extraction layer for Android APK files.  
Built with **FastAPI + SQLite + Androguard**.

---

## What it extracts

| Category | Details |
|---|---|
| **Hashes** | MD5, SHA1, SHA256 of the APK |
| **Manifest** | Package name, version, SDK targets |
| **Permissions** | All declared permissions with risk flags |
| **Components** | Activities, Services, Receivers, Providers, Intent Filters |
| **Strings** | Categorised: URLs, IPs, emails, file paths, base64, keys, commands |
| **Hardcoded IOCs** | Regex-extracted from smali + resources |
| **API calls** | Sensitive Android API calls (SMS, accessibility, reflection, crypto...) |
| **Certificate** | Subject, issuer, serial, validity, fingerprints, self-signed check |
| **Risk score** | 0–10 score with labelled flags and severity levels |
| **Decompiled zip** | smali/, res/, assets/, lib/, AndroidManifest.xml |

---

## Setup

```bash
pip install -r requirements.txt
```

Optional environment variables:

```bash
export VT_API_KEY="your_virustotal_api_key"   # for hash intel
export MAX_APK_MB=150                          # default: 150
export UPLOAD_DIR="storage/uploads"
export ARTIFACT_DIR="storage/artifacts"

export LLM_PROVIDER=gemini
export GEMINI_API_KEY=your_gemini_api_key
export LLM_MODEL=gemini-2.5-flash

#export LLM_PROVIDER=openai
#export OPENAI_API_KEY=your_openai_api_key
#export LLM_MODEL=gpt-4o-mini

export CHROMA_DB_PATH=storage/chroma_db
```

---

## Run

```bash
cd apk_extractor
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Swagger UI: http://localhost:8000/docs

---

## API Reference

### Submit APK for analysis

```
POST /api/v1/analyze
Content-Type: multipart/form-data
Body: file=<apk file>
```

Response `202`:
```json
{
  "job_id": "uuid",
  "status": "pending",
  "message": "APK accepted — analysis running in background..."
}
```

---

### Poll for results

```
GET /api/v1/jobs/{job_id}
```

Returns full `AnalysisResult` JSON once `status == "completed"`.  
Key fields for downstream GenAI service:

```json
{
  "job_id": "...",
  "status": "completed",
  "sha256": "abc123...",
  "package_name": "com.example.app",
  "permissions": ["android.permission.READ_SMS", ...],
  "hardcoded": {
    "urls": ["http://evil.com/c2"],
    "ips": ["192.168.1.100"],
    "crypto_keys": ["deadbeef..."],
    ...
  },
  "strings": {
    "urls": [...], "commands": [...], "base64_blobs": [...], ...
  },
  "api_calls": ["Landroid/telephony/SmsManager;->sendTextMessage"],
  "certificate": {
    "subject": "CN=Android Debug, ...",
    "is_self_signed": true
  },
  "risk_score": 7.5,
  "risk_flags": [
    {"flag": "PERM:READ_SMS",  "severity": "critical", "detail": "..."},
    {"flag": "HARDCODED_IPS",  "severity": "high",     "detail": "..."},
    {"flag": "SELF_SIGNED_CERT", "severity": "medium", "detail": "..."}
  ],
  "zip_artifact_available": true
}
```

---

### Download decompiled zip

```
GET /api/v1/jobs/{job_id}/download
```

Returns `application/zip` stream.  
Zip structure:
```
smali/            ← DEX bytecode as smali
res/              ← compiled resources / XMLs
assets/           ← raw assets
lib/              ← native .so files
AndroidManifest.xml
classes.dex
```

---

### List jobs

```
GET /api/v1/jobs?skip=0&limit=20&status=completed
```

---

### Delete job + artifact

```
DELETE /api/v1/jobs/{job_id}
```

---

### Hash intel lookup

```
GET /api/v1/intel/hash/{hash}                     # MD5/SHA1/SHA256
GET /api/v1/intel/hash/{hash}?sources=virustotal  # single source
GET /api/v1/intel/job/{job_id}                    # use job's sha256 automatically
```
---

## RAG Pipeline

RAG means **Retrieval Augmented Generation**.

This project uses RAG so the LLM does not guess blindly.  
It compares the current APK with previously indexed APK patterns stored in ChromaDB.

```text
APK uploaded
   ↓
Static extraction JSON generated
   ↓
JSON split into chunks:
   - Identity
   - Permissions
   - API Calls
   - IOCs
   - Risk
   ↓
Chunks converted into embeddings
   ↓
Stored in ChromaDB
   ↓
For new APK, similar past cases are retrieved
   ↓
LLM receives current APK evidence + similar cases
   ↓
Final AI verdict is generated
```

---

## RAG Endpoints

### Index APK into knowledge base

```http
POST /api/v1/rag/index
Content-Type: application/json
```

Request:

```json
{
  "job_id": "uuid-of-completed-job",
  "verdict": "UNKNOWN"
}
```

Allowed verdicts:

```text
MALICIOUS / SUSPICIOUS / SAFE / UNKNOWN
```

Response:

```json
{
  "status": "indexed",
  "job_id": "...",
  "package_name": "com.example.app",
  "chunks_indexed": 5,
  "total_indexed": 25,
  "verdict_stored": "UNKNOWN"
}
```

---

### Analyze APK using RAG + LLM

```http
POST /api/v1/rag/analyze
Content-Type: application/json
```

Request:

```json
{
  "job_id": "uuid-of-completed-job"
}
```

Response:

```json
{
  "status": "analyzed",
  "job_id": "...",
  "package_name": "com.example.app",
  "extraction_score": 9,
  "similar_cases_found": 4,
  "llm_analysis": {
    "verdict": "MALICIOUS",
    "confidence": "HIGH",
    "risk_score": 9,
    "threat_category": "Banking Trojan",
    "reasons": [
      "Requests notification access which can be used to steal OTPs",
      "Uses sensitive device identifier APIs",
      "Starts after reboot using RECEIVE_BOOT_COMPLETED"
    ],
    "behavior_summary": "This app shows behavior similar to banking trojans that steal OTPs and collect device identifiers.",
    "recommended_action": "BLOCK",
       "ioc_highlights": [
      "PERM:BIND_NOTIFICATION_LISTENER_SERVICE",
      "API:getImei",
      "SELF_SIGNED_CERT"
    ]
  }
}
```

---

### Check RAG status

```http
GET /api/v1/rag/status
```

Response:

```json
{
  "status": "ok",
  "total_chunks": 25
}
```

---
### Remove APK from knowledge base

```http
DELETE /api/v1/rag/index/{job_id}
```

---

## LLM Verdict Structure

| Field | Values |
|---|---|
| `verdict` | MALICIOUS / SUSPICIOUS / SAFE |
| `confidence` | HIGH / MEDIUM / LOW |
| `risk_score` | 0–10 |
| `threat_category` | Banking Trojan, Spyware, Adware, Unknown |
| `reasons` | Main evidence behind verdict |
| `behavior_summary` | Simple explanation of app behavior |
| `recommended_action` | BLOCK / QUARANTINE / INVESTIGATE / ALLOW |
| `ioc_highlights` | Most suspicious indicators |

---
```text
MALICIOUS:
- READ_SMS + RECEIVE_BOOT_COMPLETED + getImei
- Hardcoded C2 IPs or URLs
- Accessibility abuse
- Dynamic code loading
- REQUEST_INSTALL_PACKAGES misuse

SUSPICIOUS:
- Self-signed certificate
- Sensitive APIs without clear reason
- Extra permissions beyond app purpose
- Hardcoded IPs without strong malware behavior

SAFE:
- Permissions match app purpose
- No suspicious IOCs
- No risky API combinations
- Normal certificate and app behavior
```

---
## Verdict Decision Logic

VirusTotal response example:
```json
{
  "hash": "abc123...",
  "results": [
    {
      "source": "virustotal",
      "found": true,
      "data": {
        "malicious": 42,
        "suspicious": 3,
        "undetected": 15,
        "total_engines": 60,
        "popular_threat_name": "Android.BankBot",
        "tags": ["banker", "sms-stealer"]
      }
    }
  ]
}
```

---

## Consuming from another service

Typical downstream flow:

```python
import httpx

BASE = "http://localhost:8000"

# 1. Submit
with open("suspicious.apk", "rb") as f:
    r = httpx.post(f"{BASE}/api/v1/analyze", files={"file": f})
job_id = r.json()["job_id"]

# 2. Poll until done
import time
while True:
    result = httpx.get(f"{BASE}/api/v1/jobs/{job_id}").json()
    if result["status"] in ("completed", "failed"):
        break
    time.sleep(3)

# 3. Use structured data for GenAI prompt
permissions = result["permissions"]
iocs        = result["hardcoded"]
risk_flags  = result["risk_flags"]
risk_score  = result["risk_score"]

# 4. Download decompiled code for RAG ingestion
zip_bytes = httpx.get(f"{BASE}/api/v1/jobs/{job_id}/download").content

# 5. Optional: hash intel
intel = httpx.get(f"{BASE}/api/v1/intel/job/{job_id}").json()
```

---

## Risk score bands

| Score | Level | Meaning |
|---|---|---|
| 0 – 2 | Low | Benign indicators |
| 2 – 4 | Medium | Suspicious but not conclusive |
| 4 – 7 | High | Multiple malware indicators |
| 7 – 10 | Critical | Strong malware pattern (e.g. OTP theft combo) |
