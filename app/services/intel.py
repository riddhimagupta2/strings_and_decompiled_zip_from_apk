"""
Hash intelligence service.
- VirusTotal v3 public API (requires VT_API_KEY env var)
"""

import os
import httpx
import logging
from typing import Any

logger = logging.getLogger(__name__)

VT_API_KEY  = os.getenv("VT_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3"


async def lookup_virustotal(hash_value: str) -> dict[str, Any]:
    if not VT_API_KEY:
        return {"source": "virustotal", "found": False,
                "error": "VT_API_KEY not configured — set the env var"}
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.get(
                f"{VT_BASE_URL}/files/{hash_value}",
                headers={"x-apikey": VT_API_KEY},
            )
            if r.status_code == 404:
                return {"source": "virustotal", "found": False, "data": None}
            r.raise_for_status()
            raw = r.json()
            attrs = raw.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "source": "virustotal",
                "found":  True,
                "data": {
                    "name":             attrs.get("meaningful_name"),
                    "type":             attrs.get("type_description"),
                    "size":             attrs.get("size"),
                    "first_submission": attrs.get("first_submission_date"),
                    "last_analysis":    attrs.get("last_analysis_date"),
                    "malicious":        stats.get("malicious", 0),
                    "suspicious":       stats.get("suspicious", 0),
                    "undetected":       stats.get("undetected", 0),
                    "harmless":         stats.get("harmless", 0),
                    "total_engines":    sum(stats.values()),
                    "tags":             attrs.get("tags", []),
                    "popular_threat_name": attrs.get("popular_threat_classification", {})
                                            .get("suggested_threat_label"),
                    "signature_info":   attrs.get("signature_info", {}),
                    "androguard":       attrs.get("androguard", {}),
                },
            }
        except httpx.HTTPStatusError as e:
            msg = f"HTTP {e.response.status_code}"
            if e.response.status_code == 401:
                msg = "HTTP 401 — invalid or missing VirusTotal API key (check VT_API_KEY in .env)"
            return {"source": "virustotal", "found": False, "error": msg}
        except Exception as e:
            return {"source": "virustotal", "found": False, "error": str(e)}


async def lookup_hash(hash_value: str, sources: list[str] | None = None) -> list[dict]:
    sources = sources or ["virustotal"]
    results = []

    if "virustotal" in sources:
        vt = await lookup_virustotal(hash_value)
        results.append({
            "hash_value": hash_value,
            "hash_type": _detect_hash_type(hash_value),
            **vt,
        })

    return results


def _detect_hash_type(h: str) -> str:
    n = len(h)
    if n == 32:  return "md5"
    if n == 40:  return "sha1"
    if n == 64:  return "sha256"
    return "unknown"
