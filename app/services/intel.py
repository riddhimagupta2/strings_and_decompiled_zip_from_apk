"""
Hash intelligence service.
- Local DB lookup (check if we've seen this APK before)
- VirusTotal v3 public API (requires VT_API_KEY env var)
- MalwareBazaar public API (no key needed)
"""

import os
import httpx
import logging
from typing import Any

logger = logging.getLogger(__name__)

VT_API_KEY  = os.getenv("VT_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
MB_BASE_URL = "https://mb-api.abuse.ch/api/v1/"


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
            return {"source": "virustotal", "found": False,
                    "error": f"HTTP {e.response.status_code}"}
        except Exception as e:
            return {"source": "virustotal", "found": False, "error": str(e)}


async def lookup_malwarebazaar(hash_value: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.post(
                MB_BASE_URL,
                data={"query": "get_info", "hash": hash_value},
            )
            r.raise_for_status()
            body = r.json()
            if body.get("query_status") != "ok":
                return {"source": "malwarebazaar", "found": False, "data": None}
            entry = body["data"][0] if body.get("data") else {}
            return {
                "source": "malwarebazaar",
                "found":  bool(entry),
                "data": {
                    "file_name":    entry.get("file_name"),
                    "file_type":    entry.get("file_type"),
                    "file_size":    entry.get("file_size"),
                    "first_seen":   entry.get("first_seen"),
                    "last_seen":    entry.get("last_seen"),
                    "tags":         entry.get("tags", []),
                    "signature":    entry.get("signature"),
                    "reporter":     entry.get("reporter"),
                    "delivery_method": entry.get("delivery_method"),
                    "malware_family": entry.get("tags", []),
                } if entry else None,
            }
        except Exception as e:
            return {"source": "malwarebazaar", "found": False, "error": str(e)}


async def lookup_hash(hash_value: str, sources: list[str] | None = None) -> list[dict]:
    """
    Query one or more threat-intel sources for a file hash.
    sources: ['virustotal', 'malwarebazaar'] — defaults to both.
    """
    sources = sources or ["virustotal", "malwarebazaar"]
    results = []

    if "virustotal" in sources:
        vt = await lookup_virustotal(hash_value)
        results.append({"hash_value": hash_value,
                         "hash_type": _detect_hash_type(hash_value),
                         **vt})

    if "malwarebazaar" in sources:
        mb = await lookup_malwarebazaar(hash_value)
        results.append({"hash_value": hash_value,
                         "hash_type": _detect_hash_type(hash_value),
                         **mb})

    return results


def _detect_hash_type(h: str) -> str:
    n = len(h)
    if n == 32:  return "md5"
    if n == 40:  return "sha1"
    if n == 64:  return "sha256"
    return "unknown"
