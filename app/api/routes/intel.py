"""
Routes:
  GET  /api/v1/intel/hash/{hash_value}        — lookup a hash against all sources
  GET  /api/v1/intel/hash/{hash_value}/{src}  — lookup against specific source
  GET  /api/v1/intel/job/{job_id}             — auto-lookup using job's sha256
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
import re

from app.db.session import get_db
from app.db.models import AnalysisJob, JobStatus
from app.services.intel import lookup_hash

router = APIRouter(prefix="/api/v1/intel", tags=["Threat Intelligence"])

HASH_RE = re.compile(r'^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$')
SOURCES = {"virustotal", "malwarebazaar"}


@router.get("/hash/{hash_value}")
async def intel_by_hash(
    hash_value: str,
    sources: str = Query(
        "virustotal,malwarebazaar",
        description="Comma-separated list: virustotal,malwarebazaar",
    ),
):
    """
    Query threat-intel sources for a hash (MD5 / SHA1 / SHA256).
    Returns aggregated results from each requested source.
    """
    if not HASH_RE.match(hash_value):
        raise HTTPException(400, "Invalid hash — must be MD5 (32), SHA1 (40), or SHA256 (64) hex")

    requested = {s.strip().lower() for s in sources.split(",") if s.strip()}
    unknown   = requested - SOURCES
    if unknown:
        raise HTTPException(400, f"Unknown source(s): {unknown}. Valid: {SOURCES}")

    results = await lookup_hash(hash_value, list(requested))
    return {"hash": hash_value, "results": results}


@router.get("/hash/{hash_value}/{source}")
async def intel_by_hash_single_source(hash_value: str, source: str):
    """Query a single specific source."""
    if not HASH_RE.match(hash_value):
        raise HTTPException(400, "Invalid hash format")
    if source not in SOURCES:
        raise HTTPException(400, f"Unknown source '{source}'. Valid: {SOURCES}")

    results = await lookup_hash(hash_value, [source])
    return {"hash": hash_value, "results": results}


@router.get("/job/{job_id}")
async def intel_for_job(job_id: str, db: Session = Depends(get_db)):
    """
    Convenience endpoint — runs hash intel lookup using the SHA256
    from an already-analyzed job. Saves you from copying the hash manually.
    """
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(404, "Job not found")
    if job.status != JobStatus.completed:
        raise HTTPException(409, f"Job status is '{job.status}' — wait for completion")
    if not job.sha256:
        raise HTTPException(422, "Job has no SHA256 — extraction may have failed")

    results = await lookup_hash(job.sha256)
    return {
        "job_id":   job_id,
        "package":  job.package_name,
        "sha256":   job.sha256,
        "results":  results,
    }
