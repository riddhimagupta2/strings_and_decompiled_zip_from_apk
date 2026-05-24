"""
Routes:
  POST   /api/v1/analyze          — upload APK, kick off job
  GET    /api/v1/jobs/{job_id}    — full result JSON
  GET    /api/v1/jobs             — list all jobs (paginated)
  GET    /api/v1/jobs/{job_id}/download  — download decompiled zip
  DELETE /api/v1/jobs/{job_id}    — delete job + artifact
"""

import os
import uuid
import logging
from fastapi import APIRouter, UploadFile, File, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.db.session import get_db
from app.db.models import AnalysisJob, JobStatus
from app.schemas.analysis import JobCreateResponse, AnalysisResult, JobListItem, CertificateInfo, HardcodedIOCs
from app.services.jobs import run_analysis

router  = APIRouter(prefix="/api/v1", tags=["Analysis"])
logger  = logging.getLogger(__name__)

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "storage/uploads")
MAX_APK_MB = int(os.getenv("MAX_APK_MB", "150"))


@router.post("/analyze", response_model=JobCreateResponse, status_code=202)
async def submit_apk(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """
    Upload an APK file for static analysis.
    Returns a job_id to poll for results.
    """
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(400, "Only .apk files are accepted")

    content = await file.read()
    if len(content) > MAX_APK_MB * 1024 * 1024:
        raise HTTPException(413, f"APK exceeds {MAX_APK_MB} MB limit")

    # Magic byte check — APK is a ZIP
    if not content[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        raise HTTPException(400, "File does not appear to be a valid APK (ZIP magic missing)")

    job_id   = str(uuid.uuid4())
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    apk_path = os.path.join(UPLOAD_DIR, f"{job_id}.apk")

    with open(apk_path, "wb") as f:
        f.write(content)

    job = AnalysisJob(
        id         = job_id,
        filename   = file.filename,
        file_size  = len(content),
        status     = JobStatus.pending,
        created_at = datetime.now(timezone.utc),
        updated_at = datetime.now(timezone.utc),
    )
    db.add(job)
    db.commit()

    # Pass a fresh DB session into the background task
    from app.db.session import SessionLocal
    def _run():
        bg_db = SessionLocal()
        try:
            run_analysis(job_id, apk_path, bg_db)
        finally:
            bg_db.close()

    background_tasks.add_task(_run)

    return JobCreateResponse(
        job_id  = job_id,
        status  = JobStatus.pending,
        message = "APK accepted — analysis running in background. Poll /api/v1/jobs/{job_id} for results.",
    )


@router.get("/jobs", response_model=list[JobListItem])
def list_jobs(
    skip:   int = Query(0,  ge=0),
    limit:  int = Query(20, ge=1, le=100),
    status: str = Query(None),
    db: Session = Depends(get_db),
):
    """List all analysis jobs, newest first."""
    q = db.query(AnalysisJob)
    if status:
        try:
            q = q.filter(AnalysisJob.status == JobStatus(status))
        except ValueError:
            raise HTTPException(400, f"Invalid status '{status}'")
    jobs = q.order_by(AnalysisJob.created_at.desc()).offset(skip).limit(limit).all()
    return jobs


@router.get("/jobs/{job_id}", response_model=AnalysisResult)
def get_job(job_id: str, db: Session = Depends(get_db)):
    """Get full extraction results for a job."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(404, f"Job {job_id} not found")

    cert = None
    if job.cert_subject:
        cert = CertificateInfo(
            subject    = job.cert_subject,
            issuer     = job.cert_issuer,
            serial     = job.cert_serial,
            not_before = job.cert_not_before,
            not_after  = job.cert_not_after,
            sha1       = job.cert_sha1,
            sha256     = job.cert_sha256,
            is_self_signed = bool(job.is_self_signed),
        )

    hardcoded = None
    if job.hardcoded:
        hardcoded = HardcodedIOCs(**job.hardcoded)

    return AnalysisResult(
        job_id      = job.id,
        filename    = job.filename,
        file_size   = job.file_size,
        status      = job.status,
        created_at  = job.created_at,
        updated_at  = job.updated_at,
        error_message = job.error_message,
        md5         = job.md5,
        sha1        = job.sha1,
        sha256      = job.sha256,
        package_name  = job.package_name,
        version_name  = job.version_name,
        version_code  = job.version_code,
        min_sdk     = job.min_sdk,
        target_sdk  = job.target_sdk,
        permissions = job.permissions,
        activities  = job.activities,
        services    = job.services,
        receivers   = job.receivers,
        providers   = job.providers,
        intent_filters = job.intent_filters,
        strings     = job.strings,
        hardcoded   = hardcoded,
        api_calls   = job.api_calls,
        native_libs = job.native_libs,
        classes_count = job.classes_count,
        methods_count = job.methods_count,
        certificate = cert,
        risk_score  = job.risk_score,
        risk_flags  = job.risk_flags,
        zip_artifact_available = bool(job.zip_artifact and os.path.exists(job.zip_artifact)),
    )


@router.get("/jobs/{job_id}/download")
def download_artifact(job_id: str, db: Session = Depends(get_db)):
    """
    Download the decompiled APK contents as a zip archive.
    Contains: smali/, res/, assets/, lib/, AndroidManifest.xml
    """
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(404, "Job not found")
    if job.status != JobStatus.completed:
        raise HTTPException(409, f"Job is '{job.status}' — download available only after completion")
    if not job.zip_artifact or not os.path.exists(job.zip_artifact):
        raise HTTPException(404, "Artifact zip not found — it may have been cleaned up")

    safe_name = (job.package_name or job_id).replace("/", "_")
    return FileResponse(
        path            = job.zip_artifact,
        media_type      = "application/zip",
        filename        = f"{safe_name}_decompiled.zip",
        headers         = {"Content-Disposition": f'attachment; filename="{safe_name}_decompiled.zip"'},
    )


@router.delete("/jobs/{job_id}", status_code=204)
def delete_job(job_id: str, db: Session = Depends(get_db)):
    """Delete a job record and its artifact."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(404, "Job not found")
    if job.zip_artifact and os.path.exists(job.zip_artifact):
        try:
            os.remove(job.zip_artifact)
        except Exception:
            pass
    db.delete(job)
    db.commit()
