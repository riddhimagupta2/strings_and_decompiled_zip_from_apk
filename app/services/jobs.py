"""
Background task that runs the APK extraction and updates the DB job record.
"""

import logging
import os
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.db.models import AnalysisJob, JobStatus
from app.services.extractor import analyze_apk

logger = logging.getLogger(__name__)

ARTIFACT_DIR = os.getenv("ARTIFACT_DIR", "storage/artifacts")


def _set_progress(db: Session, job: AnalysisJob, percent: int, label: str):
    job.progress_percent = max(0, min(percent, 100))
    job.progress_label = label
    job.updated_at = datetime.now(timezone.utc)
    db.commit()


def run_analysis(job_id: str, apk_path: str, db: Session):
    """Synchronous worker — called from FastAPI BackgroundTasks."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        logger.error(f"Job {job_id} not found in DB")
        return

    job.status = JobStatus.running
    _set_progress(db, job, 1, "Starting analysis…")

    try:
        os.makedirs(ARTIFACT_DIR, exist_ok=True)

        def on_progress(percent: int, label: str):
            fresh = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
            if fresh:
                _set_progress(db, fresh, percent, label)

        results = analyze_apk(apk_path, ARTIFACT_DIR, job_id, on_progress=on_progress)

        job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            return

        job.md5             = results.get("md5")
        job.sha1            = results.get("sha1")
        job.sha256          = results.get("sha256")
        job.package_name    = results.get("package_name")
        job.version_name    = results.get("version_name")
        job.version_code    = results.get("version_code")
        job.min_sdk         = results.get("min_sdk")
        job.target_sdk      = results.get("target_sdk")
        job.permissions     = results.get("permissions")
        job.activities      = results.get("activities")
        job.services        = results.get("services")
        job.receivers       = results.get("receivers")
        job.providers       = results.get("providers")
        job.intent_filters  = results.get("intent_filters")
        job.strings         = results.get("strings")
        job.hardcoded       = results.get("hardcoded")
        job.api_calls       = results.get("api_calls")
        job.native_libs     = results.get("native_libs")
        job.classes_count   = results.get("classes_count")
        job.methods_count   = results.get("methods_count")
        job.cert_subject    = results.get("cert_subject")
        job.cert_issuer     = results.get("cert_issuer")
        job.cert_serial     = results.get("cert_serial")
        job.cert_not_before = results.get("cert_not_before")
        job.cert_not_after  = results.get("cert_not_after")
        job.cert_sha1       = results.get("cert_sha1")
        job.cert_sha256     = results.get("cert_sha256")
        job.is_self_signed  = results.get("is_self_signed")
        job.risk_score      = results.get("risk_score")
        job.risk_flags      = results.get("risk_flags")
        job.zip_artifact    = results.get("zip_artifact")

        job.status = JobStatus.completed
        job.progress_percent = 100
        job.progress_label = "Analysis complete"
        job.updated_at = datetime.now(timezone.utc)
        db.commit()
        logger.info(f"Job {job_id} completed — risk_score={job.risk_score}")

    except Exception as e:
        logger.exception(f"Job {job_id} failed: {e}")
        job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if job:
            job.status = JobStatus.failed
            job.error_message = str(e)
            job.progress_percent = 100
            job.progress_label = "Analysis failed"
            job.updated_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        try:
            os.remove(apk_path)
        except Exception:
            pass
