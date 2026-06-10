import os

from app.db.session import SessionLocal
from app.db.models import AnalysisJob
from app.schemas.analysis import AnalysisResult, CertificateInfo, HardcodedIOCs
from app.services.rag.chunker        import chunk_apk_json
from app.services.rag.embedder       import embed_texts
from app.services.rag.vector_store   import add_chunks, get_indexed_count
from app.services.rag.retriever      import retrieve_similar_cases
from app.services.rag.prompt_builder import build_prompt
from app.services.rag.llm_client     import call_llm


def load_job_json(job_id: str) -> dict:
    db = SessionLocal()
    try:
        job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            raise ValueError(f"Job {job_id} not found")

        cert = None
        if job.cert_subject:
            cert = CertificateInfo(
                subject        = job.cert_subject,
                issuer         = job.cert_issuer,
                serial         = job.cert_serial,
                not_before     = job.cert_not_before,
                not_after      = job.cert_not_after,
                sha1           = job.cert_sha1,
                sha256         = job.cert_sha256,
                is_self_signed = bool(job.is_self_signed),
            )

        hardcoded = None
        if job.hardcoded:
            hardcoded = HardcodedIOCs(**job.hardcoded)

        result = AnalysisResult(
            job_id      = job.id,
            filename    = job.filename,
            file_size   = job.file_size,
            status      = job.status,
            created_at  = job.created_at,
            updated_at  = job.updated_at,
            error_message   = job.error_message,
            progress_percent = job.progress_percent or 0,
            progress_label   = job.progress_label,
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
        return result.model_dump(mode="json")
    finally:
        db.close()


async def index_apk(job_id: str, verdict: str = "UNKNOWN") -> dict:
    apk_json = load_job_json(job_id)

    if apk_json.get("status") != "completed":
        raise ValueError(f"Job {job_id} is not completed.")

    chunks = chunk_apk_json(apk_json)

    if not chunks:
        raise ValueError("No chunks generated from APK JSON.")

    for chunk in chunks:
        chunk["metadata"]["verdict"] = verdict

    texts      = [c["text"] for c in chunks]
    embeddings = embed_texts(texts)

    add_chunks(chunks, embeddings)

    return {
        "job_id":          job_id,
        "package_name":    apk_json.get("package_name"),
        "chunks_indexed":  len(chunks),
        "total_indexed":   get_indexed_count(),
        "verdict_stored":  verdict,
    }


async def analyze_apk(job_id: str) -> dict:
    apk_json = load_job_json(job_id)

    if apk_json.get("status") != "completed":
        raise ValueError(f"Job {job_id} is not completed.")

    chunks = chunk_apk_json(apk_json)

    if not chunks:
        raise ValueError("No chunks generated from APK JSON.")

    retrieved = retrieve_similar_cases(chunks, top_k=5)

    system_prompt, user_prompt = build_prompt(chunks, retrieved)

    llm_result = call_llm(system_prompt, user_prompt)

    risk_chunk  = next((c for c in chunks if c["chunk_type"] == "risk_summary"), {})
    behav_chunk = next((c for c in chunks if c["chunk_type"] == "behavior"), {})
    rm = risk_chunk.get("metadata", {})
    bm = behav_chunk.get("metadata", {})

    return {
        "job_id":              job_id,
        "package_name":        apk_json.get("package_name"),
        "extraction_score":    apk_json.get("risk_score"),
        "composite_score":     rm.get("composite_score"),
        "behavior_score":      bm.get("behavior_score"),
        "critical_clusters":   bm.get("critical_clusters"),
        "high_clusters":       bm.get("high_clusters"),
        "triggered_clusters":  bm.get("cluster_ids"),
        "pre_verdict":         rm.get("pre_verdict"),
        "similar_cases_found": len(retrieved),
        "llm_analysis":        llm_result,
    }
