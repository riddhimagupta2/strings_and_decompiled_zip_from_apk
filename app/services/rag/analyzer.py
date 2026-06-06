import httpx
import os

from openai import timeout
from app.services.rag.chunker        import chunk_apk_json
from app.services.rag.embedder       import embed_texts, embed_text
from app.services.rag.vector_store   import add_chunks, get_indexed_count
from app.services.rag.retriever      import retrieve_similar_cases
from app.services.rag.prompt_builder import build_prompt
from app.services.rag.llm_client     import call_llm

EXTRACTION_URL = os.getenv("EXTRACTION_SERVICE_URL", "http://127.0.0.1:8001")


async def fetch_job_json(job_id: str) -> dict:
   async with httpx.AsyncClient(timeout=None) as client:
        response = await client.get(f"{EXTRACTION_URL}/api/v1/jobs/{job_id}")
        response.raise_for_status()
        return response.json()


async def index_apk(job_id: str, verdict: str = "UNKNOWN") -> dict:
   
    apk_json = await fetch_job_json(job_id)

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
   
    apk_json = await fetch_job_json(job_id)

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