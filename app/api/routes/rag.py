from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import traceback
from app.services.rag.analyzer import index_apk, analyze_apk
from app.services.rag.vector_store import get_indexed_count, delete_job_chunks

router = APIRouter(prefix="/api/v1/rag", tags=["RAG Analysis"])


class IndexRequest(BaseModel):
    job_id: str
    verdict: str = "UNKNOWN"


class AnalyzeRequest(BaseModel):
    job_id: str


@router.post("/index")
async def index_apk_endpoint(req: IndexRequest):
    try:
        result = await index_apk(req.job_id, req.verdict)
        return {"status": "indexed", **result}
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"{type(e).__name__}: {repr(e)}"
        )


@router.post("/analyze")
async def analyze_apk_endpoint(req: AnalyzeRequest):
    try:
        result = await analyze_apk(req.job_id)
        return {"status": "analyzed", **result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
def rag_status():
    return {
        "status":        "ok",
        "total_chunks":  get_indexed_count(),
    }


@router.delete("/index/{job_id}")
def delete_index(job_id: str):
    delete_job_chunks(job_id)
    return {"status": "deleted", "job_id": job_id}
