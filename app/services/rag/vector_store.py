import chromadb
from chromadb.config import Settings
import os

_client: chromadb.ClientAPI | None = None
_collection = None

COLLECTION_NAME = "apk_analysis"


def init_vector_store():
    """Startup pe call karo — ChromaDB initialize karta hai."""
    global _client, _collection

    db_path = os.getenv("CHROMA_DB_PATH", "storage/chroma_db")
    os.makedirs(db_path, exist_ok=True)

    _client = chromadb.PersistentClient(
        path=db_path,
        settings=Settings(anonymized_telemetry=False)
    )

    _collection = _client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"}  # cosine similarity use karenge
    )

    count = _collection.count()
    print(f"[VectorStore] Ready — {count} chunks indexed hain.")


def get_collection():
    """Collection instance return karo."""
    if _collection is None:
        raise RuntimeError("Vector store initialize nahi hua. init_vector_store() call karo.")
    return _collection


def add_chunks(chunks: list[dict], embeddings: list[list[float]]):
    
    collection = get_collection()

    ids        = [c["chunk_id"] for c in chunks]
    documents  = [c["text"]     for c in chunks]
    metadatas  = [c["metadata"] for c in chunks]

    
    collection.upsert(
        ids=ids,
        documents=documents,
        embeddings=embeddings,
        metadatas=metadatas,
    )
    print(f"[VectorStore] {len(chunks)} chunks indexed.")


def search_similar(
    query_embedding: list[float],
    n_results: int = 3,
    chunk_type: str | None = None,
) -> list[dict]:
   
    collection = get_collection()


    if collection.count() == 0:
        return []


    where = {"chunk_type": chunk_type} if chunk_type else None

    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=min(n_results, collection.count()),
        where=where,
        include=["documents", "metadatas", "distances"],
    )


    formatted = []
    if results and results["ids"] and results["ids"][0]:
        for i, chunk_id in enumerate(results["ids"][0]):
            formatted.append({
                "chunk_id":   chunk_id,
                "text":       results["documents"][0][i],
                "metadata":   results["metadatas"][0][i],
                "similarity": round(1 - results["distances"][0][i], 4),
            })

    return formatted


def delete_job_chunks(job_id: str):
    
    collection = get_collection()
    collection.delete(where={"job_id": job_id})
    print(f"[VectorStore] Chunks for job {job_id} have been deleted.")


def get_indexed_count() -> int:
    
    return get_collection().count()