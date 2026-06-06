from app.services.rag.embedder     import embed_text
from app.services.rag.vector_store import search_similar

MIN_SIMILARITY = 0.65

def retrieve_similar_cases(chunks: list[dict], top_k: int = 5) -> list[dict]:
  
    seen_chunk_ids = set()
    all_results    = []

   
    priority_types = ["behavior", "risk_summary"]
    chunk_map      = {c["chunk_type"]: c for c in chunks}

    for chunk_type in priority_types:
        if chunk_type not in chunk_map:
            continue

        chunk           = chunk_map[chunk_type]
        query_embedding = embed_text(chunk["text"])

        results = search_similar(
            query_embedding=query_embedding,
            n_results=top_k,
            chunk_type=chunk_type,
        )

        for result in results:
          
            if result["similarity"] < MIN_SIMILARITY:
                continue

            if result["chunk_id"] not in seen_chunk_ids:
                seen_chunk_ids.add(result["chunk_id"])
                result["matched_on"] = chunk_type
                all_results.append(result)

   
    all_results.sort(key=lambda x: x["similarity"], reverse=True)

  
    return all_results[:6]