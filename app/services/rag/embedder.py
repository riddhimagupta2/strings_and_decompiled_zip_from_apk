# services/rag/embedder.py
from sentence_transformers import SentenceTransformer
import numpy as np

_model: SentenceTransformer | None = None

def get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        print("[Embedder] Model load ho raha hai — pehli baar thoda time lagega...")
        _model = SentenceTransformer("all-MiniLM-L6-v2")
        print("[Embedder] Model ready!")
    return _model


def embed_text(text: str) -> list[float]:
  
    model = get_model()
    embedding = model.encode(text, convert_to_numpy=True)
    return embedding.tolist()


def embed_texts(texts: list[str]) -> list[list[float]]:
   
    model = get_model()
    embeddings = model.encode(texts, convert_to_numpy=True, batch_size=8)
    return embeddings.tolist()