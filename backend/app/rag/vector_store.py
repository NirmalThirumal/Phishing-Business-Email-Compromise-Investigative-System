import os
from typing import List, Dict, Any
import chromadb
from chromadb.utils import embedding_functions

RAG_DOCS_DIR = "rag_docs"
CHROMA_DIR = os.getenv("CHROMA_PERSIST_DIR", "./chroma_db")
COLLECTION_NAME = "threat_intel_kb"


class ThreatIntelRAG:
    def __init__(self, persist_dir: str = CHROMA_DIR):
        os.makedirs(persist_dir, exist_ok=True)
        self.client = chromadb.PersistentClient(path=persist_dir)
        self.embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )
        self.collection = self.client.get_or_create_collection(
            name=COLLECTION_NAME,
            embedding_function=self.embedding_fn,
            metadata={"hnsw:space": "cosine"},
        )

    def _chunk_markdown(self, text: str, max_chars: int = 700) -> List[str]:
        """Splits markdown documents cleanly by section/paragraph boundaries."""
        paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
        chunks: List[str] = []
        current = ""
        for para in paragraphs:
            if len(current) + len(para) + 2 <= max_chars:
                current = f"{current}\n\n{para}".strip()
            else:
                if current:
                    chunks.append(current)
                current = para
        if current:
            chunks.append(current)
        return chunks

    def ingest_knowledge_base(self, docs_dir: str = RAG_DOCS_DIR) -> int:
        """Reads all .md files under rag_docs/, embeds chunks, and indexes them in ChromaDB."""
        documents: List[str] = []
        metadatas: List[Dict[str, Any]] = []
        ids: List[str] = []

        doc_counter = 0
        for root, _, files in os.walk(docs_dir):
            for fname in sorted(files):
                if not fname.endswith(".md"):
                    continue
                full_path = os.path.join(root, fname)
                category = os.path.basename(root)
                with open(full_path, "r", encoding="utf-8") as f:
                    content = f.read()

                chunks = self._chunk_markdown(content)
                for idx, chunk in enumerate(chunks):
                    doc_id = f"{category}_{fname}_{idx}"
                    documents.append(chunk)
                    metadatas.append({
                        "source_file": fname,
                        "category": category,
                        "chunk_index": idx,
                    })
                    ids.append(doc_id)
                    doc_counter += 1

        if documents:
            self.collection.upsert(
                documents=documents,
                metadatas=metadatas,
                ids=ids,
            )
        return doc_counter

    def retrieve(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """Retrieves the most relevant threat intelligence passages with source citations."""
        if self.collection.count() == 0:
            self.ingest_knowledge_base()

        results = self.collection.query(
            query_texts=[query],
            n_results=min(top_k, self.collection.count()),
        )

        formatted: List[Dict[str, Any]] = []
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        for doc, meta, dist in zip(docs, metas, distances):
            similarity = round(max(0.0, 1.0 - float(dist)), 4)
            formatted.append({
                "source": f"{meta['category']}/{meta['source_file']}",
                "relevance_score": similarity,
                "content": doc,
            })
        return formatted