import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.rag.vector_store import ThreatIntelRAG

if __name__ == "__main__":
    print("Initializing ChromaDB & embedding Threat Intelligence documents...")
    rag = ThreatIntelRAG()
    count = rag.ingest_knowledge_base()
    print(f"Indexed {count} threat intelligence chunks into ChromaDB.\n")

    test_queries = [
        "CEO lookalike domain urgent wire transfer confidential board meeting reply-to gmail",
        "Office 365 password expire IP address URL anchor text mismatch credential login",
    ]

    for q in test_queries:
        print("=" * 70)
        print(f"QUERY: {q}")
        print("=" * 70)
        hits = rag.retrieve(q, top_k=2)
        print(json.dumps(hits, indent=2))