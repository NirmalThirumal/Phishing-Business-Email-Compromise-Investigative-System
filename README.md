Here is a complete `README.md` ready to save directly to `C:\Projects\Phishing & Business Email Compromise Investigative System\README.md`.

```markdown
# PhishGuard AI — Phishing & Business Email Compromise (BEC) Investigative System

**PhishGuard AI** is a full-stack Security Operations Center (SOC) investigation workbench built to triage, investigate, and explain phishing and Business Email Compromise (BEC) emails. It combines a **Dual-ML inference engine**, a **LangGraph multi-agent pipeline**, a **ChromaDB Threat Intelligence RAG knowledge base**, **real-time Gmail IMAP monitoring**, and a **React SOC Workbench** with Human-in-the-Loop (HITL) analyst feedback.

---

## Key Features

* **MIME & Header Forensics Parser (`backend/app/parsers/email_parser.py`)**: Extracts sender and display names, `Reply-To` and `Return-Path` mismatches, SPF/DKIM/DMARC authentication statuses, embedded URLs (raw IP URLs, URL shorteners, and HTML anchor-text mismatches), and attachment metadata with SHA-256 hashes.
* **Dual-ML Triage Engine (`backend/app/ml/`)**:
  * **Track A (NLP Classifier)**: TF-IDF + XGBoost model trained on a merged Apache SpamAssassin and BEC dataset.
  * **Track B (Behavioral Anomaly Detector)**: `IsolationForest` + `StandardScaler` pipeline trained on 12 structural, header, URL, and urgency features extracted from 1,500 real emails.
* **LangGraph Multi-Agent Pipeline (`backend/app/agents/graph.py` & `tools.py`)**:
  * **Email & Header Analysis Agent**: Audits SPF/DKIM/DMARC, header mismatches, display-name spoofing, and high-risk attachments.
  * **URL & Domain Investigation Agent**: Evaluates URLs and domains using Google Safe Browsing, VirusTotal, URLhaus, WHOIS domain age, IP/shortener detection, and anchor-text mismatch checks.
  * **Identity & Impersonation Agent**: Checks senders and lookalike domains against the internal corporate directory and WHOIS domain age.
  * **Threat Intelligence RAG Agent**: Retrieves relevant MITRE ATT&CK entries, CISA advisories, and internal security policies from ChromaDB (`rag_docs/`).
  * **Risk Assessment & Reporting Agent**: Synthesizes ML scores and agent findings into a structured `FinalVerdict` using Gemini with a deterministic fallback synthesizer.
* **Real-Time Gmail IMAP Monitor (`backend/app/services/realtime_monitor.py`)**: Polls `INBOX` and `[Gmail]/Spam` on a configurable schedule, investigates newly arrived emails automatically, and records results.
* **React SOC Workbench (`frontend/`)**: Branded React + Vite dashboard featuring an investigation queue, risk score and NLP probability readouts, verified vs. heuristic indicators, multi-agent cards, and a Human-in-the-Loop analyst decision panel persisted to local JSON (`data/processed/investigations_store.json`).

---

## System Architecture

```text
.eml Upload / Live Gmail IMAP Monitor
                │
                ▼
 Email Parser & Feature Extractor
                │
     ┌──────────┴──────────┐
     ▼                     ▼
Track A: XGBoost NLP  Track B: IsolationForest
  (TF-IDF + ML)        (12 Structural Features)
     │                     │
     └──────────┬──────────┘
                ▼
    LangGraph Multi-Agent Pipeline
 ┌────────┬────────┬────────┬────────┬────────┐
 ▼        ▼        ▼        ▼        ▼        ▼
Email/   URL/     Identity ChromaDB Risk/Verdict
Hdr      Domain   Agent    RAG      Synthesizer
Agent    Agent                        │
                                      ▼
                            FastAPI + JSON Store
                                      │
                                      ▼
                            React SOC Workbench

```

---

## Project Structure

```text
Phishing & Business Email Compromise Investigative System/
├── README.md
├── .vscode/
│   └── settings.json                  # Extra analysis path for backend imports
├── backend/
│   ├── evaluate_components.py         # Component & end-to-end benchmark suite
│   ├── requirements.txt
│   ├── test_agents.py
│   ├── test_ml.py
│   ├── test_parser.py
│   ├── test_rag.py
│   └── app/
│       ├── main.py                    # FastAPI entrypoint
│       ├── api/
│       │   └── routes.py              # REST endpoints for upload, queue & HITL decisions
│       ├── core/
│       │   ├── config.py              # Environment & Gemini model settings
│       │   └── storage.py             # JSON persistence for investigations & verdicts
│       ├── parsers/
│       │   └── email_parser.py        # .eml / MIME parsing & feature extraction
│       ├── ml/
│       │   ├── inference.py           # DualMLPredictor (XGBoost + IsolationForest)
│       │   ├── train_models.py
│       │   ├── upgrade_dataset_and_train.py
│       │   └── train_isolation_forest_real.py
│       ├── agents/
│       │   ├── graph.py               # LangGraph state machine & verdict synthesis
│       │   └── tools.py               # VT, Safe Browsing, URLhaus, WHOIS & directory tools
│       ├── rag/
│       │   └── vector_store.py        # ChromaDB threat intelligence retrieval
│       ├── schemas/
│       │   ├── email_schema.py
│       │   └── investigation_schema.py
│       └── services/
│           └── realtime_monitor.py    # Background Gmail IMAP polling worker
├── chroma_db/                         # Persisted ChromaDB vector store
├── data/
│   ├── processed/                     # Trained models, corpus, JSON store & benchmark report
│   ├── raw/                           # Raw email datasets (e.g., easy_ham)
│   └── sample_emls/                   # Sample .eml test files
├── frontend/
│   ├── public/
│   │   └── logo.svg                   # PhishGuard AI brand mark
│   └── src/
│       ├── App.jsx                    # SOC Workbench UI
│       └── App.css                    # Workbench stylesheet
├── notebooks/                         # Training & experimentation notebooks
├── rag_docs/                          # MITRE ATT&CK, CISA advisories & org policies
├── docker-compose.yml
├── Dockerfile.backend
└── Dockerfile.frontend

```

---

## Setup & Installation

### 1. Backend Setup

From the project root (`C:\Projects\Phishing & Business Email Compromise Investigative System`), create and activate the virtual environment and install Python dependencies:

```cmd
python -m venv venv
venv\Scripts\activate.bat
pip install -r backend\requirements.txt

```

Create a `.env` file in the project root:

```env
GOOGLE_API_KEY=your_gemini_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
GOOGLE_SAFE_BROWSING_KEY=your_safe_browsing_key
CHROMA_PERSIST_DIR=./chroma_db

# Optional: Real-Time Gmail IMAP Monitor
IMAP_HOST=imap.gmail.com
IMAP_USER=your_email@gmail.com
IMAP_APP_PASSWORD=your_gmail_app_password

```

### 2. Frontend Setup

```cmd
cd frontend
npm install

```

---

## Running the Application

Run each process in its own terminal from the project root:

1. **Start the FastAPI Backend (`http://127.0.0.1:8000`)**:
```cmd
uvicorn app.main:app --app-dir backend --reload --port 8000

```


2. **Start the React SOC Workbench (`http://localhost:5173`)**:
```cmd
cd frontend
npm run dev

```


3. **(Optional) Start the Real-Time Gmail IMAP Monitor**:
```cmd
python backend\app\services\realtime_monitor.py

```



---

## Training & Evaluation

### Train `IsolationForest` on Real Emails

```cmd
python backend\app\ml\train_isolation_forest_real.py

```

### Run Component & End-to-End Evaluation

```cmd
python backend\evaluate_components.py

```

Benchmark summary (`data/processed/component_evaluation_report.json`):

| Component | Key Metrics | Avg Latency |
| --- | --- | --- |
| **Email Parser** | **100.0%** extraction accuracy (`16/16`) | `13.34 ms` / email |
| **Track A: XGBoost NLP** (`n=680` holdout) | **97.79%** Acc · **99.4%** Prec · **92.22%** Rec · **95.68%** F1 · **0.9965** ROC-AUC · **0.2%** FPR | `0.29 ms` / email |
| **Dual ML + IsolationForest** (`n=8` ground truth) | **75.0%** Combined Acc / F1 · **0.80** IsolationForest ROC-AUC | `54.32 ms` / email |
| **Threat Intel RAG (ChromaDB)** | **75.0%** Precision@3 · **100.0%** Recall@3 · **1.0** MRR | `26.10 ms` / query |
| **Specialized Agents** | Email/Header: **87.5%** · URL/Domain: **100.0%** · Identity: **75.0%** | — |
| **End-to-End Multi-Agent Pipeline** | **100.0%** Multi-Class Acc & Macro-F1 · **100.0%** Threat F1 · **0.0%** FPR | `4,969.59 ms` / email |

---

## Disclaimer

PhishGuard AI is built for defensive security analysis, SOC triage assistance, and educational or research use. Always perform human SOC analyst verification before taking final containment actions on live email traffic.

```

```