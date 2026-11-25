import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  ShieldCheck,
  Upload,
  Mail,
  Link as LinkIcon,
  UserCheck,
  BookOpen,
  AlertTriangle,
  Clock,
  FileText,
  Send,
} from "lucide-react";
import "./App.css";

const API_BASE = "http://127.0.0.1:8000/api";

export default function App() {
  const [investigations, setInvestigations] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [decision, setDecision] = useState("Quarantine Email");
  const [notes, setNotes] = useState("");
  const [savingDecision, setSavingDecision] = useState(false);
  const [error, setError] = useState("");

  const selectedIdRef = useRef(selectedId);
  selectedIdRef.current = selectedId;

  const selectInvestigation = useCallback((item) => {
    if (!item) {
      setSelectedId(null);
      return;
    }
    setSelectedId(item.id);
    setDecision(
      item.analyst_decision && item.analyst_decision !== "Pending Review"
        ? item.analyst_decision
        : "Quarantine Email"
    );
    setNotes(item.analyst_notes || "");
  }, []);

  const fetchInvestigations = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/investigations`);
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const data = await res.json();
      setInvestigations(data);
      setError("");

      const currentId = selectedIdRef.current;
      const stillExists = currentId && data.some((item) => item.id === currentId);

      if (!stillExists && data.length > 0) {
        selectInvestigation(data[0]);
      }
    } catch (err) {
      setError("Cannot connect to FastAPI backend on port 8000.");
    }
  }, [selectInvestigation]);

  useEffect(() => {
    fetchInvestigations();
    const interval = setInterval(fetchInvestigations, 5000);
    return () => clearInterval(interval);
  }, [fetchInvestigations]);

  const selected =
    investigations.find((item) => item.id === selectedId) || null;

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploading(true);
    setError("");
    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch(`${API_BASE}/investigate/upload`, {
        method: "POST",
        body: formData,
      });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Upload failed");
      }
      const newRecord = await res.json();
      setInvestigations((prev) => [newRecord, ...prev]);
      selectInvestigation(newRecord);
    } catch (err) {
      setError(err.message);
    } finally {
      setUploading(false);
      e.target.value = "";
    }
  };

  const handleDecisionSubmit = async (e) => {
    e.preventDefault();
    if (!selected) return;
    setSavingDecision(true);
    try {
      const res = await fetch(`${API_BASE}/investigations/${selected.id}/decision`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision, notes }),
      });
      const updated = await res.json();
      setInvestigations((prev) =>
        prev.map((item) => (item.id === updated.id ? updated : item))
      );
      setSelectedId(updated.id);
      setNotes(updated.analyst_notes || "");
    } catch (err) {
      setError("Failed to save analyst decision.");
    } finally {
      setSavingDecision(false);
    }
  };

  const getRiskLevelClass = (score) => {
    if (score >= 75) return "risk-high";
    if (score >= 40) return "risk-medium";
    return "risk-low";
  };

  const getStatusBadge = (status) => {
    const validStatuses = ["malicious", "suspicious", "clean"];
    const badgeModifier = validStatuses.includes(status) ? status : "suspicious";
    return (
      <span className={`status-badge status-badge--${badgeModifier}`}>
        {status}
      </span>
    );
  };

  const getAgentIcon = (name) => {
    if (name.includes("Email")) return <Mail size={18} color="#60a5fa" />;
    if (name.includes("URL")) return <LinkIcon size={18} color="#f472b6" />;
    if (name.includes("Identity")) return <UserCheck size={18} color="#fbbf24" />;
    return <BookOpen size={18} color="#34d399" />;
  };

  return (
    <div className="app-page">
      {/* Top Navbar */}
      <header className="app-header">
        <div className="header-brand">
          <img
            src="/logo.svg"
            alt="PhishGuard AI Logo"
            className="header-logo"
          />
          <div>
            <div className="header-title-row">
              <h1 className="header-title">
                PhishGuard <span className="header-title-accent">AI</span>
              </h1>
              <span className="header-badge">SOC WORKBENCH</span>
            </div>
            <span className="header-subtitle">
              Phishing &amp; Business Email Compromise Investigative System
            </span>
          </div>
        </div>

        <label className="upload-btn">
          <Upload size={16} />
          {uploading ? "Investigating Email..." : "Upload .eml File"}
          <input
            type="file"
            accept=".eml"
            onChange={handleFileUpload}
            disabled={uploading}
            className="hidden-input"
          />
        </label>
      </header>

      {error && <div className="error-banner">{error}</div>}

      {/* Main Split Layout */}
      <div className="workspace">
        {/* Left Sidebar: Investigation Queue */}
        <aside className="sidebar">
          <h2 className="section-title">
            Investigation Queue ({investigations.length})
          </h2>
          {investigations.length === 0 ? (
            <p className="empty-queue-text">
              No emails investigated yet. Upload a <code>.eml</code> file from{" "}
              <code>data/sample_emls/</code> to begin.
            </p>
          ) : (
            investigations.map((item) => {
              const score = item.report.verdict.overall_risk_score;
              const isSelected = selected?.id === item.id;
              const isPending = item.analyst_decision === "Pending Review";

              return (
                <div
                  key={item.id}
                  onClick={() => selectInvestigation(item)}
                  className={`queue-card ${isSelected ? "queue-card--selected" : ""}`}
                >
                  <div className="queue-card-top">
                    <span className={`queue-risk-label ${getRiskLevelClass(score)}`}>
                      RISK: {score}/100
                    </span>
                    <span className="queue-id">#{item.id}</span>
                  </div>
                  <div className="queue-subject">
                    {item.report.parsed_email.subject || "(No Subject)"}
                  </div>
                  <div className="queue-sender">
                    From: {item.report.parsed_email.sender_email}
                  </div>
                  <div className="queue-card-footer">
                    <span className="classification-tag">
                      {item.report.verdict.attack_classification}
                    </span>
                    <span
                      className={`decision-status ${
                        isPending ? "decision-status--pending" : "decision-status--reviewed"
                      }`}
                    >
                      {item.analyst_decision}
                    </span>
                  </div>
                </div>
              );
            })
          )}
        </aside>

        {/* Right Main Panel: Investigation Details */}
        <main className="main-panel">
          {!selected ? (
            <div className="empty-state">
              <FileText size={48} color="#334155" />
              <h3>Select or Upload an Email to Inspect</h3>
              <p className="empty-state-desc">
                Upload <code>sample_phishing.eml</code> or <code>sample_bec.eml</code> using the
                top-right button to run NLP classification, behavioral anomaly scoring, and
                multi-agent investigation.
              </p>
            </div>
          ) : (
            <>
              {/* Top Verdict & Score Banner */}
              <div className="card">
                <div className="verdict-banner-top">
                  <div>
                    <div className="verdict-meta-row">
                      <span className="classification-pill">
                        {selected.report.verdict.attack_classification}
                      </span>
                      <span className="confidence-text">
                        Confidence: <strong>{selected.report.verdict.confidence_level}</strong>
                      </span>
                    </div>
                    <h2 className="verdict-subject">
                      {selected.report.parsed_email.subject}
                    </h2>
                    <p className="verdict-summary">
                      {selected.report.verdict.executive_summary}
                    </p>
                  </div>

                  {/* Risk Gauge Box */}
                  <div className="score-box">
                    <div
                      className={`score-value ${getRiskLevelClass(
                        selected.report.verdict.overall_risk_score
                      )}`}
                    >
                      {selected.report.verdict.overall_risk_score}
                    </div>
                    <div className="score-label">Risk Score / 100</div>
                    <div className="nlp-prob">
                      NLP Prob:{" "}
                      {(selected.report.ml_triage.nlp_phishing_probability * 100).toFixed(1)}%
                    </div>
                  </div>
                </div>

                {/* Email Headers Bar */}
                <div className="meta-grid">
                  <div>
                    <span className="meta-label">From Display &amp; Address</span>
                    <div className="meta-value">
                      {selected.report.parsed_email.sender_display_name} &lt;
                      {selected.report.parsed_email.sender_email}&gt;
                    </div>
                  </div>
                  <div>
                    <span className="meta-label">Reply-To Header</span>
                    <div className="meta-value">
                      {selected.report.parsed_email.reply_to_email || "None (Matches From)"}
                    </div>
                  </div>
                  <div>
                    <span className="meta-label">SPF / DKIM / DMARC</span>
                    <div className="meta-value">
                      {selected.report.parsed_email.auth_results.spf_status.toUpperCase()} /{" "}
                      {selected.report.parsed_email.auth_results.dkim_status.toUpperCase()} /{" "}
                      {selected.report.parsed_email.auth_results.dmarc_status.toUpperCase()}
                    </div>
                  </div>
                </div>
              </div>

              {/* Verified Indicators vs Heuristic Suspicions */}
              <div className="two-col-grid">
                <div className="card">
                  <h3 className="card-heading">
                    <AlertTriangle size={16} color="#ef4444" /> Verified Technical Indicators
                  </h3>
                  <ul className="findings-list">
                    {selected.report.verdict.verified_indicators.map((item, i) => (
                      <li key={i} className="findings-list-item">
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="card">
                  <h3 className="card-heading">
                    <Clock size={16} color="#f59e0b" /> Heuristic Suspicions &amp; Citations
                  </h3>
                  <ul className="findings-list">
                    {selected.report.verdict.heuristic_suspicions.map((item, i) => (
                      <li key={i} className="findings-list-item">
                        {item}
                      </li>
                    ))}
                  </ul>
                  {selected.report.verdict.cited_policies_and_intel.length > 0 && (
                    <div className="citations-wrapper">
                      <span className="citations-label">
                        RAG Threat Intelligence &amp; Policy Sources:
                      </span>
                      <div className="citations-list">
                        {selected.report.verdict.cited_policies_and_intel.map((src, i) => (
                          <span key={i} className="citation-badge">
                            {src}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* 4 Multi-Agent Investigation Cards */}
              <h3 className="section-title">
                LangGraph Multi-Agent Investigation Breakdown
              </h3>
              <div className="two-col-grid">
                {selected.report.agent_reports.map((agent, idx) => (
                  <div key={idx} className="card">
                    <div className="agent-card-header">
                      <div className="agent-title">
                        {getAgentIcon(agent.agent_name)}
                        {agent.agent_name}
                      </div>
                      {getStatusBadge(agent.status)}
                    </div>
                    <ul className="findings-list">
                      {agent.findings.map((f, fIdx) => (
                        <li key={fIdx} className="findings-list-item">
                          {f}
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>

              {/* Human-in-the-Loop SOC Analyst Decision Panel */}
              <div className="card hitl-card">
                <div className="hitl-header">
                  <h3 className="hitl-title">
                    <ShieldCheck size={18} color="#38bdf8" /> Human-in-the-Loop Analyst Decision Panel
                  </h3>
                  <span className="hitl-current-status">
                    Current Status: {selected.analyst_decision}
                  </span>
                </div>

                <form onSubmit={handleDecisionSubmit} className="hitl-form">
                  <div className="choice-btn-group">
                    {[
                      "Quarantine Email",
                      "Mark as Phishing / BEC",
                      "Mark as Legitimate",
                      "Escalate to Tier-2",
                    ].map((opt) => (
                      <button
                        type="button"
                        key={opt}
                        onClick={() => setDecision(opt)}
                        className={`choice-btn ${
                          decision === opt ? "choice-btn--active" : ""
                        }`}
                      >
                        {opt}
                      </button>
                    ))}
                  </div>

                  <textarea
                    rows={2}
                    placeholder="Enter SOC investigation notes (e.g., Verified via phone call with CFO — unauthorized wire request)..."
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    className="notes-textarea"
                  />

                  <div className="hitl-footer">
                    <span className="hitl-hint">
                      Analyst feedback is logged for model retraining and audit compliance.
                    </span>
                    <button
                      type="submit"
                      disabled={savingDecision}
                      className="submit-btn"
                    >
                      <Send size={14} />
                      {savingDecision ? "Saving..." : "Confirm Analyst Verdict"}
                    </button>
                  </div>
                </form>
              </div>
            </>
          )}
        </main>
      </div>
    </div>
  );
}