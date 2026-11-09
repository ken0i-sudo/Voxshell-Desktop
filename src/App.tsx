import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface PlannedFileItem {
  source_path: string;
  destination_path: string;
  file_size_bytes: number;
  will_overwrite: boolean;
  is_directory: boolean;
}

interface ValidatedFileDryRunPlan {
  command_id: string;
  raw_transcript: string;
  action_type: string;
  security_tier: "GREEN" | "YELLOW" | "RED";
  requires_auth: boolean;
  human_summary: string;
  warnings: string[];
  collision_policy: string;
  create_dest_dir: string | null;
  items: PlannedFileItem[];
  total_bytes_affected: number;
}

interface BatchExecutionReceipt {
  command_id: string;
  final_status: string;
  succeeded_count: number;
  failed_count: number;
  errors: string[];
}

interface UndoReceipt {
  command_id: string;
  command_status: string;
  restored_count: number;
  skipped_conflicts: string[];
}

interface CommandHistoryRow {
  id: string;
  raw_transcript: string;
  action_type: string;
  security_tier: string;
  execution_status: string;
  is_undoable: boolean;
  created_at_ms: number;
}

export default function App() {
  const [query, setQuery] = useState("Move all PDFs from Downloads to Documents/Invoices");
  const [activeVoiceSession, setActiveVoiceSession] = useState<string | null>(null);
  const [dryRunPlan, setDryRunPlan] = useState<ValidatedFileDryRunPlan | null>(null);
  const [statusBanner, setStatusBanner] = useState<string>("IDLE — Ready for command");
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [history, setHistory] = useState<CommandHistoryRow[]>([]);

  const refreshHistory = async () => {
    try {
      const rows = await invoke<CommandHistoryRow[]>("get_command_history", {
        limit: 15,
        offset: 0,
      });
      setHistory(rows);
    } catch (err: any) {
      console.error("Failed to fetch history:", err);
    }
  };

  useEffect(() => {
    refreshHistory();
  }, []);

  const handleTextSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorBanner(null);
    setStatusBanner("INTENT_PARSING — Running Pre-Flight Dry-Run...");
    try {
      const plan = await invoke<ValidatedFileDryRunPlan>("submit_text_query", {
        query,
      });
      setDryRunPlan(plan);
      setStatusBanner(`AWAITING_AUTH (${plan.security_tier} TIER) — 30s timeout active`);
    } catch (err: any) {
      setDryRunPlan(null);
      setStatusBanner("FAILED");
      setErrorBanner(
        typeof err === "object" && err !== null
          ? `[${err.code}] ${err.message}`
          : String(err)
      );
    }
  };

  const handleToggleVoice = async () => {
    setErrorBanner(null);
    if (!activeVoiceSession) {
      try {
        const sessionId = await invoke<string>("start_voice_session");
        setActiveVoiceSession(sessionId);
        setStatusBanner("LISTENING — Recording 16kHz Mono PCM...");
      } catch (err: any) {
        setErrorBanner(
          typeof err === "object" && err !== null
            ? `[${err.code}] ${err.message}`
            : String(err)
        );
      }
    } else {
      try {
        setStatusBanner("TRANSCRIBING — Processing WAV buffer...");
        const plan = await invoke<ValidatedFileDryRunPlan>("stop_and_process_voice", {
          sessionId: activeVoiceSession,
        });
        setActiveVoiceSession(null);
        setDryRunPlan(plan);
        setStatusBanner(`AWAITING_AUTH (${plan.security_tier} TIER)`);
      } catch (err: any) {
        setActiveVoiceSession(null);
        setStatusBanner("IDLE");
        setErrorBanner(
          typeof err === "object" && err !== null
            ? `[${err.code}] ${err.message}`
            : String(err)
        );
      }
    }
  };

  const handleAuthorize = async () => {
    if (!dryRunPlan) return;
    setErrorBanner(null);
    setStatusBanner("EXECUTING — Running atomic file operations...");
    try {
      const receipt = await invoke<BatchExecutionReceipt>("authorize_and_execute", {
        commandId: dryRunPlan.command_id,
        authMethod: "UI_CLICK",
      });
      setDryRunPlan(null);
      setStatusBanner(
        `${receipt.final_status} — ${receipt.succeeded_count} succeeded, ${receipt.failed_count} failed`
      );
      await refreshHistory();
    } catch (err: any) {
      setStatusBanner("FAILED");
      setErrorBanner(
        typeof err === "object" && err !== null
          ? `[${err.code}] ${err.message}`
          : String(err)
      );
    }
  };

  const handleCancel = async () => {
    if (!dryRunPlan) return;
    try {
      await invoke("cancel_command", { commandId: dryRunPlan.command_id });
      setDryRunPlan(null);
      setStatusBanner("CANCELLED");
      await refreshHistory();
    } catch (err: any) {
      setErrorBanner(String(err));
    }
  };

  const handleUndo = async (commandId?: string) => {
    setErrorBanner(null);
    try {
      const receipt = await invoke<UndoReceipt>("undo_command_ipc", {
        commandId: commandId ?? null,
      });
      setStatusBanner(
        `${receipt.command_status} — Restored ${receipt.restored_count} item(s). Skipped conflicts: ${receipt.skipped_conflicts.length}`
      );
      await refreshHistory();
    } catch (err: any) {
      setErrorBanner(
        typeof err === "object" && err !== null
          ? `[${err.code}] ${err.message}`
          : String(err)
      );
    }
  };

  return (
    <div style={{ fontFamily: "system-ui, sans-serif", background: "#0d1117", color: "#e6edf3", minHeight: "100vh", padding: "24px" }}>
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid #30363d", paddingBottom: "14px", marginBottom: "20px" }}>
        <div>
          <h1 style={{ margin: 0, fontSize: "20px" }}>VoxShell — Rust Core Dev Test Harness</h1>
          <p style={{ margin: "4px 0 0", fontSize: "13px", color: "#8b949e" }}>
            State: <strong style={{ color: "#58a6ff" }}>{statusBanner}</strong>
          </p>
        </div>
        <button
          onClick={() => handleUndo()}
          style={{ background: "#21262d", color: "#e6edf3", border: "1px solid #30363d", borderRadius: "6px", padding: "8px 14px", cursor: "pointer", fontWeight: 600 }}
        >
          Undo Last Command (Ctrl+Z)
        </button>
      </header>

      {errorBanner && (
        <div style={{ background: "#3d161b", border: "1px solid #f85149", color: "#ff7b72", padding: "12px 16px", borderRadius: "6px", marginBottom: "16px", fontSize: "14px" }}>
          {errorBanner}
        </div>
      )}

      <form onSubmit={handleTextSubmit} style={{ display: "flex", gap: "10px", marginBottom: "20px" }}>
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Type command (e.g. Move all PDFs from Downloads to Documents/Invoices)"
          style={{ flex: 1, background: "#161b22", color: "#e6edf3", border: "1px solid #30363d", borderRadius: "6px", padding: "10px 14px", fontSize: "14px" }}
        />
        <button
          type="submit"
          style={{ background: "#238636", color: "#fff", border: "none", borderRadius: "6px", padding: "10px 18px", cursor: "pointer", fontWeight: 600 }}
        >
          Run Dry-Run
        </button>
        <button
          type="button"
          onClick={handleToggleVoice}
          style={{
            background: activeVoiceSession ? "#da3633" : "#1f6feb",
            color: "#fff",
            border: "none",
            borderRadius: "6px",
            padding: "10px 18px",
            cursor: "pointer",
            fontWeight: 600,
          }}
        >
          {activeVoiceSession ? "Stop Mic" : "Start Mic"}
        </button>
      </form>

      {dryRunPlan && (
        <section style={{ background: "#161b22", border: `2px solid ${dryRunPlan.security_tier === "RED" ? "#f85149" : "#d29922"}`, borderRadius: "8px", padding: "16px", marginBottom: "24px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px" }}>
            <h2 style={{ margin: 0, fontSize: "16px" }}>
              [{dryRunPlan.security_tier} TIER PREVIEW] {dryRunPlan.human_summary}
            </h2>
            <span style={{ fontSize: "12px", color: "#8b949e" }}>
              {dryRunPlan.items.length} file(s) • {(dryRunPlan.total_bytes_affected / 1024).toFixed(1)} KB
            </span>
          </div>

          {dryRunPlan.warnings.map((w, idx) => (
            <div key={idx} style={{ color: "#f0883e", fontSize: "13px", marginBottom: "6px" }}>
              Warning: {w}
            </div>
          ))}

          <ul style={{ maxHeight: "180px", overflowY: "auto", background: "#0d1117", padding: "10px 24px", borderRadius: "6px", fontSize: "12px", fontFamily: "monospace" }}>
            {dryRunPlan.items.map((item, idx) => (
              <li key={idx} style={{ marginBottom: "4px" }}>
                {item.source_path} {"->"} {item.destination_path || "[STAGE-1 QUARANTINE]"}
              </li>
            ))}
          </ul>

          <div style={{ display: "flex", gap: "10px", marginTop: "14px", justifyContent: "flex-end" }}>
            <button
              onClick={handleCancel}
              autoFocus={dryRunPlan.security_tier === "RED"}
              style={{ background: "#21262d", color: "#e6edf3", border: "1px solid #30363d", borderRadius: "6px", padding: "8px 16px", cursor: "pointer" }}
            >
              Cancel (Esc)
            </button>
            <button
              onClick={handleAuthorize}
              style={{ background: dryRunPlan.security_tier === "RED" ? "#da3633" : "#d29922", color: "#fff", border: "none", borderRadius: "6px", padding: "8px 18px", cursor: "pointer", fontWeight: 600 }}
            >
              Approve & Execute
            </button>
          </div>
        </section>
      )}

      <section>
        <h3 style={{ fontSize: "15px", marginBottom: "10px" }}>SQLite WAL Audit Log (command_logs)</h3>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px", background: "#161b22", borderRadius: "6px", overflow: "hidden" }}>
          <thead>
            <tr style={{ background: "#21262d", textAlign: "left" }}>
              <th style={{ padding: "10px" }}>Action</th>
              <th style={{ padding: "10px" }}>Transcript</th>
              <th style={{ padding: "10px" }}>Tier</th>
              <th style={{ padding: "10px" }}>Status</th>
              <th style={{ padding: "10px" }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {history.length === 0 ? (
              <tr>
                <td colSpan={5} style={{ padding: "14px", color: "#8b949e", textAlign: "center" }}>
                  No commands logged yet. Put a test .pdf in ~/Downloads and click Run Dry-Run!
                </td>
              </tr>
            ) : (
              history.map((row) => (
                <tr key={row.id} style={{ borderTop: "1px solid #30363d" }}>
                  <td style={{ padding: "10px", fontFamily: "monospace" }}>{row.action_type}</td>
                  <td style={{ padding: "10px" }}>{row.raw_transcript}</td>
                  <td style={{ padding: "10px" }}>{row.security_tier}</td>
                  <td style={{ padding: "10px", fontWeight: 600 }}>{row.execution_status}</td>
                  <td style={{ padding: "10px" }}>
                    {row.is_undoable && (
                      <button
                        onClick={() => handleUndo(row.id)}
                        style={{ background: "#1f6feb", color: "#fff", border: "none", borderRadius: "4px", padding: "4px 10px", cursor: "pointer", fontSize: "12px" }}
                      >
                        Undo
                      </button>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </section>
    </div>
  );
}
