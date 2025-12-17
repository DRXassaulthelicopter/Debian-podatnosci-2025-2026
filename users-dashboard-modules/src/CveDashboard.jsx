import React, { useMemo, useRef, useState } from "react";

const DATA_URL = "/results.json";

function toText(v) {
  return v == null ? "" : String(v).toLowerCase();
}

function cveToSearchableText(row) {
  return [
    row.cve_id,
    row.severity,
    row.vector,
    row.score_version,
    row.base_score,
    row.exploitability,
    row.impact,
  ]
    .map(toText)
    .join(" ");
}

function safeNumber(x) {
  const n = Number(x);
  return Number.isFinite(n) ? n : null;
}

export default function CveDashboard() {
  const [rows, setRows] = useState([]);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [status, setStatus] = useState("idle"); // idle | loading | success | error
  const [error, setError] = useState("");

  const abortRef = useRef(null);
  const hasData = rows.length > 0;
  const isLoading = status === "loading";

  async function fetchData() {
    if (abortRef.current) abortRef.current.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setStatus("loading");
    setError("");

    try {
      const res = await fetch(DATA_URL, { signal: controller.signal });
      if (!res.ok) throw new Error(`Request failed: ${res.status} ${res.statusText}`);
      const data = await res.json();

      // supports either: array at root OR { results: [...] }
      const list = Array.isArray(data) ? data : Array.isArray(data?.results) ? data.results : [];
      setRows(list);
      setStatus("success");
    } catch (e) {
      if (e?.name === "AbortError") return;
      setStatus("error");
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      abortRef.current = null;
    }
  }

  function clear() {
    if (abortRef.current) abortRef.current.abort();
    setRows([]);
    setQuery("");
    setSeverity("ALL");
    setStatus("idle");
    setError("");
  }

  const severities = useMemo(() => {
    const set = new Set(rows.map((r) => r?.severity ?? "N/A"));
    return ["ALL", ...Array.from(set).sort()];
  }, [rows]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return rows
      .filter((r) => {
        if (severity === "ALL") return true;
        return (r?.severity ?? "N/A") === severity;
      })
      .filter((r) => (q ? cveToSearchableText(r).includes(q) : true))
      .slice()
      .sort((a, b) => {
        // Sort by base_score desc (numbers first), fallback by cve_id
        const an = safeNumber(a?.base_score);
        const bn = safeNumber(b?.base_score);
        if (an != null && bn != null) return bn - an;
        if (an != null) return -1;
        if (bn != null) return 1;
        return String(a?.cve_id ?? "").localeCompare(String(b?.cve_id ?? ""));
      });
  }, [rows, query, severity]);

  const stats = useMemo(() => {
    const counts = new Map();
    let sum = 0;
    let n = 0;

    for (const r of rows) {
      const sev = r?.severity ?? "N/A";
      counts.set(sev, (counts.get(sev) ?? 0) + 1);

      const bs = safeNumber(r?.base_score);
      if (bs != null) {
        sum += bs;
        n += 1;
      }
    }

    return {
      total: rows.length,
      avgBase: n ? sum / n : null,
      counts,
    };
  }, [rows]);

  const buttonLabel = isLoading
    ? hasData
      ? "Refreshing…"
      : "Fetching…"
    : hasData
    ? "Refresh data"
    : "Fetch data";

  return (
    <div style={styles.page}>
      <header style={styles.header}>
        <div>
          <h1 style={styles.title}>CVE Dashboard</h1>
          <p style={styles.subtitle}>
            {status === "idle" && "Click “Fetch data” to load results.json"}
            {status === "loading" && (hasData ? "Refreshing data…" : "Loading…")}
            {status === "success" && `Showing ${filtered.length} / ${rows.length}`}
            {status === "error" && (hasData ? "Refresh failed (showing previous data)" : "Error loading data")}
          </p>
        </div>

        <div style={styles.controls}>
          <button
            onClick={fetchData}
            disabled={isLoading}
            style={{ ...styles.button, ...(isLoading ? styles.buttonDisabled : null) }}
          >
            {buttonLabel}
          </button>

          <button onClick={clear} style={{ ...styles.button, ...styles.secondaryButton }}>
            Clear
          </button>

          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            disabled={!hasData}
            style={{ ...styles.select, ...(hasData ? null : styles.searchDisabled) }}
          >
            {severities.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>

          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search a phrase (CVE, vector, severity...)"
            disabled={!hasData}
            style={{ ...styles.search, ...(hasData ? null : styles.searchDisabled) }}
          />
        </div>
      </header>

      {status === "error" && (
        <div style={{ ...styles.card, ...styles.error }}>
          <div style={{ fontWeight: 700, marginBottom: 6 }}>
            {hasData ? "Refresh failed (showing previous data)" : "Couldn’t load data"}
          </div>
          <div style={{ opacity: 0.9 }}>{error}</div>
        </div>
      )}

      {hasData && (
        <div style={{ ...styles.card, marginBottom: 12 }}>
          <div style={styles.chips}>
            <span style={styles.chip}>Total: {stats.total}</span>
            <span style={styles.chip}>
              Avg base_score: {stats.avgBase == null ? "N/A" : stats.avgBase.toFixed(2)}
            </span>
            {Array.from(stats.counts.entries())
              .sort((a, b) => a[0].localeCompare(b[0]))
              .map(([k, v]) => (
                <span key={k} style={styles.chip}>
                  {k}: {v}
                </span>
              ))}
          </div>
        </div>
      )}

      {hasData ? (
        <div style={styles.card}>
          <div style={styles.tableWrap}>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>CVE</th>
                  <th style={styles.th}>Severity</th>
                  <th style={styles.th}>Base</th>
                  <th style={styles.th}>Exploitability</th>
                  <th style={styles.th}>Impact</th>
                  <th style={styles.th}>Score ver.</th>
                  <th style={styles.th}>Vector</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((r, idx) => (
                  <tr key={`${r.cve_id ?? "row"}-${idx}`}>
                    <td style={styles.td} title={r.cve_id}>{r.cve_id}</td>
                    <td style={styles.td}>{r.severity ?? "N/A"}</td>
                    <td style={styles.td}>{r.base_score ?? "N/A"}</td>
                    <td style={styles.td}>{r.exploitability ?? "N/A"}</td>
                    <td style={styles.td}>{r.impact ?? "N/A"}</td>
                    <td style={styles.td}>{r.score_version ?? "N/A"}</td>
                    <td style={{ ...styles.td, ...styles.mono }} title={r.vector}>
                      {r.vector}
                    </td>
                  </tr>
                ))}

                {filtered.length === 0 && (
                  <tr>
                    <td style={styles.td} colSpan={7}>
                      No results for “{query}”.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {isLoading && <div style={styles.refreshHint}>Refreshing…</div>}
        </div>
      ) : (
        <div style={styles.card}>
          No data loaded yet. Put the file at <b>public/results.json</b> and click <b>Fetch data</b>.
        </div>
      )}
    </div>
  );
}

const styles = {
  page: {
    minHeight: "100vh",
    padding: 24,
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif",
    background: "#0b1220",
    color: "#e9eef8",
  },
  header: {
    display: "flex",
    gap: 16,
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 16,
    flexWrap: "wrap",
  },
  title: { margin: 0, fontSize: 28 },
  subtitle: { margin: "6px 0 0", opacity: 0.8 },
  controls: { display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" },
  button: {
    padding: "10px 12px",
    borderRadius: 12,
    border: "1px solid rgba(255,255,255,0.12)",
    background: "rgba(255,255,255,0.12)",
    color: "#e9eef8",
    cursor: "pointer",
  },
  secondaryButton: { background: "rgba(255,255,255,0.06)" },
  buttonDisabled: { opacity: 0.6, cursor: "not-allowed" },

  select: {
    padding: "10px 12px",
    borderRadius: 12,
    border: "1px solid rgba(255,255,255,0.12)",
    background: "rgba(255,255,255,0.06)",
    color: "#e9eef8",
    outline: "none",
  },

  search: {
    width: 320,
    maxWidth: "100%",
    padding: "10px 12px",
    borderRadius: 12,
    border: "1px solid rgba(255,255,255,0.12)",
    background: "rgba(255,255,255,0.06)",
    color: "#e9eef8",
    outline: "none",
  },
  searchDisabled: { opacity: 0.55, cursor: "not-allowed" },

  card: {
    borderRadius: 16,
    border: "1px solid rgba(255,255,255,0.10)",
    background: "rgba(255,255,255,0.06)",
    padding: 16,
    position: "relative",
  },
  error: { borderColor: "rgba(255, 90, 90, 0.35)" },

  chips: { display: "flex", gap: 8, flexWrap: "wrap" },
  chip: {
    fontSize: 12,
    opacity: 0.9,
    border: "1px solid rgba(255,255,255,0.12)",
    background: "rgba(255,255,255,0.06)",
    padding: "6px 10px",
    borderRadius: 999,
  },

  tableWrap: { overflowX: "auto" },
  table: { width: "100%", borderCollapse: "collapse", minWidth: 980 },
  th: {
    textAlign: "left",
    fontSize: 12,
    textTransform: "uppercase",
    opacity: 0.8,
    padding: "10px 8px",
    borderBottom: "1px solid rgba(255,255,255,0.10)",
  },
  td: {
    padding: "12px 8px",
    borderBottom: "1px solid rgba(255,255,255,0.08)",
    verticalAlign: "top",
  },
  mono: { fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace", fontSize: 12 },
  refreshHint: { marginTop: 12, opacity: 0.75, fontSize: 12 },
};