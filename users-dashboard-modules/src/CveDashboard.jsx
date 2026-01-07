import React, { useMemo, useRef, useState } from "react";

const DATA_URL = "/results2.json";

function toText(v) {
  return v == null ? "" : String(v).toLowerCase();
}

function safeNumber(x) {
  if (x == null) return null;
  if (typeof x === "string" && x.trim().toLowerCase() === "n/a") return null;
  const n = Number(x);
  return Number.isFinite(n) ? n : null;
}

function packagesToText(pkgs) {
  if (!Array.isArray(pkgs)) return "";
  return pkgs
    .map((p) => `${p?.name ?? ""} ${p?.installed_version ?? ""}`.trim())
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function vulnToSearchableText(v) {
  return [
    v.cve_id,
    v.severity,
    v.score_version,
    v.vector,
    v.debsecan_status,
    v.base_score,
    v.exploitability,
    v.impact,
    packagesToText(v.affected_packages),
  ]
    .map(toText)
    .join(" ");
}

export default function CveDashboard() {
  const [platform, setPlatform] = useState(null);
  const [rows, setRows] = useState([]);

  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [debsecan, setDebsecan] = useState("ALL");

  const [status, setStatus] = useState("idle"); // idle | loading | success | error
  const [error, setError] = useState("");

  const [copiedCve, setCopiedCve] = useState("");
  const copiedTimerRef = useRef(null);

  const abortRef = useRef(null);

  const hasData = rows.length > 0;
  const isLoading = status === "loading";
  const isError = status === "error";

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

      // NEW FORMAT: { platform: {...}, vulnerabilities: [...] }
      const list = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
      setRows(list);
      setPlatform(data?.platform ?? null);

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
    setPlatform(null);
    setRows([]);
    setQuery("");
    setSeverity("ALL");
    setDebsecan("ALL");
    setStatus("idle");
    setError("");
  }

  async function copyText(text) {
    try {
      if (!text) return;

      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
      }

      setCopiedCve(text);
      if (copiedTimerRef.current) clearTimeout(copiedTimerRef.current);
      copiedTimerRef.current = setTimeout(() => setCopiedCve(""), 1200);
    } catch {
      // clipboard might be blocked; ignore
    }
  }

  const severities = useMemo(() => {
    const set = new Set(rows.map((r) => r?.severity ?? "N/A"));
    return ["ALL", ...Array.from(set).sort()];
  }, [rows]);

  const debsecanStatuses = useMemo(() => {
    const set = new Set(rows.map((r) => r?.debsecan_status ?? "N/A"));
    return ["ALL", ...Array.from(set).sort()];
  }, [rows]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();

    return rows
      .filter((r) => (severity === "ALL" ? true : (r?.severity ?? "N/A") === severity))
      .filter((r) => (debsecan === "ALL" ? true : (r?.debsecan_status ?? "N/A") === debsecan))
      .filter((r) => (q ? vulnToSearchableText(r).includes(q) : true))
      .slice()
      .sort((a, b) => {
        // Sort by base_score desc; fallback by CVE ID
        const an = safeNumber(a?.base_score);
        const bn = safeNumber(b?.base_score);
        if (an != null && bn != null) return bn - an;
        if (an != null) return -1;
        if (bn != null) return 1;
        return String(a?.cve_id ?? "").localeCompare(String(b?.cve_id ?? ""));
      });
  }, [rows, query, severity, debsecan]);

  const stats = useMemo(() => {
    const bySeverity = new Map();
    const byDebsecan = new Map();

    for (const r of rows) {
      const sev = r?.severity ?? "N/A";
      bySeverity.set(sev, (bySeverity.get(sev) ?? 0) + 1);

      const ds = r?.debsecan_status ?? "N/A";
      byDebsecan.set(ds, (byDebsecan.get(ds) ?? 0) + 1);
    }

    return { total: rows.length, bySeverity, byDebsecan };
  }, [rows]);

  const buttonLabel = isLoading
    ? hasData
      ? "Refreshing…"
      : "Fetching…"
    : hasData
    ? "Refresh data"
    : "Fetch data";

  const prettyOs =
    platform?.debian?.pretty_name ??
    (platform?.debian ? `Debian ${platform.debian.version_id ?? ""}` : null);

  return (
    <div className="page">
      <header className="header">
        <div>
          <h1 className="title">Vulnerability Dashboard</h1>
          <p className="subtitle">
            {status === "idle" && "Click “Fetch data” to load results2.json"}
            {status === "loading" && (hasData ? "Refreshing data…" : "Loading…")}
            {status === "success" && `Showing ${filtered.length} / ${rows.length}`}
            {status === "error" && (hasData ? "Refresh failed (showing previous data)" : "Error loading data")}
          </p>
        </div>

        <div className="controls">
          <button
            onClick={fetchData}
            disabled={isLoading}
            className={`button ${isLoading ? "buttonDisabled" : ""}`}
          >
            {buttonLabel}
          </button>

          <button onClick={clear} className="button buttonSecondary">
            Clear
          </button>

          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            disabled={!hasData}
            className={`select ${!hasData ? "controlDisabled" : ""}`}
            title="Filter by severity"
          >
            {severities.map((s) => (
              <option key={s} value={s}>
                Severity: {s}
              </option>
            ))}
          </select>

          <select
            value={debsecan}
            onChange={(e) => setDebsecan(e.target.value)}
            disabled={!hasData}
            className={`select ${!hasData ? "controlDisabled" : ""}`}
            title="Filter by debsecan status"
          >
            {debsecanStatuses.map((s) => (
              <option key={s} value={s}>
                Debsecan: {s}
              </option>
            ))}
          </select>

          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search a phrase (CVE, package name, version, vector...)"
            disabled={!hasData}
            className={`search ${!hasData ? "controlDisabled" : ""}`}
          />
        </div>
      </header>

      {isError && (
        <div className={`card ${hasData ? "cardErrorSoft" : "cardError"}`}>
          <div className="errorTitle">
            {hasData ? "Refresh failed (showing previous data)" : "Couldn’t load data"}
          </div>
          <div className="errorText">{error}</div>
        </div>
      )}

      {platform && (
        <div className="card cardPlatform">
          <div className="platformTitle">Platform</div>
          <div className="platformGrid">
            <div className="kv">
              <div className="kvLabel">Hostname</div>
              <div className="kvValue">{platform.hostname ?? "N/A"}</div>
            </div>
            <div className="kv">
              <div className="kvLabel">FQDN</div>
              <div className="kvValue">{platform.fqdn ?? "N/A"}</div>
            </div>
            <div className="kv">
              <div className="kvLabel">Primary IP</div>
              <div className="kvValue">{platform.ip ?? "N/A"}</div>
            </div>
            <div className="kv">
              <div className="kvLabel">OS</div>
              <div className="kvValue">{prettyOs ?? "N/A"}</div>
            </div>
          </div>
        </div>
      )}

      {hasData && (
        <div className="card cardStats">
          <div className="chips">
            <span className="chip">Total: {stats.total}</span>

            {Array.from(stats.bySeverity.entries())
              .sort((a, b) => a[0].localeCompare(b[0]))
              .map(([k, v]) => (
                <span key={`sev-${k}`} className="chip">
                  Severity {k}: {v}
                </span>
              ))}

            {Array.from(stats.byDebsecan.entries())
              .sort((a, b) => a[0].localeCompare(b[0]))
              .map(([k, v]) => (
                <span key={`ds-${k}`} className="chip">
                  Debsecan {k}: {v}
                </span>
              ))}
          </div>
        </div>
      )}

      {hasData ? (
        <div className="card">
          <div className="tableWrap tableWrapTall">
            <table className="table">
              <thead>
                <tr>
                  <th className="th">CVE</th>
                  <th className="th">Severity</th>
                  <th className="th">Debsecan</th>
                  <th className="th">Base</th>
                  <th className="th">Exploitability</th>
                  <th className="th">Impact</th>
                  <th className="th">Score ver.</th>
                  <th className="th">Packages</th>
                  <th className="th">Vector</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((r, idx) => {
                  const cve = r.cve_id ?? "";
                  const isCopied = copiedCve === cve;

                  const pkgs = Array.isArray(r.affected_packages) ? r.affected_packages : [];
                  const pkgCount = pkgs.length;

                  const pkgPreview = pkgs
                    .slice(0, 2)
                    .map((p) => `${p?.name ?? "?"} (${p?.installed_version ?? "?"})`)
                    .join(", ");

                  const pkgTitle = pkgs
                    .map((p) => `${p?.name ?? "?"} — ${p?.installed_version ?? "?"}`)
                    .join("\n");

                  return (
                    <tr className="rowHover" key={`${cve || "row"}-${idx}`}>
                      <td className="td">
                        <button
                          type="button"
                          className={`cveButton ${isCopied ? "cveButtonCopied" : ""}`}
                          onClick={() => copyText(cve)}
                          title="Click to copy CVE ID"
                        >
                          <span className="cveText">{cve || "N/A"}</span>
                          <span className="cveHint">{isCopied ? "Copied!" : "Copy"}</span>
                        </button>
                      </td>
                      <td className="td">{r.severity ?? "N/A"}</td>
                      <td className="td">{r.debsecan_status ?? "N/A"}</td>
                      <td className="td">{r.base_score ?? "N/A"}</td>
                      <td className="td">{r.exploitability ?? "N/A"}</td>
                      <td className="td">{r.impact ?? "N/A"}</td>
                      <td className="td">{r.score_version ?? "N/A"}</td>
                      <td className="td" title={pkgTitle || "No packages"}>
                        {pkgCount === 0 ? (
                          "0"
                        ) : (
                          <>
                            {pkgCount}{" "}
                            <span className="mutedInline">
                              ({pkgPreview}
                              {pkgCount > 2 ? `, +${pkgCount - 2} more` : ""})
                            </span>
                          </>
                        )}
                      </td>
                      <td className="td mono" title={r.vector}>
                        {r.vector ?? "N/A"}
                      </td>
                    </tr>
                  );
                })}

                {filtered.length === 0 && (
                  <tr>
                    <td className="td" colSpan={9}>
                      No results for “{query}”.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {isLoading && <div className="refreshHint">Refreshing…</div>}
        </div>
      ) : (
        <div className="card">
          No data loaded yet. Put the file at <b>public/results2.json</b> and click <b>Fetch data</b>.
        </div>
      )}
    </div>
  );
}