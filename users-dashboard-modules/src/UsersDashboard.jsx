import React, { useMemo, useRef, useState } from "react";

const API_URL = "https://jsonplaceholder.typicode.com/users";

function userToSearchableText(u) {
  const address = u?.address
    ? `${u.address.street ?? ""} ${u.address.suite ?? ""} ${u.address.city ?? ""} ${u.address.zipcode ?? ""}`
    : "";

  const company = u?.company ? `${u.company.name ?? ""} ${u.company.catchPhrase ?? ""}` : "";

  return [
    u.id,
    u.name,
    u.username,
    u.email,
    u.phone,
    u.website,
    company,
    address,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

export default function UsersDashboard() {
  const [users, setUsers] = useState([]);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("idle"); // idle | loading | success | error
  const [error, setError] = useState("");

  const abortRef = useRef(null);

  const hasData = users.length > 0;

  async function fetchUsers() {
    // Cancel any in-flight request
    if (abortRef.current) abortRef.current.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setStatus("loading");
    setError("");

    try {
      const res = await fetch(API_URL, { signal: controller.signal });
      if (!res.ok) throw new Error(`Request failed: ${res.status} ${res.statusText}`);
      const data = await res.json();

      setUsers(Array.isArray(data) ? data : []);
      setStatus("success");
    } catch (e) {
      // Ignore abort errors
      if (e?.name === "AbortError") return;

      setStatus("error");
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      abortRef.current = null;
    }
  }

  function clearData() {
    if (abortRef.current) abortRef.current.abort();
    setUsers([]);
    setQuery("");
    setStatus("idle");
    setError("");
  }

  const filteredUsers = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return users;
    return users.filter((u) => userToSearchableText(u).includes(q));
  }, [users, query]);

  const isLoading = status === "loading";
  const isError = status === "error";

  const buttonLabel = isLoading
    ? hasData
      ? "Refreshing…"
      : "Fetching…"
    : hasData
    ? "Refresh users"
    : "Fetch users";

  return (
    <div style={styles.page}>
      <header style={styles.header}>
        <div>
          <h1 style={styles.title}>Users Dashboard</h1>
          <p style={styles.subtitle}>
            {status === "idle" && "Click “Fetch users” to load data."}
            {status === "loading" && (hasData ? "Refreshing data…" : "Loading…")}
            {status === "success" && `Showing ${filteredUsers.length} / ${users.length}`}
            {status === "error" && (hasData ? "Refresh failed (showing cached data)" : "Error loading data")}
          </p>
        </div>

        <div style={styles.controls}>
          <button
            onClick={fetchUsers}
            disabled={isLoading}
            style={{
              ...styles.button,
              ...(isLoading ? styles.buttonDisabled : null),
            }}
          >
            {buttonLabel}
          </button>

          <button
            onClick={clearData}
            style={{ ...styles.button, ...styles.secondaryButton }}
          >
            Clear
          </button>

          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search a phrase…"
            disabled={!hasData}
            style={{
              ...styles.search,
              ...(hasData ? null : styles.searchDisabled),
            }}
          />
        </div>
      </header>

      {isError && (
        <div style={{ ...styles.card, ...styles.error }}>
          <div style={{ fontWeight: 700, marginBottom: 6 }}>
            {hasData ? "Refresh failed (showing previous data)" : "Couldn’t load data"}
          </div>
          <div style={{ opacity: 0.9 }}>{error}</div>
        </div>
      )}

      {hasData ? (
        <div style={styles.card}>
          <div style={styles.tableWrap}>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>Name</th>
                  <th style={styles.th}>Username</th>
                  <th style={styles.th}>Email</th>
                  <th style={styles.th}>Company</th>
                  <th style={styles.th}>City</th>
                  <th style={styles.th}>Website</th>
                </tr>
              </thead>
              <tbody>
                {filteredUsers.map((u) => (
                  <tr key={u.id}>
                    <td style={styles.td}>
                      <div style={{ fontWeight: 700 }}>{u.name}</div>
                      <div style={styles.muted}>{u.phone}</div>
                    </td>
                    <td style={styles.td}>{u.username}</td>
                    <td style={styles.td}>
                      <a style={styles.link} href={`mailto:${u.email}`}>
                        {u.email}
                      </a>
                    </td>
                    <td style={styles.td}>
                      <div>{u.company?.name}</div>
                      <div style={styles.muted}>{u.company?.catchPhrase}</div>
                    </td>
                    <td style={styles.td}>{u.address?.city}</td>
                    <td style={styles.td}>
                      <a
                        style={styles.link}
                        href={`https://${u.website}`}
                        target="_blank"
                        rel="noreferrer"
                      >
                        {u.website}
                      </a>
                    </td>
                  </tr>
                ))}

                {filteredUsers.length === 0 && (
                  <tr>
                    <td style={styles.td} colSpan={6}>
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
          No data loaded yet. Click <b>Fetch users</b>.
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
  controls: {
    display: "flex",
    gap: 10,
    alignItems: "center",
    flexWrap: "wrap",
  },
  button: {
    padding: "10px 12px",
    borderRadius: 12,
    border: "1px solid rgba(255,255,255,0.12)",
    background: "rgba(255,255,255,0.12)",
    color: "#e9eef8",
    cursor: "pointer",
  },
  secondaryButton: {
    background: "rgba(255,255,255,0.06)",
  },
  buttonDisabled: {
    opacity: 0.6,
    cursor: "not-allowed",
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
  searchDisabled: {
    opacity: 0.55,
    cursor: "not-allowed",
  },
  card: {
    borderRadius: 16,
    border: "1px solid rgba(255,255,255,0.10)",
    background: "rgba(255,255,255,0.06)",
    padding: 16,
    position: "relative",
  },
  refreshHint: {
    marginTop: 12,
    opacity: 0.75,
    fontSize: 12,
  },
  error: { borderColor: "rgba(255, 90, 90, 0.35)" },
  tableWrap: { overflowX: "auto" },
  table: { width: "100%", borderCollapse: "collapse", minWidth: 820 },
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
  muted: { opacity: 0.75, fontSize: 12, marginTop: 4 },
  link: { color: "#a8d1ff", textDecoration: "none" },
};