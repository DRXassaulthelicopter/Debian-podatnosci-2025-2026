import React, { useEffect, useState } from "react";
import "./App.css";

function App() {
  const [packages, setPackages] = useState([]);
  const [filtered, setFiltered] = useState([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [status, setStatus] = useState("Loading packages...");
  const [error, setError] = useState(null);

  useEffect(() => {
    async function fetchPackages() {
      try {
        setStatus("Loading packages...");
        const res = await fetch("/packages.json");
        if (!res.ok) {
          throw new Error(`HTTP error ${res.status}`);
        }
        const json = await res.json();
        const data = Array.isArray(json) ? json : json.packages || [];
        setPackages(data);
        setFiltered(data);
        setStatus(`Loaded ${data.length} packages.`);
      } catch (err) {
        console.error(err);
        setError(err.message);
        setStatus("Failed to load packages.");
      }
    }

    fetchPackages();
  }, []);

  useEffect(() => {
    const term = searchTerm.trim().toLowerCase();
    if (!term) {
      setFiltered(packages);
      return;
    }

    const filteredData = packages.filter((pkg) => {
      const id = (pkg.id || "").toLowerCase();
      const name = (pkg.name || "").toLowerCase();
      return id.includes(term) || name.includes(term);
    });

    setFiltered(filteredData);
  }, [searchTerm, packages]);

  return (
    <div className="App">
      <div className="app-container">
        <header className="app-header">
          <h1>Debian Packages Dashboard</h1>
          <p>
            Data source: <code>public/packages.json</code>
          </p>
        </header>

        <main>
          <section className="controls">
            <label className="search-label">
              Search:
              <input
                type="text"
                placeholder="Filter by package id or name..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </label>
            <span className="status">
              {status}
              {error && <span className="status-error"> ({error})</span>}
            </span>
          </section>

          <section className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th style={{ width: "30%" }}>Package ID</th>
                  <th style={{ width: "70%" }}>Name</th>
                </tr>
              </thead>
              <tbody>
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan="2" className="empty-message">
                      No packages to display.
                    </td>
                  </tr>
                ) : (
                  filtered.map((pkg) => (
                    <tr key={pkg.id}>
                      <td>
                        <span className="pill">
                          {pkg.id || "(no id)"}
                        </span>
                      </td>
                      <td>{pkg.name || "(no name)"}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </section>
        </main>
      </div>
    </div>
  );
}

export default App;
