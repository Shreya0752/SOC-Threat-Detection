import React, { useState } from 'react';

export default function ThreatTable({
  predictions = [],
  total = 0,
  page = 1,
  setPage,
  limit = 25,
  loading = false,
  filters,
  setFilters,
  onSelectEvent
}) {
  const [searchInput, setSearchInput] = useState(filters?.search || '');

  const totalPages = Math.max(1, Math.ceil(total / limit));

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setFilters({ ...filters, search: searchInput });
    setPage(1);
  };

  const getPredictionBadge = (prediction) => {
    if (prediction === 'Anomalous') {
      return (
        <span style={{
          background: '#FEF2F2',
          color: '#DC2626',
          border: '1px solid #FCA5A5',
          padding: '0.2rem 0.5rem',
          borderRadius: '4px',
          fontWeight: 700,
          fontSize: '0.75rem',
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.3rem'
        }}>
          🚨 Anomalous
        </span>
      );
    }
    return (
      <span style={{
        background: '#F0FDF4',
        color: '#16A34A',
        border: '1px solid #86EFAC',
        padding: '0.2rem 0.5rem',
        borderRadius: '4px',
        fontWeight: 600,
        fontSize: '0.75rem',
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.3rem'
      }}>
        ✅ Normal
      </span>
    );
  };

  const getSeverityBadge = (sev) => {
    const s = strNormalize(sev);
    let bg = '#F1F5F9';
    let color = '#475569';
    if (s === 'critical') { bg = '#FEF2F2'; color = '#DC2626'; }
    else if (s === 'high') { bg = '#FFF7ED'; color = '#EA580C'; }
    else if (s === 'medium') { bg = '#FFFBEB'; color = '#D97706'; }
    else if (s === 'low') { bg = '#EFF6FF'; color = '#2563EB'; }

    return (
      <span style={{
        background: bg,
        color: color,
        padding: '0.2rem 0.5rem',
        borderRadius: '4px',
        fontWeight: 600,
        fontSize: '0.75rem',
        textTransform: 'capitalize'
      }}>
        {sev}
      </span>
    );
  };

  function strNormalize(str) {
    return str ? String(str).toLowerCase().trim() : '';
  }

  return (
    <div className="chart-card" style={{ marginTop: '1rem' }}>
      <div className="chart-header" style={{ marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div>
          <h3 className="chart-title">🛡️ AI Threat Detection & Prediction Table</h3>
          <div style={{ fontSize: '0.8rem', color: '#64748B' }}>
            Displaying {predictions.length} of {total.toLocaleString()} threat prediction records (Page {page} of {totalPages})
          </div>
        </div>

        {/* Filter Controls Bar */}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'center' }}>
          {/* Prediction Filter */}
          <select
            className="filter-select"
            value={filters?.prediction || 'All'}
            onChange={(e) => {
              setFilters({ ...filters, prediction: e.target.value });
              setPage(1);
            }}
          >
            <option value="All">All Predictions</option>
            <option value="Anomalous">Anomalous Only</option>
            <option value="Normal">Normal Only</option>
          </select>

          {/* Threat Type Filter */}
          <select
            className="filter-select"
            value={filters?.threat_type || 'All'}
            onChange={(e) => {
              setFilters({ ...filters, threat_type: e.target.value });
              setPage(1);
            }}
          >
            <option value="All">All Threat Types</option>
            <option value="Brute Force">Brute Force</option>
            <option value="Malware">Malware</option>
            <option value="SQL Injection">SQL Injection</option>
            <option value="Phishing">Phishing</option>
            <option value="Privilege Escalation">Privilege Escalation</option>
            <option value="Anomalous Activity">Anomalous Activity</option>
            <option value="Normal Activity">Normal Activity</option>
          </select>

          {/* Severity Filter */}
          <select
            className="filter-select"
            value={filters?.severity || 'All'}
            onChange={(e) => {
              setFilters({ ...filters, severity: e.target.value });
              setPage(1);
            }}
          >
            <option value="All">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>

          {/* Search Input */}
          <form onSubmit={handleSearchSubmit} style={{ display: 'flex', gap: '0.2rem' }}>
            <input
              type="text"
              className="search-input"
              placeholder="Search Event ID..."
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              style={{ width: '140px', padding: '0.35rem 0.6rem' }}
            />
            <button type="submit" className="refresh-btn" style={{ padding: '0.35rem 0.6rem' }}>
              🔍
            </button>
          </form>
        </div>
      </div>

      {/* Table */}
      <div style={{ overflowX: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Event ID</th>
              <th>Threat Type</th>
              <th>Prediction</th>
              <th>Threat Confidence</th>
              <th>Threat Level</th>
              <th>Timestamp</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="7" style={{ textAlign: 'center', padding: '2rem', color: '#64748B' }}>
                  🔄 Loading prediction records from database...
                </td>
              </tr>
            ) : predictions.length === 0 ? (
              <tr>
                <td colSpan="7" style={{ textAlign: 'center', padding: '2rem', color: '#64748B' }}>
                  No threat prediction records found matching the criteria.
                </td>
              </tr>
            ) : (
              predictions.map((item) => (
                <tr key={item.id || item.event_id}>
                  <td>
                    <button
                      onClick={() => onSelectEvent(item.event_id)}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: '#2563EB',
                        fontWeight: 700,
                        cursor: 'pointer',
                        textDecoration: 'underline',
                        padding: 0
                      }}
                    >
                      {item.event_id}
                    </button>
                  </td>
                  <td style={{ fontWeight: 600, color: '#0F172A' }}>{item.threat_type}</td>
                  <td>{getPredictionBadge(item.prediction)}</td>
                  <td>
                    <span style={{ fontWeight: 700, color: '#1E293B' }}>
                      {item.confidence_score !== undefined ? `${item.confidence_score}%` : 'N/A'}
                    </span>
                  </td>
                  <td>{getSeverityBadge(item.severity)}</td>
                  <td style={{ fontSize: '0.75rem', color: '#64748B' }}>
                    {item.prediction_timestamp ? item.prediction_timestamp.substring(0, 19).replace('T', ' ') : 'N/A'}
                  </td>
                  <td>
                    <button
                      className="refresh-btn"
                      onClick={() => onSelectEvent(item.event_id)}
                      style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem' }}
                    >
                      🔍 Investigate
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '1rem', paddingTop: '0.75rem', borderTop: '1px solid #E2E8F0', fontSize: '0.85rem' }}>
        <div style={{ color: '#64748B' }}>
          Page {page} of {totalPages} ({total.toLocaleString()} items)
        </div>
        <div style={{ display: 'flex', gap: '0.4rem' }}>
          <button
            className="refresh-btn"
            disabled={page <= 1 || loading}
            onClick={() => setPage(p => Math.max(1, p - 1))}
            style={{ opacity: page <= 1 ? 0.5 : 1 }}
          >
            ◀ Prev
          </button>
          <button
            className="refresh-btn"
            disabled={page >= totalPages || loading}
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            style={{ opacity: page >= totalPages ? 0.5 : 1 }}
          >
            Next ▶
          </button>
        </div>
      </div>
    </div>
  );
}
