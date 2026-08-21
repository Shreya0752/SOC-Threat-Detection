import React, { useState } from 'react';

export default function EventTable({ events, total, page, setPage, limit, loading }) {
  const [selectedEvent, setSelectedEvent] = useState(null);

  const getSeverityBadgeClass = (sev) => {
    switch (sev?.toLowerCase()) {
      case 'critical': return 'badge-critical';
      case 'high': return 'badge-high';
      case 'medium': return 'badge-medium';
      case 'low': return 'badge-low';
      default: return 'badge-low';
    }
  };

  const totalPages = Math.ceil(total / limit) || 1;

  return (
    <div className="table-card">
      <div className="chart-header">
        <h3 className="chart-title">🛡️ Security Event Logs</h3>
        <span style={{ fontSize: '0.85rem', color: '#64748B' }}>
          Showing {events.length} of {total} events
        </span>
      </div>

      <div className="table-wrapper">
        <table className="custom-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Event Type</th>
              <th>Severity</th>
              <th>Source IP</th>
              <th>Status</th>
              <th>User</th>
              <th>MITRE ATT&CK</th>
              <th>Threat Match</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="9" style={{ textAlign: 'center', padding: '2rem', color: '#64748B' }}>
                  Loading security events from backend...
                </td>
              </tr>
            ) : events.length === 0 ? (
              <tr>
                <td colSpan="9" style={{ textAlign: 'center', padding: '2rem', color: '#64748B' }}>
                  No security events found matching current filter criteria.
                </td>
              </tr>
            ) : (
              events.map((evt) => (
                <tr key={evt.id || evt.event_id}>
                  <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.8rem', color: '#475569' }}>
                    {evt.timestamp}
                  </td>
                  <td style={{ fontWeight: 600, color: '#0F172A' }}>{evt.event_type}</td>
                  <td>
                    <span className={`badge ${getSeverityBadgeClass(evt.severity)}`}>
                      {evt.severity}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'JetBrains Mono, monospace', color: '#2563EB' }}>
                    {evt.source_ip}
                  </td>
                  <td>
                    <span style={{
                      color: evt.status?.toLowerCase() === 'blocked' ? '#DC2626' :
                             evt.status?.toLowerCase() === 'detected' ? '#EA580C' : '#059669',
                      fontWeight: 500
                    }}>
                      {evt.status}
                    </span>
                  </td>
                  <td style={{ color: '#0F172A' }}>{evt.username || 'N/A'}</td>
                  <td>
                    {evt.mitre_id && evt.mitre_id !== 'Unknown' ? (
                      <span style={{ color: '#0D9488', fontSize: '0.8rem', fontWeight: 600 }}>
                        {evt.mitre_id} ({evt.technique_name})
                      </span>
                    ) : (
                      <span style={{ color: '#94A3B8', fontSize: '0.8rem' }}>Unmapped</span>
                    )}
                  </td>
                  <td>
                    {evt.threat_match ? (
                      <span className="badge badge-critical">Matched</span>
                    ) : (
                      <span style={{ color: '#94A3B8', fontSize: '0.8rem' }}>No Match</span>
                    )}
                  </td>
                  <td>
                    <button
                      onClick={() => setSelectedEvent(evt)}
                      style={{
                        background: '#FFF7ED',
                        border: '1px solid #FFEDD5',
                        color: '#EA580C',
                        borderRadius: '6px',
                        padding: '0.25rem 0.5rem',
                        fontSize: '0.75rem',
                        fontWeight: 600,
                        cursor: 'pointer'
                      }}
                    >
                      Details
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Controls */}
      <div className="pagination">
        <span>Page {page} of {totalPages}</span>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button 
            className="page-btn" 
            disabled={page <= 1 || loading}
            onClick={() => setPage(page - 1)}
          >
            Previous
          </button>
          <button 
            className="page-btn" 
            disabled={page >= totalPages || loading}
            onClick={() => setPage(page + 1)}
          >
            Next
          </button>
        </div>
      </div>

      {/* Event Details Modal */}
      {selectedEvent && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(15, 23, 42, 0.5)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999,
          padding: '1rem'
        }}>
          <div style={{
            background: '#FFFFFF',
            border: '1px solid #CBD5E1',
            borderRadius: '16px',
            width: '90vw',
            maxWidth: '750px',
            maxHeight: '90vh',
            overflowY: 'auto',
            padding: '1.5rem',
            color: '#0F172A',
            boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)'
          }}>
            <div style={{ position: 'sticky', top: 0, background: '#FFFFFF', zIndex: 10, display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '1px solid #E2E8F0', paddingBottom: '0.75rem' }}>
              <h3 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#0F172A', margin: 0 }}>Event Details: {selectedEvent.event_id}</h3>
              <button 
                onClick={() => setSelectedEvent(null)}
                style={{ background: '#F1F5F9', border: 'none', borderRadius: '50%', width: '32px', height: '32px', cursor: 'pointer', fontWeight: 700, color: '#475569', fontSize: '1rem', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
              >
                ✕
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.85rem', fontSize: '0.85rem' }}>
              <div><strong>Timestamp:</strong> {selectedEvent.timestamp}</div>
              <div><strong>Event Type:</strong> {selectedEvent.event_type}</div>
              <div><strong>Severity:</strong> {selectedEvent.severity}</div>
              <div><strong>Status:</strong> {selectedEvent.status}</div>
              <div><strong>Source IP:</strong> {selectedEvent.source_ip}</div>
              <div><strong>Destination IP:</strong> {selectedEvent.destination_ip}</div>
              <div><strong>Username:</strong> {selectedEvent.username}</div>
              <div><strong>Device:</strong> {selectedEvent.device_name} ({selectedEvent.os})</div>
              <div><strong>Failed Logins:</strong> {selectedEvent.failed_login_attempts}</div>
              <div><strong>Malware Detected:</strong> {selectedEvent.malware_detected}</div>
              <div><strong>MITRE ID:</strong> {selectedEvent.mitre_id} ({selectedEvent.technique_name})</div>
              <div><strong>MITRE Tactic:</strong> {selectedEvent.tactic}</div>
              <div><strong>Threat Name:</strong> {selectedEvent.threat_name}</div>
              <div><strong>Threat Indicator:</strong> {selectedEvent.threat_indicator ? 'Yes' : 'No'}</div>
              <div><strong>CVSS Score:</strong> {selectedEvent.cvss_score}</div>
              <div><strong>Department:</strong> {selectedEvent.department}</div>
            </div>

            {selectedEvent.engineered_features && (
              <div style={{ marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid #E2E8F0' }}>
                <h4 style={{ fontSize: '0.9rem', marginBottom: '0.5rem', color: '#EA580C' }}>Engineered Features</h4>
                <pre style={{ background: '#F8FAFC', border: '1px solid #E2E8F0', padding: '0.75rem', borderRadius: '8px', fontSize: '0.75rem', color: '#334155' }}>
                  {JSON.stringify(selectedEvent.engineered_features, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
