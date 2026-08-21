import React from 'react';

export default function Sidebar({ activeTab, setActiveTab }) {
  const navItems = [
    { id: 'overview', label: 'Overview', icon: '📊' },
    { id: 'ai-detection', label: 'AI Threat Detection', icon: '🤖' },
    { id: 'events', label: 'Security Events', icon: '🛡️' },
    { id: 'threats', label: 'Threat Intelligence', icon: '⚠️' },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: '🔍' },
    { id: 'analytics', label: 'Analytics', icon: '📈' }
  ];

  return (
    <div className="sidebar">
      <div className="sidebar-logo">
        <div className="sidebar-logo-icon">SOC</div>
        <div>
          <div className="sidebar-logo-text">ThreatDetect AI</div>
          <div style={{ fontSize: '0.7rem', color: '#64748B' }}>SOC Security Console</div>
        </div>
      </div>

      <nav className="sidebar-nav">
        {navItems.map((item) => (
          <button
            key={item.id}
            className={`nav-item ${activeTab === item.id ? 'active' : ''}`}
            onClick={() => setActiveTab(item.id)}
          >
            <span>{item.icon}</span>
            <span>{item.label}</span>
          </button>
        ))}
      </nav>

      <div style={{ marginTop: 'auto', paddingTop: '1.5rem', borderTop: '1px solid #E2E8F0' }}>
        <div style={{ fontSize: '0.75rem', color: '#64748B' }}>SOC Threat Intelligence</div>
        <div style={{ fontSize: '0.8rem', color: '#475569', fontWeight: 500, marginTop: '0.2rem' }}>
          Data Aggregation & Intel Layer
        </div>
      </div>
    </div>
  );
}
