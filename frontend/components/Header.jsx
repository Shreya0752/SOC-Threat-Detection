import React from 'react';

export default function Header({ activeTab, onRefresh, lastRefreshed, pollingInterval, setPollingInterval, user, onLogout }) {
  const titles = {
    overview: 'SOC Security Overview',
    'ai-detection': 'AI Threat Detection & Anomaly Analysis Engine',
    events: 'Security Event Logs',
    threats: 'Threat Intelligence Feeds & Matches',
    vulnerabilities: 'Vulnerability Analysis',
    analytics: 'Analytics & MITRE ATT&CK Mapping'
  };

  return (
    <header className="top-header">
      <div className="header-title">
        <span>{titles[activeTab] || 'Dashboard'}</span>
      </div>

      <div className="header-controls">
        <div className="live-indicator">
          <div className="pulse-dot"></div>
          <span>API Connected (Polling: {pollingInterval ? `${pollingInterval / 1000}s` : 'Off'})</span>
        </div>

        <select 
          className="filter-select"
          value={pollingInterval} 
          onChange={(e) => setPollingInterval(Number(e.target.value))}
          style={{ padding: '0.35rem 0.6rem' }}
        >
          <option value={5000}>Auto 5s</option>
          <option value={10000}>Auto 10s</option>
          <option value={30000}>Auto 30s</option>
          <option value={0}>Manual Only</option>
        </select>

        <button className="refresh-btn" onClick={onRefresh} title="Refresh Data">
          🔄 Refresh
        </button>

        <div className="user-profile">
          <div className="user-avatar">{user?.username ? user.username[0].toUpperCase() : 'A'}</div>
          <div>
            <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#0F172A' }}>{user?.username || 'SOC Analyst'}</div>
            <div style={{ fontSize: '0.7rem', color: '#64748B' }}>Tier 2 Security Analyst</div>
          </div>
          <button 
            onClick={onLogout}
            style={{ 
              background: '#FFFFFF', 
              border: '1px solid #CBD5E1', 
              color: '#475569', 
              borderRadius: '6px', 
              padding: '0.3rem 0.6rem',
              fontSize: '0.75rem',
              cursor: 'pointer',
              marginLeft: '0.5rem',
              boxShadow: '0 2px 4px rgba(0,0,0,0.02)'
            }}
          >
            Logout
          </button>
        </div>
      </div>
    </header>
  );
}
