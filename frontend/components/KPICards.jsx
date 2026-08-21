import React from 'react';

export default function KPICards({ stats }) {
  const cards = [
    {
      title: 'Total Events',
      value: stats?.total_events ?? '...',
      subtext: `${stats?.cleaning_stats?.rows_before_cleaning || stats?.total_events || 0} Raw Logs Ingested`,
      icon: '🛡️',
      color: '#2563EB',
      bg: '#DBEAFE'
    },
    {
      title: 'Critical Threats',
      value: stats?.critical_events ?? '...',
      subtext: 'Critical Severity Events',
      icon: '🚨',
      color: '#DC2626',
      bg: '#FEE2E2'
    },
    {
      title: 'High Severity Alerts',
      value: stats?.high_events ?? '...',
      subtext: 'High Risk Events',
      icon: '⚠️',
      color: '#EA580C',
      bg: '#FFEDD5'
    },
    {
      title: 'Vulnerabilities',
      value: stats?.vulnerabilities ?? '...',
      subtext: 'Vulnerability-Tracked Events',
      icon: '🔍',
      color: '#D97706',
      bg: '#FEF3C7'
    },
    {
      title: 'Active Incidents',
      value: stats?.active_incidents ?? '...',
      subtext: 'Open Security Tickets',
      icon: '⚡',
      color: '#0D9488',
      bg: '#CCFBF1'
    }
  ];

  return (
    <div className="kpi-grid">
      {cards.map((card, idx) => (
        <div key={idx} className="kpi-card">
          <div className="kpi-header">
            <span className="kpi-title">{card.title}</span>
            <div className="kpi-icon" style={{ backgroundColor: card.bg, color: card.color }}>
              <span style={{ fontSize: '1.2rem' }}>{card.icon}</span>
            </div>
          </div>
          <div className="kpi-value">{card.value}</div>
          <div className="kpi-subtext">{card.subtext}</div>
        </div>
      ))}
    </div>
  );
}
