import React from 'react';

export default function M2KPICards({ summary, loading, error }) {
  const total = summary?.total_predictions || 0;
  const anomalous = summary?.anomalous || 0;
  const normal = summary?.normal || 0;
  const high = summary?.threat_levels?.High || 0;
  const critical = summary?.threat_levels?.Critical || 0;

  const cards = [
    { title: 'Total Events', value: total, subtitle: 'Scanned Security Logs', color: '#2563EB', icon: '⚡' },
    { title: 'Anomalies Detected', value: anomalous, subtitle: `${summary?.anomaly_percentage || 0}% Anomaly Rate`, color: '#DC2626', icon: '🚨' },
    { title: 'Normal Events', value: normal, subtitle: 'Baseline Activity', color: '#16A34A', icon: '✅' },
    { title: 'High-Risk Events', value: high, subtitle: 'High Severity Threat Level', color: '#EA580C', icon: '⚠️' },
    { title: 'Critical Threats', value: critical, subtitle: 'Critical Severity Threat Level', color: '#9333EA', icon: '🔥' }
  ];

  if (loading) {
    return (
      <div className="kpi-grid">
        {[1, 2, 3, 4, 5].map((idx) => (
          <div key={idx} className="kpi-card" style={{ opacity: 0.6, minHeight: '90px' }}>
            <div style={{ fontSize: '0.85rem', color: '#64748B' }}>Loading metric...</div>
          </div>
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div className="chart-card" style={{ borderLeft: '4px solid #EF4444', marginBottom: '1rem' }}>
        <div style={{ color: '#DC2626', fontWeight: 600 }}>Error loading AI Summary KPIs</div>
        <div style={{ fontSize: '0.85rem', color: '#64748B', marginTop: '0.2rem' }}>{error}</div>
      </div>
    );
  }

  return (
    <div className="kpi-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))' }}>
      {cards.map((c, idx) => (
        <div key={idx} className="kpi-card" style={{ borderLeft: `4px solid ${c.color}` }}>
          <div className="kpi-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>{c.title}</span>
            <span style={{ fontSize: '1.1rem' }}>{c.icon}</span>
          </div>
          <div className="kpi-value" style={{ color: c.color }}>{c.value.toLocaleString()}</div>
          <div className="kpi-subtitle">{c.subtitle}</div>
        </div>
      ))}
    </div>
  );
}
