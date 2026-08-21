import React from 'react';

export default function ConfidenceCard({ confidenceScore, threatLevel, anomalyScore }) {
  const score = confidenceScore ?? 0;
  const level = threatLevel || 'Low';

  let color = '#16A34A';
  if (score >= 85) color = '#DC2626';
  else if (score >= 70) color = '#EA580C';
  else if (score >= 50) color = '#D97706';

  return (
    <div className="kpi-card" style={{ background: '#FFFFFF', border: '1px solid #E2E8F0', borderRadius: '12px', padding: '1.25rem' }}>
      <div className="kpi-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
        <span className="kpi-title" style={{ fontSize: '0.8rem', color: '#64748B', fontWeight: 600, textTransform: 'uppercase' }}>AI Threat Confidence</span>
        <span style={{ fontSize: '0.75rem', fontWeight: 700, padding: '0.2rem 0.5rem', borderRadius: '4px', background: '#F1F5F9', color }}>{level}</span>
      </div>
      <div className="kpi-value" style={{ fontSize: '2rem', fontWeight: 700, color }}>{score}%</div>
      <div className="kpi-subtext" style={{ fontSize: '0.8rem', color: '#64748B', marginTop: '0.25rem' }}>
        Anomaly Score: {anomalyScore ?? 0}
      </div>
    </div>
  );
}
