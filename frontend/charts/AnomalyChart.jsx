import React from 'react';

export default function AnomalyChart({ summary }) {
  const normal = summary?.normal || 0;
  const anomalous = summary?.anomalous || 0;
  const total = summary?.total_predictions || normal + anomalous || 1;

  const items = [
    { label: 'Normal', count: normal, color: '#16A34A', pct: ((normal / total) * 100).toFixed(1) },
    { label: 'Anomalous', count: anomalous, color: '#DC2626', pct: ((anomalous / total) * 100).toFixed(1) }
  ];

  // SVG Donut Calculations
  let cumulativeAngle = 0;
  const radius = 60;
  const strokeWidth = 24;
  const circumference = 2 * Math.PI * radius;

  return (
    <div className="chart-card">
      <div className="chart-header">
        <h3 className="chart-title">🍩 Anomaly Distribution</h3>
        <span style={{ fontSize: '0.8rem', color: '#64748B' }}>Isolation Forest Output</span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-around', flexWrap: 'wrap', gap: '1rem', padding: '0.5rem 0' }}>
        {/* Native SVG Donut Chart */}
        <div style={{ position: 'relative', width: '160px', height: '160px' }}>
          <svg width="160" height="160" viewBox="0 0 160 160">
            <g transform="rotate(-90 80 80)">
              {items.map((item, idx) => {
                const strokeDasharray = `${(item.count / total) * circumference} ${circumference}`;
                const strokeDashoffset = -cumulativeAngle;
                cumulativeAngle += (item.count / total) * circumference;
                return (
                  <circle
                    key={idx}
                    cx="80"
                    cy="80"
                    r={radius}
                    fill="transparent"
                    stroke={item.color}
                    strokeWidth={strokeWidth}
                    strokeDasharray={strokeDasharray}
                    strokeDashoffset={strokeDashoffset}
                    style={{ transition: 'all 0.5s ease' }}
                  />
                );
              })}
            </g>
          </svg>
          <div style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '1.2rem', fontWeight: 700, color: '#0F172A' }}>{total}</div>
            <div style={{ fontSize: '0.65rem', color: '#64748B', textTransform: 'uppercase' }}>Total Events</div>
          </div>
        </div>

        {/* Legend */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', flex: 1, minWidth: '140px' }}>
          {items.map((item, idx) => (
            <div key={idx} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.9rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ width: '12px', height: '12px', borderRadius: '50%', backgroundColor: item.color }} />
                <span style={{ color: '#0F172A', fontWeight: 600 }}>{item.label}</span>
              </div>
              <div>
                <span style={{ fontWeight: 700, color: '#0F172A', marginRight: '0.4rem' }}>{item.count.toLocaleString()}</span>
                <span style={{ fontSize: '0.75rem', color: '#64748B' }}>({item.pct}%)</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
