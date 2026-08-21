import React from 'react';

export default function ThreatDistributionChart({ stats }) {
  const critical = stats?.critical_events || 0;
  const high = stats?.high_events || 0;
  const medium = stats?.medium_events || 0;
  const low = stats?.low_events || 0;

  const total = critical + high + medium + low || 1;

  const items = [
    { label: 'Critical', count: critical, color: '#DC2626', pct: ((critical / total) * 100).toFixed(1) },
    { label: 'High', count: high, color: '#EA580C', pct: ((high / total) * 100).toFixed(1) },
    { label: 'Medium', count: medium, color: '#D97706', pct: ((medium / total) * 100).toFixed(1) },
    { label: 'Low', count: low, color: '#2563EB', pct: ((low / total) * 100).toFixed(1) }
  ];

  // SVG Donut Calculations
  let cumulativeAngle = 0;
  const radius = 60;
  const strokeWidth = 24;
  const circumference = 2 * Math.PI * radius;

  return (
    <div className="chart-card">
      <div className="chart-header">
        <h3 className="chart-title">🍕 Severity Distribution</h3>
        <span style={{ fontSize: '0.8rem', color: '#64748B' }}>Pie / Donut Chart</span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-around', flexWrap: 'wrap', gap: '1rem', padding: '0.5rem 0' }}>
        {/* SVG Donut Chart */}
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
            <div style={{ fontSize: '0.65rem', color: '#64748B', textTransform: 'uppercase' }}>Total</div>
          </div>
        </div>

        {/* Legend List */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', flex: 1, minWidth: '140px' }}>
          {items.map((item, idx) => (
            <div key={idx} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.85rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: item.color }} />
                <span style={{ color: '#0F172A', fontWeight: 500 }}>{item.label}</span>
              </div>
              <div>
                <span style={{ fontWeight: 700, color: '#0F172A', marginRight: '0.4rem' }}>{item.count}</span>
                <span style={{ fontSize: '0.75rem', color: '#64748B' }}>({item.pct}%)</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
