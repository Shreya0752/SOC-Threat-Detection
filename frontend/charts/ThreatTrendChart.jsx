import React from 'react';

export default function ThreatTrendChart({ anomalies = [] }) {
  // Aggregate anomalies count by hour
  const timeCounts = {};
  if (anomalies && anomalies.length > 0) {
    anomalies.forEach(item => {
      const timeStr = item.event_timestamp || item.prediction_timestamp || "";
      const timeKey = timeStr.length >= 13 ? timeStr.substring(11, 13) + ":00" : "00:00";
      timeCounts[timeKey] = (timeCounts[timeKey] || 0) + 1;
    });
  }

  const sortedHours = Object.keys(timeCounts).sort();
  const dataPoints = sortedHours.length > 0 ? sortedHours.map(h => ({ time: h, count: timeCounts[h] })) : [
    { time: '00:00', count: 12 },
    { time: '04:00', count: 25 },
    { time: '08:00', count: 48 },
    { time: '12:00', count: 65 },
    { time: '16:00', count: 42 },
    { time: '20:00', count: 28 }
  ];

  const maxVal = Math.max(...dataPoints.map(d => d.count), 1);
  const width = 500;
  const height = 140;
  const padding = 25;

  // Compute Native SVG Polyline points
  const points = dataPoints.map((d, idx) => {
    const x = padding + (idx / Math.max(dataPoints.length - 1, 1)) * (width - 2 * padding);
    const y = height - padding - (d.count / maxVal) * (height - 2 * padding);
    return `${x},${y}`;
  }).join(' ');

  return (
    <div className="chart-card">
      <div className="chart-header">
        <h3 className="chart-title">📈 Threat Trend (Anomalies Over Time)</h3>
        <span style={{ fontSize: '0.8rem', color: '#64748B' }}>Native Line Chart</span>
      </div>

      <div style={{ position: 'relative', width: '100%', overflowX: 'auto' }}>
        <svg width="100%" height={height} viewBox={`0 0 ${width} ${height}`}>
          <defs>
            <linearGradient id="anomLineGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#DC2626" stopOpacity="0.35" />
              <stop offset="100%" stopColor="#EF4444" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          <line x1={padding} y1={height - padding} x2={width - padding} y2={height - padding} stroke="#E2E8F0" strokeWidth="1" />
          <line x1={padding} y1={padding} x2={width - padding} y2={padding} stroke="#E2E8F0" strokeWidth="1" strokeDasharray="4 4" />

          {/* Area fill */}
          {dataPoints.length > 1 && (
            <polygon
              points={`${padding},${height - padding} ${points} ${width - padding},${height - padding}`}
              fill="url(#anomLineGrad)"
            />
          )}

          {/* Polyline */}
          <polyline
            fill="none"
            stroke="#DC2626"
            strokeWidth="3"
            points={points}
            strokeLinecap="round"
          />

          {/* Data Points */}
          {dataPoints.map((d, idx) => {
            const x = padding + (idx / Math.max(dataPoints.length - 1, 1)) * (width - 2 * padding);
            const y = height - padding - (d.count / maxVal) * (height - 2 * padding);
            return (
              <g key={idx}>
                <circle cx={x} cy={y} r="4" fill="#DC2626" stroke="#FFFFFF" strokeWidth="1.5" />
                <text x={x} y={height - 5} fill="#64748B" fontSize="10" textAnchor="middle">{d.time}</text>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}
