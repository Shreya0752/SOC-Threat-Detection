import React from 'react';

export default function EventTrendGraph({ events }) {
  // Aggregate events by hour / date
  const timeCounts = {};
  events.forEach(evt => {
    // extract date/hour e.g. "2025-08-01 14:00" or just time string
    const timeKey = evt.timestamp ? evt.timestamp.substring(11, 13) + ':00' : '00:00';
    timeCounts[timeKey] = (timeCounts[timeKey] || 0) + 1;
  });

  const sortedHours = Object.keys(timeCounts).sort();
  const dataPoints = sortedHours.length > 0 ? sortedHours.map(h => ({ time: h, count: timeCounts[h] })) : [
    { time: '00:00', count: 15 },
    { time: '04:00', count: 28 },
    { time: '08:00', count: 45 },
    { time: '12:00', count: 62 },
    { time: '16:00', count: 39 },
    { time: '20:00', count: 21 }
  ];

  const maxVal = Math.max(...dataPoints.map(d => d.count), 1);
  const width = 500;
  const height = 140;
  const padding = 20;

  // Compute SVG Points
  const points = dataPoints.map((d, idx) => {
    const x = padding + (idx / Math.max(dataPoints.length - 1, 1)) * (width - 2 * padding);
    const y = height - padding - (d.count / maxVal) * (height - 2 * padding);
    return `${x},${y}`;
  }).join(' ');

  return (
    <div className="chart-card">
      <div className="chart-header">
        <h3 className="chart-title">📈 Event Trend Over Time</h3>
        <span style={{ fontSize: '0.8rem', color: '#64748B' }}>Line Graph (Events / Hour)</span>
      </div>

      <div style={{ position: 'relative', width: '100%', overflowX: 'auto' }}>
        <svg width="100%" height={height} viewBox={`0 0 ${width} ${height}`}>
          <defs>
            <linearGradient id="lineGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#3B82F6" stopOpacity="0.35" />
              <stop offset="100%" stopColor="#38BDF8" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          <line x1={padding} y1={height - padding} x2={width - padding} y2={height - padding} stroke="#E2E8F0" strokeWidth="1" />
          <line x1={padding} y1={padding} x2={width - padding} y2={padding} stroke="#E2E8F0" strokeWidth="1" strokeDasharray="4 4" />

          {/* Area fill */}
          {dataPoints.length > 1 && (
            <polygon
              points={`${padding},${height - padding} ${points} ${width - padding},${height - padding}`}
              fill="url(#lineGrad)"
            />
          )}

          {/* Polyline */}
          <polyline
            fill="none"
            stroke="#3B82F6"
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
                <circle cx={x} cy={y} r="4" fill="#3B82F6" stroke="#FFFFFF" strokeWidth="1.5" />
                <text x={x} y={height - 5} fill="#64748B" fontSize="10" textAnchor="middle">{d.time}</text>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}
