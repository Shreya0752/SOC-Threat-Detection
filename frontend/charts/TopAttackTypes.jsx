import React, { useState } from 'react';

export default function TopAttackTypes({ threats = [] }) {
  const [hoveredIdx, setHoveredIdx] = useState(null);

  // Extract top 6 security event types from dynamic API data
  const data = threats && threats.length > 0 ? threats.slice(0, 6) : [
    { event_type: 'File Access', count: 198 },
    { event_type: 'Sql Injection Attempt', count: 195 },
    { event_type: 'Privilege Escalation', count: 191 },
    { event_type: 'Brute Force', count: 189 },
    { event_type: 'Failed Login', count: 179 },
    { event_type: 'Login Success', count: 179 }
  ];

  // Calculate maximum value for X-axis scale
  const maxCount = Math.max(...data.map(d => d.count), 1);
  const step = 50;
  const maxScale = Math.ceil((maxCount * 1.1) / step) * step || 250;

  // X-axis numerical scale ticks (0, 50, 100, 150, 200, 250)
  const ticks = [];
  for (let val = 0; val <= maxScale; val += step) {
    ticks.push(val);
  }

  // SVG Chart Layout Dimensions
  const svgWidth = 700;
  const svgHeight = 280;
  const leftMargin = 175; // Y-axis event category space
  const rightMargin = 60;  // End data label space
  const topMargin = 25;
  const bottomMargin = 45; // X-axis ticks & title space

  const chartWidth = svgWidth - leftMargin - rightMargin;
  const chartHeight = svgHeight - topMargin - bottomMargin;
  const slotHeight = chartHeight / Math.max(data.length, 1);
  const barHeight = 20;

  return (
    <div className="chart-card">
      <div className="chart-header">
        <h3 className="chart-title">📊 Top Security Event Types</h3>
        <span style={{ fontSize: '0.8rem', color: '#64748B' }}>Horizontal Bar Chart</span>
      </div>

      <div style={{ position: 'relative', width: '100%', overflowX: 'auto', marginTop: '0.5rem' }}>
        <svg width="100%" height={svgHeight} viewBox={`0 0 ${svgWidth} ${svgHeight}`}>
          <defs>
            <linearGradient id="svgBarGrad" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="#3B82F6" />
              <stop offset="100%" stopColor="#38BDF8" />
            </linearGradient>
            <linearGradient id="svgBarGradHover" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="#2563EB" />
              <stop offset="100%" stopColor="#0284C7" />
            </linearGradient>
          </defs>

          {/* Y-Axis Title Header */}
          <text x="15" y="16" fontSize="11" fontWeight="600" fill="#64748B">Event Type</text>

          {/* Vertical Gridlines & X-Axis Numeric Scale Ticks */}
          {ticks.map((tickVal, idx) => {
            const xPos = leftMargin + (tickVal / maxScale) * chartWidth;
            return (
              <g key={`grid-tick-${idx}`}>
                <line
                  x1={xPos}
                  y1={topMargin}
                  x2={xPos}
                  y2={topMargin + chartHeight}
                  stroke="#E2E8F0"
                  strokeWidth="1"
                  strokeDasharray={tickVal === 0 ? "none" : "3 3"}
                />
                <text
                  x={xPos}
                  y={topMargin + chartHeight + 18}
                  textAnchor="middle"
                  fontSize="11"
                  fill="#64748B"
                  fontFamily="Inter, system-ui, sans-serif"
                >
                  {tickVal}
                </text>
              </g>
            );
          })}

          {/* Horizontal Bars & Y-Axis Category Text Labels */}
          {data.map((item, idx) => {
            const yCenter = topMargin + idx * slotHeight + slotHeight / 2;
            const barY = yCenter - barHeight / 2;
            const barLength = (item.count / maxScale) * chartWidth;
            const isHovered = hoveredIdx === idx;

            return (
              <g
                key={`bar-group-${idx}`}
                onMouseEnter={() => setHoveredIdx(idx)}
                onMouseLeave={() => setHoveredIdx(null)}
                style={{ cursor: 'pointer' }}
              >
                {/* Y-Axis Event Type Label */}
                <text
                  x={leftMargin - 12}
                  y={barY + barHeight / 2 + 4}
                  textAnchor="end"
                  fontSize="12"
                  fontWeight={isHovered ? "700" : "500"}
                  fill={isHovered ? "#2563EB" : "#0F172A"}
                  fontFamily="Inter, system-ui, sans-serif"
                >
                  {item.event_type}
                </text>

                {/* Bar Background Track */}
                <rect
                  x={leftMargin}
                  y={barY}
                  width={chartWidth}
                  height={barHeight}
                  fill="#F8FAFC"
                  rx="4"
                />

                {/* Scaled Bar Rect */}
                <rect
                  x={leftMargin}
                  y={barY}
                  width={Math.max(barLength, 4)}
                  height={barHeight}
                  fill={isHovered ? "url(#svgBarGradHover)" : "url(#svgBarGrad)"}
                  rx="4"
                  style={{ transition: 'all 0.3s ease-in-out' }}
                />

                {/* Exact Count Data Label */}
                <text
                  x={leftMargin + barLength + 8}
                  y={barY + barHeight / 2 + 4}
                  fontSize="12"
                  fontWeight="700"
                  fill={isHovered ? "#1D4ED8" : "#2563EB"}
                  fontFamily="Inter, system-ui, sans-serif"
                >
                  {item.count}
                </text>

                {/* Native Tooltip on Hover */}
                <title>{`${item.event_type}: ${item.count} events`}</title>
              </g>
            );
          })}

          {/* Y-Axis Solid Border Line */}
          <line
            x1={leftMargin}
            y1={topMargin}
            x2={leftMargin}
            y2={topMargin + chartHeight}
            stroke="#94A3B8"
            strokeWidth="1.5"
          />

          {/* X-Axis Solid Border Line */}
          <line
            x1={leftMargin}
            y1={topMargin + chartHeight}
            x2={leftMargin + chartWidth}
            y2={topMargin + chartHeight}
            stroke="#94A3B8"
            strokeWidth="1.5"
          />

          {/* X-Axis Title */}
          <text
            x={leftMargin + chartWidth / 2}
            y={topMargin + chartHeight + 38}
            textAnchor="middle"
            fontSize="11"
            fontWeight="600"
            fill="#64748B"
            fontFamily="Inter, system-ui, sans-serif"
          >
            Number of Events
          </text>
        </svg>
      </div>
    </div>
  );
}
