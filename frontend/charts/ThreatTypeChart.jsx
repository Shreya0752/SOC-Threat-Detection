import React, { useState } from 'react';

export default function ThreatTypeChart({ threatTypes = {} }) {
  const [hoveredIdx, setHoveredIdx] = useState(null);

  // Convert object dictionary from API into sorted array
  const entries = Object.entries(threatTypes || {});
  const data = entries.length > 0 
    ? entries.map(([type, count]) => ({ threat_type: type, count })).sort((a, b) => b.count - a.count)
    : [
        { threat_type: 'Brute Force', count: 429 },
        { threat_type: 'Normal Activity', count: 349 },
        { threat_type: 'Anomalous Activity', count: 314 },
        { threat_type: 'SQL Injection', count: 195 },
        { threat_type: 'Privilege Escalation', count: 191 },
        { threat_type: 'Malware', count: 165 },
        { threat_type: 'Phishing', count: 157 }
      ];

  // Calculate maximum value for X-axis scale
  const maxCount = Math.max(...data.map(d => d.count), 1);
  const step = 100;
  const maxScale = Math.ceil((maxCount * 1.1) / step) * step || 500;

  // X-axis numerical scale ticks
  const ticks = [];
  for (let val = 0; val <= maxScale; val += step) {
    ticks.push(val);
  }

  // SVG Chart Layout Dimensions
  const svgWidth = 700;
  const svgHeight = Math.max(260, data.length * 36 + 60);
  const leftMargin = 175; // Y-axis category space
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
        <h3 className="chart-title">📊 Top Threat Types</h3>
        <span style={{ fontSize: '0.8rem', color: '#64748B' }}>Native Horizontal Bar Chart</span>
      </div>

      <div style={{ position: 'relative', width: '100%', overflowX: 'auto', marginTop: '0.5rem' }}>
        <svg width="100%" height={svgHeight} viewBox={`0 0 ${svgWidth} ${svgHeight}`}>
          <defs>
            <linearGradient id="ttBarGrad" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="#DC2626" />
              <stop offset="100%" stopColor="#F87171" />
            </linearGradient>
            <linearGradient id="ttBarGradHover" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="#B91C1C" />
              <stop offset="100%" stopColor="#EF4444" />
            </linearGradient>
          </defs>

          {/* Y-Axis Title Header */}
          <text x="15" y="16" fontSize="11" fontWeight="600" fill="#64748B">Threat Type</text>

          {/* Vertical Gridlines & X-Axis Numeric Scale Ticks */}
          {ticks.map((tickVal, idx) => {
            const xPos = leftMargin + (tickVal / maxScale) * chartWidth;
            return (
              <g key={`tt-grid-tick-${idx}`}>
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
                key={`tt-bar-group-${idx}`}
                onMouseEnter={() => setHoveredIdx(idx)}
                onMouseLeave={() => setHoveredIdx(null)}
                style={{ cursor: 'pointer' }}
              >
                {/* Y-Axis Threat Type Label */}
                <text
                  x={leftMargin - 12}
                  y={barY + barHeight / 2 + 4}
                  textAnchor="end"
                  fontSize="12"
                  fontWeight={isHovered ? "700" : "500"}
                  fill={isHovered ? "#DC2626" : "#0F172A"}
                  fontFamily="Inter, system-ui, sans-serif"
                >
                  {item.threat_type}
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
                  fill={isHovered ? "url(#ttBarGradHover)" : "url(#ttBarGrad)"}
                  rx="4"
                  style={{ transition: 'all 0.3s ease-in-out' }}
                />

                {/* Exact Count Data Label */}
                <text
                  x={leftMargin + barLength + 8}
                  y={barY + barHeight / 2 + 4}
                  fontSize="12"
                  fontWeight="700"
                  fill={isHovered ? "#991B1B" : "#DC2626"}
                  fontFamily="Inter, system-ui, sans-serif"
                >
                  {item.count.toLocaleString()}
                </text>

                {/* Native Tooltip on Hover */}
                <title>{`${item.threat_type}: ${item.count} events`}</title>
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
            Number of Classified Events
          </text>
        </svg>
      </div>
    </div>
  );
}
