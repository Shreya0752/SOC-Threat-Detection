import React from 'react';

export default function Filters({ filters, setFilters, eventTypes = [] }) {
  const handleReset = () => {
    setFilters({
      severity: 'All',
      date: '',
      eventType: 'All',
      ipAddress: '',
      search: ''
    });
  };

  return (
    <div className="filter-bar">
      <div className="filter-group">
        <span className="filter-label">Severity:</span>
        <select 
          className="filter-select"
          value={filters.severity}
          onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
        >
          <option value="All">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
      </div>

      <div className="filter-group">
        <span className="filter-label">Date:</span>
        <input 
          type="date"
          className="filter-input"
          value={filters.date}
          onChange={(e) => setFilters({ ...filters, date: e.target.value })}
        />
      </div>

      <div className="filter-group">
        <span className="filter-label">Event Type:</span>
        <select 
          className="filter-select"
          value={filters.eventType}
          onChange={(e) => setFilters({ ...filters, eventType: e.target.value })}
        >
          <option value="All">All Event Types</option>
          {eventTypes.map((type, idx) => (
            <option key={idx} value={type}>{type}</option>
          ))}
        </select>
      </div>

      <div className="filter-group">
        <span className="filter-label">IP Address:</span>
        <input 
          type="text"
          placeholder="Filter by IP..."
          className="filter-input"
          value={filters.ipAddress}
          onChange={(e) => setFilters({ ...filters, ipAddress: e.target.value })}
        />
      </div>

      <div className="filter-group">
        <span className="filter-label">Search:</span>
        <input 
          type="text"
          placeholder="User / Device / ID..."
          className="filter-input"
          value={filters.search}
          onChange={(e) => setFilters({ ...filters, search: e.target.value })}
        />
      </div>

      <button 
        className="refresh-btn" 
        onClick={handleReset}
        style={{ marginLeft: 'auto' }}
      >
        Clear Filters
      </button>
    </div>
  );
}
