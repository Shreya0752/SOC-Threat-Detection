import React, { useState, useEffect, useCallback } from 'react';
import Sidebar from '../components/Sidebar';
import Header from '../components/Header';
import KPICards from '../components/KPICards';
import Filters from '../components/Filters';
import EventTable from '../components/EventTable';
import ThreatDistributionChart from '../charts/ThreatDistributionChart';
import EventTrendGraph from '../charts/EventTrendGraph';
import TopAttackTypes from '../charts/TopAttackTypes';
import ThreatDetection from './ThreatDetection';
import { fetchEvents, fetchStats, fetchThreats } from '../services/api';

export default function Dashboard({ user, onLogout }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [stats, setStats] = useState(null);
  const [threats, setThreats] = useState([]);
  const [events, setEvents] = useState([]);
  const [totalEvents, setTotalEvents] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [pollingInterval, setPollingInterval] = useState(10000); // 10s default
  const [lastRefreshed, setLastRefreshed] = useState(new Date());

  const [filters, setFilters] = useState({
    severity: 'All',
    date: '',
    eventType: 'All',
    ipAddress: '',
    search: ''
  });

  const loadDashboardData = useCallback(async () => {
    setLoading(true);
    try {
      const [statsData, threatsData, eventsData] = await Promise.all([
        fetchStats(),
        fetchThreats(),
        fetchEvents({ ...filters, page, limit: 25 })
      ]);

      setStats(statsData);
      setThreats(threatsData || []);
      setEvents(eventsData?.events || []);
      setTotalEvents(eventsData?.total || 0);
      setLastRefreshed(new Date());
    } catch (err) {
      console.error("Dashboard fetch error:", err);
    } finally {
      setLoading(false);
    }
  }, [filters, page]);

  useEffect(() => {
    loadDashboardData();
  }, [loadDashboardData]);

  // Polling setup
  useEffect(() => {
    if (pollingInterval <= 0) return;
    const timer = setInterval(() => {
      loadDashboardData();
    }, pollingInterval);
    return () => clearInterval(timer);
  }, [pollingInterval, loadDashboardData]);

  const eventTypesList = threats.map(t => t.event_type);

  return (
    <div className="app-container">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />

      <div className="main-wrapper">
        <Header
          activeTab={activeTab}
          onRefresh={loadDashboardData}
          lastRefreshed={lastRefreshed}
          pollingInterval={pollingInterval}
          setPollingInterval={setPollingInterval}
          user={user}
          onLogout={onLogout}
        />

        {activeTab === 'ai-detection' ? (
          <ThreatDetection />
        ) : (
          <div className="dashboard-body">
            {/* Top KPI Cards on Overview */}
            <KPICards stats={stats} />

            {/* Interactive Filters Bar */}
            <Filters
              filters={filters}
              setFilters={(newFilters) => {
                setFilters(newFilters);
                setPage(1);
              }}
              eventTypes={eventTypesList}
            />

            {/* Main Visualizations Grid */}
            {(activeTab === 'overview' || activeTab === 'analytics' || activeTab === 'threats') && (
              <div className="charts-grid">
                <EventTrendGraph events={events} />
                <ThreatDistributionChart stats={stats} />
              </div>
            )}

            {activeTab === 'overview' && (
              <div style={{ marginTop: '0.5rem' }}>
                <TopAttackTypes threats={threats} />
              </div>
            )}

            {/* Detailed Threat Intelligence View */}
            {activeTab === 'threats' && (
              <div className="chart-card">
                <h3 className="chart-title">Threat Intelligence Feed Matches & Rules</h3>
                <div style={{ fontSize: '0.85rem', color: '#475569', marginTop: '0.5rem' }}>
                  <p><strong>Threat Intel Match Count:</strong> {stats?.threat_matches || 0}</p>
                  <p><strong>Rule Indicators:</strong> Brute Force detection (failed logins &ge; 5) & Malware alerts</p>
                  <p style={{ fontSize: '0.8rem', marginTop: '0.5rem', color: '#64748B' }}>
                    Note: Matched against raw IOC lookup feed (`threat_intelligence.csv`). Unmatched events transparently designated as `No Match` without fabricating artificial records.
                  </p>
                </div>
              </div>
            )}

            {/* Detailed Vulnerability View */}
            {activeTab === 'vulnerabilities' && (
              <div className="chart-card">
                <h3 className="chart-title"> Vulnerability & CVE Intelligence</h3>
                <div style={{ fontSize: '0.85rem', color: '#475569', marginTop: '0.5rem' }}>
                  <p><strong>Vulnerability Events Count:</strong> {stats?.vulnerabilities || 0}</p>
                  <p><strong>CVE Lookup Dataset:</strong> Priv Escalation (CVE-2024-1045, CVSS 9.5)</p>
                </div>
              </div>
            )}

            {/* Event Log Table */}
            <EventTable
              events={events}
              total={totalEvents}
              page={page}
              setPage={setPage}
              limit={25}
              loading={loading}
            />
          </div>
        )}
      </div>
    </div>
  );
}

