import React, { useState, useEffect, useCallback } from 'react';
import M2KPICards from '../components/M2KPICards';
import AnomalyChart from '../charts/AnomalyChart';
import ThreatTrendChart from '../charts/ThreatTrendChart';
import ThreatTypeChart from '../charts/ThreatTypeChart';
import ModelInfoCard from '../components/ModelInfoCard';
import ThreatTable from '../components/ThreatTable';
import EventDetailsModal from '../components/EventDetailsModal';
import {
  fetchThreatSummary,
  fetchModelPerformance,
  fetchPredictions,
  fetchAnomalies
} from '../services/api';

export default function ThreatDetection() {
  const [summary, setSummary] = useState(null);
  const [performance, setPerformance] = useState(null);
  const [anomalies, setAnomalies] = useState([]);
  const [predictions, setPredictions] = useState([]);
  const [totalPredictions, setTotalPredictions] = useState(0);

  const [page, setPage] = useState(1);
  const [loadingSummary, setLoadingSummary] = useState(true);
  const [loadingTable, setLoadingTable] = useState(true);
  const [summaryError, setSummaryError] = useState(null);

  const [selectedEventId, setSelectedEventId] = useState(null);

  const [filters, setFilters] = useState({
    prediction: 'All',
    threat_type: 'All',
    severity: 'All',
    search: ''
  });

  // Load summary and model metrics
  const loadSummaryData = useCallback(async () => {
    setLoadingSummary(true);
    setSummaryError(null);
    try {
      const [sumRes, perfRes, anomRes] = await Promise.all([
        fetchThreatSummary(),
        fetchModelPerformance(),
        fetchAnomalies({ page: 1, limit: 100 })
      ]);

      if (sumRes && !sumRes.error) {
        setSummary(sumRes);
      } else if (sumRes?.error) {
        setSummaryError(sumRes.error);
      }

      if (perfRes && !perfRes.error) {
        setPerformance(perfRes);
      }

      if (anomRes && anomRes.anomalies) {
        setAnomalies(anomRes.anomalies);
      }
    } catch (err) {
      console.error("Error loading summary telemetry:", err);
      setSummaryError(err.message);
    } finally {
      setLoadingSummary(false);
    }
  }, []);

  // Load predictions table page data
  const loadTableData = useCallback(async () => {
    setLoadingTable(true);
    try {
      const predRes = await fetchPredictions({
        page,
        limit: 25,
        prediction: filters.prediction,
        threat_type: filters.threat_type,
        severity: filters.severity,
        search: filters.search
      });

      if (predRes && predRes.predictions) {
        setPredictions(predRes.predictions);
        setTotalPredictions(predRes.total || 0);
      }
    } catch (err) {
      console.error("Error loading predictions table:", err);
    } finally {
      setLoadingTable(false);
    }
  }, [page, filters]);

  useEffect(() => {
    loadSummaryData();
  }, [loadSummaryData]);

  useEffect(() => {
    loadTableData();
  }, [loadTableData]);

  return (
    <div className="dashboard-body">
      {/* Top AI Detection KPI Overview */}
      <M2KPICards
        summary={summary}
        loading={loadingSummary}
        error={summaryError}
      />

      {/* Main AI Visualizations Grid */}
      <div className="charts-grid" style={{ marginTop: '1rem' }}>
        <AnomalyChart summary={summary} />
        <ThreatTrendChart anomalies={anomalies} />
      </div>

      {/* Threat Type Distribution & Model Performance Grid */}
      <div className="charts-grid" style={{ marginTop: '1rem', gridTemplateColumns: '1fr 1fr' }}>
        <ThreatTypeChart threatTypes={summary?.threat_types} />
        <ModelInfoCard performance={performance} loading={loadingSummary} />
      </div>

      {/* Main Threat Predictions Data Table */}
      <ThreatTable
        predictions={predictions}
        total={totalPredictions}
        page={page}
        setPage={setPage}
        limit={25}
        loading={loadingTable}
        filters={filters}
        setFilters={setFilters}
        onSelectEvent={(eventId) => setSelectedEventId(eventId)}
      />

      {/* Event Investigation Modal */}
      {selectedEventId && (
        <EventDetailsModal
          eventId={selectedEventId}
          onClose={() => setSelectedEventId(null)}
        />
      )}
    </div>
  );
}
