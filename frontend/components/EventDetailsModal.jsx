import React, { useState, useEffect } from 'react';
import { fetchPredictionByEventId, predictEvent } from '../services/api';

export default function EventDetailsModal({ eventId, onClose }) {
  const [predictionData, setPredictionData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [repredicting, setRepredicting] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!eventId) return;
    let isMounted = true;
    setLoading(true);
    setError(null);

    fetchPredictionByEventId(eventId)
      .then(data => {
        if (isMounted) {
          if (data) {
            setPredictionData(data);
          } else {
            setError(`No prediction record found for ${eventId}`);
          }
          setLoading(false);
        }
      })
      .catch(err => {
        if (isMounted) {
          setError(err.message || "Failed to load prediction details");
          setLoading(false);
        }
      });

    return () => { isMounted = false; };
  }, [eventId]);

  const handleRunPredict = async () => {
    setRepredicting(true);
    try {
      const res = await predictEvent(eventId);
      if (res && !res.error) {
        setPredictionData(res);
      } else {
        alert(res?.error || "Failed to execute prediction pipeline.");
      }
    } catch (err) {
      alert("Error: " + err.message);
    } finally {
      setRepredicting(false);
    }
  };

  if (!eventId) return null;

  const isAnomalous = predictionData?.prediction === 'Anomalous';

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(15, 23, 42, 0.65)',
      backdropFilter: 'blur(4px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 9999,
      padding: '1rem'
    }}>
      <div style={{
        background: '#FFFFFF',
        borderRadius: '12px',
        maxWidth: '650px',
        width: '100%',
        maxHeight: '90vh',
        overflowY: 'auto',
        boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
        border: '1px solid #CBD5E1',
        padding: '1.5rem'
      }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #E2E8F0', pb: '1rem', marginBottom: '1rem' }}>
          <div>
            <div style={{ fontSize: '0.75rem', color: '#64748B', fontWeight: 600, textTransform: 'uppercase' }}>
              SOC Threat Event Investigation
            </div>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#0F172A', marginTop: '0.2rem' }}>
              Event ID: {eventId}
            </h2>
          </div>
          <button
            onClick={onClose}
            style={{
              background: '#F1F5F9',
              border: 'none',
              borderRadius: '50%',
              width: '32px',
              height: '32px',
              cursor: 'pointer',
              fontWeight: 700,
              fontSize: '1rem',
              color: '#475569'
            }}
          >
            ✕
          </button>
        </div>

        {/* Content */}
        {loading ? (
          <div style={{ textAlign: 'center', padding: '2rem', color: '#64748B' }}>
            🔄 Loading prediction telemetry for {eventId}...
          </div>
        ) : error ? (
          <div style={{ padding: '1rem', background: '#FEF2F2', borderRadius: '8px', color: '#DC2626', fontSize: '0.9rem' }}>
            ⚠️ {error}
          </div>
        ) : (
          <div>
            {/* KPI Badges row */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '0.75rem', marginBottom: '1.25rem' }}>
              <div style={{ background: isAnomalous ? '#FEF2F2' : '#F0FDF4', padding: '0.75rem', borderRadius: '8px', border: `1px solid ${isAnomalous ? '#FCA5A5' : '#86EFAC'}` }}>
                <div style={{ fontSize: '0.7rem', color: '#64748B' }}>Prediction Status</div>
                <div style={{ fontSize: '1rem', fontWeight: 700, color: isAnomalous ? '#DC2626' : '#16A34A', marginTop: '0.2rem' }}>
                  {isAnomalous ? '🚨 Anomalous' : '✅ Normal'}
                </div>
              </div>

              <div style={{ background: '#F8FAFC', padding: '0.75rem', borderRadius: '8px', border: '1px solid #E2E8F0' }}>
                <div style={{ fontSize: '0.7rem', color: '#64748B' }}>Threat Confidence</div>
                <div style={{ fontSize: '1rem', fontWeight: 700, color: '#2563EB', marginTop: '0.2rem' }}>
                  {predictionData?.confidence_score ?? 0}%
                </div>
              </div>

              <div style={{ background: '#F8FAFC', padding: '0.75rem', borderRadius: '8px', border: '1px solid #E2E8F0' }}>
                <div style={{ fontSize: '0.7rem', color: '#64748B' }}>Threat Level</div>
                <div style={{ fontSize: '1rem', fontWeight: 700, color: '#0F172A', marginTop: '0.2rem' }}>
                  {predictionData?.severity || 'Low'}
                </div>
              </div>
            </div>

            {/* Detailed Properties */}
            <div style={{ background: '#F8FAFC', borderRadius: '8px', padding: '1rem', border: '1px solid #E2E8F0', marginBottom: '1.25rem', fontSize: '0.85rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                <div><strong>Threat Type:</strong> {predictionData?.threat_type || 'Unknown'}</div>
                <div><strong>Anomaly Score:</strong> {predictionData?.anomaly_score ?? 0}</div>
                <div><strong>Model Version:</strong> {predictionData?.model_version || 'isolation_forest_v1'}</div>
                <div><strong>Prediction Time:</strong> {predictionData?.prediction_timestamp || 'N/A'}</div>
              </div>
            </div>

            {/* Explainable AI Reason Code Breakdown */}
            <div style={{ background: '#F0F9FF', border: '1px solid #BAE6FD', borderRadius: '8px', padding: '1rem', marginBottom: '1.25rem' }}>
              <h4 style={{ fontSize: '0.9rem', fontWeight: 700, color: '#0369A1', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                🔍 AI Analysis & Reason Breakdown
              </h4>
              {predictionData?.explanation && predictionData.explanation.length > 0 ? (
                <ul style={{ margin: 0, paddingLeft: '1.2rem', fontSize: '0.85rem', color: '#0C4A6E' }}>
                  {predictionData.explanation.map((reason, idx) => (
                    <li key={idx} style={{ marginBottom: '0.3rem' }}>
                      <span style={{ color: '#0284C7', fontWeight: 'bold', marginRight: '0.3rem' }}>✓</span> {reason}
                    </li>
                  ))}
                </ul>
              ) : (
                <div style={{ fontSize: '0.85rem', color: '#0C4A6E' }}>No specific reason codes logged.</div>
              )}
            </div>

            {/* Modal Actions */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', pt: '0.5rem' }}>
              <button
                onClick={handleRunPredict}
                disabled={repredicting}
                style={{
                  background: '#2563EB',
                  color: '#FFFFFF',
                  border: 'none',
                  borderRadius: '6px',
                  padding: '0.5rem 1rem',
                  fontSize: '0.85rem',
                  fontWeight: 600,
                  cursor: 'pointer'
                }}
              >
                {repredicting ? '⚡ Processing...' : '⚡ Re-Predict Event (POST /predict)'}
              </button>
              <button
                onClick={onClose}
                style={{
                  background: '#E2E8F0',
                  color: '#334155',
                  border: 'none',
                  borderRadius: '6px',
                  padding: '0.5rem 1rem',
                  fontSize: '0.85rem',
                  fontWeight: 600,
                  cursor: 'pointer'
                }}
              >
                Close View
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
