import React from 'react';

export default function ModelInfoCard({ performance, loading, error }) {
  if (loading) {
    return (
      <div className="chart-card" style={{ opacity: 0.6 }}>
        <div style={{ color: '#64748B' }}>Loading model specifications...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="chart-card" style={{ borderLeft: '4px solid #EF4444' }}>
        <div style={{ color: '#DC2626', fontWeight: 600 }}>Error loading model info</div>
        <div style={{ fontSize: '0.85rem', color: '#64748B' }}>{error}</div>
      </div>
    );
  }

  return (
    <div className="chart-card">
      <div className="chart-header" style={{ marginBottom: '0.75rem' }}>
        <h3 className="chart-title">AI Anomaly Detection Model Architecture</h3>
        <span className="badge" style={{ backgroundColor: '#EFF6FF', color: '#2563EB', fontWeight: 600 }}>
          Unsupervised Engine
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '0.75rem', fontSize: '0.85rem' }}>
        <div style={{ background: '#F8FAFC', padding: '0.6rem 0.8rem', borderRadius: '6px', border: '1px solid #E2E8F0' }}>
          <div style={{ fontSize: '0.7rem', color: '#64748B', textTransform: 'uppercase' }}>Model Algorithm</div>
          <div style={{ fontWeight: 700, color: '#0F172A', marginTop: '0.2rem' }}>{performance?.model_name || 'Isolation Forest'}</div>
        </div>

        <div style={{ background: '#F8FAFC', padding: '0.6rem 0.8rem', borderRadius: '6px', border: '1px solid #E2E8F0' }}>
          <div style={{ fontSize: '0.7rem', color: '#64748B', textTransform: 'uppercase' }}>Model Version</div>
          <div style={{ fontWeight: 700, color: '#0F172A', marginTop: '0.2rem' }}>{performance?.model_version || 'isolation_forest_v1'}</div>
        </div>

        <div style={{ background: '#F8FAFC', padding: '0.6rem 0.8rem', borderRadius: '6px', border: '1px solid #E2E8F0' }}>
          <div style={{ fontSize: '0.7rem', color: '#64748B', textTransform: 'uppercase' }}>Estimators (n_trees)</div>
          <div style={{ fontWeight: 700, color: '#0F172A', marginTop: '0.2rem' }}>{performance?.n_estimators || 200}</div>
        </div>

        <div style={{ background: '#F8FAFC', padding: '0.6rem 0.8rem', borderRadius: '6px', border: '1px solid #E2E8F0' }}>
          <div style={{ fontSize: '0.7rem', color: '#64748B', textTransform: 'uppercase' }}>Random State</div>
          <div style={{ fontWeight: 700, color: '#0F172A', marginTop: '0.2rem' }}>{performance?.random_state || 42}</div>
        </div>

        <div style={{ background: '#F8FAFC', padding: '0.6rem 0.8rem', borderRadius: '6px', border: '1px solid #E2E8F0' }}>
          <div style={{ fontSize: '0.7rem', color: '#64748B', textTransform: 'uppercase' }}>Mean Anomaly Score</div>
          <div style={{ fontWeight: 700, color: '#2563EB', marginTop: '0.2rem' }}>{performance?.mean_anomaly_score ?? -0.017}</div>
        </div>

        <div style={{ background: '#F8FAFC', padding: '0.6rem 0.8rem', borderRadius: '6px', border: '1px solid #E2E8F0' }}>
          <div style={{ fontSize: '0.7rem', color: '#64748B', textTransform: 'uppercase' }}>Median Anomaly Score</div>
          <div style={{ fontWeight: 700, color: '#2563EB', marginTop: '0.2rem' }}>{performance?.median_anomaly_score ?? -0.014}</div>
        </div>
      </div>

      <div style={{ fontSize: '0.75rem', color: '#64748B', marginTop: '0.75rem', fontStyle: 'italic' }}>
        * Note: Isolation Forest operates in an unsupervised manner without artificial labels. Anomaly status is determined statistically relative to learned behavioral baselines.
      </div>
    </div>
  );
}
