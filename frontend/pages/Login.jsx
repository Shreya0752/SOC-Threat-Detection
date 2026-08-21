import React, { useState } from 'react';
import { login } from '../services/api';

export default function Login({ onLoginSuccess }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMessage('');

    if (!username.trim()) {
      setErrorMessage('Please enter your username.');
      return;
    }
    if (!password.trim()) {
      setErrorMessage('Please enter your password.');
      return;
    }

    setIsLoading(true);

    try {
      const response = await login(username.trim(), password.trim());
      if (response && response.user) {
        onLoginSuccess(response.user);
      }
    } catch (err) {
      setErrorMessage(err.message || 'Invalid username or password.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="login-logo">
          <span style={{ fontSize: '1.8rem' }}>🛡️</span>
        </div>

        <h2 className="login-title">SOC ThreatDetect AI</h2>
        <p className="login-subtitle">
          Security Operations Center — Data Aggregation & Intel Console
        </p>

        {errorMessage && (
          <div style={{
            background: '#FEE2E2',
            border: '1px solid #FCA5A5',
            color: '#DC2626',
            padding: '0.65rem 0.85rem',
            borderRadius: '8px',
            fontSize: '0.85rem',
            marginBottom: '1rem',
            textAlign: 'left'
          }}>
             {errorMessage}
          </div>
        )}

        <form onSubmit={handleSubmit} className="login-form">
          <div className="form-group">
            <label className="form-label">Analyst Username</label>
            <input
              type="text"
              className="form-input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter username"
              disabled={isLoading}
              autoFocus
            />
          </div>

          <div className="form-group">
            <label className="form-label">Security Key / Password</label>
            <div style={{ position: 'relative' }}>
              <input
                type={showPassword ? 'text' : 'password'}
                className="form-input"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                disabled={isLoading}
                style={{ paddingRight: '2.5rem' }}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                style={{
                  position: 'absolute',
                  right: '0.75rem',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: '#F1F5F9',
                  border: '1px solid #CBD5E1',
                  borderRadius: '4px',
                  color: '#475569',
                  cursor: 'pointer',
                  fontSize: '0.75rem',
                  fontWeight: '500',
                  padding: '0.2rem 0.5rem'
                }}
                title={showPassword ? "Hide password" : "Show password"}
              >
                {showPassword ? 'Hide' : 'Show'}
              </button>
            </div>
          </div>

          <button
            type="submit"
            className="login-submit-btn"
            disabled={isLoading}
            style={{ opacity: isLoading ? 0.7 : 1, cursor: isLoading ? 'not-allowed' : 'pointer' }}
          >
            {isLoading ? 'Authenticating...' : 'Access SOC Console'}
          </button>
        </form>
      </div>
    </div>
  );
}
