import React, { useState, useEffect } from 'react';
import Sidebar from '../components/Sidebar';
import { getStats } from '../services/api';
import usePageId from '../hooks/usePageId';

const Dashboard = () => {
  usePageId('dashboard');
  const [stats, setStats] = useState({
    devices: 0,
    profiles: 0,
    rules: 0,
    requests_today: 0,
    blocked_today: 0,
    dns_queries_today: 0,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    try {
      setLoading(true);
      const data = await getStats();
      setStats(data);
      setError('');
    } catch (err) {
      setError('Failed to load statistics');
      console.error('Error loading stats:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app-container" data-page="dashboard">
      <Sidebar />
      <main className="main-content">
        <div className="page-header">
          <h2>Dashboard</h2>
          <button onClick={loadStats} className="btn btn-secondary" disabled={loading}>
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>

        {error && <div className="error-message">{error}</div>}

        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-icon">📱</div>
            <div className="stat-content">
              <div className="stat-value">{stats.devices || 0}</div>
              <div className="stat-label">Total Devices</div>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon">👤</div>
            <div className="stat-content">
              <div className="stat-value">{stats.profiles || 0}</div>
              <div className="stat-label">Active Profiles</div>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon">📋</div>
            <div className="stat-content">
              <div className="stat-value">{stats.rules || 0}</div>
              <div className="stat-label">Rules</div>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon">🌐</div>
            <div className="stat-content">
              <div className="stat-value">{stats.requests_today || 0}</div>
              <div className="stat-label">Requests Today</div>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon">🚫</div>
            <div className="stat-content">
              <div className="stat-value">{stats.blocked_today || 0}</div>
              <div className="stat-label">Blocked Today</div>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon">🔍</div>
            <div className="stat-content">
              <div className="stat-value">{stats.dns_queries_today || 0}</div>
              <div className="stat-label">DNS Queries Today</div>
            </div>
          </div>
        </div>

        <div className="info-section">
          <h2>Quick Stats</h2>
          <p>Welcome to KProxy Admin Dashboard. Use the navigation menu to manage devices, profiles, rules, and view logs.</p>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;
