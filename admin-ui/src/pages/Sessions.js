import React, { useState, useEffect } from 'react';
import Sidebar from '../components/Sidebar';
import { getActiveSessions, getDailyUsage, terminateSession } from '../services/api';
import usePageId from '../hooks/usePageId';

const Sessions = () => {
  usePageId('sessions');
  const [activeTab, setActiveTab] = useState('active');
  const [sessions, setSessions] = useState([]);
  const [usageData, setUsageData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (activeTab === 'active') {
      loadActiveSessions();
    } else {
      loadUsageData();
    }
  }, [activeTab]);

  const loadActiveSessions = async () => {
    try {
      setLoading(true);
      const data = await getActiveSessions();
      setSessions(data.sessions || []);
      setError('');
    } catch (err) {
      setError('Failed to load active sessions');
      console.error('Error loading sessions:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadUsageData = async () => {
    try {
      setLoading(true);
      const data = await getDailyUsage('today');
      setUsageData(data.usages || []);
      setError('');
    } catch (err) {
      setError('Failed to load usage data');
      console.error('Error loading usage:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleTerminateSession = async (sessionId) => {
    if (!window.confirm('Are you sure you want to terminate this session?')) {
      return;
    }

    try {
      await terminateSession(sessionId);
      loadActiveSessions();
    } catch (err) {
      setError('Failed to terminate session');
      console.error('Error terminating session:', err);
    }
  };

  const handleRefresh = () => {
    if (activeTab === 'active') {
      loadActiveSessions();
    } else {
      loadUsageData();
    }
  };

  const formatDuration = (seconds) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    if (hours > 0) {
      return `${hours}h ${minutes}m ${secs}s`;
    } else if (minutes > 0) {
      return `${minutes}m ${secs}s`;
    }
    return `${secs}s`;
  };

  const formatTimestamp = (timestamp) => {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp);
    return date.toLocaleString();
  };

  return (
    <div className="app-container" data-page="sessions">
      <Sidebar />
      <div className="main-content">
        <div className="page-header">
          <h1>Sessions & Usage</h1>
          <button
            id="refreshBtn"
            onClick={handleRefresh}
            className="btn btn-secondary"
            disabled={loading}
          >
            {loading ? 'Loading...' : 'Refresh'}
          </button>
        </div>

        {error && <div className="error-message">{error}</div>}

        <div className="tabs">
          <button
            data-tab="active"
            className={`tab ${activeTab === 'active' ? 'active' : ''}`}
            onClick={() => setActiveTab('active')}
          >
            Active Sessions
          </button>
          <button
            data-tab="usage"
            className={`tab ${activeTab === 'usage' ? 'active' : ''}`}
            onClick={() => setActiveTab('usage')}
          >
            Usage Statistics
          </button>
        </div>

        <div className="tab-content">
          {activeTab === 'active' && (
            <div id="activeTab" className="tab-pane">
              <h2>Active Sessions</h2>
              {sessions.length === 0 ? (
                <p>No active sessions</p>
              ) : (
                <div className="table-container">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Device ID</th>
                        <th>Limit ID</th>
                        <th>Started</th>
                        <th>Last Activity</th>
                        <th>Duration</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sessions.map((session) => (
                        <tr key={session.id}>
                          <td>{session.device_id}</td>
                          <td>{session.limit_id}</td>
                          <td>{formatTimestamp(session.start_time)}</td>
                          <td>{formatTimestamp(session.last_activity)}</td>
                          <td>{formatDuration(session.duration_seconds || 0)}</td>
                          <td>
                            <button
                              onClick={() => handleTerminateSession(session.id)}
                              className="btn btn-sm btn-danger"
                            >
                              Terminate
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {activeTab === 'usage' && (
            <div id="usageTab" className="tab-pane">
              <h2>Daily Usage Statistics</h2>
              {usageData.length === 0 ? (
                <p>No usage data available</p>
              ) : (
                <div className="table-container">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Device ID</th>
                        <th>Limit ID</th>
                        <th>Date</th>
                        <th>Total Duration</th>
                      </tr>
                    </thead>
                    <tbody>
                      {usageData.map((usage, idx) => (
                        <tr key={idx}>
                          <td>{usage.device_id}</td>
                          <td>{usage.limit_id}</td>
                          <td>{usage.date}</td>
                          <td>{formatDuration(usage.total_seconds || 0)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Sessions;
