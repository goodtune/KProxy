import React, { useState, useEffect } from 'react';
import Sidebar from '../components/Sidebar';
import { getRequestLogs, getDNSLogs } from '../services/api';

const Logs = () => {
  const [logType, setLogType] = useState('requests');
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [filters, setFilters] = useState({
    device_id: '',
    limit: 100,
  });

  useEffect(() => {
    loadLogs();
  }, [logType]);

  const loadLogs = async () => {
    try {
      setLoading(true);
      let data;
      if (logType === 'requests') {
        data = await getRequestLogs(filters);
      } else {
        data = await getDNSLogs(filters);
      }
      setLogs(data || []);
      setError('');
    } catch (err) {
      setError('Failed to load logs');
      console.error('Error loading logs:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleRefresh = () => {
    loadLogs();
  };

  const formatTimestamp = (timestamp) => {
    if (!timestamp) return '-';
    return new Date(timestamp).toLocaleString();
  };

  return (
    <div className="app-container">
      <Sidebar />
      <div className="main-content">
        <div className="page-header">
          <h1>Logs</h1>
          <div className="log-controls">
            <select
              value={logType}
              onChange={(e) => setLogType(e.target.value)}
              className="log-type-select"
            >
              <option value="requests">HTTP/HTTPS Requests</option>
              <option value="dns">DNS Queries</option>
            </select>
            <button onClick={handleRefresh} className="btn btn-secondary" disabled={loading}>
              {loading ? 'Refreshing...' : 'Refresh'}
            </button>
          </div>
        </div>

        {error && <div className="error-message">{error}</div>}

        <div className="filters-section">
          <div className="form-group">
            <label>Device ID</label>
            <input
              type="text"
              placeholder="Filter by device ID"
              value={filters.device_id}
              onChange={(e) => setFilters({ ...filters, device_id: e.target.value })}
            />
          </div>
          <div className="form-group">
            <label>Domain</label>
            <input
              type="text"
              placeholder="Filter by domain"
              value={filters.domain || ''}
              onChange={(e) => setFilters({ ...filters, domain: e.target.value })}
            />
          </div>
          <div className="form-group">
            <label>Limit</label>
            <select
              value={filters.limit}
              onChange={(e) => setFilters({ ...filters, limit: parseInt(e.target.value) })}
            >
              <option value="50">50</option>
              <option value="100">100</option>
              <option value="250">250</option>
              <option value="500">500</option>
            </select>
          </div>
          <button onClick={loadLogs} className="btn btn-primary">Apply Filters</button>
        </div>

        {loading ? (
          <div className="loading">Loading logs...</div>
        ) : (
          <div className="table-container">
            {logType === 'requests' ? (
              <table className="data-table logs-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Device</th>
                    <th>Method</th>
                    <th>Host</th>
                    <th>Path</th>
                    <th>Action</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.length === 0 ? (
                    <tr>
                      <td colSpan="7" className="empty-message">No logs found</td>
                    </tr>
                  ) : (
                    logs.map((log, index) => (
                      <tr key={index}>
                        <td className="timestamp">{formatTimestamp(log.timestamp)}</td>
                        <td>{log.device_name || log.device_id || '-'}</td>
                        <td>{log.method || 'GET'}</td>
                        <td>{log.host || log.url}</td>
                        <td className="path">{log.path || '/'}</td>
                        <td>
                          <span className={`badge ${log.action === 'ALLOW' ? 'badge-success' : 'badge-danger'}`}>
                            {log.action || 'ALLOW'}
                          </span>
                        </td>
                        <td>{log.status_code || '-'}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            ) : (
              <table className="data-table logs-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Device</th>
                    <th>Query</th>
                    <th>Type</th>
                    <th>Action</th>
                    <th>Response</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.length === 0 ? (
                    <tr>
                      <td colSpan="6" className="empty-message">No logs found</td>
                    </tr>
                  ) : (
                    logs.map((log, index) => (
                      <tr key={index}>
                        <td className="timestamp">{formatTimestamp(log.timestamp)}</td>
                        <td>{log.device_name || log.device_id || '-'}</td>
                        <td>{log.query || log.domain}</td>
                        <td>{log.query_type || 'A'}</td>
                        <td>
                          <span className={`badge ${
                            log.action === 'INTERCEPT' ? 'badge-warning' :
                            log.action === 'BYPASS' ? 'badge-success' :
                            'badge-danger'
                          }`}>
                            {log.action || 'INTERCEPT'}
                          </span>
                        </td>
                        <td className="dns-response">{log.response || '-'}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default Logs;
