import React, { useState, useEffect } from 'react';
import Sidebar from '../components/Sidebar';
import { getRequestLogs, getDNSLogs } from '../services/api';
import usePageId from '../hooks/usePageId';

const Logs = () => {
  usePageId('logs');
  const [activeTab, setActiveTab] = useState('request');
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showClearModal, setShowClearModal] = useState(false);
  const [filters, setFilters] = useState({
    device_id: '',
    domain: '',
    action: '',
    limit: 100,
  });

  useEffect(() => {
    loadLogs();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab]);

  const loadLogs = async () => {
    try {
      setLoading(true);
      let data;
      if (activeTab === 'request') {
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

  const handleApplyFilters = () => {
    loadLogs();
  };

  const handleClearLogs = () => {
    setShowClearModal(true);
  };

  const confirmClearLogs = async () => {
    // TODO: Implement clear logs API call
    setShowClearModal(false);
  };

  const cancelClearLogs = () => {
    setShowClearModal(false);
  };

  const formatTimestamp = (timestamp) => {
    if (!timestamp) return '-';
    return new Date(timestamp).toLocaleString();
  };

  return (
    <div className="app-container" data-page="logs">
      <Sidebar />
      <div className="main-content">
        <div className="page-header">
          <h1>System Logs</h1>
          <div className="header-actions">
            <button id="refreshBtn" onClick={handleRefresh} className="btn btn-secondary" disabled={loading}>
              {loading ? 'Refreshing...' : 'Refresh'}
            </button>
            <button id="clearLogsBtn" onClick={handleClearLogs} className="btn btn-danger">
              Clear Logs
            </button>
          </div>
        </div>

        {error && <div className="error-message">{error}</div>}

        {/* Clear Logs Modal */}
        <div id="clearLogsModal" className={`modal ${showClearModal ? '' : 'hidden'}`}>
          <div className="modal-content">
            <div className="modal-header">
              <h2>Clear Logs</h2>
              <button onClick={cancelClearLogs} className="close-btn">&times;</button>
            </div>
            <div className="modal-body">
              <p>Are you sure you want to clear all logs? This action cannot be undone.</p>
            </div>
            <div className="modal-actions">
              <button onClick={confirmClearLogs} className="btn btn-danger">
                Clear All Logs
              </button>
              <button id="cancelClearBtn" onClick={cancelClearLogs} className="btn btn-secondary">
                Cancel
              </button>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="tabs">
          <button
            data-tab="request"
            className={`tab ${activeTab === 'request' ? 'active' : ''}`}
            onClick={() => setActiveTab('request')}
          >
            HTTP/HTTPS Requests
          </button>
          <button
            data-tab="dns"
            className={`tab ${activeTab === 'dns' ? 'active' : ''}`}
            onClick={() => setActiveTab('dns')}
          >
            DNS Queries
          </button>
        </div>

        {/* Filters */}
        <div className="filters-section">
          <div className="form-group">
            <label htmlFor="filterDomain">Domain</label>
            <input
              id="filterDomain"
              type="text"
              placeholder="Filter by domain"
              value={filters.domain}
              onChange={(e) => setFilters({ ...filters, domain: e.target.value })}
            />
          </div>
          <div className="form-group">
            <label htmlFor="filterAction">Action</label>
            <select
              id="filterAction"
              value={filters.action}
              onChange={(e) => setFilters({ ...filters, action: e.target.value })}
            >
              <option value="">All Actions</option>
              <option value="allow">Allow</option>
              <option value="block">Block</option>
              <option value="intercept">Intercept</option>
              <option value="bypass">Bypass</option>
            </select>
          </div>
          <div className="form-group">
            <label htmlFor="filterLimit">Limit</label>
            <select
              id="filterLimit"
              value={filters.limit}
              onChange={(e) => setFilters({ ...filters, limit: parseInt(e.target.value) })}
            >
              <option value="50">50</option>
              <option value="100">100</option>
              <option value="250">250</option>
              <option value="500">500</option>
            </select>
          </div>
          <button id="applyFiltersBtn" onClick={handleApplyFilters} className="btn btn-primary">
            Apply Filters
          </button>
        </div>

        {/* Log Count */}
        <div id="logCount" className="log-count">
          Showing {logs.length} logs
        </div>

        {/* Logs Table */}
        {loading ? (
          <div className="loading">Loading logs...</div>
        ) : (
          <div className="table-container">
            {activeTab === 'request' ? (
              <table id="requestLogsTable" className="data-table logs-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Device</th>
                    <th>Method</th>
                    <th>Host</th>
                    <th>Path</th>
                    <th>Action</th>
                    <th>Reason</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.length === 0 ? (
                    <tr>
                      <td colSpan="8" className="empty-message">No logs found</td>
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
                        <td className="reason">{log.reason || '-'}</td>
                        <td>{log.status_code || '-'}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            ) : (
              <table id="dnsLogsTable" className="data-table logs-table">
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
