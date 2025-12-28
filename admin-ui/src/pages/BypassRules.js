import React, { useState, useEffect } from 'react';
import Sidebar from '../components/Sidebar';
import { getBypassRules, createBypassRule, updateBypassRule, deleteBypassRule, getDevices } from '../services/api';

const BypassRules = () => {
  const [rules, setRules] = useState([]);
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [editingRule, setEditingRule] = useState(null);
  const [formData, setFormData] = useState({
    domain: '',
    reason: '',
    enabled: true,
    device_ids: [],
  });

  useEffect(() => {
    loadRules();
    loadDevices();
  }, []);

  const loadRules = async () => {
    try {
      setLoading(true);
      const data = await getBypassRules();
      setRules(data || []);
      setError('');
    } catch (err) {
      setError('Failed to load bypass rules');
      console.error('Error loading bypass rules:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadDevices = async () => {
    try {
      const data = await getDevices();
      setDevices(data || []);
    } catch (err) {
      console.error('Error loading devices:', err);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      if (editingRule) {
        await updateBypassRule(editingRule.id, formData);
      } else {
        await createBypassRule(formData);
      }

      setShowForm(false);
      setEditingRule(null);
      setFormData({
        domain: '',
        reason: '',
        enabled: true,
        device_ids: [],
      });
      loadRules();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to save bypass rule');
    }
  };

  const handleEdit = (rule) => {
    setEditingRule(rule);
    setFormData({
      domain: rule.domain || '',
      reason: rule.reason || '',
      enabled: rule.enabled !== undefined ? rule.enabled : true,
      device_ids: rule.device_ids || [],
    });
    setShowForm(true);
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Are you sure you want to delete this bypass rule?')) return;

    try {
      await deleteBypassRule(id);
      loadRules();
    } catch (err) {
      setError('Failed to delete bypass rule');
    }
  };

  const handleCancel = () => {
    setShowForm(false);
    setEditingRule(null);
    setFormData({
      domain: '',
      reason: '',
      enabled: true,
      device_ids: [],
    });
  };

  const handleDeviceToggle = (deviceId) => {
    const newDeviceIds = formData.device_ids.includes(deviceId)
      ? formData.device_ids.filter(id => id !== deviceId)
      : [...formData.device_ids, deviceId];
    setFormData({ ...formData, device_ids: newDeviceIds });
  };

  return (
    <div className="app-container">
      <Sidebar />
      <div className="main-content">
        <div className="page-header">
          <h1>Bypass Rules</h1>
          <button onClick={() => setShowForm(true)} className="btn btn-primary">
            Add Bypass Rule
          </button>
        </div>

        <div className="info-box">
          <p>Bypass rules allow domains to skip proxy interception at the DNS level.
          Traffic to these domains will be forwarded directly to upstream DNS servers.</p>
        </div>

        {error && <div className="error-message">{error}</div>}

        {showForm && (
          <div className="form-card">
            <h2>{editingRule ? 'Edit Bypass Rule' : 'Add New Bypass Rule'}</h2>
            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label>Domain Pattern *</label>
                <input
                  type="text"
                  value={formData.domain}
                  onChange={(e) => setFormData({ ...formData, domain: e.target.value })}
                  placeholder="e.g., .example.com or *.google.com"
                  required
                />
                <small>Use .domain.com for suffix matching or *.domain.com for wildcards</small>
              </div>

              <div className="form-group">
                <label>Reason (optional)</label>
                <input
                  type="text"
                  value={formData.reason}
                  onChange={(e) => setFormData({ ...formData, reason: e.target.value })}
                  placeholder="e.g., Required for OS updates"
                />
              </div>

              <div className="form-group">
                <label>
                  <input
                    type="checkbox"
                    checked={formData.enabled}
                    onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
                  />
                  {' '}Enabled
                </label>
              </div>

              <div className="form-group">
                <label>Apply to Specific Devices (optional)</label>
                <small>Leave all unchecked to apply to all devices</small>
                <div style={{ maxHeight: '200px', overflowY: 'auto', border: '1px solid #ddd', padding: '10px', marginTop: '5px' }}>
                  {devices.length === 0 ? (
                    <p>No devices available</p>
                  ) : (
                    devices.map(device => (
                      <div key={device.id} style={{ marginBottom: '5px' }}>
                        <label>
                          <input
                            type="checkbox"
                            checked={formData.device_ids.includes(device.id)}
                            onChange={() => handleDeviceToggle(device.id)}
                          />
                          {' '}{device.name} ({device.identifiers?.join(', ') || 'No identifiers'})
                        </label>
                      </div>
                    ))
                  )}
                </div>
              </div>

              <div className="form-actions">
                <button type="submit" className="btn btn-primary">
                  {editingRule ? 'Update' : 'Create'}
                </button>
                <button type="button" onClick={handleCancel} className="btn btn-secondary">
                  Cancel
                </button>
              </div>
            </form>
          </div>
        )}

        {loading ? (
          <div className="loading">Loading bypass rules...</div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Reason</th>
                  <th>Devices</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {rules.length === 0 ? (
                  <tr>
                    <td colSpan="5" className="empty-message">No bypass rules found</td>
                  </tr>
                ) : (
                  rules.map((rule) => (
                    <tr key={rule.id}>
                      <td><strong>{rule.domain}</strong></td>
                      <td>{rule.reason || '-'}</td>
                      <td>
                        {rule.device_ids && rule.device_ids.length > 0
                          ? rule.device_ids.map(id => devices.find(d => d.id === id)?.name || id).join(', ')
                          : 'All devices'}
                      </td>
                      <td>
                        <span className={`badge ${rule.enabled ? 'badge-success' : 'badge-secondary'}`}>
                          {rule.enabled ? 'Enabled' : 'Disabled'}
                        </span>
                      </td>
                      <td className="actions">
                        <button onClick={() => handleEdit(rule)} className="btn btn-sm btn-secondary">
                          Edit
                        </button>
                        <button onClick={() => handleDelete(rule.id)} className="btn btn-sm btn-danger">
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default BypassRules;
