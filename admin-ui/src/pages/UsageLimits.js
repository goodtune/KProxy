import React, { useState, useEffect } from 'react';
import Sidebar from '../components/Sidebar';
import { getUsageLimits, createUsageLimit, updateUsageLimit, deleteUsageLimit, getProfiles } from '../services/api';

const UsageLimits = () => {
  const [limits, setLimits] = useState([]);
  const [profiles, setProfiles] = useState([]);
  const [selectedProfile, setSelectedProfile] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [editingLimit, setEditingLimit] = useState(null);
  const [formData, setFormData] = useState({
    category: '',
    domains: [],
    daily_minutes: 60,
    reset_time: '00:00',
    inject_timer: false,
  });

  useEffect(() => {
    loadProfiles();
  }, []);

  useEffect(() => {
    if (selectedProfile) {
      loadLimits();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedProfile]);

  const loadProfiles = async () => {
    try {
      const data = await getProfiles();
      setProfiles(data || []);
      if (data && data.length > 0) {
        setSelectedProfile(data[0].id);
      }
    } catch (err) {
      console.error('Error loading profiles:', err);
    }
  };

  const loadLimits = async () => {
    if (!selectedProfile) return;

    try {
      setLoading(true);
      const data = await getUsageLimits(selectedProfile);
      setLimits(data || []);
      setError('');
    } catch (err) {
      setError('Failed to load usage limits');
      console.error('Error loading usage limits:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!selectedProfile) {
      setError('Please select a profile first');
      return;
    }

    try {
      const limitData = {
        ...formData,
        daily_minutes: parseInt(formData.daily_minutes, 10),
      };

      if (editingLimit) {
        await updateUsageLimit(selectedProfile, editingLimit.id, limitData);
      } else {
        await createUsageLimit(selectedProfile, limitData);
      }

      setShowForm(false);
      setEditingLimit(null);
      resetForm();
      loadLimits();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to save usage limit');
    }
  };

  const handleEdit = (limit) => {
    setEditingLimit(limit);
    setFormData({
      category: limit.category || '',
      domains: limit.domains || [],
      daily_minutes: limit.daily_minutes || 60,
      reset_time: limit.reset_time || '00:00',
      inject_timer: limit.inject_timer || false,
    });
    setShowForm(true);
  };

  const handleDelete = async (limitId) => {
    if (!window.confirm('Are you sure you want to delete this usage limit?')) return;
    if (!selectedProfile) return;

    try {
      await deleteUsageLimit(selectedProfile, limitId);
      loadLimits();
    } catch (err) {
      setError('Failed to delete usage limit');
    }
  };

  const resetForm = () => {
    setFormData({
      category: '',
      domains: [],
      daily_minutes: 60,
      reset_time: '00:00',
      inject_timer: false,
    });
  };

  const handleCancel = () => {
    setShowForm(false);
    setEditingLimit(null);
    resetForm();
  };

  const formatMinutes = (minutes) => {
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    if (hours === 0) return `${mins}m`;
    if (mins === 0) return `${hours}h`;
    return `${hours}h ${mins}m`;
  };

  return (
    <div className="app-container">
      <Sidebar />
      <div className="main-content">
        <div className="page-header">
          <h1>Usage Limits</h1>
          <div>
            <select
              value={selectedProfile}
              onChange={(e) => setSelectedProfile(e.target.value)}
              style={{ marginRight: '10px', padding: '8px' }}
            >
              {profiles.map(profile => (
                <option key={profile.id} value={profile.id}>{profile.name}</option>
              ))}
            </select>
            <button onClick={() => setShowForm(true)} className="btn btn-primary" disabled={!selectedProfile}>
              Add Usage Limit
            </button>
          </div>
        </div>

        <div className="info-box">
          <p>Usage limits restrict daily time spent on specific categories or domains. Limits reset daily at the specified time.</p>
        </div>

        {error && <div className="error-message">{error}</div>}

        {showForm && (
          <div className="form-card">
            <h2>{editingLimit ? 'Edit Usage Limit' : 'Add New Usage Limit'}</h2>
            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label>Category (optional)</label>
                <input
                  type="text"
                  value={formData.category}
                  onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                  placeholder="e.g., social_media, streaming, gaming"
                />
                <small>Category name for grouping related domains. Must match category in rules.</small>
              </div>

              <div className="form-group">
                <label>Domains (comma-separated, optional)</label>
                <input
                  type="text"
                  value={formData.domains.join(', ')}
                  onChange={(e) => setFormData({
                    ...formData,
                    domains: e.target.value.split(',').map(d => d.trim()).filter(d => d)
                  })}
                  placeholder="e.g., youtube.com, facebook.com"
                />
                <small>Specific domains to limit. Leave empty to use category matching only.</small>
              </div>

              {!formData.category && formData.domains.length === 0 && (
                <div className="error-message">
                  Either category or domains must be specified
                </div>
              )}

              <div className="form-group">
                <label>Daily Time Limit (minutes) *</label>
                <input
                  type="number"
                  value={formData.daily_minutes}
                  onChange={(e) => setFormData({ ...formData, daily_minutes: e.target.value })}
                  min="1"
                  max="1440"
                  required
                />
                <small>{formatMinutes(parseInt(formData.daily_minutes || 0))} per day</small>
              </div>

              <div className="form-group">
                <label>Daily Reset Time *</label>
                <input
                  type="time"
                  value={formData.reset_time}
                  onChange={(e) => setFormData({ ...formData, reset_time: e.target.value })}
                  required
                />
                <small>Time when daily usage counters reset</small>
              </div>

              <div className="form-group">
                <label>
                  <input
                    type="checkbox"
                    checked={formData.inject_timer}
                    onChange={(e) => setFormData({ ...formData, inject_timer: e.target.checked })}
                  />
                  {' '}Inject Timer Overlay
                </label>
                <small>Show time remaining overlay on limited sites</small>
              </div>

              <div className="form-actions">
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={!formData.category && formData.domains.length === 0}
                >
                  {editingLimit ? 'Update' : 'Create'}
                </button>
                <button type="button" onClick={handleCancel} className="btn btn-secondary">
                  Cancel
                </button>
              </div>
            </form>
          </div>
        )}

        {loading ? (
          <div className="loading">Loading usage limits...</div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Category</th>
                  <th>Domains</th>
                  <th>Daily Limit</th>
                  <th>Reset Time</th>
                  <th>Timer</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {limits.length === 0 ? (
                  <tr>
                    <td colSpan="6" className="empty-message">
                      {selectedProfile ? 'No usage limits found for this profile' : 'Select a profile to view usage limits'}
                    </td>
                  </tr>
                ) : (
                  limits.map((limit) => (
                    <tr key={limit.id}>
                      <td>{limit.category || '-'}</td>
                      <td>
                        {limit.domains && limit.domains.length > 0
                          ? limit.domains.join(', ')
                          : '-'}
                      </td>
                      <td><strong>{formatMinutes(limit.daily_minutes)}</strong></td>
                      <td>{limit.reset_time}</td>
                      <td>
                        <span className={`badge ${limit.inject_timer ? 'badge-success' : 'badge-secondary'}`}>
                          {limit.inject_timer ? 'Enabled' : 'Disabled'}
                        </span>
                      </td>
                      <td className="actions">
                        <button onClick={() => handleEdit(limit)} className="btn btn-sm btn-secondary">
                          Edit
                        </button>
                        <button onClick={() => handleDelete(limit.id)} className="btn btn-sm btn-danger">
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

export default UsageLimits;
