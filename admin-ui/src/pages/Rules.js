import React, { useState, useEffect } from 'react';
import Sidebar from '../components/Sidebar';
import { getRules, createRule, updateRule, deleteRule, getProfiles } from '../services/api';

const Rules = () => {
  const [rules, setRules] = useState([]);
  const [profiles, setProfiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [editingRule, setEditingRule] = useState(null);
  const [formData, setFormData] = useState({
    profile_id: '',
    domain: '',
    paths: [],
    action: 'ALLOW',
    priority: 100,
    category: '',
    inject_timer: false,
  });

  useEffect(() => {
    loadRules();
    loadProfiles();
  }, []);

  const loadRules = async () => {
    try {
      setLoading(true);
      const data = await getRules();
      setRules(data || []);
      setError('');
    } catch (err) {
      setError('Failed to load rules');
      console.error('Error loading rules:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadProfiles = async () => {
    try {
      const data = await getProfiles();
      setProfiles(data || []);
    } catch (err) {
      console.error('Error loading profiles:', err);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const ruleData = {
        ...formData,
        priority: parseInt(formData.priority, 10),
      };

      if (editingRule) {
        await updateRule(formData.profile_id, editingRule.id, ruleData);
      } else {
        await createRule(ruleData);
      }

      setShowForm(false);
      setEditingRule(null);
      setFormData({
        profile_id: '',
        domain: '',
        paths: [],
        action: 'ALLOW',
        priority: 100,
        category: '',
        inject_timer: false,
      });
      loadRules();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to save rule');
    }
  };

  const handleEdit = (rule) => {
    setEditingRule(rule);
    setFormData({
      profile_id: rule.profile_id || '',
      domain: rule.domain || '',
      paths: rule.paths || [],
      action: rule.action || 'ALLOW',
      priority: rule.priority || 100,
      category: rule.category || '',
      inject_timer: rule.inject_timer || false,
    });
    setShowForm(true);
  };

  const handleDelete = async (rule) => {
    if (!window.confirm('Are you sure you want to delete this rule?')) return;

    try {
      await deleteRule(rule.profile_id, rule.id);
      loadRules();
    } catch (err) {
      setError('Failed to delete rule');
    }
  };

  const handleCancel = () => {
    setShowForm(false);
    setEditingRule(null);
    setFormData({
      profile_id: '',
      domain: '',
      paths: [],
      action: 'ALLOW',
      priority: 100,
      category: '',
      inject_timer: false,
    });
  };

  return (
    <div className="app-container">
      <Sidebar />
      <div className="main-content">
        <div className="page-header">
          <h1>Rules</h1>
          <button onClick={() => setShowForm(true)} className="btn btn-primary">
            Add Rule
          </button>
        </div>

        {error && <div className="error-message">{error}</div>}

        {showForm && (
          <div className="form-card">
            <h2>{editingRule ? 'Edit Rule' : 'Add New Rule'}</h2>
            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label>Profile</label>
                <select
                  value={formData.profile_id}
                  onChange={(e) => setFormData({ ...formData, profile_id: e.target.value })}
                  required
                >
                  <option value="">Select Profile</option>
                  {profiles.map((profile) => (
                    <option key={profile.id} value={profile.id}>
                      {profile.name}
                    </option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label>Domain Pattern</label>
                <input
                  type="text"
                  value={formData.domain}
                  onChange={(e) => setFormData({ ...formData, domain: e.target.value })}
                  placeholder="e.g., *.youtube.com or .facebook.com"
                  required
                />
              </div>

              <div className="form-group">
                <label>Path Patterns (optional, comma-separated)</label>
                <input
                  type="text"
                  value={Array.isArray(formData.paths) ? formData.paths.join(', ') : ''}
                  onChange={(e) => {
                    const value = e.target.value;
                    // Only split and filter on blur or when submitting, allow free typing
                    setFormData({
                      ...formData,
                      paths: value ? value.split(',').map(p => p.trim()) : []
                    });
                  }}
                  onBlur={(e) => {
                    // Clean up empty entries when user leaves the field
                    setFormData({
                      ...formData,
                      paths: formData.paths.filter(p => p)
                    });
                  }}
                  placeholder="e.g., /watch, /videos/*"
                />
                <small>Enter multiple path patterns separated by commas</small>
              </div>

              <div className="form-group">
                <label>Action</label>
                <select
                  value={formData.action}
                  onChange={(e) => setFormData({ ...formData, action: e.target.value })}
                  required
                >
                  <option value="ALLOW">ALLOW</option>
                  <option value="BLOCK">BLOCK</option>
                  <option value="BYPASS">BYPASS</option>
                </select>
              </div>

              <div className="form-group">
                <label>Priority (higher = evaluated first)</label>
                <input
                  type="number"
                  value={formData.priority}
                  onChange={(e) => setFormData({ ...formData, priority: e.target.value })}
                  min="0"
                  max="1000"
                  required
                />
              </div>

              <div className="form-group">
                <label>Category (optional, for usage tracking)</label>
                <input
                  type="text"
                  value={formData.category}
                  onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                  placeholder="e.g., social_media, streaming, gaming"
                />
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
                <small>Show time remaining overlay for ALLOW rules with usage limits</small>
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
          <div className="loading">Loading rules...</div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Profile</th>
                  <th>Domain</th>
                  <th>Path</th>
                  <th>Action</th>
                  <th>Priority</th>
                  <th>Category</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {rules.length === 0 ? (
                  <tr>
                    <td colSpan="7" className="empty-message">No rules found</td>
                  </tr>
                ) : (
                  rules.map((rule) => (
                    <tr key={rule.id}>
                      <td>{profiles.find(p => p.id === rule.profile_id)?.name || 'Unknown'}</td>
                      <td>{rule.domain}</td>
                      <td>{rule.paths && rule.paths.length > 0 ? rule.paths.join(', ') : '-'}</td>
                      <td>
                        <span className={`badge ${
                          rule.action === 'ALLOW' ? 'badge-success' :
                          rule.action === 'BLOCK' ? 'badge-danger' :
                          'badge-info'
                        }`}>
                          {rule.action}
                        </span>
                      </td>
                      <td>{rule.priority}</td>
                      <td>{rule.category || '-'}</td>
                      <td className="actions">
                        <button onClick={() => handleEdit(rule)} className="btn btn-sm btn-secondary">
                          Edit
                        </button>
                        <button onClick={() => handleDelete(rule)} className="btn btn-sm btn-danger">
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

export default Rules;
