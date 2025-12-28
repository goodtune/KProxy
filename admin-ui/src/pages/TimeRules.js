import React, { useState, useEffect } from 'react';
import Sidebar from '../components/Sidebar';
import { getTimeRules, createTimeRule, updateTimeRule, deleteTimeRule, getProfiles, getRules } from '../services/api';

const DAYS_OF_WEEK = [
  { value: 0, label: 'Sunday' },
  { value: 1, label: 'Monday' },
  { value: 2, label: 'Tuesday' },
  { value: 3, label: 'Wednesday' },
  { value: 4, label: 'Thursday' },
  { value: 5, label: 'Friday' },
  { value: 6, label: 'Saturday' },
];

const TimeRules = () => {
  const [timeRules, setTimeRules] = useState([]);
  const [profiles, setProfiles] = useState([]);
  const [rules, setRules] = useState([]);
  const [selectedProfile, setSelectedProfile] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [editingRule, setEditingRule] = useState(null);
  const [formData, setFormData] = useState({
    days_of_week: [],
    start_time: '00:00',
    end_time: '23:59',
    rule_ids: [],
  });

  useEffect(() => {
    loadProfiles();
  }, []);

  useEffect(() => {
    if (selectedProfile) {
      loadTimeRules();
      loadRules();
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

  const loadTimeRules = async () => {
    if (!selectedProfile) return;

    try {
      setLoading(true);
      const data = await getTimeRules(selectedProfile);
      setTimeRules(data || []);
      setError('');
    } catch (err) {
      setError('Failed to load time rules');
      console.error('Error loading time rules:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadRules = async () => {
    if (!selectedProfile) return;

    try {
      const data = await getRules();
      const profileRules = data.filter(r => r.profile_id === selectedProfile);
      setRules(profileRules);
    } catch (err) {
      console.error('Error loading rules:', err);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!selectedProfile) {
      setError('Please select a profile first');
      return;
    }

    try {
      if (editingRule) {
        await updateTimeRule(selectedProfile, editingRule.id, formData);
      } else {
        await createTimeRule(selectedProfile, formData);
      }

      setShowForm(false);
      setEditingRule(null);
      resetForm();
      loadTimeRules();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to save time rule');
    }
  };

  const handleEdit = (rule) => {
    setEditingRule(rule);
    setFormData({
      days_of_week: rule.days_of_week || [],
      start_time: rule.start_time || '00:00',
      end_time: rule.end_time || '23:59',
      rule_ids: rule.rule_ids || [],
    });
    setShowForm(true);
  };

  const handleDelete = async (ruleId) => {
    if (!window.confirm('Are you sure you want to delete this time rule?')) return;
    if (!selectedProfile) return;

    try {
      await deleteTimeRule(selectedProfile, ruleId);
      loadTimeRules();
    } catch (err) {
      setError('Failed to delete time rule');
    }
  };

  const resetForm = () => {
    setFormData({
      days_of_week: [],
      start_time: '00:00',
      end_time: '23:59',
      rule_ids: [],
    });
  };

  const handleCancel = () => {
    setShowForm(false);
    setEditingRule(null);
    resetForm();
  };

  const handleDayToggle = (day) => {
    const newDays = formData.days_of_week.includes(day)
      ? formData.days_of_week.filter(d => d !== day)
      : [...formData.days_of_week, day].sort();
    setFormData({ ...formData, days_of_week: newDays });
  };

  const handleRuleToggle = (ruleId) => {
    const newRuleIds = formData.rule_ids.includes(ruleId)
      ? formData.rule_ids.filter(id => id !== ruleId)
      : [...formData.rule_ids, ruleId];
    setFormData({ ...formData, rule_ids: newRuleIds });
  };

  const formatDays = (days) => {
    if (!days || days.length === 0) return 'All days';
    if (days.length === 7) return 'All days';
    return days.map(d => DAYS_OF_WEEK.find(day => day.value === d)?.label || d).join(', ');
  };

  return (
    <div className="app-container">
      <Sidebar />
      <div className="main-content">
        <div className="page-header">
          <h1>Time Rules</h1>
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
              Add Time Rule
            </button>
          </div>
        </div>

        <div className="info-box">
          <p>Time rules restrict when specific rules are active. Select days and time ranges to limit when rules apply.</p>
        </div>

        {error && <div className="error-message">{error}</div>}

        {showForm && (
          <div className="form-card">
            <h2>{editingRule ? 'Edit Time Rule' : 'Add New Time Rule'}</h2>
            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label>Days of Week *</label>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px', marginTop: '5px' }}>
                  {DAYS_OF_WEEK.map(day => (
                    <label key={day.value} style={{ display: 'flex', alignItems: 'center' }}>
                      <input
                        type="checkbox"
                        checked={formData.days_of_week.includes(day.value)}
                        onChange={() => handleDayToggle(day.value)}
                      />
                      {' '}{day.label}
                    </label>
                  ))}
                </div>
                {formData.days_of_week.length === 0 && <small className="error-text">Select at least one day</small>}
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
                <div className="form-group">
                  <label>Start Time *</label>
                  <input
                    type="time"
                    value={formData.start_time}
                    onChange={(e) => setFormData({ ...formData, start_time: e.target.value })}
                    required
                  />
                </div>

                <div className="form-group">
                  <label>End Time *</label>
                  <input
                    type="time"
                    value={formData.end_time}
                    onChange={(e) => setFormData({ ...formData, end_time: e.target.value })}
                    required
                  />
                </div>
              </div>

              <div className="form-group">
                <label>Apply to Specific Rules (optional)</label>
                <small>Leave all unchecked to apply to all rules in this profile</small>
                <div style={{ maxHeight: '200px', overflowY: 'auto', border: '1px solid #ddd', padding: '10px', marginTop: '5px' }}>
                  {rules.length === 0 ? (
                    <p>No rules available for this profile</p>
                  ) : (
                    rules.map(rule => (
                      <div key={rule.id} style={{ marginBottom: '5px' }}>
                        <label>
                          <input
                            type="checkbox"
                            checked={formData.rule_ids.includes(rule.id)}
                            onChange={() => handleRuleToggle(rule.id)}
                          />
                          {' '}{rule.domain} - {rule.action}
                        </label>
                      </div>
                    ))
                  )}
                </div>
              </div>

              <div className="form-actions">
                <button type="submit" className="btn btn-primary" disabled={formData.days_of_week.length === 0}>
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
          <div className="loading">Loading time rules...</div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Days</th>
                  <th>Time Range</th>
                  <th>Applies To</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {timeRules.length === 0 ? (
                  <tr>
                    <td colSpan="4" className="empty-message">
                      {selectedProfile ? 'No time rules found for this profile' : 'Select a profile to view time rules'}
                    </td>
                  </tr>
                ) : (
                  timeRules.map((rule) => (
                    <tr key={rule.id}>
                      <td>{formatDays(rule.days_of_week)}</td>
                      <td>{rule.start_time} - {rule.end_time}</td>
                      <td>
                        {rule.rule_ids && rule.rule_ids.length > 0
                          ? `${rule.rule_ids.length} specific rule(s)`
                          : 'All rules'}
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

export default TimeRules;
