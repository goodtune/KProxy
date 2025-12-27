import React, { useState, useEffect } from 'react';
import Sidebar from '../components/Sidebar';
import { getProfiles, createProfile, updateProfile, deleteProfile } from '../services/api';

const Profiles = () => {
  const [profiles, setProfiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [editingProfile, setEditingProfile] = useState(null);
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    default_allow: true,
  });

  useEffect(() => {
    loadProfiles();
  }, []);

  const loadProfiles = async () => {
    try {
      setLoading(true);
      const data = await getProfiles();
      setProfiles(data || []);
      setError('');
    } catch (err) {
      setError('Failed to load profiles');
      console.error('Error loading profiles:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      if (editingProfile) {
        await updateProfile(editingProfile.id, formData);
      } else {
        await createProfile(formData);
      }

      setShowForm(false);
      setEditingProfile(null);
      setFormData({ name: '', description: '', default_allow: true });
      loadProfiles();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to save profile');
    }
  };

  const handleEdit = (profile) => {
    setEditingProfile(profile);
    setFormData({
      name: profile.name,
      description: profile.description || '',
      default_allow: profile.default_allow !== false,
    });
    setShowForm(true);
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Are you sure you want to delete this profile?')) return;

    try {
      await deleteProfile(id);
      loadProfiles();
    } catch (err) {
      setError('Failed to delete profile');
    }
  };

  const handleCancel = () => {
    setShowForm(false);
    setEditingProfile(null);
    setFormData({ name: '', description: '', default_allow: true });
  };

  return (
    <div className="app-container">
      <Sidebar />
      <div className="main-content">
        <div className="page-header">
          <h1>Profiles</h1>
          <button onClick={() => setShowForm(true)} className="btn btn-primary">
            Add Profile
          </button>
        </div>

        {error && <div className="error-message">{error}</div>}

        {showForm && (
          <div className="form-card">
            <h2>{editingProfile ? 'Edit Profile' : 'Add New Profile'}</h2>
            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label>Profile Name</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder="e.g., Kids Profile"
                  required
                />
              </div>

              <div className="form-group">
                <label>Description</label>
                <textarea
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder="Profile description"
                  rows="3"
                />
              </div>

              <div className="form-group">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={formData.default_allow}
                    onChange={(e) => setFormData({ ...formData, default_allow: e.target.checked })}
                  />
                  Default Allow (Allow all traffic unless blocked by rules)
                </label>
              </div>

              <div className="form-actions">
                <button type="submit" className="btn btn-primary">
                  {editingProfile ? 'Update' : 'Create'}
                </button>
                <button type="button" onClick={handleCancel} className="btn btn-secondary">
                  Cancel
                </button>
              </div>
            </form>
          </div>
        )}

        {loading ? (
          <div className="loading">Loading profiles...</div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Description</th>
                  <th>Default Policy</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {profiles.length === 0 ? (
                  <tr>
                    <td colSpan="4" className="empty-message">No profiles found</td>
                  </tr>
                ) : (
                  profiles.map((profile) => (
                    <tr key={profile.id}>
                      <td>{profile.name}</td>
                      <td>{profile.description || '-'}</td>
                      <td>
                        <span className={`badge ${profile.default_allow ? 'badge-success' : 'badge-danger'}`}>
                          {profile.default_allow ? 'Allow' : 'Block'}
                        </span>
                      </td>
                      <td className="actions">
                        <button onClick={() => handleEdit(profile)} className="btn btn-sm btn-secondary">
                          Edit
                        </button>
                        <button onClick={() => handleDelete(profile.id)} className="btn btn-sm btn-danger">
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

export default Profiles;
