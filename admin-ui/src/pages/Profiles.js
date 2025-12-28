import React, { useState, useEffect } from 'react';
import Sidebar from '../components/Sidebar';
import { getProfiles, createProfile, updateProfile, deleteProfile } from '../services/api';

const Profiles = () => {
  const [profiles, setProfiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [activeTab, setActiveTab] = useState('settings');
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

      setShowModal(false);
      setEditingProfile(null);
      setActiveTab('settings');
      setFormData({ name: '', description: '', default_allow: true });
      loadProfiles();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to save profile');
    }
  };

  const handleCardClick = (profile) => {
    setEditingProfile(profile);
    setFormData({
      name: profile.name,
      description: profile.description || '',
      default_allow: profile.default_allow !== false,
    });
    setActiveTab('settings');
    setShowModal(true);
  };

  const handleNewProfile = () => {
    setEditingProfile(null);
    setFormData({ name: '', description: '', default_allow: true });
    setActiveTab('settings');
    setShowModal(true);
  };

  const handleDelete = async (e, id) => {
    e.stopPropagation(); // Prevent card click
    if (!window.confirm('Are you sure you want to delete this profile?')) return;

    try {
      await deleteProfile(id);
      loadProfiles();
    } catch (err) {
      setError('Failed to delete profile');
    }
  };

  const handleCloseModal = () => {
    setShowModal(false);
    setEditingProfile(null);
    setActiveTab('settings');
    setFormData({ name: '', description: '', default_allow: true });
  };

  return (
    <div className="app-container" data-page="profiles">
      <Sidebar />
      <div className="main-content">
        <div className="page-header">
          <h1>Profiles</h1>
          <button id="newProfileBtn" onClick={handleNewProfile} className="btn btn-primary">
            Add Profile
          </button>
        </div>

        {error && <div className="error-message">{error}</div>}

        {/* Modal */}
        <div id="profileModal" className={`modal ${showModal ? '' : 'hidden'}`}>
          <div className="modal-content modal-large">
            <div className="modal-header">
              <h2>{editingProfile ? 'Edit Profile' : 'New Profile'}</h2>
              <button id="closeModalBtn" onClick={handleCloseModal} className="close-btn">&times;</button>
            </div>

            {/* Tabs */}
            <div className="tabs">
              <button
                data-tab="settings"
                className={`tab ${activeTab === 'settings' ? 'active' : ''}`}
                onClick={() => setActiveTab('settings')}
              >
                Settings
              </button>
              {editingProfile && (
                <>
                  <button
                    data-tab="rules"
                    className={`tab ${activeTab === 'rules' ? 'active' : ''}`}
                    onClick={() => setActiveTab('rules')}
                  >
                    Rules
                  </button>
                  <button
                    data-tab="time-rules"
                    className={`tab ${activeTab === 'time-rules' ? 'active' : ''}`}
                    onClick={() => setActiveTab('time-rules')}
                  >
                    Time Rules
                  </button>
                  <button
                    data-tab="usage-limits"
                    className={`tab ${activeTab === 'usage-limits' ? 'active' : ''}`}
                    onClick={() => setActiveTab('usage-limits')}
                  >
                    Usage Limits
                  </button>
                </>
              )}
            </div>

            {/* Tab Content */}
            <div className="tab-content">
              {activeTab === 'settings' && (
                <div id="settingsTab" className="tab-pane">
                  <form id="profileForm" onSubmit={handleSubmit}>
                    <div className="form-group">
                      <label htmlFor="profileName">Profile Name</label>
                      <input
                        id="profileName"
                        type="text"
                        value={formData.name}
                        onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                        placeholder="e.g., Kids Profile"
                        required
                      />
                    </div>

                    <div className="form-group">
                      <label htmlFor="profileDescription">Description</label>
                      <textarea
                        id="profileDescription"
                        value={formData.description}
                        onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                        placeholder="Profile description"
                        rows="3"
                      />
                    </div>

                    <div className="form-group">
                      <label className="checkbox-label">
                        <input
                          id="profileDefaultAllow"
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
                      <button type="button" onClick={handleCloseModal} className="btn btn-secondary">
                        Cancel
                      </button>
                    </div>
                  </form>
                </div>
              )}

              {activeTab === 'rules' && editingProfile && (
                <div id="rulesTab" className="tab-pane">
                  <p>Rules management for profile: {editingProfile.name}</p>
                  <p>This tab would contain rule management UI</p>
                </div>
              )}

              {activeTab === 'time-rules' && editingProfile && (
                <div id="timeRulesTab" className="tab-pane">
                  <p>Time rules for profile: {editingProfile.name}</p>
                  <p>This tab would contain time rule management UI</p>
                </div>
              )}

              {activeTab === 'usage-limits' && editingProfile && (
                <div id="usageLimitsTab" className="tab-pane">
                  <p>Usage limits for profile: {editingProfile.name}</p>
                  <p>This tab would contain usage limit management UI</p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Profiles Grid */}
        {loading ? (
          <div className="loading">Loading profiles...</div>
        ) : (
          <div id="profilesGrid" className="profiles-grid">
            {profiles.length === 0 ? (
              <div className="empty-message">No profiles found. Create one to get started.</div>
            ) : (
              profiles.map((profile) => (
                <div
                  key={profile.id}
                  className="profile-card"
                  onClick={() => handleCardClick(profile)}
                >
                  <div className="card-header">
                    <h3>{profile.name}</h3>
                    <span className={`badge ${profile.default_allow ? 'badge-success' : 'badge-danger'}`}>
                      {profile.default_allow ? 'Allow' : 'Block'}
                    </span>
                  </div>
                  <div className="card-body">
                    <p className="card-description">{profile.description || 'No description'}</p>
                  </div>
                  <div className="card-actions">
                    <button
                      onClick={(e) => handleDelete(e, profile.id)}
                      className="btn btn-sm btn-danger"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default Profiles;
