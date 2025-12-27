import React, { useState, useEffect } from 'react';
import Sidebar from '../components/Sidebar';
import { getDevices, createDevice, updateDevice, deleteDevice, getProfiles } from '../services/api';

const Devices = () => {
  const [devices, setDevices] = useState([]);
  const [profiles, setProfiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [editingDevice, setEditingDevice] = useState(null);
  const [formData, setFormData] = useState({
    name: '',
    profile_id: '',
    identifiers: '',
  });

  useEffect(() => {
    loadDevices();
    loadProfiles();
  }, []);

  const loadDevices = async () => {
    try {
      setLoading(true);
      const data = await getDevices();
      setDevices(data || []);
      setError('');
    } catch (err) {
      setError('Failed to load devices');
      console.error('Error loading devices:', err);
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
      const deviceData = {
        ...formData,
        identifiers: formData.identifiers.split(',').map(id => id.trim()).filter(id => id),
      };

      if (editingDevice) {
        await updateDevice(editingDevice.id, deviceData);
      } else {
        await createDevice(deviceData);
      }

      setShowForm(false);
      setEditingDevice(null);
      setFormData({ name: '', profile_id: '', identifiers: '' });
      loadDevices();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to save device');
    }
  };

  const handleEdit = (device) => {
    setEditingDevice(device);
    setFormData({
      name: device.name,
      profile_id: device.profile_id || '',
      identifiers: Array.isArray(device.identifiers) ? device.identifiers.join(', ') : '',
    });
    setShowForm(true);
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Are you sure you want to delete this device?')) return;

    try {
      await deleteDevice(id);
      loadDevices();
    } catch (err) {
      setError('Failed to delete device');
    }
  };

  const handleCancel = () => {
    setShowForm(false);
    setEditingDevice(null);
    setFormData({ name: '', profile_id: '', identifiers: '' });
  };

  return (
    <div className="app-container">
      <Sidebar />
      <div className="main-content">
        <div className="page-header">
          <h1>Devices</h1>
          <button onClick={() => setShowForm(true)} className="btn btn-primary">
            Add Device
          </button>
        </div>

        {error && <div className="error-message">{error}</div>}

        {showForm && (
          <div className="form-card">
            <h2>{editingDevice ? 'Edit Device' : 'Add New Device'}</h2>
            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label>Device Name</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder="e.g., Kids iPad"
                  required
                />
              </div>

              <div className="form-group">
                <label>Profile</label>
                <select
                  value={formData.profile_id}
                  onChange={(e) => setFormData({ ...formData, profile_id: e.target.value })}
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
                <label>Identifiers (IP, MAC, or CIDR - comma separated)</label>
                <input
                  type="text"
                  value={formData.identifiers}
                  onChange={(e) => setFormData({ ...formData, identifiers: e.target.value })}
                  placeholder="e.g., 192.168.1.100, aa:bb:cc:dd:ee:ff"
                  required
                />
              </div>

              <div className="form-actions">
                <button type="submit" className="btn btn-primary">
                  {editingDevice ? 'Update' : 'Create'}
                </button>
                <button type="button" onClick={handleCancel} className="btn btn-secondary">
                  Cancel
                </button>
              </div>
            </form>
          </div>
        )}

        {loading ? (
          <div className="loading">Loading devices...</div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Profile</th>
                  <th>Identifiers</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {devices.length === 0 ? (
                  <tr>
                    <td colSpan="4" className="empty-message">No devices found</td>
                  </tr>
                ) : (
                  devices.map((device) => (
                    <tr key={device.id}>
                      <td>{device.name}</td>
                      <td>{profiles.find(p => p.id === device.profile_id)?.name || 'None'}</td>
                      <td>
                        {Array.isArray(device.identifiers)
                          ? device.identifiers.join(', ')
                          : device.identifiers}
                      </td>
                      <td className="actions">
                        <button onClick={() => handleEdit(device)} className="btn btn-sm btn-secondary">
                          Edit
                        </button>
                        <button onClick={() => handleDelete(device.id)} className="btn btn-sm btn-danger">
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

export default Devices;
