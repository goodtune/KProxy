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
    description: '',
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
        name: formData.name,
        description: formData.description,
        profile_id: formData.profile_id,
        identifiers: formData.identifiers.split('\n').map(id => id.trim()).filter(id => id),
      };

      if (editingDevice) {
        await updateDevice(editingDevice.id, deviceData);
      } else {
        await createDevice(deviceData);
      }

      setShowForm(false);
      setEditingDevice(null);
      setFormData({ name: '', description: '', profile_id: '', identifiers: '' });
      loadDevices();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to save device');
    }
  };

  const handleEdit = (device) => {
    setEditingDevice(device);
    setFormData({
      name: device.name,
      description: device.description || '',
      profile_id: device.profile_id || '',
      identifiers: Array.isArray(device.identifiers) ? device.identifiers.join('\n') : '',
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
    setFormData({ name: '', description: '', profile_id: '', identifiers: '' });
  };

  return (
    <div className="app-container" data-page="devices">
      <Sidebar />
      <div className="main-content">
        <div className="page-header">
          <h1>Devices</h1>
          <button id="newDeviceBtn" onClick={() => setShowForm(true)} className="btn btn-primary">
            Add Device
          </button>
        </div>

        {error && <div className="error-message">{error}</div>}

        {/* Modal */}
        <div id="deviceModal" className={`modal ${showForm ? '' : 'hidden'}`}>
          <div className="modal-content">
            <div className="modal-header">
              <h2>{editingDevice ? 'Edit Device' : 'Add New Device'}</h2>
              <button id="closeModalBtn" onClick={handleCancel} className="close-btn">&times;</button>
            </div>
            <form id="deviceForm" onSubmit={handleSubmit}>
              <div className="form-group">
                <label htmlFor="deviceName">Device Name</label>
                <input
                  id="deviceName"
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder="e.g., Kids iPad"
                  required
                />
              </div>

              <div className="form-group">
                <label htmlFor="deviceDescription">Description (optional)</label>
                <input
                  id="deviceDescription"
                  type="text"
                  value={formData.description || ''}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder="Device description"
                />
              </div>

              <div className="form-group">
                <label htmlFor="deviceProfile">Profile</label>
                <select
                  id="deviceProfile"
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
                <label htmlFor="deviceIdentifiers">Identifiers (one per line: IP, MAC, or CIDR)</label>
                <textarea
                  id="deviceIdentifiers"
                  value={formData.identifiers}
                  onChange={(e) => setFormData({ ...formData, identifiers: e.target.value })}
                  placeholder="192.168.1.100&#10;aa:bb:cc:dd:ee:ff&#10;10.0.0.0/24"
                  rows="4"
                  required
                />
              </div>

              <div className="form-actions">
                <button type="submit" className="btn btn-primary">
                  {editingDevice ? 'Update' : 'Create'}
                </button>
                <button id="cancelBtn" type="button" onClick={handleCancel} className="btn btn-secondary">
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>

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
              <tbody id="devicesTableBody">
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
