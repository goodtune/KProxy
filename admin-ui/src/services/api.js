import axios from 'axios';

// Base API URL - configure via environment variable or use relative path for embedded mode
// When served from the Go binary, use relative path. For development, use full URL.
const API_BASE_URL = process.env.REACT_APP_API_URL || (
  process.env.NODE_ENV === 'production' ? '/api' : 'https://localhost:8443/api'
);

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add token to headers
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Auth endpoints
export const login = async (username, password) => {
  const response = await api.post('/auth/login', { username, password });
  if (response.data.token) {
    localStorage.setItem('token', response.data.token);
  }
  return response.data;
};

export const logout = () => {
  localStorage.removeItem('token');
  window.location.href = '/login';
};

export const me = async () => {
  const response = await api.get('/auth/me');
  return response.data;
};

export const isAuthenticated = () => {
  return !!localStorage.getItem('token');
};

// Device endpoints
export const getDevices = async () => {
  const response = await api.get('/devices');
  return response.data.devices || [];
};

export const getDevice = async (id) => {
  const response = await api.get(`/devices/${id}`);
  return response.data;
};

export const createDevice = async (device) => {
  const response = await api.post('/devices', device);
  return response.data;
};

export const updateDevice = async (id, device) => {
  const response = await api.put(`/devices/${id}`, device);
  return response.data;
};

export const deleteDevice = async (id) => {
  const response = await api.delete(`/devices/${id}`);
  return response.data;
};

// Profile endpoints
export const getProfiles = async () => {
  const response = await api.get('/profiles');
  return response.data.profiles || [];
};

export const getProfile = async (id) => {
  const response = await api.get(`/profiles/${id}`);
  return response.data;
};

export const createProfile = async (profile) => {
  const response = await api.post('/profiles', profile);
  return response.data;
};

export const updateProfile = async (id, profile) => {
  const response = await api.put(`/profiles/${id}`, profile);
  return response.data;
};

export const deleteProfile = async (id) => {
  const response = await api.delete(`/profiles/${id}`);
  return response.data;
};

// Rules endpoints
export const getRules = async () => {
  const response = await api.get('/rules');
  return response.data.rules || [];
};

export const getRule = async (id) => {
  const response = await api.get(`/rules/${id}`);
  return response.data;
};

export const createRule = async (rule) => {
  const response = await api.post('/rules', rule);
  return response.data;
};

export const updateRule = async (id, rule) => {
  const response = await api.put(`/rules/${id}`, rule);
  return response.data;
};

export const deleteRule = async (id) => {
  const response = await api.delete(`/rules/${id}`);
  return response.data;
};

// Logs endpoints
export const getRequestLogs = async (params) => {
  const response = await api.get('/logs/requests', { params });
  return response.data.logs || [];
};

export const getDNSLogs = async (params) => {
  const response = await api.get('/logs/dns', { params });
  return response.data.logs || [];
};

export const getUsageLogs = async (params) => {
  const response = await api.get('/logs/usage', { params });
  return response.data;
};

// Stats endpoints
export const getStats = async () => {
  const response = await api.get('/stats');
  return response.data;
};

export default api;
