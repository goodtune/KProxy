import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import './App.css';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Devices from './pages/Devices';
import Profiles from './pages/Profiles';
import Rules from './pages/Rules';
import TimeRules from './pages/TimeRules';
import UsageLimits from './pages/UsageLimits';
import BypassRules from './pages/BypassRules';
import Logs from './pages/Logs';
import Sessions from './pages/Sessions';
import { isAuthenticated } from './services/api';

// Protected Route component
const ProtectedRoute = ({ children }) => {
  return isAuthenticated() ? children : <Navigate to="/login" />;
};

function App() {
  return (
    <Router basename="/admin">
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <Dashboard />
            </ProtectedRoute>
          }
        />
        <Route
          path="/devices"
          element={
            <ProtectedRoute>
              <Devices />
            </ProtectedRoute>
          }
        />
        <Route
          path="/profiles"
          element={
            <ProtectedRoute>
              <Profiles />
            </ProtectedRoute>
          }
        />
        <Route
          path="/rules"
          element={
            <ProtectedRoute>
              <Rules />
            </ProtectedRoute>
          }
        />
        <Route
          path="/time-rules"
          element={
            <ProtectedRoute>
              <TimeRules />
            </ProtectedRoute>
          }
        />
        <Route
          path="/usage-limits"
          element={
            <ProtectedRoute>
              <UsageLimits />
            </ProtectedRoute>
          }
        />
        <Route
          path="/bypass-rules"
          element={
            <ProtectedRoute>
              <BypassRules />
            </ProtectedRoute>
          }
        />
        <Route
          path="/logs"
          element={
            <ProtectedRoute>
              <Logs />
            </ProtectedRoute>
          }
        />
        <Route
          path="/sessions"
          element={
            <ProtectedRoute>
              <Sessions />
            </ProtectedRoute>
          }
        />
        <Route path="/" element={<Navigate to="/dashboard" />} />
        <Route path="*" element={<Navigate to="/dashboard" />} />
      </Routes>
    </Router>
  );
}

export default App;
