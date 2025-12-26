import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { logout } from '../services/api';

const Sidebar = () => {
  const location = useLocation();

  const isActive = (path) => {
    return location.pathname === path ? 'active' : '';
  };

  const handleLogout = () => {
    if (window.confirm('Are you sure you want to logout?')) {
      logout();
    }
  };

  return (
    <div className="sidebar">
      <div className="sidebar-header">
        <h2>KProxy Admin</h2>
      </div>
      <nav className="sidebar-nav">
        <Link to="/dashboard" className={`nav-item ${isActive('/dashboard')}`}>
          <span className="nav-icon">📊</span>
          Dashboard
        </Link>
        <Link to="/devices" className={`nav-item ${isActive('/devices')}`}>
          <span className="nav-icon">📱</span>
          Devices
        </Link>
        <Link to="/profiles" className={`nav-item ${isActive('/profiles')}`}>
          <span className="nav-icon">👤</span>
          Profiles
        </Link>
        <Link to="/rules" className={`nav-item ${isActive('/rules')}`}>
          <span className="nav-icon">📋</span>
          Rules
        </Link>
        <Link to="/logs" className={`nav-item ${isActive('/logs')}`}>
          <span className="nav-icon">📄</span>
          Logs
        </Link>
      </nav>
      <div className="sidebar-footer">
        <button onClick={handleLogout} className="logout-btn">
          <span className="nav-icon">🚪</span>
          Logout
        </button>
      </div>
    </div>
  );
};

export default Sidebar;
