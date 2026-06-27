import React, { useState } from 'react';
import { Shield, Lock, User, Eye, EyeOff, AlertCircle } from 'lucide-react';
import axios from 'axios';

export default function LoginPage({ onLogin }) {
  const [form,    setForm]    = useState({ username: '', password: '' });
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState('');
  const [showPwd, setShowPwd] = useState(false);

  const DEMO_ACCOUNTS = [
    { username: 'admin',   password: 'admin123',   role: 'Admin',   color: '#ef4444' },
    { username: 'analyst', password: 'analyst123', role: 'Analyst', color: '#3b82f6' },
    { username: 'viewer',  password: 'viewer123',  role: 'Viewer',  color: '#22c55e' },
  ];

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const res = await axios.post('/api/auth/login', form);
      const { access_token, username, role } = res.data;

      localStorage.setItem('soc_token',    access_token);
      localStorage.setItem('soc_username', username);
      localStorage.setItem('soc_role',     role);

      onLogin({ username, role, token: access_token });
    } catch (err) {
      setError(
        err.response?.data?.detail ||
        'Login failed. Check your credentials.'
      );
    } finally {
      setLoading(false);
    }
  };

  const quickLogin = (account) => {
    setForm({ username: account.username, password: account.password });
  };

  return (
    <div className="login-page">
      {/* Background */}
      <div className="login-bg">
        <div className="login-bg-glow" />
      </div>

      <div className="login-container">
        {/* Logo */}
        <div className="login-logo">
          <div className="login-logo-icon">
            <Shield size={32} color="white" />
          </div>
          <h1 className="login-title">SOC ASSISTANT</h1>
          <p className="login-subtitle">AI-Powered Security Operations Center</p>
        </div>

        {/* Card */}
        <div className="login-card">
          <div className="login-card-header">
            <Lock size={16} />
            <span>Secure Sign In</span>
          </div>

          {/* Error */}
          {error && (
            <div className="login-error">
              <AlertCircle size={14} />
              {error}
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="login-form">
            <div className="form-group">
              <label>Username</label>
              <div className="input-icon-wrap">
                <User size={15} className="input-icon" />
                <input
                  type="text"
                  value={form.username}
                  onChange={e => setForm(p => ({ ...p, username: e.target.value }))}
                  placeholder="Enter username"
                  required
                  autoFocus
                />
              </div>
            </div>

            <div className="form-group">
              <label>Password</label>
              <div className="input-icon-wrap">
                <Lock size={15} className="input-icon" />
                <input
                  type={showPwd ? 'text' : 'password'}
                  value={form.password}
                  onChange={e => setForm(p => ({ ...p, password: e.target.value }))}
                  placeholder="Enter password"
                  required
                />
                <button
                  type="button"
                  className="pwd-toggle"
                  onClick={() => setShowPwd(!showPwd)}
                >
                  {showPwd ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              className="submit-btn"
              disabled={loading}
            >
              {loading
                ? <><span className="spinner" /> Authenticating...</>
                : <><Lock size={15} /> Sign In</>
              }
            </button>
          </form>

          {/* Demo accounts */}
          <div className="demo-accounts">
            <p className="demo-label">Quick Demo Login:</p>
            <div className="demo-btns">
              {DEMO_ACCOUNTS.map(acc => (
                <button
                  key={acc.username}
                  className="demo-btn"
                  style={{ borderColor: `${acc.color}40`, color: acc.color }}
                  onClick={() => quickLogin(acc)}
                  type="button"
                >
                  {acc.role}
                </button>
              ))}
            </div>
          </div>
        </div>

        <p className="login-footer">
          🔒 All sessions are JWT-authenticated and time-limited
        </p>
      </div>
    </div>
  );
}