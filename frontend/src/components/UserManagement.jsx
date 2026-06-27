import React, { useState, useEffect, useCallback } from 'react';
import {
  Users, Shield, UserCheck, Eye, Trash2,
  ToggleLeft, ToggleRight, AlertCircle,
  RefreshCw, Crown
} from 'lucide-react';
import axios from 'axios';
import toast from 'react-hot-toast';

const ROLE_CONFIG = {
  admin:   { color: '#ef4444', label: '🔴 Admin',   bg: 'rgba(239,68,68,0.1)' },
  analyst: { color: '#3b82f6', label: '🔵 Analyst', bg: 'rgba(59,130,246,0.1)' },
  viewer:  { color: '#22c55e', label: '🟢 Viewer',  bg: 'rgba(34,197,94,0.1)' },
};

export default function UserManagement({ currentUser }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const authHeaders = () => ({
    headers: {
      Authorization: `Bearer ${localStorage.getItem('soc_token')}`
    }
  });

  const handleAuthFailure = useCallback((message) => {
    toast.error(message || 'Session expired. Please sign in again.');
    localStorage.removeItem('soc_token');
    localStorage.removeItem('soc_username');
    localStorage.removeItem('soc_role');
    localStorage.removeItem('soc_user_id');
    window.location.reload();
  }, []);

  const extractError = (err, fallback) =>
    err?.response?.data?.detail || err?.message || fallback;

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    try {
      const res = await axios.get('/api/auth/users', authHeaders());
      setUsers(res.data.users || []);
      setError('');
    } catch (err) {
      if (err.response?.status === 401) {
        handleAuthFailure('Your session has expired. Please sign in again.');
        return;
      }
      if (err.response?.status === 403) {
        setError('Access denied. Only admins can view user management.');
        return;
      }
      setError(extractError(err, 'Failed to load users'));
    } finally {
      setLoading(false);
    }
  }, [handleAuthFailure]);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  const handleRoleChange = async (userId, username, currentRole, newRole) => {
    if (currentRole === newRole) return;

    const confirmed = window.confirm(
      `Change role for "${username}" from "${currentRole}" to "${newRole}"?`
    );
    if (!confirmed) return;

    try {
      await axios.put(
        `/api/auth/users/${userId}/role`,
        { role: newRole },
        authHeaders()
      );
      toast.success(`Role updated for "${username}" → ${newRole}`);
      fetchUsers();
    } catch (err) {
      if (err.response?.status === 401) {
        handleAuthFailure('Your session has expired. Please sign in again.');
        return;
      }
      toast.error(extractError(err, 'Role update failed'));
    }
  };

  const handleToggleActive = async (userId, username, isActive) => {
    const action = isActive ? 'deactivate' : 'activate';
    const confirmed = window.confirm(
      `${action[0].toUpperCase() + action.slice(1)} user "${username}"?`
    );
    if (!confirmed) return;

    try {
      const res = await axios.put(
        `/api/auth/users/${userId}/toggle`,
        {},
        authHeaders()
      );
      toast.success(res.data.message);
      fetchUsers();
    } catch (err) {
      if (err.response?.status === 401) {
        handleAuthFailure('Your session has expired. Please sign in again.');
        return;
      }
      toast.error(extractError(err, 'Toggle failed'));
    }
  };

  const handleDelete = async (userId, username) => {
    const confirmed = window.confirm(
      `Permanently delete user "${username}"?\n\nThis action cannot be undone.`
    );
    if (!confirmed) return;

    try {
      await axios.delete(`/api/auth/users/${userId}`, authHeaders());
      toast.success(`User "${username}" deleted`);
      fetchUsers();
    } catch (err) {
      if (err.response?.status === 401) {
        handleAuthFailure('Your session has expired. Please sign in again.');
        return;
      }
      toast.error(extractError(err, 'Delete failed'));
    }
  };

  if (loading) {
    return (
      <div className="loading-text">
        <RefreshCw size={16} style={{ display: 'inline', marginRight: 8 }} />
        Loading users...
      </div>
    );
  }

  if (error) {
    return (
      <div className="auth-alert auth-alert-error">
        <AlertCircle size={14} /> {error}
      </div>
    );
  }

  const totalUsers = users.length;
  const activeUsers = users.filter(u => u.is_active).length;
  const adminUsers = users.filter(u => u.role === 'admin').length;

  return (
    <div className="user-mgmt">
      {/* Header */}
      <div className="dashboard-header">
        <h1>👥 User Management</h1>
        <p>Manage user accounts, roles, and access permissions</p>
      </div>

      {/* Stats */}
      <div
        className="stat-grid"
        style={{ gridTemplateColumns: 'repeat(3,1fr)', marginBottom: '1.5rem' }}
      >
        {[
          { label: 'Total Users', value: totalUsers, icon: Users, color: '#3b82f6' },
          { label: 'Active', value: activeUsers, icon: UserCheck, color: '#22c55e' },
          { label: 'Admins', value: adminUsers, icon: Crown, color: '#ef4444' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="stat-card">
            <div className="stat-icon" style={{ background: `${color}18`, color }}>
              <Icon size={18} />
            </div>
            <div className="stat-value">{value}</div>
            <div className="stat-label">{label}</div>
          </div>
        ))}
      </div>

      {/* Safety Note */}
      <div
        className="auth-info-banner"
        style={{ margin: '0 0 1rem 0' }}
      >
        <Shield size={14} />
        <span>
          <strong>Safety rules:</strong> the last remaining admin cannot be demoted,
          deactivated, or deleted. Self-demotion and self-deletion are also blocked.
        </span>
      </div>

      {/* Users Table */}
      <div className="alerts-table-container">
        <div className="table-header">
          <h2>All Users</h2>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="clear-btn" onClick={fetchUsers}>
              <RefreshCw size={13} /> Refresh
            </button>
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="alerts-table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>

            <tbody>
              {users.map(user => {
                const isSelf = user.id === currentUser.user_id;
                const rc = ROLE_CONFIG[user.role] || ROLE_CONFIG.viewer;

                return (
                  <tr key={user.id}>
                    {/* Username */}
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div
                          style={{
                            width: 28,
                            height: 28,
                            borderRadius: 8,
                            background: rc.bg,
                            color: rc.color,
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            fontSize: '0.7rem',
                            fontWeight: 700
                          }}
                        >
                          {user.username[0].toUpperCase()}
                        </div>

                        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                          {user.username}
                          {isSelf && (
                            <span
                              style={{
                                marginLeft: 6,
                                fontSize: '0.68rem',
                                color: 'var(--text-muted)',
                                background: 'rgba(255,255,255,0.05)',
                                padding: '1px 6px',
                                borderRadius: 10
                              }}
                            >
                              you
                            </span>
                          )}
                        </span>
                      </div>
                    </td>

                    {/* Email */}
                    <td style={{ color: 'var(--text-secondary)', fontSize: '0.82rem' }}>
                      {user.email}
                    </td>

                    {/* Role selector */}
                    <td>
                      {isSelf ? (
                        <span
                          className="tag"
                          style={{
                            background: rc.bg,
                            color: rc.color,
                            border: `1px solid ${rc.color}40`
                          }}
                        >
                          {rc.label}
                        </span>
                      ) : (
                        <select
                          value={user.role}
                          onChange={(e) =>
                            handleRoleChange(user.id, user.username, user.role, e.target.value)
                          }
                          style={{
                            background: rc.bg,
                            color: rc.color,
                            border: `1px solid ${rc.color}40`,
                            borderRadius: 20,
                            padding: '0.18rem 0.6rem',
                            fontSize: '0.75rem',
                            fontWeight: 700,
                            cursor: 'pointer'
                          }}
                        >
                          <option value="admin">Admin</option>
                          <option value="analyst">Analyst</option>
                          <option value="viewer">Viewer</option>
                        </select>
                      )}
                    </td>

                    {/* Status */}
                    <td>
                      <span className={`tag ${user.is_active ? 'tag-low' : 'tag-critical'}`}>
                        {user.is_active ? '✅ Active' : '❌ Inactive'}
                      </span>
                    </td>

                    {/* Created */}
                    <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                      {user.created_at
                        ? new Date(user.created_at).toLocaleDateString()
                        : '—'}
                    </td>

                    {/* Actions */}
                    <td>
                      {!isSelf && (
                        <div style={{ display: 'flex', gap: 6 }}>
                          <button
                            className="clear-btn"
                            onClick={() => handleToggleActive(user.id, user.username, user.is_active)}
                            title={user.is_active ? 'Deactivate user' : 'Activate user'}
                          >
                            {user.is_active ? (
                              <ToggleRight size={13} style={{ color: 'var(--low)' }} />
                            ) : (
                              <ToggleLeft size={13} style={{ color: 'var(--critical)' }} />
                            )}
                          </button>

                          <button
                            className="clear-btn"
                            onClick={() => handleDelete(user.id, user.username)}
                            title="Delete user"
                            style={{ borderColor: 'rgba(239,68,68,0.3)' }}
                          >
                            <Trash2 size={13} style={{ color: 'var(--critical)' }} />
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}

              {users.length === 0 && (
                <tr>
                  <td colSpan="6">
                    <div className="empty-state" style={{ padding: '2rem 1rem' }}>
                      <div className="empty-state-icon">👤</div>
                      <p>No users found.</p>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* RBAC Reference */}
      <div className="rbac-reference">
        <h3>🔐 Role Permissions Reference</h3>

        <div className="rbac-grid">
          {[
            {
              role: 'Admin',
              color: '#ef4444',
              icon: Crown,
              permissions: [
                '✅ Full dashboard access',
                '✅ Analyze security alerts',
                '✅ Use AI SOC Chat',
                '✅ Manage knowledge base',
                '✅ Export reports (PDF/CSV)',
                '✅ Manage all users',
                '✅ Change user roles',
                '✅ Delete alerts',
              ]
            },
            {
              role: 'Analyst',
              color: '#3b82f6',
              icon: Shield,
              permissions: [
                '✅ Full dashboard access',
                '✅ Analyze security alerts',
                '✅ Use AI SOC Chat',
                '✅ Manage knowledge base',
                '✅ Export reports (PDF/CSV)',
                '❌ Cannot manage users',
                '❌ Cannot change roles',
                '❌ Cannot delete alerts',
              ]
            },
            {
              role: 'Viewer',
              color: '#22c55e',
              icon: Eye,
              permissions: [
                '✅ Read-only dashboard',
                '✅ View summary/statistics',
                '✅ Export reports (CSV)',
                '❌ Cannot analyze alerts',
                '❌ Cannot use AI Chat',
                '❌ Cannot upload documents',
                '❌ Cannot manage users',
                '❌ Cannot delete anything',
              ]
            },
          ].map(({ role, color, icon: Icon, permissions }) => (
            <div
              key={role}
              className="rbac-card"
              style={{ borderColor: `${color}25` }}
            >
              <div className="rbac-card-header" style={{ color }}>
                <Icon size={16} />
                <strong>{role}</strong>
              </div>

              <ul className="rbac-list">
                {permissions.map((p, i) => (
                  <li
                    key={i}
                    style={{
                      color: p.startsWith('✅')
                        ? 'var(--text-secondary)'
                        : 'var(--text-muted)'
                    }}
                  >
                    {p}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}