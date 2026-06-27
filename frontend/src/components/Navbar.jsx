import React, { useState } from 'react';
import {
  Shield, BarChart2, Search, MessageSquare,
  Database, Users, ChevronDown, LogOut,
  User, Lock, Crown, Eye, ListChecks,
  Menu, X, FileSearch
} from 'lucide-react';

const ALL_TABS = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    icon: BarChart2,
    roles: ['admin', 'analyst', 'viewer'],
    desc: 'Available to all roles'
  },
  {
    id: 'alerts',
    label: 'Alerts',
    icon: ListChecks,
    roles: ['admin', 'analyst', 'viewer'],
    desc: 'Read-only alerts and analysis history'
  },
  {
    id: 'analyze',
    label: 'Analyze',
    icon: Search,
    roles: ['admin', 'analyst'],
    desc: 'Admin & Analyst only'
  },
  {
    id: 'chat',
    label: 'SOC Chat',
    icon: MessageSquare,
    roles: ['admin', 'analyst'],
    desc: 'Admin & Analyst only'
  },
  {
    id: 'docs',
    label: 'Knowledge Base',
    icon: Database,
    roles: ['admin', 'analyst'],
    desc: 'Admin & Analyst only'
  },
  {
    id: 'audit',
    label: 'Audit Logs',
    icon: FileSearch,
    roles: ['admin'],
    desc: 'Admin only'
  },
  {
    id: 'users',
    label: 'Users',
    icon: Users,
    roles: ['admin'],
    desc: 'Admin only'
  },
];

const ROLE_CONFIG = {
  admin: {
    color: '#ef4444',
    bg: 'rgba(239,68,68,0.12)',
    icon: Crown,
    label: 'Admin'
  },
  analyst: {
    color: '#3b82f6',
    bg: 'rgba(59,130,246,0.12)',
    icon: Shield,
    label: 'Analyst'
  },
  viewer: {
    color: '#22c55e',
    bg: 'rgba(34,197,94,0.12)',
    icon: Eye,
    label: 'Viewer'
  },
};

export default function Navbar({
  activeTab,
  setActiveTab,
  backendOnline,
  user,
  onLogout,
  allowedTabs
}) {
  const [showMenu, setShowMenu] = useState(false);
  const [showRoleInfo, setShowRoleInfo] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  const rc = ROLE_CONFIG[user?.role] || ROLE_CONFIG.viewer;
  const RoleIcon = rc.icon;

  const visibleTabs = ALL_TABS.filter(tab => allowedTabs?.includes(tab.id));

  const handleTabClick = (tab) => {
    const isAllowed = allowedTabs?.includes(tab.id);
    if (isAllowed) {
      setActiveTab(tab.id);
      setShowMenu(false);
      setShowRoleInfo(false);
      setMobileOpen(false);
    }
  };

  return (
    <nav className="navbar pro-navbar">
      {/* Left: Brand */}
      <div className="navbar-left">
        <div className="navbar-brand">
          <div className="brand-icon-wrap">
            <Shield size={18} color="white" />
          </div>
          <div className="brand-text-wrap">
            <span className="brand-name">SOC ASSISTANT</span>
            <span className="brand-badge">AI-Powered</span>
          </div>
        </div>
      </div>

      {/* Center: Tabs */}
      <div className="navbar-center desktop-only">
        <div className="navbar-tabs center-tabs">
          {visibleTabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;

            return (
              <div
                key={tab.id}
                className="nav-tab-wrap"
                title={tab.label}
              >
                <button
                  className={[
                    'nav-tab',
                    isActive ? 'active' : ''
                  ].join(' ')}
                  onClick={() => handleTabClick(tab)}
                >
                  <Icon size={14} />
                  {tab.label}
                </button>
              </div>
            );
          })}
        </div>
      </div>

      {/* Right: status + role + user */}
      <div className="navbar-right desktop-only">
        <div className="status-dot">
          <div className={`status-dot-circle ${backendOnline ? '' : 'offline'}`} />
          <span>{backendOnline ? 'Online' : 'Offline'}</span>
        </div>

        {user && (
          <div
            className="role-info-pill"
            style={{
              background: rc.bg,
              border: `1px solid ${rc.color}35`,
              color: rc.color
            }}
            onClick={() => {
              setShowRoleInfo(!showRoleInfo);
              setShowMenu(false);
            }}
            title="Your current role and permissions"
          >
            <RoleIcon size={12} />
            <span>{rc.label}</span>

            {showRoleInfo && (
              <div className="role-tooltip">
                <div className="role-tooltip-header">
                  <RoleIcon size={13} />
                  <strong>{rc.label} Permissions</strong>
                </div>
                <ul className="role-tooltip-list">
                  {ALL_TABS.map(t => {
                    const allowed = t.roles.includes(user.role);
                    return (
                      <li key={t.id} className={allowed ? 'allowed' : 'denied'}>
                        {allowed ? '✅' : '🔒'} {t.label}
                      </li>
                    );
                  })}
                </ul>
              </div>
            )}
          </div>
        )}

        {user && (
          <div className="user-menu-wrap">
            <button
              className="user-menu-btn"
              onClick={() => {
                setShowMenu(!showMenu);
                setShowRoleInfo(false);
              }}
            >
              <div
                className="user-avatar"
                style={{
                  background: rc.bg,
                  border: `1px solid ${rc.color}44`,
                  color: rc.color
                }}
              >
                <User size={13} />
              </div>

              <span className="user-name">{user.username}</span>
              <ChevronDown size={12} style={{ color: 'var(--text-muted)' }} />
            </button>

            {showMenu && (
              <div className="user-dropdown">
                <div className="user-dropdown-header">
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <div
                      style={{
                        width: 32,
                        height: 32,
                        borderRadius: 8,
                        background: rc.bg,
                        color: rc.color,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontSize: '1rem',
                        fontWeight: 700
                      }}
                    >
                      {user.username[0].toUpperCase()}
                    </div>
                    <div>
                      <div style={{ fontWeight: 700, fontSize: '0.88rem' }}>
                        {user.username}
                      </div>
                      <div
                        style={{
                          fontSize: '0.72rem',
                          color: rc.color,
                          fontWeight: 600,
                          textTransform: 'uppercase',
                          letterSpacing: '0.06em'
                        }}
                      >
                        {rc.label}
                      </div>
                    </div>
                  </div>
                </div>

                <div className="user-dropdown-permissions">
                  <p className="dropdown-section-label">Your Access</p>
                  {ALL_TABS.map(t => {
                    const allowed = allowedTabs?.includes(t.id);
                    const TIcon = t.icon;
                    return (
                      <div
                        key={t.id}
                        className={`dropdown-perm-item ${allowed ? 'allowed' : 'denied'}`}
                      >
                        <TIcon size={12} />
                        <span>{t.label}</span>
                        {allowed
                          ? <span className="perm-yes">✓</span>
                          : <Lock size={10} className="perm-no" />
                        }
                      </div>
                    );
                  })}
                </div>

                <button
                  className="user-dropdown-item logout"
                  onClick={() => {
                    setShowMenu(false);
                    onLogout();
                  }}
                >
                  <LogOut size={13} />
                  Sign Out
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Mobile toggle */}
      <button
        className="mobile-menu-btn mobile-only"
        onClick={() => {
          setMobileOpen(!mobileOpen);
          setShowMenu(false);
          setShowRoleInfo(false);
        }}
        aria-label="Toggle navigation menu"
      >
        {mobileOpen ? <X size={18} /> : <Menu size={18} />}
      </button>

      {/* Mobile panel */}
      {mobileOpen && (
        <div className="mobile-nav-panel mobile-only">
          <div className="mobile-nav-section">
            <div className="mobile-status-row">
              <div className="status-dot">
                <div className={`status-dot-circle ${backendOnline ? '' : 'offline'}`} />
                <span>{backendOnline ? 'Online' : 'Offline'}</span>
              </div>

              <div
                className="role-info-pill"
                style={{
                  background: rc.bg,
                  border: `1px solid ${rc.color}35`,
                  color: rc.color
                }}
              >
                <RoleIcon size={12} />
                <span>{rc.label}</span>
              </div>
            </div>
          </div>

          <div className="mobile-nav-section">
            {visibleTabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;

              return (
                <button
                  key={tab.id}
                  className={[
                    'mobile-nav-item',
                    isActive ? 'active' : ''
                  ].join(' ')}
                  onClick={() => handleTabClick(tab)}
                >
                  <div className="mobile-nav-item-left">
                    <Icon size={15} />
                    <span>{tab.label}</span>
                  </div>
                </button>
              );
            })}
          </div>

          {user && (
            <div className="mobile-nav-section">
              <div className="mobile-user-card">
                <div
                  className="user-avatar"
                  style={{
                    background: rc.bg,
                    border: `1px solid ${rc.color}44`,
                    color: rc.color
                  }}
                >
                  <User size={13} />
                </div>
                <div>
                  <div className="user-name">{user.username}</div>
                  <div style={{ fontSize: '0.72rem', color: rc.color, fontWeight: 600 }}>
                    {rc.label}
                  </div>
                </div>
              </div>

              <button
                className="mobile-signout-btn"
                onClick={() => {
                  setMobileOpen(false);
                  onLogout();
                }}
              >
                <LogOut size={14} />
                Sign Out
              </button>
            </div>
          )}
        </div>
      )}
    </nav>
  );
}