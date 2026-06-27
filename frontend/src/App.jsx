import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import Dashboard from './components/Dashboard';
import AlertForm from './components/AlertForm';
import ResultPanel from './components/ResultPanel';
import ChatPanel from './components/ChatPanel';
import DocUploadPanel from './components/DocUploadPanel';
import UserManagement from './components/UserManagement';
import AlertsHistory from './components/AlertsHistory';
import AuditLogs from './components/AuditLogs';
import {
  LoginPage,
  SignupPage,
  ForgotPasswordPage
} from './components/AuthPages';
import { Toaster } from 'react-hot-toast';
import { checkHealth } from './services/api';
import axios from 'axios';
import './styles/App.css';

const ROLE_TABS = {
  admin: ['dashboard', 'alerts', 'analyze', 'chat', 'docs', 'audit', 'users'],
  analyst: ['dashboard', 'alerts', 'analyze', 'chat', 'docs'],
  viewer: ['dashboard', 'alerts']
};

function BackendBanner({ status, details }) {
  if (status === 'checking') return (
    <div className="backend-banner checking">
      ⏳ Connecting to backend...
    </div>
  );

  if (status === 'degraded') return (
    <div className="backend-banner checking">
      ⚠️ Backend is running in degraded mode
      {details?.rag_ready === false && <> — RAG not fully ready</>}
    </div>
  );

  if (status === 'offline') return (
    <div className="backend-banner offline">
      <strong>⚠️ Backend Offline</strong>&nbsp;— Run:&nbsp;
      <code>
        python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
      </code>
      &nbsp;then refresh.
    </div>
  );

  return null;
}

function AccessDenied() {
  return (
    <div className="empty-state" style={{ padding: '6rem 2rem' }}>
      <div className="empty-state-icon">🔒</div>
      <h2 style={{ color: 'var(--critical)', marginBottom: '0.5rem' }}>
        Access Denied
      </h2>
      <p>
        You do not have permission to access this section.<br />
        Contact your administrator to request access.
      </p>
    </div>
  );
}

export default function App() {
  const [authView, setAuthView] = useState('login');
  const [user, setUser] = useState(null);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [analysisResult, setAnalysisResult] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [backendStatus, setBackendStatus] = useState('checking');
  const [backendDetails, setBackendDetails] = useState(null);

  useEffect(() => {
    const token = localStorage.getItem('soc_token');
    const username = localStorage.getItem('soc_username');
    const role = localStorage.getItem('soc_role');
    const user_id = localStorage.getItem('soc_user_id');

    if (token && username && role) {
      axios
        .get('/api/auth/verify', {
          headers: { Authorization: `Bearer ${token}` }
        })
        .then(() => {
          setUser({ token, username, role, user_id });
          setActiveTab('dashboard');
        })
        .catch(() => {
          localStorage.clear();
          setUser(null);
        });
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    const check = async () => {
      try {
        const res = await checkHealth();
        const data = res.data || {};

        if (!cancelled) {
          setBackendDetails(data);
          setBackendStatus(data.status === 'degraded' ? 'degraded' : 'online');
        }
      } catch {
        if (!cancelled) {
          setBackendStatus('offline');
          setBackendDetails(null);
        }
      }
    };

    check();
    const interval = setInterval(check, 30000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const handleLogin = (userData) => {
    setUser(userData);
    setActiveTab('dashboard');
  };

  const handleLogout = () => {
    localStorage.removeItem('soc_token');
    localStorage.removeItem('soc_username');
    localStorage.removeItem('soc_role');
    localStorage.removeItem('soc_user_id');
    setUser(null);
    setAuthView('login');
    setAnalysisResult(null);
  };

  const handleTabChange = (tab) => {
    if (!user) return;
    const allowed = ROLE_TABS[user.role] || [];
    if (allowed.includes(tab)) {
      setActiveTab(tab);
    }
  };

  if (!user) {
    return (
      <>
        <Toaster position="top-right" />
        {authView === 'login' && (
          <LoginPage
            onLogin={handleLogin}
            onSwitchToSignup={() => setAuthView('signup')}
            onForgotPassword={() => setAuthView('forgot')}
          />
        )}
        {authView === 'signup' && (
          <SignupPage
            onSignupSuccess={() => setAuthView('login')}
            onSwitchToLogin={() => setAuthView('login')}
          />
        )}
        {authView === 'forgot' && (
          <ForgotPasswordPage
            onBackToLogin={() => setAuthView('login')}
          />
        )}
      </>
    );
  }

  const allowedTabs = ROLE_TABS[user.role] || ['dashboard'];
  const canAccess = (tab) => allowedTabs.includes(tab);

  return (
    <div className="app">
      <Toaster position="top-right" />

      <Navbar
        activeTab={activeTab}
        setActiveTab={handleTabChange}
        backendOnline={backendStatus === 'online' || backendStatus === 'degraded'}
        user={user}
        onLogout={handleLogout}
        allowedTabs={allowedTabs}
      />

      <BackendBanner status={backendStatus} details={backendDetails} />

      <main className="main-content">
        {activeTab === 'dashboard' && (
          <Dashboard user={user} />
        )}

        {activeTab === 'alerts' && (
          canAccess('alerts')
            ? <AlertsHistory user={user} />
            : <AccessDenied />
        )}

        {activeTab === 'analyze' && (
          canAccess('analyze') ? (
            <div className="analyze-layout">
              <AlertForm
                setResult={setAnalysisResult}
                setIsAnalyzing={setIsAnalyzing}
                isAnalyzing={isAnalyzing}
                user={user}
              />
              {(analysisResult || isAnalyzing) && (
                <ResultPanel
                  result={analysisResult}
                  isLoading={isAnalyzing}
                />
              )}
            </div>
          ) : <AccessDenied />
        )}

        {activeTab === 'chat' && (
          canAccess('chat')
            ? <ChatPanel user={user} />
            : <AccessDenied />
        )}

        {activeTab === 'docs' && (
          canAccess('docs') ? (
            <div className="kb-page-wrap">
              <DocUploadPanel />
            </div>
          ) : <AccessDenied />
        )}

        {activeTab === 'audit' && (
          canAccess('audit')
            ? <AuditLogs />
            : <AccessDenied />
        )}

        {activeTab === 'users' && (
          canAccess('users')
            ? <UserManagement currentUser={user} />
            : <AccessDenied />
        )}
      </main>
    </div>
  );
}