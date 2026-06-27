// AuthPages.jsx
import React, { useState, useEffect } from 'react';
import {
  Shield, Lock, User, Mail, Eye, EyeOff,
  AlertCircle, CheckCircle, XCircle,
  ArrowRight, UserPlus, ArrowLeft
} from 'lucide-react';

import {
  signInWithPopup,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut
} from "firebase/auth";

import {
  auth,
  googleProvider
} from "../firebase/firebase";

import axios from 'axios';

/* ── Block clipboard actions on sensitive password fields ───────────────── */
const blockClipboard = (e) => {
  e.preventDefault();
};

/* ── Password strength checker ───────────────────────────────────────────── */
function PasswordStrength({ password }) {
  const rules = [
    { id: 'length', label: 'At least 8 characters', test: (p) => p.length >= 8 },
    { id: 'uppercase', label: 'Uppercase letter (A–Z)', test: (p) => /[A-Z]/.test(p) },
    { id: 'lowercase', label: 'Lowercase letter (a–z)', test: (p) => /[a-z]/.test(p) },
    { id: 'number', label: 'Number (0–9)', test: (p) => /\d/.test(p) },
    {
      id: 'special',
      label: 'Special character (!@#$...)',
      test: (p) => /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(p)
    },
  ];

  if (!password) return null;

  const passed = rules.filter(r => r.test(password)).length;
  const pct = (passed / rules.length) * 100;

  const color =
    pct <= 40 ? 'var(--critical)' :
    pct <= 60 ? 'var(--high)' :
    pct <= 80 ? 'var(--medium)' :
    'var(--low)';

  const label =
    pct <= 40 ? 'Weak' :
    pct <= 60 ? 'Fair' :
    pct <= 80 ? 'Good' :
    'Strong';

  return (
    <div className="pwd-strength">
      <div className="pwd-strength-bar-wrap">
        <div className="pwd-strength-bar" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="pwd-strength-label" style={{ color }}>
        {label}
      </span>
      <div className="pwd-rules">
        {rules.map(rule => {
          const ok = rule.test(password);
          return (
            <div key={rule.id} className={`pwd-rule ${ok ? 'pass' : 'fail'}`}>
              {ok ? <CheckCircle size={11} /> : <XCircle size={11} />}
              {rule.label}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ── Reusable alert message ──────────────────────────────────────────────── */
function AlertMsg({ type, message }) {
  if (!message) return null;
  const isError = type === 'error';
  return (
    <div className={`auth-alert ${isError ? 'auth-alert-error' : 'auth-alert-success'}`}>
      {isError ? <AlertCircle size={14} /> : <CheckCircle size={14} />}
      <span>{message}</span>
    </div>
  );
}

/* ── Shared page wrapper ─────────────────────────────────────────────────── */
function AuthPageWrapper({ subtitle, children }) {
  return (
    <div className="auth-page">
      <div className="auth-bg">
        <div className="auth-bg-glow" />
        <div className="auth-bg-grid" />
      </div>

      <div className="auth-container">
        <div className="auth-logo">
          <div className="auth-logo-icon">
            <Shield size={32} color="white" />
          </div>
          <h1 className="auth-title">SOC ASSISTANT</h1>
          <p className="auth-subtitle">{subtitle}</p>
        </div>
        {children}
        <p className="auth-footer">
          🔒 JWT-authenticated · bcrypt hashed passwords · Role-based access
        </p>
      </div>
    </div>
  );
}

/*
═════════════════════════════════════════════════════════
═
LOGIN PAGE
═════════════════════════════════════════════════════════
═
*/
export function LoginPage({ onLogin, onSwitchToSignup, onForgotPassword }) {
  const [form, setForm] = useState({ username: '', password: '' });

  // FIX: separate loading states
  const [loginLoading, setLoginLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);

  const [error, setError] = useState('');
  const [showPwd, setShowPwd] = useState(false);

  const handleChange = (e) =>
    setForm(p => ({ ...p, [e.target.name]: e.target.value }));

  // ============================================================
  // GOOGLE LOGIN BUTTON (Firebase -> backend JWT exchange)
  // ============================================================
  const handleGoogleLogin = async () => {
    setError('');
    setGoogleLoading(true);

    try {
      const result = await signInWithPopup(auth, googleProvider);

      const user = result.user;
      const userEmail =
        user.email ||
        user.providerData?.[0]?.email ||
        user.reloadUserInfo?.email ||
        null;

      console.log("ReloadUserInfo Email:", user.reloadUserInfo?.email);

      // Force refresh token
      const firebaseToken = await user.getIdToken(true);

      // ─────────────────────────────────────────────────────────
      // TEMPORARY DEBUG (per instructions): log payload before axios
      // ─────────────────────────────────────────────────────────
      const payload = {
        firebase_token: firebaseToken,
        email: userEmail
      };

      const res = await axios.post('/api/auth/firebase-login', payload);

      const { access_token, user_id, username, role } = res.data;

      localStorage.setItem('soc_token', access_token);
      localStorage.setItem('soc_user_id', user_id);
      localStorage.setItem('soc_username', username);
      localStorage.setItem('soc_role', role);

      onLogin({ token: access_token, user_id, username, role });
    } catch (err) {
      console.error(err);
      setError(
        err.response?.data?.detail ||
        err.message ||
        'Google login failed.'
      );
    } finally {
      setGoogleLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!form.username.trim()) {
      setError('Username is required');
      return;
    }
    if (!form.password) {
      setError('Password is required');
      return;
    }

    setLoginLoading(true);

    try {
      const res = await axios.post('/api/auth/login', {
        username: form.username,
        password: form.password
      });

      const { access_token, user_id, username, role } = res.data;

      localStorage.setItem('soc_token', access_token);
      localStorage.setItem('soc_user_id', user_id);
      localStorage.setItem('soc_username', username);
      localStorage.setItem('soc_role', role);

      onLogin({ token: access_token, user_id, username, role });
    } catch (err) {
      setError(err.response?.data?.detail || 'Login failed. Please check your credentials.');
    } finally {
      setLoginLoading(false);
    }
  };

  return (
    <AuthPageWrapper subtitle="AI-Powered Security Operations Center">
      <div className="auth-card">
        <div className="auth-card-header">
          <Lock size={15} />
          <span>Sign In to Your Account</span>
        </div>

        <form onSubmit={handleSubmit} autoComplete="off" className="auth-form">
          <AlertMsg type="error" message={error} />

          {/* Username */}
          <div className="form-group">
            <label htmlFor="login_username">
              Username <span className="req">*</span>
            </label>

            <div className="auth-input-wrap">
              <User size={14} className="auth-input-icon" />
              <input
                id="login_username"
                type="text"
                name="username"
                value={form.username}
                onChange={handleChange}
                placeholder="Enter your username"
                autoComplete="off"
                autoFocus
                required
              />
            </div>
          </div>

          {/* Password */}
          <div className="form-group">
            <label htmlFor="login_password">
              Password <span className="req">*</span>
            </label>
            <div className="auth-input-wrap">
              <Lock size={14} className="auth-input-icon" />
              <input
                id="login_password"
                type={showPwd ? 'text' : 'password'}
                name="password"
                value={form.password}
                onChange={handleChange}
                placeholder="Enter your password"
                autoComplete="new-password"
                required
                onPaste={blockClipboard}
                onCopy={blockClipboard}
                onCut={blockClipboard}
              />
              <button
                type="button"
                className="pwd-toggle"
                onClick={() => setShowPwd(p => !p)}
                tabIndex={-1}
              >
                {showPwd ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>

            {onForgotPassword && (
              <button
                type="button"
                className="auth-switch-btn"
                style={{ fontSize: '0.75rem', alignSelf: 'flex-end', marginTop: '0.3rem' }}
                onClick={onForgotPassword}
              >
                Forgot password?
              </button>
            )}
          </div>

          <button type="submit" className="submit-btn" disabled={loginLoading}>
            {loginLoading
              ? <><span className="spinner" /> Signing in...</>
              : <><ArrowRight size={15} /> Sign In</>
            }
          </button>

          {/* OAuth divider + Google button (new UI) */}
          <div className="oauth-divider">
            <span>or continue with</span>
          </div>
          <div className="google-login-wrap">
            <button
              type="button"
              className="google-btn"
              onClick={handleGoogleLogin}
              disabled={googleLoading}
            >
              {googleLoading ? (
                <span className="spinner" />
              ) : (
                <img
                  src="https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg"
                  alt="Google"
                  className="google-icon"
                />
              )}
            </button>
          </div>
        </form>

        <div className="auth-switch">
          <span>Don't have an account?</span>
          <button className="auth-switch-btn" onClick={onSwitchToSignup}>
            Create Account
          </button>
        </div>
      </div>
    </AuthPageWrapper>
  );
}

/*
═════════════════════════════════════════════════════════
═
SIGNUP PAGE
═════════════════════════════════════════════════════════
═
*/
export function SignupPage({ onSignupSuccess, onSwitchToLogin, onLogin }) {
  const [form, setForm] = useState({
    username: '',
    email: '',
    password: '',
    confirm: '',
    role: 'analyst'
  });

  // FIX: separate loading states (signup submit vs google)
  const [loginLoading, setLoginLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);

  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const [showPwd, setShowPwd] = useState(false);
  const [showConf, setShowConf] = useState(false);

  const [touched, setTouched] = useState({});
  const [isFirstUser, setIsFirstUser] = useState(false);

  useEffect(() => {
    axios.get('/api/auth/signup-check')
      .then(res => setIsFirstUser(res.data?.is_first_user === true))
      .catch(() => setIsFirstUser(false));
  }, []);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setForm(p => ({ ...p, [name]: value }));
    setTouched(p => ({ ...p, [name]: true }));
    setError('');
  };

  const getFieldError = (field) => {
    if (!touched[field]) return '';

    switch (field) {
      case 'username':
        if (!form.username) return 'Username is required';
        if (form.username.length < 3) return 'Minimum 3 characters';
        if (form.username.length > 30) return 'Maximum 30 characters';
        if (!/^[a-zA-Z0-9_]+$/.test(form.username))
          return 'Only letters, numbers, underscores allowed';
        return '';
      case 'email':
        if (!form.email) return 'Email is required';
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email))
          return 'Invalid email format (e.g. name@company.com)';
        return '';
      case 'confirm':
        if (!form.confirm) return 'Please confirm your password';
        if (form.confirm !== form.password) return 'Passwords do not match';
        return '';
      default:
        return '';
    }
  };

  const isFormValid = () => {
    const pwdRules = [
      form.password.length >= 8,
      /[A-Z]/.test(form.password),
      /[a-z]/.test(form.password),
      /\d/.test(form.password),
      /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(form.password)
    ];

    return (
      form.username.length >= 3 &&
      /^[a-zA-Z0-9_]+$/.test(form.username) &&
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email) &&
      pwdRules.every(Boolean) &&
      form.password === form.confirm
    );
  };

  // Google sign-in from signup page (same flow as login)
  const handleGoogleLogin = async () => {
    setError('');
    setGoogleLoading(true);

    try {
      const result = await signInWithPopup(auth, googleProvider);

      const user = result.user;
      const userEmail =
        user.email ||
        user.providerData?.[0]?.email ||
        user.reloadUserInfo?.email ||
        null;

      console.log("Resolved Google Email:", userEmail);

      const firebaseToken = await user.getIdToken(true);

      // ─────────────────────────────────────────────────────────
      // TEMPORARY DEBUG (per instructions): log payload before axios
      // ─────────────────────────────────────────────────────────
      const payload = {
        firebase_token: firebaseToken,
        email: userEmail
      };

      console.log("REQUEST PAYLOAD", payload);

      const res = await axios.post('/api/auth/firebase-login', payload);

      const { access_token, user_id, username, role } = res.data;

      localStorage.setItem('soc_token', access_token);
      localStorage.setItem('soc_user_id', user_id);
      localStorage.setItem('soc_username', username);
      localStorage.setItem('soc_role', role);

      onSignupSuccess?.({
        token: access_token,
        user_id,
        username,
        role
      });
    } catch (err) {
      setError(
        err.response?.data?.detail ||
        err.message ||
        'Google signup failed.'
      );
    } finally {
      setGoogleLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    setTouched({
      username: true,
      email: true,
      password: true,
      confirm: true
    });

    if (!isFormValid()) {
      setError('Please fix all validation errors before submitting.');
      return;
    }

    setLoginLoading(true);

    try {
      const res = await axios.post('/api/auth/signup', {
        username: form.username.trim().toLowerCase(),
        email: form.email.trim().toLowerCase(),
        password: form.password,
        role: isFirstUser ? 'admin' : form.role
      });

      setSuccess(
        res.data.is_first_admin
          ? '🎉 Admin account created! Redirecting to sign in...'
          : '✅ Account created successfully! Redirecting to sign in...'
      );

      setTimeout(() => onSignupSuccess?.(), 2000);
    } catch (err) {
      const detail = err.response?.data?.detail;
      if (Array.isArray(detail)) setError(detail.map(e => e.msg).join(', '));
      else setError(detail || 'Registration failed. Please try again.');
    } finally {
      setLoginLoading(false);
    }
  };

  const roles = [
    { value: 'analyst', label: '🔍Analyst', desc: 'Analyze alerts, AI chat, knowledge base' },
    { value: 'viewer', label: '👁️Viewer', desc: 'Read-only dashboard access' },
  ];

  return (
    <AuthPageWrapper subtitle="Create your account">
      <div className="auth-card" style={{ maxWidth: 480 }}>
        <div className="auth-card-header">
          <UserPlus size={15} />
          <span>
            {isFirstUser ? '🛡️ Create First Admin Account' : 'Register New Account'}
          </span>
        </div>

        {isFirstUser && (
          <div className="auth-info-banner">
            <Shield size={14} />
            <span>
              No users exist yet. This account will automatically be granted <strong>Admin</strong>
              privileges.
            </span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="auth-form">
          <AlertMsg type="error" message={error} />
          <AlertMsg type="success" message={success} />

          {/* Username */}
          <div className="form-group">
            <label htmlFor="signup_username">
              Username <span className="req">*</span>
            </label>
            <div className="auth-input-wrap">
              <User size={14} className="auth-input-icon" />
              <input
                id="signup_username"
                type="text"
                name="username"
                value={form.username}
                onChange={handleChange}
                placeholder="e.g. john_smith"
                autoComplete="username"
                autoFocus
                className={getFieldError('username') ? 'input-error' : ''}
              />
            </div>
            {getFieldError('username') && (
              <span className="field-error">{getFieldError('username')}</span>
            )}
            <span className="field-hint">
              3–30 characters · letters, numbers, underscores only
            </span>
          </div>

          {/* Email */}
          <div className="form-group">
            <label htmlFor="signup_email">
              Email Address <span className="req">*</span>
            </label>
            <div className="auth-input-wrap">
              <Mail size={14} className="auth-input-icon" />
              <input
                id="signup_email"
                type="email"
                name="email"
                value={form.email}
                onChange={handleChange}
                placeholder="e.g. john@company.com"
                autoComplete="email"
                className={getFieldError('email') ? 'input-error' : ''}
              />
            </div>
            {getFieldError('email') && (
              <span className="field-error">{getFieldError('email')}</span>
            )}
          </div>

          {/* Password */}
          <div className="form-group">
            <label htmlFor="signup_password">
              Password <span className="req">*</span>
            </label>
            <div className="auth-input-wrap">
              <Lock size={14} className="auth-input-icon" />
              <input
                id="signup_password"
                type={showPwd ? 'text' : 'password'}
                name="password"
                value={form.password}
                onChange={handleChange}
                placeholder="Create a strong password"
                autoComplete="new-password"
                onPaste={blockClipboard}
                onCopy={blockClipboard}
                onCut={blockClipboard}
              />
              <button
                type="button"
                className="pwd-toggle"
                onClick={() => setShowPwd(p => !p)}
                tabIndex={-1}
              >
                {showPwd ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
            <PasswordStrength password={form.password} />
          </div>

          {/* Confirm Password */}
          <div className="form-group">
            <label htmlFor="signup_confirm_password">
              Confirm Password <span className="req">*</span>
            </label>
            <div className="auth-input-wrap">
              <Lock size={14} className="auth-input-icon" />
              <input
                id="signup_confirm_password"
                type={showConf ? 'text' : 'password'}
                name="confirm"
                value={form.confirm}
                onChange={handleChange}
                placeholder="Re-enter your password"
                autoComplete="new-password"
                className={getFieldError('confirm') ? 'input-error' : ''}
                onPaste={blockClipboard}
                onCopy={blockClipboard}
                onCut={blockClipboard}
              />
              <button
                type="button"
                className="pwd-toggle"
                onClick={() => setShowConf(p => !p)}
                tabIndex={-1}
              >
                {showConf ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
            {getFieldError('confirm') && (
              <span className="field-error">{getFieldError('confirm')}</span>
            )}
          </div>

          {!isFirstUser && (
            <div className="form-group">
              <label htmlFor="signup_role_dummy">Role</label>

              {/* Hidden dummy input to associate label with a "form field" without changing UI/behavior */}
              <input
                id="signup_role_dummy"
                type="text"
                value={form.role}
                readOnly
                tabIndex={-1}
                aria-hidden="true"
                style={{ position: 'absolute', opacity: 0, width: 1, height: 1, pointerEvents: 'none' }}
              />

              <div className="role-selector">
                {roles.map(r => (
                  <button
                    key={r.value}
                    type="button"
                    className={`role-btn ${form.role === r.value ? 'active' : ''}`}
                    onClick={() => setForm(p => ({ ...p, role: r.value }))}
                  >
                    <span className="role-btn-label">{r.label}</span>
                    <span className="role-btn-desc">{r.desc}</span>
                  </button>
                ))}
              </div>

              <span className="field-hint">
                Admin role can only be granted by an existing admin after registration.
              </span>
            </div>
          )}

          <button
            type="submit"
            className="submit-btn"
            disabled={loginLoading || !isFormValid()}
          >
            {loginLoading
              ? <><span className="spinner" /> Creating account...</>
              : <><UserPlus size={15} /> Create Account</>
            }
          </button>

          {/* ADD SAME GOOGLE LOGIN TO SIGNUP */}
          <div className="oauth-divider">
            <span>or continue with</span>
          </div>
          <div className="google-login-wrap">
            <button
              type="button"
              className="google-btn"
              onClick={handleGoogleLogin}
              disabled={googleLoading}
            >
              {googleLoading ? (
                <span className="spinner" />
              ) : (
                <img
                  src="https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg"
                  alt="Google"
                  className="google-icon"
                />
              )}
            </button>
          </div>
        </form>

        <div className="auth-switch">
          <span>Already have an account?</span>
          <button className="auth-switch-btn" onClick={onSwitchToLogin}>
            Sign In
          </button>
        </div>
      </div>
    </AuthPageWrapper>
  );
}

/*
═════════════════════════════════════════════════════════
═
FORGOT PASSWORD PAGE
═════════════════════════════════════════════════════════
═
*/
export function ForgotPasswordPage({ onBackToLogin }) {
  const [step, setStep] = useState('request');
  const [email, setEmail] = useState('');
  const [token, setToken] = useState('');
  const [demoToken, setDemoToken] = useState('');
  const [newPwd, setNewPwd] = useState('');
  const [confirmPwd, setConfirmPwd] = useState('');
  const [showPwd, setShowPwd] = useState(false);

  // Forgot-password uses a single loading state (no OAuth here)
  const [loading, setLoading] = useState(false);

  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const steps = ['Enter Email', 'Set Password', 'Done'];
  const stepIndex = { request: 0, reset: 1, done: 2 };

  const handleRequest = async (e) => {
    e.preventDefault();
    setError('');

    if (!email.trim()) {
      setError('Email address is required');
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      setError('Invalid email format');
      return;
    }

    setLoading(true);

    try {
      const res = await axios.post('/api/auth/forgot-password', {
        email: email.trim().toLowerCase()
      });

      if (res.data.demo_token) {
        setDemoToken(res.data.demo_token);
        setToken(res.data.demo_token);
      }

      setStep('reset');
    } catch (err) {
      setError(err.response?.data?.detail || 'Request failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleReset = async (e) => {
    e.preventDefault();
    setError('');

    if (!token.trim()) {
      setError('Reset token is required');
      return;
    }
    if (newPwd !== confirmPwd) {
      setError('Passwords do not match');
      return;
    }

    const pwdValid = [
      newPwd.length >= 8,
      /[A-Z]/.test(newPwd),
      /[a-z]/.test(newPwd),
      /\d/.test(newPwd),
      /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(newPwd)
    ].every(Boolean);

    if (!pwdValid) {
      setError('Password does not meet strength requirements');
      return;
    }

    setLoading(true);

    try {
      const res = await axios.post('/api/auth/reset-password', {
        token: token.trim(),
        new_password: newPwd
      });

      setSuccess(res.data.message || 'Password reset successfully!');
      setStep('done');
    } catch (err) {
      setError(err.response?.data?.detail || 'Reset failed. Token may have expired.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthPageWrapper subtitle="Reset your password">
      <div className="auth-card" style={{ maxWidth: 460 }}>
        <div className="auth-card-header">
          <Lock size={15} />
          <span>
            {step === 'request' && 'Forgot Password'}
            {step === 'reset' && 'Set New Password'}
            {step === 'done' && 'Password Reset Complete'}
          </span>
        </div>

        <div className="reset-steps">
          {steps.map((label, i) => {
            const current = stepIndex[step];
            const isActive = i === current;
            const isDone = i < current;

            return (
              <div
                key={i}
                className={[
                  'reset-step',
                  isActive ? 'active' : '',
                  isDone ? 'completed' : ''
                ].join(' ')}
              >
                <div className="reset-step-circle">
                  {isDone ? <CheckCircle size={13} /> : i + 1}
                </div>
                <span>{label}</span>
              </div>
            );
          })}
        </div>

        <div className="auth-form">
          <AlertMsg type="error" message={error} />
          <AlertMsg type="success" message={success} />

          {step === 'request' && (
            <form onSubmit={handleRequest}>
              <div className="form-group">
                <label htmlFor="forgot_email">
                  Registered Email Address <span className="req">*</span>
                </label>
                <div className="auth-input-wrap">
                  <Mail size={14} className="auth-input-icon" />
                  <input
                    id="forgot_email"
                    type="email"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    placeholder="Enter the email on your account"
                    autoFocus
                    required
                  />
                </div>
                <span className="field-hint">
                  A reset token will be generated for your account.
                </span>
              </div>

              <button
                type="submit"
                className="submit-btn"
                disabled={loading}
                style={{ marginTop: '0.25rem' }}
              >
                {loading
                  ? <><span className="spinner" /> Processing...</>
                  : <><ArrowRight size={15} /> Get Reset Token</>
                }
              </button>
            </form>
          )}

          {step === 'reset' && (
            <form onSubmit={handleReset}>
              {demoToken && (
                <div className="demo-token-box">
                  <div className="demo-token-label">
                    🔑 DEMO MODE — Your Reset Token:
                  </div>
                  <div className="demo-token-value">{demoToken}</div>
                  <div className="demo-token-hint">
                    In production this would be emailed to you.
                    Token expires in 30 minutes.
                  </div>
                </div>
              )}

              <div className="form-group">
                <label htmlFor="reset_token">
                  Reset Token <span className="req">*</span>
                </label>
                <div className="auth-input-wrap">
                  <Lock size={14} className="auth-input-icon" />
                  <input
                    id="reset_token"
                    type="text"
                    value={token}
                    onChange={e => setToken(e.target.value)}
                    placeholder="Paste your reset token here"
                    style={{
                      fontFamily: 'JetBrains Mono, monospace',
                      fontSize: '0.78rem'
                    }}
                    required
                  />
                </div>
              </div>

              <div className="form-group">
                <label htmlFor="reset_new_password">
                  New Password <span className="req">*</span>
                </label>
                <div className="auth-input-wrap">
                  <Lock size={14} className="auth-input-icon" />
                  <input
                    id="reset_new_password"
                    type={showPwd ? 'text' : 'password'}
                    value={newPwd}
                    onChange={e => setNewPwd(e.target.value)}
                    placeholder="Create a new strong password"
                    autoComplete="new-password"
                    onPaste={blockClipboard}
                    onCopy={blockClipboard}
                    onCut={blockClipboard}
                  />
                  <button
                    type="button"
                    className="pwd-toggle"
                    onClick={() => setShowPwd(p => !p)}
                    tabIndex={-1}
                  >
                    {showPwd ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                </div>
                <PasswordStrength password={newPwd} />
              </div>

              <div className="form-group">
                <label htmlFor="reset_confirm_new_password">
                  Confirm New Password <span className="req">*</span>
                </label>
                <div className="auth-input-wrap">
                  <Lock size={14} className="auth-input-icon" />
                  <input
                    id="reset_confirm_new_password"
                    type="password"
                    value={confirmPwd}
                    onChange={e => setConfirmPwd(e.target.value)}
                    placeholder="Repeat your new password"
                    autoComplete="new-password"
                    className={
                      confirmPwd && confirmPwd !== newPwd
                        ? 'input-error'
                        : ''
                    }
                    onPaste={blockClipboard}
                    onCopy={blockClipboard}
                    onCut={blockClipboard}
                    required
                  />
                </div>
                {confirmPwd && confirmPwd !== newPwd && (
                  <span className="field-error">Passwords do not match</span>
                )}
              </div>

              <button
                type="submit"
                className="submit-btn"
                disabled={loading || !token.trim() || !newPwd || newPwd !== confirmPwd}
                style={{ marginTop: '0.25rem' }}
              >
                {loading
                  ? <><span className="spinner" /> Resetting...</>
                  : <><Lock size={15} /> Reset Password</>
                }
              </button>
            </form>
          )}

          {step === 'done' && (
            <div style={{ textAlign: 'center', padding: '1.5rem 0 0.5rem' }}>
              <div style={{ fontSize: '3.5rem', marginBottom: '1rem' }}>🎉</div>
              <p style={{
                color: 'var(--text-secondary)',
                fontSize: '0.9rem',
                lineHeight: 1.7
              }}>
                Your password has been reset successfully.<br />
                You can now sign in with your new password.
              </p>
              <button
                className="submit-btn"
                onClick={onBackToLogin}
                style={{ marginTop: '1.5rem' }}
              >
                <ArrowRight size={15} /> Go to Sign In
              </button>
            </div>
          )}
        </div>

        {step !== 'done' && (
          <div className="auth-switch">
            <ArrowLeft size={13} style={{ color: 'var(--text-muted)' }} />
            <button className="auth-switch-btn" onClick={onBackToLogin}>
              Back to Sign In
            </button>
          </div>
        )}
      </div>
    </AuthPageWrapper>
  );
}