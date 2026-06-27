// frontend/src/services/api.js
import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || '';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 300000,
  headers: {
    'Content-Type': 'application/json',
  },
});

/* ── Attach JWT token automatically to every request ───────────────────── */
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('soc_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

/* ── Normalize API errors ──────────────────────────────────────────────── */
api.interceptors.response.use(
  (res) => res,
  (err) => {
    const status = err.response?.status;
    const requestId =
      err.response?.headers?.['x-request-id'] ||
      err.response?.data?.request_id ||
      null;

    const message =
      err.response?.data?.error?.message ||
      err.response?.data?.detail ||
      err.response?.data?.message ||
      err.message ||
      'Unknown error';

    const wrapped = new Error(message);
    wrapped.status = status;
    wrapped.requestId = requestId;

    return Promise.reject(wrapped);
  }
);

/* ── Health / System Status ────────────────────────────────────────────── */
export const checkHealth = () => api.get('/health');
export const getReadyStatus = () => api.get('/ready');
export const getSystemStatus = () => api.get('/system/status');
export const getTaskStatus = (taskId) => api.get(`/api/tasks/${taskId}`);

/* ── Dashboard ─────────────────────────────────────────────────────────── */
export const getDashboardOverview = (range = '24h') =>
  api.get(`/api/dashboard/overview?range=${encodeURIComponent(range)}`);

export const getDashboardTimeseries = (range = '24h', interval = 'hour') =>
  api.get(
    `/api/dashboard/timeseries?range=${encodeURIComponent(range)}&interval=${encodeURIComponent(interval)}`
  );

/* ── Alerts ─────────────────────────────────────────────────────────────── */
export const analyzeAlert = (data) => api.post('/api/analyze-alert', data);

export const getAlerts = (limit = 20, offset = 0, severity = '', decision = '') =>
  api.get(
    `/api/alerts?limit=${limit}&offset=${offset}&severity=${encodeURIComponent(
      severity
    )}&decision=${encodeURIComponent(decision)}`
  );

export const getAlertDetail = (id) => api.get(`/api/alerts/${id}`);

export const correlateAlerts = (ids) =>
  api.post('/api/correlate-alerts', { alert_ids: ids });

/* ── Chat ───────────────────────────────────────────────────────────────── */

export const sendChatMessage = (sessionId, message, useRag = true) =>
  api.post('/api/chat', {
    session_id: sessionId,
    message,
    use_rag: useRag,
  });

/**
 * Streaming SOC chat using fetch + ReadableStream.
 *
 * Why fetch instead of EventSource?
 * - We need POST body.
 * - We need Authorization header.
 * - Native EventSource only supports GET and cannot send custom headers.
 *
 * Backend returns text/event-stream:
 * event: meta
 * data: {...}
 *
 * event: token
 * data: {"delta":"..."}
 *
 * event: done
 * data: {...}
 */
export async function streamChatMessage(sessionId, message, useRag = true, onEvent) {
  const token = localStorage.getItem('soc_token');

  const url = API_BASE
    ? `${API_BASE.replace(/\/$/, '')}/api/chat/stream`
    : '/api/chat/stream';

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      session_id: sessionId,
      message,
      use_rag: useRag,
    }),
  });

  if (!res.ok) {
    let msg = `Chat stream failed: HTTP ${res.status}`;

    try {
      const data = await res.json();
      msg = data?.detail || data?.message || data?.error?.message || msg;
    } catch {
      // ignore JSON parse failure
    }

    throw new Error(msg);
  }

  if (!res.body) {
    throw new Error('Streaming is not supported by this browser.');
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder('utf-8');

  let buffer = '';

  while (true) {
    const { value, done } = await reader.read();

    if (done) break;

    buffer += decoder.decode(value, { stream: true });

    const rawEvents = buffer.split('\n\n');
    buffer = rawEvents.pop() || '';

    for (const rawEvent of rawEvents) {
      if (!rawEvent.trim()) continue;

      const lines = rawEvent.split('\n');

      let eventName = 'message';
      let dataText = '';

      for (const line of lines) {
        if (line.startsWith('event:')) {
          eventName = line.slice('event:'.length).trim();
        } else if (line.startsWith('data:')) {
          dataText += line.slice('data:'.length).trim();
        }
      }

      if (!dataText) continue;

      let payload;

      try {
        payload = JSON.parse(dataText);
      } catch {
        payload = { raw: dataText };
      }

      onEvent?.(eventName, payload);

      if (eventName === 'error') {
        throw new Error(payload?.message || 'Chat stream error.');
      }
    }
  }
}

export const getChatHistory = (sessionId) =>
  api.get(`/api/chat/history/${sessionId}`);

export const clearChatHistory = (sessionId) =>
  api.delete(`/api/chat/history/${sessionId}`);

export const listChatSessions = (limit = 20) =>
  api.get(`/api/chat/sessions?limit=${limit}`);

export const deleteChatSession = (sessionId) =>
  api.delete(`/api/chat/history/${sessionId}`);

/* ── Documents / Knowledge Base ────────────────────────────────────────── */
export const uploadDocument = (file, docType) => {
  const form = new FormData();
  form.append('file', file);
  form.append('doc_type', docType);

  return api.post('/api/upload-docs', form, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
};

export const getKBStats = () => api.get('/api/knowledge-base/stats');

export const queryKnowledgeBase = (query, topK = 3) =>
  api.post('/api/knowledge-base/query', {
    query,
    top_k: topK,
  });

export const resetKnowledgeBase = () => api.post('/api/knowledge-base/reset');

export const reloadKnowledgeBase = () => api.post('/api/knowledge-base/reload');

export const getKBDocuments = (search = '', docType = '') =>
  api.get(
    `/api/knowledge-base/documents?search=${encodeURIComponent(
      search
    )}&doc_type=${encodeURIComponent(docType)}`
  );

export const deleteKBDocument = (docId) =>
  api.delete(`/api/knowledge-base/documents/${docId}`);

/**
 * SSE EventSource connection for dashboard events.
 * Token is passed in query because native EventSource cannot send Authorization headers.
 */
export const openSecurityEventsSSE = () => {
  const token = localStorage.getItem('soc_token') || '';
  const qs = `token=${encodeURIComponent(token)}`;

  const url = API_BASE
    ? `${API_BASE.replace(/\/$/, '')}/api/stream/events?${qs}`
    : `/api/stream/events?${qs}`;

  return new EventSource(url);
};

/* ── Exports ────────────────────────────────────────────────────────────── */
export const exportAlertsCsv = () =>
  api.get('/api/export/alerts/csv', {
    responseType: 'blob',
  });

export const exportAlertPdf = (alertId) =>
  api.get(`/api/export/alert/${alertId}/pdf`, {
    responseType: 'blob',
  });

/* ── Admin / Audit ─────────────────────────────────────────────────────── */
export const getAuditLogs = (limit = 100, eventType = '', userQuery = '') => {
  const params = new URLSearchParams();
  params.set('limit', String(limit));
  params.set('event_type', eventType || '');

  const q = String(userQuery || '').trim();

  if (q) {
    if (q.startsWith('usr_')) {
      params.set('user_display_id', q);
    } else {
      params.set('user_id', q);
    }
  }

  return api.get(`/api/admin/audit-logs?${params.toString()}`);
};

export default api;
