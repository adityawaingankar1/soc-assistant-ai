import React, { useEffect, useState, useCallback } from 'react';
import {
  RefreshCw, FileDown, Eye, ShieldAlert,
  Activity, Search, Filter, User as UserIcon
} from 'lucide-react';
import {
  getAlerts,
  getAlertDetail,
  exportAlertsCsv,
  exportAlertPdf
} from '../services/api';
import toast from 'react-hot-toast';

const severityOptions = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const decisionOptions = ['', 'escalate', 'enrich', 'dismiss'];

function tagClass(value = '') {
  const v = String(value).toLowerCase();
  if (v === 'critical') return 'tag tag-critical';
  if (v === 'high') return 'tag tag-high';
  if (v === 'medium') return 'tag tag-medium';
  if (v === 'low') return 'tag tag-low';
  if (v === 'info') return 'tag tag-info';
  if (v === 'escalate') return 'tag tag-escalate';
  if (v === 'enrich') return 'tag tag-enrich';
  if (v === 'dismiss') return 'tag tag-dismiss';
  return 'tag tag-pending';
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function renderActionNode(a) {
  if (typeof a === 'string') return a;
  if (isPlainObject(a)) {
    const primary = a.action || a.task || a.name || a.title || JSON.stringify(a);
    const owner = a.owner_team || a.owner || null;
    const approval = a.approval_level || a.approval || null;
    const requires = Array.isArray(a.requires) ? a.requires : [];
    return (
      <div>
        <div>{primary}</div>
        {(owner || approval || requires.length) && (
          <div style={{ marginTop: 4, fontSize: '0.85rem', opacity: 0.85 }}>
            {(owner || approval) && (
              <div>
                {owner && <span><strong>Owner:</strong> {owner}</span>}
                {owner && approval && <span> • </span>}
                {approval && <span><strong>Approval:</strong> {approval}</span>}
              </div>
            )}
            {requires.length > 0 && (
              <div>
                <strong>Gating:</strong>
                <ul style={{ margin: '4px 0 0 18px' }}>
                  {requires.slice(0, 5).map((r, i) => <li key={i}>{String(r)}</li>)}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
    );
  }
  return String(a);
}

function formatPct01(v) {
  const n = Number(v);
  if (Number.isFinite(n)) return `${Math.round(n * 100)}%`;
  return '—';
}

export default function AlertsHistory({ user }) {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [filters, setFilters] = useState({ severity: '', decision: '' });

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getAlerts(50, 0, filters.severity, filters.decision);
      setRows(res.data?.data || []);
    } catch (err) {
      toast.error(err.message || 'Failed to load alerts');
    } finally {
      setLoading(false);
    }
  }, [filters]);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  const openAlertDetail = async (alertId) => {
    setDetailLoading(true);
    try {
      const res = await getAlertDetail(alertId);
      setSelectedAlert(res.data);
    } catch (err) {
      toast.error(err.message || 'Failed to load alert detail');
    } finally {
      setDetailLoading(false);
    }
  };

  const handleExportCsv = async () => {
    try {
      const res = await exportAlertsCsv();
      const blob = new Blob([res.data], { type: 'text/csv' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `soc_alerts_export.csv`;
      a.click();
      window.URL.revokeObjectURL(url);
      toast.success('CSV export downloaded');
    } catch (err) {
      toast.error(err.message || 'CSV export failed');
    }
  };

  const handleExportPdf = async (alertId) => {
    try {
      const res = await exportAlertPdf(alertId);
      const blob = new Blob([res.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `alert_${alertId.slice(0, 8)}.pdf`;
      a.click();
      window.URL.revokeObjectURL(url);
      toast.success('PDF export downloaded');
    } catch (err) {
      toast.error(err.message || 'PDF export failed');
    }
  };

  const detailRouterHint =
    selectedAlert?.analysis?.router_hint ||
    selectedAlert?.analysis?.enrichment_data?.soc_artifacts?.router_hint ||
    null;

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h1>📋 Alerts</h1>
        <p>Browse previously analyzed alerts and review AI triage results</p>
      </div>

      <div className="alerts-history-toolbar">
        <div className="alerts-history-filters">
          <div className="alerts-filter">
            <Filter size={14} />
            <select
              value={filters.severity}
              onChange={(e) => setFilters(prev => ({ ...prev, severity: e.target.value }))}
            >
              {severityOptions.map(opt => (
                <option key={opt} value={opt}>
                  {opt || 'All Severities'}
                </option>
              ))}
            </select>
          </div>

          <div className="alerts-filter">
            <Search size={14} />
            <select
              value={filters.decision}
              onChange={(e) => setFilters(prev => ({ ...prev, decision: e.target.value }))}
            >
              {decisionOptions.map(opt => (
                <option key={opt} value={opt}>
                  {opt || 'All Decisions'}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 8 }}>
          <button className="clear-btn" onClick={fetchAlerts} type="button">
            <RefreshCw size={13} /> Refresh
          </button>
          <button className="clear-btn" onClick={handleExportCsv} type="button">
            <FileDown size={13} /> Export CSV
          </button>
        </div>
      </div>

      <div className="alerts-table-container" style={{ marginBottom: '1.2rem' }}>
        <div className="table-header">
          <h2>Analyzed Alerts</h2>
          <span className="table-count">{rows.length} records</span>
        </div>

        {loading ? (
          <div className="loading-text">Loading alerts...</div>
        ) : rows.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">🗂️</div>
            <p>No alerts found for the selected filters.</p>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="alerts-table">
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Severity</th>
                  <th>Asset</th>
                  <th>MITRE</th>
                  <th>Decision</th>
                  <th>Router Hint</th>
                  <th>Attack Type</th>
                  <th>Confidence</th>
                  <th>Analyzed By</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>

              <tbody>
                {rows.map((row) => {
                  const a = row.alert || {};
                  const r = row.response || {};
                  const analyzedBy = a.created_by_username || a.created_by_display_id || '—';

                  const hint = r.router_hint || null;

                  return (
                    <tr key={a.id}>
                      <td>{a.source || '—'}</td>
                      <td><span className={tagClass(a.severity)}>{a.severity || '—'}</span></td>
                      <td>{a.asset || '—'}</td>
                      <td>{a.mitre || '—'}</td>

                      <td>
                        {r.triage_decision
                          ? <span className={tagClass(r.triage_decision)}>{r.triage_decision}</span>
                          : '—'}
                      </td>

                      <td>
                        {hint?.decision ? (
                          <div>
                            <span className={tagClass(hint.decision)}>{hint.decision}</span>
                            <div style={{ fontSize: 12, opacity: 0.8, marginTop: 2 }}>
                              {formatPct01(hint.confidence)}
                            </div>
                          </div>
                        ) : (
                          <span style={{ opacity: 0.6 }}>—</span>
                        )}
                      </td>

                      <td>{r.attack_type || '—'}</td>

                      <td>
                        {typeof r.confidence_score === 'number'
                          ? `${Math.round(r.confidence_score * 100)}%`
                          : '—'}
                      </td>

                      <td style={{ whiteSpace: 'nowrap' }}>
                        <UserIcon size={12} style={{ marginRight: 6, color: 'var(--text-muted)' }} />
                        {analyzedBy}
                      </td>

                      <td>{a.created_at ? new Date(a.created_at).toLocaleString() : '—'}</td>

                      <td>
                        <div style={{ display: 'flex', gap: 6 }}>
                          <button
                            className="clear-btn"
                            onClick={() => openAlertDetail(a.id)}
                            title="View detail"
                            type="button"
                          >
                            <Eye size={13} />
                          </button>

                          {(user?.role === 'admin' || user?.role === 'analyst') && (
                            <button
                              className="clear-btn"
                              onClick={() => handleExportPdf(a.id)}
                              title="Export PDF"
                              type="button"
                            >
                              <FileDown size={13} />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>

            </table>
          </div>
        )}
      </div>

      {(selectedAlert || detailLoading) && (
        <div className="alerts-detail-panel glass-card">
          <div className="table-header">
            <h2>
              <ShieldAlert size={16} style={{ display: 'inline', marginRight: 8 }} />
              Alert Detail
            </h2>
            <button className="clear-btn" onClick={() => setSelectedAlert(null)} type="button">
              Close
            </button>
          </div>

          {detailLoading ? (
            <div className="loading-text">Loading alert detail...</div>
          ) : selectedAlert ? (
            <div className="alerts-detail-content">
              <div className="alerts-detail-grid">
                <div className="alerts-detail-card">
                  <h3>Alert Info</h3>
                  <p><strong>ID:</strong> <code>{selectedAlert.alert?.id}</code></p>
                  <p><strong>Source:</strong> {selectedAlert.alert?.source || '—'}</p>
                  <p><strong>Severity:</strong> {selectedAlert.alert?.severity || '—'}</p>
                  <p><strong>Asset:</strong> {selectedAlert.alert?.asset || '—'}</p>
                  <p><strong>MITRE:</strong> {selectedAlert.alert?.mitre_mapping || '—'}</p>
                  <p><strong>IOC List:</strong> {selectedAlert.alert?.ioc_list || '—'}</p>
                  <p>
                    <strong>Analyzed By:</strong>{' '}
                    {selectedAlert.alert?.created_by_username || selectedAlert.alert?.created_by_display_id || '—'}
                  </p>
                </div>

                <div className="alerts-detail-card">
                  <h3>AI Analysis</h3>
                  <p><strong>Decision:</strong> {selectedAlert.analysis?.triage_decision || '—'}</p>
                  <p><strong>Risk Level:</strong> {selectedAlert.analysis?.risk_level || '—'}</p>
                  <p><strong>Attack Type:</strong> {selectedAlert.analysis?.attack_type || '—'}</p>
                  <p>
                    <strong>Confidence:</strong>{' '}
                    {typeof selectedAlert.analysis?.confidence_score === 'number'
                      ? `${Math.round(selectedAlert.analysis.confidence_score * 100)}%`
                      : '—'}
                  </p>

                  <div style={{ marginTop: 10 }}>
                    <p style={{ marginBottom: 6 }}><strong>Router Hint (pre-screen):</strong></p>
                    {detailRouterHint ? (
                      <div style={{ fontSize: '0.95rem' }}>
                        <div>
                          <span className={tagClass(detailRouterHint.decision)} style={{ marginRight: 8 }}>
                            {detailRouterHint.decision}
                          </span>
                          {detailRouterHint.confidence != null && (
                            <span style={{ opacity: 0.8 }}>
                              {formatPct01(detailRouterHint.confidence)}
                            </span>
                          )}
                        </div>
                        {detailRouterHint.reason && (
                          <div style={{ marginTop: 4, opacity: 0.85 }}>
                            {String(detailRouterHint.reason)}
                          </div>
                        )}
                      </div>
                    ) : (
                      <div style={{ opacity: 0.7 }}>—</div>
                    )}
                  </div>
                </div>
              </div>

              <div className="alerts-detail-card">
                <h3>Description</h3>
                <p>{selectedAlert.alert?.description || '—'}</p>
              </div>

              <div className="alerts-detail-card">
                <h3><Activity size={15} style={{ display: 'inline', marginRight: 6 }} />Explanation</h3>
                <p>{selectedAlert.analysis?.explanation || '—'}</p>
              </div>

              {selectedAlert.analysis?.recommended_actions?.length > 0 && (
                <div className="alerts-detail-card">
                  <h3>Recommended Actions</h3>
                  <ol>
                    {selectedAlert.analysis.recommended_actions.map((a, idx) => (
                      <li key={idx}>{renderActionNode(a)}</li>
                    ))}
                  </ol>
                </div>
              )}

              {selectedAlert.analysis?.follow_up_questions?.length > 0 && (
                <div className="alerts-detail-card">
                  <h3>Follow-up Questions</h3>
                  <ul>
                    {selectedAlert.analysis.follow_up_questions.map((q, idx) => (
                      <li key={idx}>{String(q)}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}