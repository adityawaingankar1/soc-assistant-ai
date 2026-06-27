import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { getAuditLogs } from '../services/api';
import { Activity, RefreshCw, Filter, ShieldCheck, User as UserIcon } from 'lucide-react';
import toast from 'react-hot-toast';

const REDACTED_VALUES = new Set(['[redacted]', '[REDACTED]']);
const ACTOR_USERNAME_KEYS = new Set([
  'username',
  'listed_by',
  'uploaded_by',
  'deleted_by',
  'cleared_by',
  'performed_by',
  'analyzed_by',
  'reset_by',
  'reloaded_by'
]);

function hydrateUsernames(eventData, actorUsername) {
  if (!eventData || !actorUsername) return eventData;

  const walk = (node) => {
    if (Array.isArray(node)) return node.map(walk);
    if (node && typeof node === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(node)) {
        if (ACTOR_USERNAME_KEYS.has(k) && typeof v === 'string' && REDACTED_VALUES.has(v)) {
          out[k] = actorUsername;
        } else {
          out[k] = walk(v);
        }
      }
      return out;
    }
    return node;
  };

  return walk(eventData);
}

export default function AuditLogs() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  const [filters, setFilters] = useState({
    eventType: '',
    userQuery: ''
  });

  const loadLogs = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getAuditLogs(150, filters.eventType, filters.userQuery);
      setLogs(res.data.logs || []);
    } catch (err) {
      toast.error(err.message || 'Failed to load audit logs');
    } finally {
      setLoading(false);
    }
  }, [filters.eventType, filters.userQuery]);

  useEffect(() => { loadLogs(); }, [loadLogs]);

  const hydratedLogs = useMemo(() => {
    return (logs || []).map((log) => {
      const actorUsername = log?.actor?.username || null;
      return {
        ...log,
        _hydrated_event_data: hydrateUsernames(log?.event_data, actorUsername)
      };
    });
  }, [logs]);

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h1>🧾 Audit Logs</h1>
        <p>Operational visibility into admin, KB, chat, alert, export, and streaming activity</p>
      </div>

      <div className="alerts-history-toolbar">
        <div className="alerts-history-filters">
          <div className="alerts-filter">
            <Filter size={14} />
            <input
              type="text"
              placeholder="Filter by event type..."
              value={filters.eventType}
              onChange={(e) => setFilters(prev => ({ ...prev, eventType: e.target.value }))}
            />
          </div>

          <div className="alerts-filter">
            <ShieldCheck size={14} />
            <input
              type="text"
              placeholder="Filter by User UUID or Display ID (usr_...)"
              value={filters.userQuery}
              onChange={(e) => setFilters(prev => ({ ...prev, userQuery: e.target.value }))}
            />
          </div>
        </div>

        <button className="clear-btn" onClick={loadLogs}>
          <RefreshCw size={13} /> Refresh
        </button>
      </div>

      <div className="alerts-table-container">
        <div className="table-header">
          <h2>System Activity</h2>
          <span className="table-count">{hydratedLogs.length} records</span>
        </div>

        {loading ? (
          <div className="loading-text">
            <Activity size={16} style={{ display: 'inline', marginRight: 8 }} />
            Loading audit logs...
          </div>
        ) : hydratedLogs.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">🧾</div>
            <p>No audit logs found for the selected filters.</p>
          </div>
        ) : (
          <div className="audit-log-list">
            {hydratedLogs.map((log) => (
              <div key={log.id} className="audit-log-item">
                <div className="audit-log-top">
                  <span className="audit-log-type">{log.event_type}</span>
                  <span className="audit-log-time">
                    {log.created_at ? new Date(log.created_at).toLocaleString() : '—'}
                  </span>
                </div>

                {/* Outside: only display_id */}
                <div className="audit-log-user" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <UserIcon size={14} />
                  <span>Actor:</span>
                  <code>{log.actor?.display_id || 'system'}</code>
                </div>

                <pre className="audit-log-json">
                  {JSON.stringify(log._hydrated_event_data, null, 2)}
                </pre>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}