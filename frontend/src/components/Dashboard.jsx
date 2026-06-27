import React, { useEffect, useMemo, useState, useCallback } from 'react';
import ReactECharts from 'echarts-for-react';
import {
  AlertCircle, Activity, AlertTriangle, CheckCircle,
  Clock, Database, Shield, Zap, TrendingUp, RefreshCw,
  Radio, BarChart3, Eye
} from 'lucide-react';

import {
  getDashboardOverview,
  getDashboardTimeseries,
  getKBStats,
  openSecurityEventsSSE
} from '../services/api';

const ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#facc15',
  LOW: '#3b82f6',
  INFO: '#a78bfa'
};

const EVENT_ICONS = {
  alert_analyzed: '🔍',
  chat_message_processed: '💬',
  chat_message_streamed: '💬',
  kb_document_uploaded: '📄',
  kb_document_deleted: '🗑️',
  ws_analysis_completed: '✅',
  ws_analysis_requested: '⚡',
  sse_client_connected: '🔗',
};

function hourLabel(bucketStr) {
  if (!bucketStr) return '';
  const parts = bucketStr.split(' ');
  return parts.length === 2 ? parts[1] : bucketStr;
}

function pct(x) {
  if (typeof x !== 'number') return '—';
  return `${Math.round(x * 100)}%`;
}

function timeAgo(ts) {
  if (!ts) return '—';
  const diff = (Date.now() - new Date(ts).getTime()) / 1000;
  if (diff < 60) return `${Math.round(diff)}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  return `${Math.round(diff / 3600)}h ago`;
}

function formatEventDetail(type, data) {
  if (!data || typeof data !== 'object') return '—';
  if (type === 'alert_analyzed') {
    return `${data.severity || '—'} • ${data.triage_decision || '—'} • ${typeof data.confidence_score === 'number' ? pct(data.confidence_score) : '—'}`;
  }
  if (type === 'chat_message_processed' || type === 'chat_message_streamed') {
    return `${data.rag_used ? 'RAG' : 'Direct'} • ${data.message_preview?.slice(0, 60) || '—'}`;
  }
  if (type === 'kb_document_uploaded') return `${data.filename || 'file'} • ${data.chunks_ingested ?? '—'} chunks`;
  if (type === 'ws_analysis_completed') return `${data.triage_decision || '—'} • ${data.risk_level || '—'}`;
  try {
    const str = JSON.stringify(data);
    return str.length > 100 ? str.slice(0, 100) + '…' : str;
  } catch { return '—'; }
}

function StatCard({ label, value, icon: Icon, color, subtitle, pulse }) {
  return (
    <div className="dash-stat-card">
      <div className="dash-stat-icon" style={{ background: `${color}18`, color }}>
        <Icon size={20} />
      </div>
      <div className="dash-stat-info">
        <div className="dash-stat-value" style={{ color }}>{value}</div>
        <div className="dash-stat-label">{label}</div>
        {subtitle && <div className="dash-stat-sub">{subtitle}</div>}
      </div>
      {pulse && <div className="dash-stat-pulse" style={{ background: color }} />}
    </div>
  );
}

export default function Dashboard() {
  const range = '24h';
  const interval = 'hour';
  const [overview, setOverview] = useState(null);
  const [series, setSeries] = useState([]);
  const [kbStats, setKbStats] = useState(null);
  const [sseStatus, setSseStatus] = useState('connecting');
  const [liveEvents, setLiveEvents] = useState([]);
  const [liveCounts, setLiveCounts] = useState({});
  const [lastEventAt, setLastEventAt] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [refreshing, setRefreshing] = useState(false);

  const refresh = useCallback(async () => {
    setError('');
    setRefreshing(true);
    try {
      const [o, t, kb] = await Promise.allSettled([
        getDashboardOverview(range),
        getDashboardTimeseries(range, interval),
        getKBStats()
      ]);
      if (o.status === 'fulfilled') setOverview(o.value.data || null);
      if (t.status === 'fulfilled') setSeries(t.value.data?.series || []);
      if (kb.status === 'fulfilled') setKbStats(kb.value.data || null);
      if (o.status === 'rejected' && t.status === 'rejected') {
        setError('Failed to load dashboard data. Check backend connectivity.');
      }
    } catch {
      setError('Unexpected dashboard error.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  useEffect(() => {
    const es = openSecurityEventsSSE();
    es.addEventListener('hello', () => setSseStatus('connected'));
    es.addEventListener('security_event', (msg) => {
      setSseStatus('connected');
      try {
        const evt = JSON.parse(msg.data || '{}');
        const ts = evt.ts || new Date().toISOString();
        const type = evt.event_type || 'unknown';
        const data = evt.data || null;
        setLastEventAt(ts);
        setLiveCounts(prev => ({ ...prev, [type]: (prev[type] || 0) + 1 }));
        setLiveEvents(prev => [{ ts, type, data }, ...prev].slice(0, 50));
        if (['alert_analyzed', 'alert_deleted', 'kb_document_uploaded', 'kb_document_deleted'].includes(type)) {
          refresh();
        }
      } catch {}
    });
    es.addEventListener('heartbeat', () => {
      setSseStatus(prev => prev !== 'connected' ? 'connected' : prev);
    });
    es.onerror = () => setSseStatus('error');
    return () => es.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refresh]);

  const sseLabel = sseStatus === 'connected' ? 'Live' : sseStatus === 'error' ? 'Offline' : 'Connecting';
  const sseColor = sseStatus === 'connected' ? '#22c55e' : sseStatus === 'error' ? '#ef4444' : '#facc15';

  const kpis = useMemo(() => {
    const total = overview?.total_alerts ?? 0;
    const sev = overview?.by_severity || {};
    const decision = overview?.by_decision || {};
    return {
      total, critical: sev.CRITICAL || 0, high: sev.HIGH || 0,
      medium: sev.MEDIUM || 0, low: sev.LOW || 0,
      escalated: decision.escalate || 0, dismissed: decision.dismiss || 0,
      enriched: decision.enrich || 0
    };
  }, [overview]);

  const totalLiveEvents = useMemo(() => Object.values(liveCounts).reduce((a, b) => a + b, 0), [liveCounts]);

  // Chart: Alerts Over Time
  const alertsChartOption = useMemo(() => {
    const x = (series || []).map(r => hourLabel(r.t));
    const activeSev = ORDER.filter(sev => (series || []).some(row => (row?.[sev] || 0) > 0));
    if (!activeSev.length) {
      return {
        backgroundColor: 'transparent',
        graphic: { type: 'text', left: 'center', top: 'middle', style: { text: 'No alerts in selected range', fill: '#8b949e', fontSize: 14 } },
        xAxis: { type: 'category', data: [] }, yAxis: { type: 'value' }, series: []
      };
    }
    return {
      backgroundColor: 'transparent',
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, backgroundColor: 'rgba(13,17,23,0.95)', borderColor: 'rgba(255,255,255,0.08)', textStyle: { color: '#c9d1d9' } },
      legend: { top: 6, right: 10, textStyle: { color: '#8b949e', fontSize: 11 }, itemWidth: 14, itemHeight: 8 },
      grid: { left: 45, right: 15, top: 45, bottom: 50 },
      xAxis: { type: 'category', data: x, axisLabel: { color: '#8b949e', rotate: 45, fontSize: 10 }, axisLine: { lineStyle: { color: 'rgba(255,255,255,0.08)' } } },
      yAxis: { type: 'value', axisLabel: { color: '#8b949e' }, splitLine: { lineStyle: { color: 'rgba(255,255,255,0.06)' } } },
      series: activeSev.map(sev => ({
        name: sev, type: 'bar', stack: 'total', barMaxWidth: 22,
        itemStyle: { color: COLORS[sev], borderRadius: [2, 2, 0, 0] },
        emphasis: { focus: 'series' },
        data: (series || []).map(r => r?.[sev] || 0),
      }))
    };
  }, [series]);

  // Chart: Decision Breakdown (Pie)
  const decisionChartOption = useMemo(() => {
    const data = [
      { value: kpis.escalated, name: 'Escalate', itemStyle: { color: '#ef4444' } },
      { value: kpis.enriched, name: 'Enrich', itemStyle: { color: '#facc15' } },
      { value: kpis.dismissed, name: 'Dismiss', itemStyle: { color: '#22c55e' } },
    ].filter(d => d.value > 0);
    if (!data.length) return null;
    return {
      backgroundColor: 'transparent',
      tooltip: { trigger: 'item', backgroundColor: 'rgba(13,17,23,0.95)', textStyle: { color: '#c9d1d9' } },
      series: [{
        type: 'pie', radius: ['45%', '72%'], center: ['50%', '50%'],
        label: { color: '#c9d1d9', fontSize: 11 },
        labelLine: { lineStyle: { color: 'rgba(255,255,255,0.15)' } },
        itemStyle: { borderColor: '#0a0f1e', borderWidth: 2 },
        data, emphasis: { scaleSize: 6 }
      }]
    };
  }, [kpis]);

  // Chart: Severity Breakdown (Bar)
  const severityChartOption = useMemo(() => {
    const data = ORDER.map(sev => ({ name: sev, value: overview?.by_severity?.[sev] || 0 })).filter(d => d.value > 0);
    if (!data.length) return null;
    return {
      backgroundColor: 'transparent',
      tooltip: { trigger: 'axis', backgroundColor: 'rgba(13,17,23,0.95)', textStyle: { color: '#c9d1d9' } },
      grid: { left: 70, right: 15, top: 10, bottom: 20 },
      xAxis: { type: 'value', axisLabel: { color: '#8b949e' }, splitLine: { lineStyle: { color: 'rgba(255,255,255,0.06)' } } },
      yAxis: { type: 'category', data: data.map(d => d.name), axisLabel: { color: '#c9d1d9', fontWeight: 600 } },
      series: [{ type: 'bar', data: data.map(d => ({ value: d.value, itemStyle: { color: COLORS[d.name], borderRadius: [0, 4, 4, 0] } })), barMaxWidth: 16 }]
    };
  }, [overview]);

  return (
    <div className="dashboard">
      {/* Header */}
      <div className="dash-header">
        <div className="dash-header-left">
          <div className="dash-header-icon"><Shield size={22} /></div>
          <div>
            <h1 className="dash-title">Security Operations Center</h1>
            <p className="dash-subtitle">Real-time threat monitoring & analysis dashboard</p>
          </div>
        </div>
        <div className="dash-header-right">
          <div className="dash-sse-status" style={{ borderColor: `${sseColor}40` }}>
            <Radio size={14} style={{ color: sseColor }} className={sseStatus === 'connected' ? 'sse-pulse' : ''} />
            <span style={{ color: sseColor, fontWeight: 600 }}>{sseLabel}</span>
            {lastEventAt && <span className="dash-last-event">{timeAgo(lastEventAt)}</span>}
          </div>
          <button className="dash-refresh-btn" onClick={refresh} disabled={refreshing}>
            <RefreshCw size={14} className={refreshing ? 'spin-anim' : ''} /> Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="dash-error">
          <AlertCircle size={14} /> {error}
        </div>
      )}

      {/* KPI Cards */}
      <div className="dash-kpi-grid">
        <StatCard label="Total Alerts" value={loading ? '—' : kpis.total} icon={Shield} color="#60a5fa" subtitle="Last 24 hours" />
        <StatCard label="Critical" value={loading ? '—' : kpis.critical} icon={AlertTriangle} color="#ef4444" subtitle="Immediate action" pulse={kpis.critical > 0} />
        <StatCard label="High" value={loading ? '—' : kpis.high} icon={Zap} color="#f97316" subtitle="Priority review" />
        <StatCard label="Escalated" value={loading ? '—' : kpis.escalated} icon={TrendingUp} color="#f97316" subtitle="Sent to IR" />
        <StatCard label="Dismissed" value={loading ? '—' : kpis.dismissed} icon={CheckCircle} color="#22c55e" subtitle="False positives" />
        <StatCard label="Live Events" value={totalLiveEvents} icon={Activity} color="#a78bfa" subtitle="This session" pulse={sseStatus === 'connected'} />
        <StatCard label="KB Chunks" value={kbStats?.total_chunks ?? '—'} icon={Database} color="#14b8a6" subtitle={kbStats?.embedding_model || '—'} />
        <StatCard label="SSE Stream" value={sseLabel} icon={Radio} color={sseColor} subtitle={lastEventAt ? timeAgo(lastEventAt) : 'Waiting…'} />
      </div>

      {/* Charts Row */}
      <div className="dash-charts-row">
        <div className="dash-chart-card dash-chart-wide">
          <div className="dash-chart-header">
            <BarChart3 size={16} /> <h3>Alerts Over Time ({range})</h3>
            <span className="dash-chart-count">{series.length} data points</span>
          </div>
          {loading ? (
            <div className="dash-chart-loading"><Activity size={16} className="spin-anim" /> Loading…</div>
          ) : (
            <ReactECharts option={alertsChartOption} style={{ height: 300 }} />
          )}
        </div>

        <div className="dash-chart-card">
          <div className="dash-chart-header">
            <Eye size={16} /> <h3>Triage Decisions</h3>
          </div>
          {decisionChartOption ? (
            <ReactECharts option={decisionChartOption} style={{ height: 260 }} />
          ) : (
            <div className="dash-chart-empty">No triage data yet</div>
          )}
        </div>

        <div className="dash-chart-card">
          <div className="dash-chart-header">
            <AlertTriangle size={16} /> <h3>By Severity</h3>
          </div>
          {severityChartOption ? (
            <ReactECharts option={severityChartOption} style={{ height: 260 }} />
          ) : (
            <div className="dash-chart-empty">No severity data yet</div>
          )}
        </div>
      </div>

      {/* Live Events Feed + Recent Alerts */}
      <div className="dash-bottom-row">
        {/* Live Event Feed */}
        <div className="dash-feed-card">
          <div className="dash-chart-header">
            <Radio size={16} className={sseStatus === 'connected' ? 'sse-pulse' : ''} />
            <h3>Live Event Feed</h3>
            <span className="dash-chart-count">{liveEvents.length} events</span>
          </div>
          {liveEvents.length === 0 ? (
            <div className="dash-chart-empty">
              <Radio size={24} style={{ marginBottom: 8, opacity: 0.4 }} />
              <div>Waiting for real-time events…</div>
              <div style={{ fontSize: '0.75rem', marginTop: 4, opacity: 0.6 }}>Analyze an alert or send a chat message to see events here</div>
            </div>
          ) : (
            <div className="dash-feed-scroll">
              {liveEvents.map((e, idx) => (
                <div key={idx} className="dash-feed-item">
                  <span className="dash-feed-icon">{EVENT_ICONS[e.type] || '📋'}</span>
                  <div className="dash-feed-info">
                    <div className="dash-feed-type">{e.type.replace(/_/g, ' ')}</div>
                    <div className="dash-feed-detail">{formatEventDetail(e.type, e.data)}</div>
                  </div>
                  <span className="dash-feed-time">{timeAgo(e.ts)}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent Analyzed Alerts */}
        <div className="dash-feed-card">
          <div className="dash-chart-header">
            <Shield size={16} />
            <h3>Recent Analyzed Alerts</h3>
            <span className="dash-chart-count">{overview?.recent_alerts?.length || 0} results</span>
          </div>
          {!overview?.recent_alerts?.length ? (
            <div className="dash-chart-empty">
              <Shield size={24} style={{ marginBottom: 8, opacity: 0.4 }} />
              <div>No alerts analyzed yet</div>
              <div style={{ fontSize: '0.75rem', marginTop: 4, opacity: 0.6 }}>Use Alert Analysis to see results here</div>
            </div>
          ) : (
            <div className="dash-feed-scroll">
              {overview.recent_alerts.map((a) => (
                <div key={a.alert_id} className="dash-alert-item">
                  <div className="dash-alert-top">
                    <span className={`dash-sev-badge dash-sev-${(a.severity || 'medium').toLowerCase()}`}>{a.severity}</span>
                    <span className={`dash-decision-badge dash-dec-${(a.triage_decision || 'enrich').toLowerCase()}`}>{a.triage_decision || '—'}</span>
                    <span className="dash-alert-conf">{pct(a.confidence_score)}</span>
                  </div>
                  <div className="dash-alert-meta">
                    <span>{a.source || '—'}</span>
                    <span>•</span>
                    <code>{a.asset || '—'}</code>
                    <span>•</span>
                    <span className="dash-feed-time">{a.created_at ? new Date(a.created_at).toLocaleString() : '—'}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}