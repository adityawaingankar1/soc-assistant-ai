import React, { useState, useMemo, useCallback } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import {
  AlertTriangle, CheckCircle, Info, Shield,
  Zap, FileText, HelpCircle, ChevronDown, Activity,
  Copy, Check, Download
} from 'lucide-react';

const RISK_CONFIG = {
  CRITICAL: { badgeCls: 'badge badge-critical', label: '🔴CRITICAL', icon: AlertTriangle },
  HIGH: { badgeCls: 'badge badge-high', label: '🟠 HIGH', icon: AlertTriangle },
  MEDIUM: { badgeCls: 'badge badge-medium', label: '🟠 MEDIUM', icon: Info },
  LOW: { badgeCls: 'badge badge-low', label: '🟢 LOW', icon: CheckCircle },
  INFO: { badgeCls: 'badge badge-neutral', label: '🔵INFO', icon: Info },
};

const DECISION_CONFIG = {
  escalate: { badgeCls: 'badge badge-escalate', label: '⚡ ESCALATE', desc: 'High-confidence threat — initiate incident response' },
  enrich: { badgeCls: 'badge badge-enrich', label: '🔍ENRICH', desc: 'Suspicious — additional investigation needed' },
  dismiss: { badgeCls: 'badge badge-dismiss', label: '✅DISMISS', desc: 'Likely benign / false positive — no immediate action required' },
};

function ConfidenceBar({ score }) {
  const pct = Math.round((score || 0) * 100);
  const color = pct > 80 ? 'var(--low)' : pct > 60 ? 'var(--medium)' : 'var(--high)';
  return (
    <div className="confidence-bar-container">
      <div className="confidence-label">
        <span>AI Confidence Score</span>
        <span className="confidence-value" style={{ color }}>{pct}%</span>
      </div>
      <div className="confidence-track">
        <div
          className="confidence-fill"
          style={{ width: `${pct}%`, background: `linear-gradient(90deg, ${color}, ${color}aa)` }}
        />
      </div>
    </div>
  );
}

function Section({ title, icon: Icon, children, defaultOpen = false, accentColor }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="collapsible-section">
      <button className="collapsible-header" onClick={() => setOpen(!open)} type="button">
        <div
          className="collapsible-header-icon"
          style={accentColor ? { background: `${accentColor}18`, color: accentColor } : {}}
        >
          <Icon size={13} />
        </div>
        <span>{title}</span>
        <ChevronDown size={14} className={`collapsible-chevron ${open ? 'open' : ''}`} />
      </button>
      {open && <div className="collapsible-content">{children}</div>}
    </div>
  );
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function getActionPrimaryText(action) {
  if (typeof action === 'string') return action;
  if (isPlainObject(action)) {
    return (
      action.action ||
      action.task ||
      action.name ||
      action.title ||
      JSON.stringify(action)
    );
  }
  return String(action);
}

function ActionMeta({ actionObj }) {
  if (!isPlainObject(actionObj)) return null;
  const owner = actionObj.owner_team || actionObj.owner || null;
  const approval = actionObj.approval_level || actionObj.approval || null;
  const requires = Array.isArray(actionObj.requires) ? actionObj.requires : [];
  const risk = actionObj.risk || null;
  const why = actionObj.why || null;
  const hasAny = owner || approval || (requires && requires.length) || risk || why;
  if (!hasAny) return null;
  return (
    <div style={{ marginTop: 6, fontSize: '0.82rem', opacity: 0.9 }}>
      {(owner || approval) && (
        <div style={{ marginBottom: 2 }}>
          {owner && <span><strong>Owner:</strong> {owner}</span>}
          {owner && approval && <span> • </span>}
          {approval && <span><strong>Approval:</strong> {approval}</span>}
        </div>
      )}
      {why && (
        <div style={{ marginBottom: 2 }}>
          <strong>Why:</strong> {String(why)}
        </div>
      )}
      {risk && (
        <div style={{ marginBottom: 2 }}>
          <strong>Risk:</strong> {String(risk)}
        </div>
      )}
      {requires && requires.length > 0 && (
        <div>
          <strong>Gating:</strong>
          <ul style={{ margin: '4px 0 0 18px' }}>
            {requires.slice(0, 6).map((r, i) => (
              <li key={i}>{String(r)}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function extractSentinelKqlPayload(analysis) {
  const soc = analysis?.enrichment_data?.soc_artifacts || {};
  const obj = soc?.sentinel_kql;
  const result = obj?.result && isPlainObject(obj.result) ? obj.result : (isPlainObject(obj) ? obj : null);
  const queries = Array.isArray(result?.queries) ? result.queries : [];
  return { result: result || null, queries };
}

function categorizeKqlQuery(q) {
  const name = String(q?.name || '').toLowerCase();
  const body = String(q?.query || '').toLowerCase();
  const has = (s) => name.includes(s) || body.includes(s);
  if (has('signinlogs') || has('identity') || has('oauth') || has('conditional access')) return 'Identity';
  if (has('w3ciislog') || has('iis') || has('waf') || has('web') || has('http')) return 'Web';
  if (has('dns') || has('dnsevents') || has('domain')) return 'DNS';
  if (has('devicefileevents') || has('hash') || has('file')) return 'File';
  if (has('devicenetworkevents') || has('commonsecuritylog') || has('network') || has('remoteip') ||
      has('ip sightings')) return 'Network';
  return 'General';
}

function detectKqlTables(kql) {
  const text = String(kql || '');
  const lines = text.split('\n');
  const tables = new Set();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const next = (lines[i + 1] || '').trim();
    if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(line) && next.startsWith('|')) {
      tables.add(line);
    }
  }
  return Array.from(tables);
}

const OFTEN_MISSING_TABLES = new Set(['W3CIISLog', 'DnsEvents', 'SecurityEvent', 'CommonSecurityLog']);

function downloadTextFile(filename, content, mime = 'text/plain') {
  const blob = new Blob([content], { type: mime });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  window.URL.revokeObjectURL(url);
}

function buildKqlBundleText(queries, meta = {}) {
  const header = [
    `// Generated by SOC Assistant`,
    `// GeneratedAt: ${new Date().toISOString()}`,
    meta?.incident_type ? `// IncidentType: ${meta.incident_type}` : null,
    meta?.affected_asset ? `// Asset: ${meta.affected_asset}` : null,
    meta?.time_window_hours ? `// TimeWindowHours: ${meta.time_window_hours}` : null,
    `//`,
    `// NOTE: Some tables may not exist in your workspace depending on connectors (e.g., W3CIISLog, DnsEvents).`,
    `//`
  ].filter(Boolean).join('\n');

  const blocks = (queries || []).map((q, idx) => {
    const name = q?.name || `Query ${idx + 1}`;
    const desc = q?.description || '';
    const body = String(q?.query || '').trim();
    return [
      `// ===== ${name} =====`,
      desc ? `// ${desc}` : null,
      body,
      ''
    ].filter(Boolean).join('\n');
  });

  return header + '\n\n' + blocks.join('\n');
}

function KqlQueryCard({ q, idx, baseFile, onCopy }) {
  const [copied, setCopied] = useState(false);
  const name = q?.name || `KQL Query ${idx + 1}`;
  const desc = q?.description || '';
  const body = String(q?.query || '').trim();
  const tables = useMemo(() => detectKqlTables(body), [body]);
  const missingLikely = useMemo(() => tables.filter(t => OFTEN_MISSING_TABLES.has(t)), [tables]);

  const downloadOne = () => {
    const safeName = String(name).replace(/[^\w-]+/g, '_').slice(0, 60);
    downloadTextFile(`${baseFile}_q${idx + 1}_${safeName}.kql`, body, 'text/plain');
  };

  const copyOne = async () => {
    await onCopy(body);
    setCopied(true);
    setTimeout(() => setCopied(false), 1400);
  };

  return (
    <div style={{
      border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: 10,
      padding: '0.75rem',
      background: 'rgba(13,17,23,0.55)',
      marginBottom: '0.75rem'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'flex-start' }}>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700, marginBottom: 4 }}>{name}</div>
          {desc && <div style={{ opacity: 0.85, fontSize: '0.9rem', marginBottom: 8 }}>{desc}</div>}
          {tables.length > 0 && (
            <div style={{ fontSize: '0.82rem', opacity: 0.85, marginBottom: 6 }}>
              <strong>Tables:</strong> {tables.join(', ')}
            </div>
          )}
          {missingLikely.length > 0 && (
            <div style={{
              fontSize: '0.82rem',
              border: '1px solid rgba(250, 204, 21, 0.35)',
              background: 'rgba(250, 204, 21, 0.10)',
              padding: '0.45rem 0.6rem',
              borderRadius: 8,
              marginBottom: 6
            }}>
              <strong>Workspace note:</strong> May be missing in some workspaces:
              <div style={{ marginTop: 4 }}>
                {missingLikely.map((t) => (
                  <code key={t} style={{ marginRight: 8 }}>{t}</code>
                ))}
              </div>
            </div>
          )}
        </div>

        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button type="button" className="clear-btn" onClick={copyOne} disabled={!body} title="Copy KQL">
            {copied ? <><Check size={14} /> Copied</> : <><Copy size={14} /> Copy</>}
          </button>
          <button type="button" className="clear-btn" onClick={downloadOne} disabled={!body} title="Download this query">
            <Download size={14} /> Download
          </button>
        </div>
      </div>

      <pre style={{
        margin: 0,
        marginTop: 8,
        padding: '0.75rem',
        borderRadius: 8,
        overflowX: 'auto',
        background: '#0d1117',
        border: '1px solid rgba(255,255,255,0.06)',
        fontSize: '0.82rem',
        lineHeight: 1.6
      }}>
        {body || '(empty query)'}
      </pre>
    </div>
  );
}

export default function ResultPanel({ result, isLoading }) {
  const [copiedAll, setCopiedAll] = useState(false);
  const [kqlTab, setKqlTab] = useState('All');

  const analysis = useMemo(() => (result?.analysis || result || {}), [result]);

  const riskConf = RISK_CONFIG[analysis.risk_level] || RISK_CONFIG.MEDIUM;
  const decisionConf = DECISION_CONFIG[analysis.triage_decision] || DECISION_CONFIG.enrich;
  const RiskIcon = riskConf.icon;

  const routerHint = useMemo(() => {
    return (
      analysis?.router_hint ||
      analysis?.enrichment_data?.soc_artifacts?.router_hint ||
      null
    );
  }, [analysis]);

  const qualityChecks = useMemo(() => {
    const qc = analysis?.enrichment_data?.soc_artifacts?.quality_checks;
    return Array.isArray(qc) ? qc : [];
  }, [analysis]);

  const actions = useMemo(() => {
    const arr = analysis.recommended_actions || [];
    return Array.isArray(arr) ? arr : [arr];
  }, [analysis.recommended_actions]);

  const kqlPayload = useMemo(() => extractSentinelKqlPayload(analysis), [analysis]);
  const kqlQueries = useMemo(() => (kqlPayload.queries || []), [kqlPayload]);

  const kqlValidationWarnings = useMemo(() => {
    const v = kqlPayload?.result?.validation;
    const warnings = v?.warnings;
    return Array.isArray(warnings) ? warnings : [];
  }, [kqlPayload]);

  const kqlWithCategory = useMemo(
    () => kqlQueries.map((q, idx) => ({ q, idx, category: categorizeKqlQuery(q) })),
    [kqlQueries]
  );

  const kqlCategories = useMemo(() => {
    const set = new Set(kqlWithCategory.map(x => x.category));
    return ['All', ...Array.from(set).sort()];
  }, [kqlWithCategory]);

  const filteredKql = useMemo(
    () => (kqlTab === 'All' ? kqlWithCategory : kqlWithCategory.filter(x => x.category === kqlTab)),
    [kqlWithCategory, kqlTab]
  );

  const kqlBundleText = useMemo(
    () => buildKqlBundleText(kqlQueries, kqlPayload.result || {}),
    [kqlQueries, kqlPayload]
  );

  const allTables = useMemo(() => {
    const set = new Set();
    for (const q of kqlQueries) {
      for (const t of detectKqlTables(q?.query)) set.add(t);
    }
    return Array.from(set).sort();
  }, [kqlQueries]);

  const missingLikelyGlobal = useMemo(
    () => allTables.filter(t => OFTEN_MISSING_TABLES.has(t)),
    [allTables]
  );

  const copyText = useCallback(async (text) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.cssText = 'position:fixed;opacity:0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
  }, []);

  const copyAllQueries = useCallback(async () => {
    await copyText(kqlBundleText);
    setCopiedAll(true);
    setTimeout(() => setCopiedAll(false), 1400);
  }, [copyText, kqlBundleText]);

  const handleDownloadAll = useCallback(() => {
    const base = result?.alert_id ? `sentinel_${String(result.alert_id).slice(0, 8)}` : `sentinel_${Date.now()}`;
    downloadTextFile(`${base}.kql`, kqlBundleText, 'text/plain');
  }, [kqlBundleText, result]);

  if (isLoading) {
    return (
      <div className="result-panel loading">
        <div className="loading-animation">
          <div className="pulse-ring" />
          <div className="pulse-ring-2" />
          <div className="loading-icon-wrap">
            <Shield size={26} />
          </div>
        </div>
        <div className="loading-title">AI Agents Analyzing...</div>
        <div className="loading-steps">
          {[
            { icon: '🔀', text: 'Routing & triage classification' },
            { icon: '🟠', text: 'Entity typing + normalization' },
            { icon: '🔍', text: 'Threat intel + CVE enrichment' },
            { icon: '🧷', text: 'Evidence scoping/linkage (anti-contamination)' },
            { icon: '📚', text: 'RAG context retrieval (if needed)' },
            { icon: '📝', text: 'LLM narrative + ticket pack' },
            { icon: '🧪', text: 'Generate Sentinel KQL investigation queries' },
          ].map((step, i) => (
            <div key={i} className="loading-step" style={{ animationDelay: `${i * 0.45}s` }}>
              <span className="loading-step-dot" style={{ animationDelay: `${i * 0.2}s` }} />
              {step.icon} {step.text}
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (result?.status === 'processing') {
    return (
    <div className="result-panel loading">
      <div className="loading-title">
        Investigation queued...
      </div>
    </div>
    );
  }
  if (!result) return null;

  const baseFile = result?.alert_id ? `sentinel_${String(result.alert_id).slice(0, 8)}` : `sentinel_${Date.now()}`;

  return (
    <div className="result-panel">
      <div className="result-header">
        <div className="result-badges">
          <span className={riskConf.badgeCls}>
            <RiskIcon size={11} /> {riskConf.label}
          </span>
          <span className={decisionConf.badgeCls}>{decisionConf.label}</span>
        </div>

        <div className="attack-type">{analysis.attack_type || 'Unknown Attack Type'}</div>
        <div className="decision-desc">{decisionConf.desc}</div>

        {routerHint && (
          <div style={{ marginTop: 8, fontSize: '0.92rem', opacity: 0.9 }}>
            <strong>Router Hint (pre-screen):</strong>{' '}
            <span style={{ fontWeight: 700 }}>
              {String(routerHint.decision || '').toUpperCase()}
            </span>
            {routerHint.confidence != null && (
              <span style={{ marginLeft: 10 }}>
                ({Math.round(Number(routerHint.confidence) * 100)}%)
              </span>
            )}
          </div>
        )}
      </div>

      <ConfidenceBar score={analysis.confidence_score} />

      <div className="result-sections">
        {qualityChecks.length > 0 && (
          <Section title={`Quality Checks (${qualityChecks.length})`} icon={AlertTriangle} defaultOpen={true} accentColor="var(--high)">
            <ul className="questions-list">
              {qualityChecks.map((w, i) => (
                <li key={i} className="question">• {String(w)}</li>
              ))}
            </ul>
          </Section>
        )}

        <Section title="AI Analysis Explanation" icon={Info} defaultOpen={true} accentColor="var(--accent-bright)">
          <div className="explanation">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>
              {String(analysis.explanation || '')}
            </ReactMarkdown>
          </div>
        </Section>

        <Section title={`Recommended Actions (${actions.length})`} icon={Zap} defaultOpen={true} accentColor="var(--medium)">
          <ol className="actions-list">
            {actions.map((action, i) => (
              <li key={i} className="action-item">
                <span className="action-num">{i + 1}</span>
                <div style={{ flex: 1 }}>
                  <div>{getActionPrimaryText(action)}</div>
                  <ActionMeta actionObj={action} />
                </div>
              </li>
            ))}
          </ol>
        </Section>

        {kqlQueries.length > 0 && (
          <Section title={`Sentinel KQL Queries (${kqlQueries.length})`} icon={Activity} defaultOpen={false} accentColor="var(--teal)">
            <div style={{ marginBottom: 10, opacity: 0.9, fontSize: '0.9rem' }}>
              <div><strong>Tables referenced:</strong> {allTables.length ? allTables.join(', ') : '—'}</div>

              {kqlValidationWarnings.length > 0 && (
                <div style={{
                  marginTop: 10,
                  padding: '0.6rem 0.75rem',
                  borderRadius: 10,
                  border: '1px solid rgba(248, 113, 113, 0.35)',
                  background: 'rgba(248, 113, 113, 0.08)'
                }}>
                  <strong>KQL Validation Warnings:</strong>
                  <ul style={{ margin: '6px 0 0 18px' }}>
                    {kqlValidationWarnings.map((w, i) => <li key={i}>{String(w)}</li>)}
                  </ul>
                </div>
              )}

              {missingLikelyGlobal.length > 0 && (
                <div style={{
                  marginTop: 10,
                  padding: '0.6rem 0.75rem',
                  borderRadius: 10,
                  border: '1px solid rgba(250, 204, 21, 0.35)',
                  background: 'rgba(250, 204, 21, 0.10)'
                }}>
                  <strong>Workspace note:</strong> These tables may be missing in some Sentinel workspaces:&nbsp;
                  {missingLikelyGlobal.map(t => <code key={t} style={{ marginRight: 8 }}>{t}</code>)}
                </div>
              )}
            </div>

            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 10 }}>
              {kqlCategories.map((cat) => (
                <button
                  key={cat}
                  type="button"
                  className="clear-btn"
                  onClick={() => setKqlTab(cat)}
                  style={{
                    borderColor: kqlTab === cat ? 'rgba(96,165,250,0.6)' : undefined,
                    background: kqlTab === cat ? 'rgba(96,165,250,0.12)' : undefined
                  }}
                >
                  {cat}
                </button>
              ))}
              <div style={{ flex: 1 }} />
              <button type="button" className="clear-btn" onClick={copyAllQueries} title="Copy all queries">
                {copiedAll ? <><Check size={14} /> Copied</> : <><Copy size={14} /> Copy All</>}
              </button>
              <button type="button" className="clear-btn" onClick={handleDownloadAll} title="Download .kql file">
                <Download size={14} /> Download .kql
              </button>
            </div>

            {filteredKql.map(({ q, idx, category }) => (
              <KqlQueryCard
                key={idx}
                idx={idx}
                baseFile={baseFile}
                q={{ ...q, name: q?.name ? `${q.name} (${category})` : `KQL Query (${category})` }}
                onCopy={copyText}
              />
            ))}
          </Section>
        )}

        {analysis.playbook && (
          <Section title="Response Playbook" icon={FileText} defaultOpen={false} accentColor="var(--purple)">
            <div className="playbook-content">
              <ReactMarkdown remarkPlugins={[remarkGfm]}>
                {String(analysis.playbook || '')}
              </ReactMarkdown>
            </div>
          </Section>
        )}

        {analysis.follow_up_questions?.length > 0 && (
          <Section title="Follow-up Questions" icon={HelpCircle} defaultOpen={false} accentColor="var(--accent-bright)">
            <ul className="questions-list">
              {analysis.follow_up_questions.map((q, i) => (
                <li key={i} className="question">❓ {String(q)}</li>
              ))}
            </ul>
          </Section>
        )}

        {analysis.enrichment_data && Object.keys(analysis.enrichment_data).length > 0 && (
          <Section title="Agent Enrichment Data" icon={Activity} defaultOpen={false} accentColor="var(--high)">
            <div className="enrichment-cards">
              {Object.entries(analysis.enrichment_data).map(([key, value]) => {
                if (!value || (typeof value === 'object' && Object.keys(value).length === 0)) return null;
                const label = key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
                return (
                  <div key={key} className="enrichment-card">
                    <div className="enrichment-card-header">{label}</div>
                    <div className="enrichment-card-body">
                      {typeof value === 'string' ? (
                        <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{value}</p>
                      ) : Array.isArray(value) ? (
                        <ul style={{ margin: 0, paddingLeft: '1.2rem' }}>
                          {value.slice(0, 10).map((item, i) => (
                            <li key={i} style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: 2 }}>
                              {typeof item === 'string' ? item : JSON.stringify(item)}
                            </li>
                          ))}
                          {value.length > 10 && <li style={{ color: 'var(--text-muted)' }}>... +{value.length - 10} more</li>}
                        </ul>
                      ) : (
                        <pre className="enrichment-json-mini">
                          {JSON.stringify(value, null, 2)}
                        </pre>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </Section>
        )}
      </div>
    </div>
  );
}