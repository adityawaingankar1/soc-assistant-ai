import React, { useState, useRef, useEffect, useCallback } from 'react';
import {
  Upload, FileText, CheckCircle, AlertCircle, Database,
  Search, RefreshCw, RotateCcw, ShieldCheck, Trash2
} from 'lucide-react';
import {
  uploadDocument,
  getKBStats,
  queryKnowledgeBase,
  resetKnowledgeBase,
  reloadKnowledgeBase,
  getKBDocuments,
  deleteKBDocument
} from '../services/api';
import toast from 'react-hot-toast';

const DOC_TYPES = [
  { value: 'mitre_attack', label: '⚔️ MITRE ATT&CK', desc: 'Attack techniques and TTPs' },
  { value: 'runbook', label: '📋 Runbook', desc: 'Response procedures' },
  { value: 'incident_history', label: '📁 Incident History', desc: 'Past incident reports' },
  { value: 'cve_database', label: '🔓 CVE Database', desc: 'Vulnerability data' },
  { value: 'custom', label: '📄 Custom', desc: 'Any security document' },
];

function formatBytes(bytes = 0) {
  if (!bytes) return '0 B';
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / (1024 ** i)).toFixed(i === 0 ? 0 : 1)} ${sizes[i]}`;
}

export default function DocUploadPanel() {
  const [docType, setDocType] = useState('custom');
  const [uploading, setUploading] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [kbStats, setKbStats] = useState(null);

  const [query, setQuery] = useState('');
  const [querying, setQuerying] = useState(false);
  const [queryResults, setQueryResults] = useState(null);

  const [adminBusy, setAdminBusy] = useState(false);

  const [docInventory, setDocInventory] = useState([]);
  const [inventorySearch, setInventorySearch] = useState('');
  const [inventoryLoading, setInventoryLoading] = useState(false);

  const fileRef = useRef();
  const role = localStorage.getItem('soc_role');
  const isAdmin = role === 'admin';

  const loadStats = useCallback(() => {
    getKBStats()
      .then(r => setKbStats(r.data))
      .catch(() => {});
  }, []);

  const loadInventory = useCallback(async () => {
    setInventoryLoading(true);
    try {
      const res = await getKBDocuments(inventorySearch, '');
      setDocInventory(res.data.documents || []);
    } catch (err) {
      if (!String(err.message).includes('404')) {
        toast.error(err.message || 'Failed to load KB documents');
      }
      setDocInventory([]);
    } finally {
      setInventoryLoading(false);
    }
  }, [inventorySearch]);

  useEffect(() => {
    loadStats();
  }, [loadStats]);

  useEffect(() => {
    loadInventory();
  }, [loadInventory]);

  const handleUpload = async (file) => {
    if (!file) return;

    const allowed = ['.txt', '.md', '.pdf'];
    const ext = '.' + file.name.split('.').pop().toLowerCase();

    if (!allowed.includes(ext)) {
      toast.error(`File type not supported. Use: ${allowed.join(', ')}`);
      return;
    }

    setUploading(true);
    const toastId = toast.loading(`📤 Uploading ${file.name}...`);

    try {
      const res = await uploadDocument(file, docType);
      const doc = res.data.document;

      setUploadedFiles(prev => [{
        ...doc,
        status: 'success',
        time: new Date().toLocaleTimeString()
      }, ...prev]);

      setKbStats(res.data.kb_stats);
      loadInventory();

      toast.success(
        `✅ ${doc.filename} — ${doc.chunks_ingested} chunks ingested`,
        { id: toastId }
      );
    } catch (err) {
      toast.error(`Upload failed: ${err.message}`, { id: toastId });

      setUploadedFiles(prev => [{
        filename: file.name,
        doc_type: docType,
        status: 'error',
        error: err.message,
        time: new Date().toLocaleTimeString()
      }, ...prev]);
    } finally {
      setUploading(false);
      if (fileRef.current) fileRef.current.value = '';
    }
  };

  const onDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) handleUpload(file);
  };

  const handleTestQuery = async () => {
    if (!query.trim()) return;

    setQuerying(true);
    setQueryResults(null);

    try {
      const res = await queryKnowledgeBase(query.trim(), 4);
      setQueryResults(res.data);
      toast.success(`Found ${res.data.matches_found} relevant chunk(s)`);
    } catch (err) {
      toast.error(err.message || 'KB query failed');
    } finally {
      setQuerying(false);
    }
  };

  const handleResetKB = async () => {
    if (!window.confirm('Reset the entire knowledge base? This will remove all indexed chunks and document inventory.')) return;

    setAdminBusy(true);
    try {
      const res = await resetKnowledgeBase();
      toast.success(res.data.message || 'Knowledge base reset');
      setKbStats(res.data.stats);
      setUploadedFiles([]);
      setQueryResults(null);
      setDocInventory([]);
    } catch (err) {
      toast.error(err.message || 'Reset failed');
    } finally {
      setAdminBusy(false);
    }
  };

  const handleReloadKB = async () => {
    if (!window.confirm('Reload the sample knowledge base?')) return;

    setAdminBusy(true);
    try {
      const res = await reloadKnowledgeBase();
      toast.success(`Reloaded sample KB (${res.data.chunks_loaded} chunks)`);
      setKbStats(res.data.stats);
      loadStats();
      loadInventory();
    } catch (err) {
      toast.error(err.message || 'Reload failed');
    } finally {
      setAdminBusy(false);
    }
  };

  const handleDeleteDocument = async (docId, filename) => {
    if (!window.confirm(`Delete document "${filename}" from the knowledge base?`)) return;

    try {
      const res = await deleteKBDocument(docId);
      toast.success(res.data.message || 'Document deleted');
      setKbStats(res.data.stats);
      loadInventory();
    } catch (err) {
      toast.error(err.message || 'Delete failed');
    }
  };

  return (
    <div className="doc-upload-panel">
      <div className="form-header">
        <div className="form-header-top">
          <div className="form-header-icon">
            <Database size={16} />
          </div>
          <h2>Knowledge Base Manager</h2>
        </div>
        <p>Upload security documents to improve AI analysis accuracy and SOC chat grounding</p>
      </div>

      {kbStats && (
        <div className="kb-stats" style={{ margin: '0 1.5rem 1rem' }}>
          <Database size={14} />
          <span><strong>{kbStats.total_chunks}</strong> chunks indexed</span>
          <div className="kb-divider" />
          <span>Model: <strong>{kbStats.embedding_model}</strong></span>
          <div className="kb-divider" />
          <span>Chunk size: <strong>{kbStats.chunk_size}</strong> / overlap <strong>{kbStats.chunk_overlap}</strong></span>
        </div>
      )}

      <div className="kb-layout">
        {/* LEFT COLUMN */}
        <div className="kb-left">
          {isAdmin && (
            <div className="kb-admin-actions">
              <button className="clear-btn" onClick={handleReloadKB} disabled={adminBusy} type="button">
                <RefreshCw size={13} /> Reload Sample KB
              </button>
              <button
                className="clear-btn"
                onClick={handleResetKB}
                disabled={adminBusy}
                type="button"
                style={{ borderColor: 'rgba(239,68,68,0.25)' }}
              >
                <RotateCcw size={13} /> Reset KB
              </button>
            </div>
          )}

          <div className="form-group">
            <label>Document Type</label>
            <div className="doc-type-grid">
              {DOC_TYPES.map(dt => (
                <button
                  key={dt.value}
                  className={`doc-type-btn ${docType === dt.value ? 'active' : ''}`}
                  onClick={() => setDocType(dt.value)}
                  type="button"
                >
                  <span className="doc-type-label">{dt.label}</span>
                  <span className="doc-type-desc">{dt.desc}</span>
                </button>
              ))}
            </div>
          </div>

          <div
            className={`drop-zone ${dragOver ? 'drag-over' : ''} ${uploading ? 'uploading' : ''}`}
            onDragOver={e => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={onDrop}
            onClick={() => !uploading && fileRef.current?.click()}
          >
            <input
              ref={fileRef}
              type="file"
              accept=".txt,.md,.pdf"
              style={{ display: 'none' }}
              onChange={e => handleUpload(e.target.files[0])}
            />
            {uploading ? (
              <>
                <span className="spinner" style={{ width: 28, height: 28, borderWidth: 3 }} />
                <p className="drop-zone-text">Processing document...</p>
              </>
            ) : (
              <>
                <Upload size={28} style={{ color: 'var(--accent)', opacity: dragOver ? 1 : 0.6 }} />
                <p className="drop-zone-text">
                  {dragOver ? 'Drop file here!' : 'Drag & drop or click to upload'}
                </p>
                <p className="drop-zone-hint">Supports: .txt, .md, .pdf</p>
              </>
            )}
          </div>

          <div className="kb-test-panel">
            <label className="kb-section-label">Test the Knowledge Base</label>

            <div className="kb-query-row">
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Ask a question to test KB retrieval..."
              />
              <button
                className="clear-btn"
                type="button"
                onClick={handleTestQuery}
                disabled={querying || !query.trim()}
              >
                <Search size={13} />
                {querying ? 'Querying...' : 'Test'}
              </button>
            </div>

            <span className="field-hint">
              Example: "What is our ransomware playbook?" or "What does T1566.001 mean?"
            </span>
          </div>
        </div>

        {/* RIGHT COLUMN */}
        <div className="kb-right">
          {queryResults && (
            <div className="kb-output-card">
              <p className="upload-history-label">
                KB Retrieval Results ({queryResults.matches_found})
              </p>

              {queryResults.matches?.length > 0 ? queryResults.matches.map((m, i) => (
                <div key={i} className="upload-item success kb-highlight-item">
                  <ShieldCheck size={14} />
                  <div className="upload-item-info">
                    <span className="upload-item-name">
                      {m.source} · {m.doc_type} · chunk {m.chunk_index + 1}/{m.chunk_total}
                    </span>
                    <span className="upload-item-meta kb-bright-meta">
                      {m.snippet}
                    </span>
                  </div>
                </div>
              )) : (
                <div className="upload-item error kb-highlight-item">
                  <AlertCircle size={14} />
                  <div className="upload-item-info">
                    <span className="upload-item-name">No matches found</span>
                    <span className="upload-item-meta kb-bright-meta">Try a broader or more specific query.</span>
                  </div>
                </div>
              )}
            </div>
          )}

          <div className="kb-output-card">
            <div className="kb-inventory-header">
              <p className="upload-history-label" style={{ marginBottom: 0 }}>Knowledge Base Inventory</p>
              <div className="kb-search-row">
                <input
                  type="text"
                  value={inventorySearch}
                  onChange={(e) => setInventorySearch(e.target.value)}
                  placeholder="Search documents by filename..."
                />
                <button className="clear-btn" onClick={loadInventory} type="button">
                  <RefreshCw size={13} />
                </button>
              </div>
            </div>

            {inventoryLoading ? (
              <div className="loading-text" style={{ padding: '1.25rem 0' }}>Loading KB inventory...</div>
            ) : docInventory.length === 0 ? (
              <div className="empty-state" style={{ padding: '2rem 1rem' }}>
                <div className="empty-state-icon">📚</div>
                <p>No uploaded knowledge base documents found.</p>
              </div>
            ) : (
              docInventory.map((doc) => (
                <div key={doc.id} className="upload-item success kb-highlight-item">
                  <FileText size={14} />
                  <div className="upload-item-info">
                    <span className="upload-item-name">{doc.filename}</span>
                    <span className="upload-item-meta kb-bright-meta">
                      {doc.doc_type} · {doc.chunks_ingested} chunks · {formatBytes(doc.file_size_bytes)} · by {doc.uploaded_by_username || 'unknown'} · {doc.created_at ? new Date(doc.created_at).toLocaleString() : ''}
                    </span>
                    {doc.preview_text && (
                      <span className="upload-item-meta kb-preview-text">
                        <strong>Preview:</strong> {doc.preview_text}
                      </span>
                    )}
                  </div>

                  {isAdmin && (
                    <button
                      className="clear-btn"
                      onClick={() => handleDeleteDocument(doc.id, doc.filename)}
                      type="button"
                      title="Delete document"
                      style={{ borderColor: 'rgba(239,68,68,0.25)' }}
                    >
                      <Trash2 size={13} style={{ color: 'var(--critical)' }} />
                    </button>
                  )}
                </div>
              ))
            )}
          </div>

          {uploadedFiles.length > 0 && (
            <div className="kb-output-card">
              <p className="upload-history-label">Recent Upload Session</p>
              {uploadedFiles.map((f, i) => (
                <div key={i} className={`upload-item ${f.status} kb-highlight-item`}>
                  <FileText size={14} />
                  <div className="upload-item-info">
                    <span className="upload-item-name">{f.filename || f.name}</span>

                    {f.status === 'success' ? (
                      <>
                        <span className="upload-item-meta kb-bright-meta">
                          {f.doc_type || f.type} · {f.chunks_ingested || f.chunks} chunks · {formatBytes(f.file_size_bytes || f.fileSize)} · {f.time}
                        </span>
                        {f.preview_text || f.previewText ? (
                          <span className="upload-item-meta kb-preview-text">
                            <strong>Preview:</strong> {f.preview_text || f.previewText}
                          </span>
                        ) : null}
                      </>
                    ) : (
                      <span className="upload-item-meta kb-bright-meta">Error: {f.error}</span>
                    )}
                  </div>

                  {f.status === 'success'
                    ? <CheckCircle size={14} color="var(--low)" />
                    : <AlertCircle size={14} color="var(--critical)" />
                  }
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}