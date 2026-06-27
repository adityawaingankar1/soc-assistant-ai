// frontend/src/components/ChatPanel.jsx
import React, {
  useState,
  useRef,
  useEffect,
  useCallback,
  useMemo,
} from 'react';

import {
  streamChatMessage,
  clearChatHistory,
  getChatHistory,
  listChatSessions,
} from '../services/api';

import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkBreaks from 'remark-breaks';

import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism';

import {
  Send,
  Trash2,
  Bot,
  User,
  Copy,
  Check,
  Plus,
  RefreshCw,
} from 'lucide-react';

import toast from 'react-hot-toast';
import { v4 as uuidv4 } from 'uuid';

const GREETING = {
  role: 'assistant',
  content:
    "Hello! I'm your AI SOC Assistant.\n\n" +
    'How can I help you today?',
};

const QUICK_QUESTIONS = [
  'What is phishing?',
  'Difference between IDS and IPS',
  'What is T1566.001 and how do I detect it?',
  'How do I contain a ransomware incident?',
  'What is a SIEM?',
];

function decodeJwt(token) {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');

    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => `%${(`00${c.charCodeAt(0).toString(16)}`).slice(-2)}`)
        .join('')
    );

    return JSON.parse(jsonPayload);
  } catch {
    return null;
  }
}

function getUserScopedSessionKey() {
  const token = localStorage.getItem('soc_token');
  const payload = token ? decodeJwt(token) : null;
  const username = payload?.username || 'unknown';

  return `soc_chat_session_id_${username}`;
}

function normalizeIso(ts) {
  if (!ts || typeof ts !== 'string') return ts;

  const hasTz = /Z$|[+\-]\d{2}:\d{2}$/.test(ts);
  return hasTz ? ts : `${ts}Z`;
}

const dtf = new Intl.DateTimeFormat(undefined, {
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: true,
  timeZoneName: 'short',
});

function formatTs(ts) {
  if (!ts) return '';

  try {
    return dtf.format(new Date(normalizeIso(ts)));
  } catch {
    return '';
  }
}

function CodeBlock({ language, value }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = value;
      ta.style.cssText = 'position:fixed;opacity:0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }

    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  }, [value]);

  return (
    <div className="cb-wrapper">
      <div className="cb-header">
        <span className="cb-lang">{language || 'code'}</span>

        <button className="cb-copy" onClick={handleCopy} type="button">
          {copied ? (
            <>
              <Check size={14} /> Copied
            </>
          ) : (
            <>
              <Copy size={14} /> Copy code
            </>
          )}
        </button>
      </div>

      <SyntaxHighlighter language={language || 'text'} style={oneDark}>
        {value}
      </SyntaxHighlighter>
    </div>
  );
}

function MessageContent({ content }) {
  const components = useMemo(
    () => ({
      // Headings
      h1: ({ children }) => <h1 className="md-h1">{children}</h1>,
      h2: ({ children }) => <h2 className="md-h2">{children}</h2>,
      h3: ({ children }) => <h3 className="md-h3">{children}</h3>,
      h4: ({ children }) => <h4 className="md-h4">{children}</h4>,

      // Paragraphs
      p: ({ children }) => <p className="md-p">{children}</p>,

      // Inline formatting
      strong: ({ children }) => <strong className="md-strong">{children}</strong>,
      em: ({ children }) => <em className="md-em">{children}</em>,

      // Inline code
      code({ className, children, inline, node, ...props }) {
        const match = /language-(\w+)/.exec(className || '');
        const codeText = String(children).replace(/\n$/, '');

        if (!inline && (match || codeText.includes('\n'))) {
          return (
            <CodeBlock
              language={match ? match[1] : ''}
              value={codeText}
            />
          );
        }

        return <code className="md-inline-code" {...props}>{children}</code>;
      },

      // Code blocks
      pre({ children, node }) {
        const codeNode = node?.children?.[0];

        if (codeNode?.tagName === 'code') {
          const cls = codeNode.properties?.className;
          const langMatch = /language-(\w+)/.exec(
            Array.isArray(cls) ? cls[0] || '' : cls || ''
          );
          const language = langMatch ? langMatch[1] : '';

          let text = '';
          const walk = (n) => {
            if (n.type === 'text') text += n.value;
            if (n.children) n.children.forEach(walk);
          };
          walk(codeNode);

          return (
            <CodeBlock
              language={language}
              value={text.replace(/\n$/, '')}
            />
          );
        }

        return <pre>{children}</pre>;
      },

      // Lists
      ul: ({ children }) => <ul className="md-ul">{children}</ul>,
      ol: ({ children }) => <ol className="md-ol">{children}</ol>,
      li: ({ children }) => <li className="md-li">{children}</li>,

      // Tables
      table: ({ children }) => (
        <div className="md-table-wrap">
          <table className="md-table">{children}</table>
        </div>
      ),
      thead: ({ children }) => <thead className="md-thead">{children}</thead>,
      th: ({ children }) => <th className="md-th">{children}</th>,
      td: ({ children }) => <td className="md-td">{children}</td>,

      // Block elements
      blockquote: ({ children }) => <blockquote className="md-blockquote">{children}</blockquote>,
      a: ({ children, href }) => <a className="md-link" href={href} target="_blank" rel="noopener noreferrer">{children}</a>,
      hr: () => <hr className="md-hr" />,
    }),
    []
  );

  return (
    <div className="md-body">
      <ReactMarkdown
        remarkPlugins={[remarkGfm, remarkBreaks]}
        components={components}
      >
        {content || ''}
      </ReactMarkdown>
    </div>
  );
}

export default function ChatPanel() {
  const tokenPayload = useMemo(() => {
    const token = localStorage.getItem('soc_token');
    return token ? decodeJwt(token) : null;
  }, []);

  const isAdmin = (tokenPayload?.role || '').toLowerCase() === 'admin';

  const [messages, setMessages] = useState([GREETING]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const [sessionId, setSessionId] = useState(() => {
    const key = getUserScopedSessionKey();
    const stored = localStorage.getItem(key);
    const sid = stored || uuidv4();

    localStorage.setItem(key, sid);

    return sid;
  });

  const [sessionTitle, setSessionTitle] = useState('');
  const [sessions, setSessions] = useState([]);
  const [sessionOwner, setSessionOwner] = useState(null);
  const [copiedIdx, setCopiedIdx] = useState(null);

  const messagesEndRef = useRef(null);

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, scrollToBottom]);

  const loadSessions = useCallback(async () => {
    try {
      const res = await listChatSessions(30);
      const list = res.data.sessions || [];

      setSessions(list);

      const current = list.find((s) => s.session_id === sessionId);
      if (current?.title) setSessionTitle(current.title);
    } catch (e) {
      console.warn('Failed to load chat sessions:', e);
    }
  }, [sessionId]);

  const loadHistory = useCallback(
    async (sid) => {
      try {
        const res = await getChatHistory(sid);

        setSessionOwner(isAdmin ? res.data.owner || null : null);
        setSessionTitle(res.data.title || '');

        const msgs = (res.data.messages || []).map((m) => ({
          role: m.role,
          content: m.content,
          timestamp: m.timestamp || null,
        }));

        setMessages(msgs.length ? msgs : [GREETING]);
      } catch {
        setSessionOwner(null);
        setSessionTitle('');
        setMessages([GREETING]);
      }
    },
    [isAdmin]
  );

  useEffect(() => {
    loadSessions();
    loadHistory(sessionId);
  }, [sessionId, loadSessions, loadHistory]);

  const formatSessionLabel = (s) => {
    const title = (s.title || '').trim() || 'New SOC Chat';
    const msgs = s.message_count ?? 0;
    const last = s.last_active ? formatTs(s.last_active) : '—';

    if (isAdmin) {
      const uname = (s.username || 'unknown-user').trim() || 'unknown-user';
      return `${uname} • ${title} • ${msgs} msgs • Last: ${last}`;
    }

    return `${title} • ${msgs} msgs • Last: ${last}`;
  };

  const copyMessage = useCallback(async (text, idx) => {
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

    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 1800);
  }, []);

  const startNewChat = useCallback(async () => {
    const newId = uuidv4();
    const key = getUserScopedSessionKey();

    localStorage.setItem(key, newId);

    setSessionId(newId);
    setSessionOwner(null);
    setSessionTitle('');
    setMessages([GREETING]);

    toast.success('New chat started');

    await loadSessions();
  }, [loadSessions]);

  const sendMessage = async (e) => {
    e.preventDefault();

    if (!input.trim() || isLoading) return;

    const userMessage = input.trim();
    const localTs = new Date().toISOString();

    setInput('');

    setMessages((prev) => [
      ...prev,
      {
        role: 'user',
        content: userMessage,
        timestamp: localTs,
      },
      {
        role: 'assistant',
        content: '',
        timestamp: new Date().toISOString(),
        streaming: true,
        rag_used: false,
      },
    ]);

    setIsLoading(true);

    let finalRagUsed = false;

    try {
      await streamChatMessage(
        sessionId,
        userMessage,
        true,
        (eventName, payload) => {
          if (eventName === 'meta') {
            finalRagUsed = !!payload.rag_used;
            return;
          }

          if (eventName === 'token') {
            const delta = payload.delta || '';

            if (!delta) return;

            setMessages((prev) => {
              const next = [...prev];

              let idx = next.length - 1;
              while (
                idx >= 0 &&
                !(next[idx].role === 'assistant' && next[idx].streaming)
              ) {
                idx -= 1;
              }

              if (idx >= 0) {
                next[idx] = {
                  ...next[idx],
                  content: `${next[idx].content || ''}${delta}`,
                  rag_used: finalRagUsed,
                };
              }

              return next;
            });

            return;
          }

          if (eventName === 'done') {
            if (payload?.title) {
              setSessionTitle(payload.title);
            }

            finalRagUsed = !!payload.rag_used;

            setMessages((prev) => {
              const next = [...prev];

              let idx = next.length - 1;
              while (
                idx >= 0 &&
                !(next[idx].role === 'assistant' && next[idx].streaming)
              ) {
                idx -= 1;
              }

              if (idx >= 0) {
                next[idx] = {
                  ...next[idx],
                  streaming: false,
                  rag_used: finalRagUsed,
                  timestamp: new Date().toISOString(),
                };
              }

              return next;
            });

            return;
          }

          if (eventName === 'error') {
            throw new Error(payload?.message || 'Chat stream error.');
          }
        }
      );

      await loadSessions();
    } catch (error) {
      toast.error(`Chat error: ${error.message}`);

      setMessages((prev) => {
        const next = [...prev];

        let idx = next.length - 1;
        while (
          idx >= 0 &&
          !(next[idx].role === 'assistant' && next[idx].streaming)
        ) {
          idx -= 1;
        }

        if (idx >= 0) {
          next[idx] = {
            ...next[idx],
            content:
              next[idx].content ||
              'Sorry, I encountered an error. Please try again.',
            streaming: false,
            error: true,
          };
        } else {
          next.push({
            role: 'assistant',
            content: 'Sorry, I encountered an error. Please try again.',
            error: true,
          });
        }

        return next;
      });
    } finally {
      setIsLoading(false);
    }
  };

  const deleteCurrentSession = async () => {
    try {
      await clearChatHistory(sessionId);

      setMessages([GREETING]);
      setSessionTitle('');

      toast.success('Chat history deleted');

      await loadSessions();
    } catch {
      toast.error('Failed to delete history');
    }
  };

  const hasStreamingAssistant = messages.some(
    (m) => m.role === 'assistant' && m.streaming
  );

  const headerTitle = (sessionTitle || 'SOC AI Assistant').trim();

  return (
    <div className="chat-panel">
      <div className="chat-header">
        <div className="chat-title">
          <Bot size={20} />
          <h2>{headerTitle}</h2>

          <span className="session-badge">
            Session: {sessionId.slice(0, 8)}
          </span>

          {isAdmin && sessionOwner?.username && (
            <span className="session-badge" style={{ marginLeft: 8 }}>
              Owner: {sessionOwner.username}
            </span>
          )}
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button className="clear-btn" onClick={startNewChat} type="button">
            <Plus size={16} /> New Chat
          </button>

          <button className="clear-btn" onClick={loadSessions} type="button">
            <RefreshCw size={16} /> Refresh Sessions
          </button>

          <button
            className="clear-btn"
            onClick={deleteCurrentSession}
            type="button"
          >
            <Trash2 size={16} /> Delete History
          </button>
        </div>
      </div>

      <div className="quick-questions">
        {QUICK_QUESTIONS.map((q, i) => (
          <button
            key={i}
            className="quick-q-btn"
            onClick={() => setInput(q)}
            type="button"
          >
            {q}
          </button>
        ))}
      </div>

      <div
        style={{
          padding: '0.5rem 0.75rem',
          borderBottom: '1px solid rgba(255,255,255,0.08)',
        }}
      >
        <label
          htmlFor="sessionSelect"
          style={{ fontSize: '0.85rem', opacity: 0.8 }}
        >
          {isAdmin ? 'All sessions:' : 'My sessions:'}
        </label>

        <select
          id="sessionSelect"
          value={sessionId}
          onChange={(e) => {
            const sid = e.target.value;
            const key = getUserScopedSessionKey();

            localStorage.setItem(key, sid);
            setSessionId(sid);
          }}
          style={{
            marginLeft: '0.5rem',
            padding: '0.35rem',
            background: '#0d1117',
            color: '#c9d1d9',
          }}
        >
          {sessions.map((s) => (
            <option key={s.session_id} value={s.session_id}>
              {formatSessionLabel(s)}
            </option>
          ))}
        </select>
      </div>

      <div className="messages-container">
        {messages.map((msg, i) => (
          <div key={i} className={`message ${msg.role}`}>
            <div className="message-avatar">
              {msg.role === 'assistant' ? <Bot size={18} /> : <User size={18} />}
            </div>

            <div className="message-bubble">
              {msg.role === 'assistant' ? (
                <>
                  {msg.content ? (
                    <MessageContent content={msg.content} />
                  ) : msg.streaming ? (
                    <div className="typing">
                      <span />
                      <span />
                      <span />
                    </div>
                  ) : null}

                  {msg.streaming && msg.content && (
                    <span className="stream-cursor">▌</span>
                  )}
                </>
              ) : (
                <p>{msg.content}</p>
              )}

              {msg.timestamp && (
                <div
                  style={{
                    marginTop: 6,
                    fontSize: '0.72rem',
                    opacity: 0.65,
                  }}
                >
                  {formatTs(msg.timestamp)}
                </div>
              )}

              {msg.role === 'assistant' && !msg.error && !msg.streaming && (
                <div className="msg-actions">
                  <button
                    className="msg-action-btn"
                    onClick={() => copyMessage(msg.content, i)}
                    type="button"
                    title="Copy message"
                  >
                    {copiedIdx === i ? (
                      <>
                        <Check size={14} />
                        <span>Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy size={14} />
                        <span>Copy</span>
                      </>
                    )}
                  </button>

                  {msg.rag_used && (
                    <small className="rag-indicator">RAG-enhanced</small>
                  )}
                </div>
              )}

              {msg.role === 'assistant' && msg.streaming && (
                <div className="msg-actions">
                  <small className="rag-indicator">Generating...</small>
                </div>
              )}
            </div>
          </div>
        ))}

        {isLoading && !hasStreamingAssistant && (
          <div className="message assistant">
            <div className="message-avatar">
              <Bot size={18} />
            </div>

            <div className="message-bubble typing">
              <span />
              <span />
              <span />
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      <form className="chat-input-form" onSubmit={sendMessage}>
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask about phishing, MITRE, CVEs, incidents..."
          disabled={isLoading}
          className="chat-input"
        />

        <button
          type="submit"
          className="send-btn"
          disabled={isLoading || !input.trim()}
        >
          <Send size={18} />
        </button>
      </form>
    </div>
  );
}
