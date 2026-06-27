import React, { useState } from 'react';
import { analyzeAlert, getTaskStatus } from '../services/api';
import toast from 'react-hot-toast';
import { Send } from 'lucide-react';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

const SAMPLE_ALERTS = [
  {
    label: '🔴 Ransomware Indicator',
    data: {
      alert_source: 'CrowdStrike EDR',
      severity: 'CRITICAL',
      affected_asset: 'SRV-DB-01',
      ioc_list: 'd41d8cd98f00b204e9800998ecf8427e, 192.168.1.100',
      mitre_mapping: 'T1486 - Data Encrypted for Impact',
      description:
        'Suspicious mass file encryption detected. vssadmin.exe deleting shadow copies. Outbound connection to known C2 IP.',
      additional_context: ''
    }
  },
  {
    label: '🟠 Phishing Attempt',
    data: {
      alert_source: 'Microsoft Defender',
      severity: 'HIGH',
      affected_asset: 'WS-001',
      ioc_list: 'evil-domain.ru, phishing@evil-domain.ru',
      mitre_mapping: 'T1566.001 - Spearphishing Attachment',
      description:
        'User opened suspicious email attachment. cmd.exe spawned from outlook.exe. HTTP beacon to unknown domain.',
      additional_context: ''
    }
  },
  {
    label: '🟢 Nessus Scan (False Positive)',
    data: {
      alert_source: 'Palo Alto NGFW',
      severity: 'LOW',
      affected_asset: '10.0.1.200',
      ioc_list: '10.0.1.5',
      mitre_mapping: '',
      description:
        'Port scan detected from internal IP. Source matches authorized Nessus vulnerability scanner schedule.',
      additional_context: ''
    }
  }
];

const initialForm = {
  alert_source: '',
  severity: 'HIGH',
  affected_asset: '',
  ioc_list: '',
  mitre_mapping: '',
  description: '',
  additional_context: ''
};

export default function AlertForm({ setResult, setIsAnalyzing, isAnalyzing }) {
  const [form, setForm] = useState(initialForm);

  const loadSample = (sample) => {
    setForm(sample.data);
    toast.success(`Loaded sample: ${sample.label}`);
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setForm(prev => ({ ...prev, [name]: value }));
  };

  const sanitizePayload = () => ({
    alert_source: form.alert_source.trim(),
    severity: form.severity,
    affected_asset: form.affected_asset.trim(),
    ioc_list: form.ioc_list.trim(),
    mitre_mapping: form.mitre_mapping.trim(),
    description: form.description.trim(),
    additional_context: form.additional_context.trim(),
    timestamp: new Date().toISOString()
  });

  const validateForm = () => {
    const payload = sanitizePayload();

    if (!payload.alert_source) return 'Alert source is required';
    if (!payload.affected_asset) return 'Affected asset is required';
    if (!payload.description) return 'Alert description is required';

    if (payload.alert_source.length > 120) return 'Alert source is too long (max 120 characters)';
    if (payload.affected_asset.length > 200) return 'Affected asset is too long (max 200 characters)';

    if (payload.description.length < 15) return 'Alert description should be more detailed (minimum 15 characters)';
    if (payload.description.length > 5000) return 'Alert description is too long (max 5000 characters)';

    if (payload.ioc_list.length > 2000) return 'IOC list is too long (max 2000 characters)';
    if (payload.mitre_mapping.length > 200) return 'MITRE mapping is too long (max 200 characters)';
    if (payload.additional_context.length > 2000) return 'Additional context is too long (max 2000 characters)';

    return null;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    const validationError = validateForm();
    if (validationError) {
      toast.error(validationError);
      return;
    }

    const payload = sanitizePayload();

    setIsAnalyzing(true);
    setResult(null);

    const toastId = toast.loading('🔍 Analyzing alert with AI agents...');

    try {
      const response = await analyzeAlert(payload);
      const taskId = response.data.task_id;

      toast.loading('⏳ Investigation queued...', { id: toastId });

      let completed = false;

      // Polling timeout protection (5 minutes)
      const started = Date.now();

      while (!completed) {
        if (Date.now() - started > 300000) {
          completed = true;
          toast.error('⏱ Investigation timed out', { id: toastId });
          break;
        }

        await new Promise(r => setTimeout(r, 2500));

        const taskResp = await getTaskStatus(taskId);
        const status = taskResp.data.status;

        if (status === 'SUCCESS') {
          completed = true;
          setResult(taskResp.data.result);
          const secs = taskResp.data.result?.processing_time_seconds;
          toast.success('✅ Investigation completed in ${secs}s', { id: toastId, duration: 3000, });
        } else if (status === 'FAILURE') {
          completed = true;
          toast.error('❌ Investigation failed', { id: toastId });
        }
      }
    } catch (error) {
      toast.error(`Analysis failed: ${error.message}`, { id: toastId });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleReset = () => {
    setForm(initialForm);
    setResult(null);
    toast.success('Form cleared');
  };

  return (
    <div className="alert-form-container">
      <div className="form-header">
        <h2>🔍 Alert Analysis</h2>
        <p>Submit a security alert for AI-powered triage</p>
      </div>

      {/* Sample Alerts */}
      <div className="sample-alerts">
        <label className="sample-alerts-label">Quick Samples</label>
        <div className="sample-buttons">
          {SAMPLE_ALERTS.map((s, i) => (
            <button
              key={i}
              type="button"
              className="sample-btn"
              onClick={() => loadSample(s)}
              disabled={isAnalyzing}
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>

      <form onSubmit={handleSubmit} className="alert-form">
        <div className="form-row">
          <div className="form-group">
            <label>Alert Source <span className="req">*</span></label>
            <input
              type="text"
              name="alert_source"
              value={form.alert_source}
              onChange={handleChange}
              placeholder="e.g., CrowdStrike EDR, Splunk SIEM"
              required
              maxLength={120}
            />
          </div>

          <div className="form-group">
            <label>Severity <span className="req">*</span></label>
            <select
              name="severity"
              value={form.severity}
              onChange={handleChange}
            >
              {SEVERITIES.map(s => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>
        </div>

        <div className="form-row">
          <div className="form-group">
            <label>Affected Asset <span className="req">*</span></label>
            <input
              type="text"
              name="affected_asset"
              value={form.affected_asset}
              onChange={handleChange}
              placeholder="e.g., WS-001, 10.0.1.50, SRV-DB-01"
              required
              maxLength={200}
            />
          </div>

          <div className="form-group">
            <label>MITRE ATT&amp;CK Mapping</label>
            <input
              type="text"
              name="mitre_mapping"
              value={form.mitre_mapping}
              onChange={handleChange}
              placeholder="e.g., T1566.001"
              maxLength={200}
            />
          </div>
        </div>

        <div className="form-group">
          <label>IOC List</label>
          <input
            type="text"
            name="ioc_list"
            value={form.ioc_list}
            onChange={handleChange}
            placeholder="Comma-separated: IPs, domains, hashes, URLs"
            maxLength={2000}
          />
          <span className="field-hint">
            Separate multiple indicators with commas.
          </span>
        </div>

        <div className="form-group">
          <label>Alert Description <span className="req">*</span></label>
          <textarea
            name="description"
            value={form.description}
            onChange={handleChange}
            placeholder="Describe the alert event in detail..."
            rows={4}
            required
            maxLength={5000}
          />
          <span className="field-hint">
            Include process behavior, network activity, users involved, and timing if known.
          </span>
        </div>

        <div className="form-group">
          <label>Additional Context</label>
          <textarea
            name="additional_context"
            value={form.additional_context}
            onChange={handleChange}
            placeholder="User reports, prior incidents, environment notes..."
            rows={2}
            maxLength={2000}
          />
        </div>

        <div style={{ display: 'flex', gap: 10 }}>
          <button
            type="submit"
            className="submit-btn"
            disabled={isAnalyzing}
          >
            {isAnalyzing ? (
              <>
                <span className="spinner" />
                Analyzing with AI Agents...
              </>
            ) : (
              <>
                <Send size={16} />
                Analyze Alert
              </>
            )}
          </button>

          <button
            type="button"
            className="clear-btn"
            onClick={handleReset}
            disabled={isAnalyzing}
            style={{ minWidth: 110, justifyContent: 'center' }}
          >
            Reset
          </button>
        </div>
      </form>
    </div>
  );
}