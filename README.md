# 🛡️ SOC Assistant — AI-Powered Security Triage

> Automated Security Incident Triage & Response Playbook Generator
> powered by NVIDIA LLaMA 3.1, RAG, and multi-agent AI

## ✨ Features
- 🔀 **Router Agent** — Auto-classify alerts: dismiss/enrich/escalate
- 🔍 **Parallel Enrichment** — Simultaneous threat intel, asset lookup, history
- 📚 **RAG Pipeline** — MITRE ATT&CK, CVEs, runbooks, incident history
- 🧠 **Attack Chain Correlation** — Multi-alert pattern detection
- 🔧 **Tool System** — SIEM query, IOC enrichment, ticket creation, isolation
- 💬 **SOC Chat** — Multi-turn AI assistant with RAG
- 📊 **Dashboard** — Real-time alert monitoring

## 🚀 Quick Start
\`\`\`bash
cp .env.example .env
# Add your NVIDIA_API_KEY from https://build.nvidia.com
pip install -r requirements.txt
uvicorn backend.main:app --reload
\`\`\`

## 🔑 Environment Variables
| Variable | Description | Required |
|---|---|---|
| NVIDIA_API_KEY | NVIDIA NIM API key | ✅ |
| NVIDIA_MODEL | Model name | Default: llama-3.1-70b-instruct |
| DATABASE_URL | SQLite URL | Default: sqlite:///./soc_assistant.db |

## 📖 API Endpoints
| Method | Endpoint | Description |
|---|---|---|
| POST | /api/analyze-alert | Analyze security alert |
| POST | /api/chat | Multi-turn SOC chat |
| POST | /api/upload-docs | Upload to knowledge base |
| POST | /api/correlate-alerts | Attack chain detection |
| GET | /api/alerts | List all alerts |
| GET | /docs | Interactive API documentation |