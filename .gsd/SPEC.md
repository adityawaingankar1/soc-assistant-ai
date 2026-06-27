# SPEC.md — SOC Assistant UX & Performance Overhaul

> **Status**: `FINALIZED`

## Vision
Transform the SOC Assistant from a functional but slow, plain-looking tool into a fast, visually polished, premium cybersecurity platform — fixing slow chat responses, broken markdown rendering, basic dashboard, and raw JSON-heavy alert analysis.

## Goals
1. **Speed**: Eliminate long wait times in SOC Chat (faster first-token, streaming UX)
2. **Presentation**: Rich markdown rendering in chat (no walls of text, no "Summary" prefix)
3. **Dashboard**: Modern real-time dashboard with proper layout, better charts, useful data
4. **Alert Analysis**: Clean visual presentation, no raw JSON dumps, structured display
5. **Backend Performance**: Optimize prompts, token limits, model selection

## Non-Goals (Out of Scope)
- New features (no new endpoints/agents)
- Authentication/RBAC changes
- Splunk/Sentinel connector logic changes
- Database schema changes

## Users
SOC analysts and admins using the web UI for security triage, chat, and monitoring.

## Constraints
- Existing React + FastAPI stack (no framework changes)
- NVIDIA LLaMA API dependency (can optimize usage, not replace)
- Must maintain backward compatibility with existing API contracts

## Success Criteria
- [ ] Chat responses start streaming within 2-3 seconds (vs current long waits)
- [ ] Chat renders proper markdown: headers, bullets, code blocks, tables
- [ ] "Summary" word never appears as response prefix
- [ ] Dashboard has professional layout with real-time data
- [ ] Alert analysis shows structured cards, not raw JSON
