import React, { useState } from 'react'

const SIEMS = [
  { id: 'spl',         name: 'Splunk SPL' },
  { id: 'kql',         name: 'Microsoft KQL (Sentinel/Defender)' },
  { id: 'aql',         name: 'IBM QRadar AQL' },
  { id: 'yara_l',      name: 'Chronicle YARA-L' },
  { id: 'esql',        name: 'Elastic ES|QL' },
  { id: 'leql',        name: 'Rapid7 LEQL' },
  { id: 'crowdstrike', name: 'CrowdStrike (Falcon LogScale)' },
  { id: 'xql',         name: 'Palo Alto XSIAM XQL' },
  { id: 'lucene',      name: 'Lucene (generic)' },
  { id: 'sumo',        name: 'Sumo Logic' },
]

const LOG_SOURCES = [
  { id: 'windows_security_events', name: 'Windows Security Event Log' },
  { id: 'sysmon',                  name: 'Sysmon (System Monitor)' },
  { id: 'firewall',                name: 'Firewall / Network Perimeter Logs' },
  { id: 'edr',                     name: 'Endpoint Detection & Response (EDR)' },
  { id: 'dns',                     name: 'DNS Logs' },
  { id: 'identity_provider',       name: 'Identity Provider (Azure AD / Okta)' },
  { id: 'proxy_web_gateway',       name: 'Web Proxy / Secure Web Gateway' },
  { id: 'email_security',          name: 'Email Security Gateway' },
  { id: 'cloud_infrastructure',    name: 'Cloud Infrastructure (AWS/Azure/GCP)' },
  { id: 'm365_audit',              name: 'Microsoft 365 Unified Audit Log' },
  { id: 'linux_os',                name: 'Linux OS Logs (syslog / auditd)' },
  { id: 'vpn',                     name: 'VPN / Remote Access Logs' },
  { id: 'dlp',                     name: 'Data Loss Prevention (DLP)' },
  { id: 'waf',                     name: 'Web Application Firewall (WAF)' },
  { id: 'saas_productivity',       name: 'SaaS / Productivity Apps' },
  { id: 'kubernetes',              name: 'Kubernetes / Container Logs' },
  { id: 'mfa',                     name: 'MFA / Authentication App Logs' },
]

export default function OrgSetup({ userId, onComplete }) {
  const [orgName, setOrgName] = useState('')
  const [primarySiem, setPrimarySiem] = useState('spl')
  const [logSources, setLogSources] = useState(new Set())
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  const toggle = (id) => {
    const next = new Set(logSources)
    next.has(id) ? next.delete(id) : next.add(id)
    setLogSources(next)
  }

  const submit = async (e) => {
    e.preventDefault()
    if (!orgName.trim()) return
    setSubmitting(true)
    setError(null)
    try {
      await onComplete({
        version: 1,
        org_name: orgName.trim(),
        primary_siem: primarySiem,
        log_sources_deployed: Array.from(logSources),
        created_at: new Date().toISOString(),
        created_by_user_id: userId,
      })
    } catch (err) {
      setError(err?.message || 'Save failed')
      setSubmitting(false)
    }
  }

  return (
    <div style={S.page}>
      <form onSubmit={submit} style={S.card}>
        <h1 style={S.h1}>Welcome to TDL Playbook</h1>
        <p style={S.sub}>One-time setup. You can change all of this later.</p>

        <label style={S.label}>
          Organization name
          <input
            type="text"
            value={orgName}
            onChange={(e) => setOrgName(e.target.value)}
            placeholder="Acme Security"
            required
            style={S.input}
            autoFocus
          />
        </label>

        <label style={S.label}>
          Primary SIEM platform
          <select
            value={primarySiem}
            onChange={(e) => setPrimarySiem(e.target.value)}
            style={S.input}
          >
            {SIEMS.map((s) => (
              <option key={s.id} value={s.id}>{s.name}</option>
            ))}
          </select>
        </label>

        <div style={S.label}>
          Log sources currently deployed
          <div style={S.sublabel}>
            Drives the recommendation engine. Pick what you actually have running.
          </div>
          <div style={S.grid}>
            {LOG_SOURCES.map((src) => {
              const checked = logSources.has(src.id)
              return (
                <label key={src.id} style={{ ...S.chip, ...(checked ? S.chipOn : {}) }}>
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => toggle(src.id)}
                    style={S.checkbox}
                  />
                  {src.name}
                </label>
              )
            })}
          </div>
        </div>

        {error && <div style={S.error}>{error}</div>}

        <div style={S.footer}>
          <span style={S.count}>{logSources.size} of {LOG_SOURCES.length} log sources selected</span>
          <button type="submit" disabled={submitting || !orgName.trim()} style={S.button}>
            {submitting ? 'Saving…' : 'Continue to dashboard'}
          </button>
        </div>
      </form>
    </div>
  )
}

const S = {
  page: {
    minHeight: '100vh',
    background: '#0B0B11',
    color: '#E6E7EE',
    padding: '32px 16px',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'flex-start',
    fontFamily: 'system-ui, -apple-system, sans-serif',
  },
  card: {
    width: '100%',
    maxWidth: 720,
    background: '#15161D',
    border: '1px solid #262833',
    borderRadius: 12,
    padding: 32,
    display: 'flex',
    flexDirection: 'column',
    gap: 20,
  },
  h1: { margin: 0, fontSize: 24, fontWeight: 700 },
  sub: { margin: 0, color: '#9598A8', fontSize: 14 },
  label: { display: 'flex', flexDirection: 'column', gap: 6, fontSize: 13, fontWeight: 600 },
  sublabel: { fontWeight: 400, color: '#9598A8', fontSize: 12, marginTop: 2 },
  input: {
    background: '#0B0B11',
    border: '1px solid #262833',
    borderRadius: 6,
    padding: '10px 12px',
    color: '#E6E7EE',
    fontSize: 14,
    fontFamily: 'inherit',
    outline: 'none',
  },
  grid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
    gap: 8,
    marginTop: 8,
  },
  chip: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
    padding: '8px 10px',
    background: '#0B0B11',
    border: '1px solid #262833',
    borderRadius: 6,
    fontWeight: 400,
    fontSize: 13,
    cursor: 'pointer',
    userSelect: 'none',
  },
  chipOn: {
    borderColor: '#7C5CFF',
    background: 'rgba(124,92,255,0.08)',
  },
  checkbox: { accentColor: '#7C5CFF' },
  footer: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginTop: 8,
    paddingTop: 16,
    borderTop: '1px solid #262833',
  },
  count: { color: '#9598A8', fontSize: 13 },
  error: {
    background: 'rgba(248,113,113,.08)',
    border: '1px solid rgba(248,113,113,.4)',
    color: '#F87171',
    borderRadius: 6,
    padding: '10px 12px',
    fontSize: 13,
  },
  button: {
    background: '#7C5CFF',
    color: '#fff',
    border: 'none',
    borderRadius: 6,
    padding: '10px 18px',
    fontSize: 14,
    fontWeight: 600,
    cursor: 'pointer',
  },
}
