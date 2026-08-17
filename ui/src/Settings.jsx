import React, { useState, useEffect, useMemo } from 'react'
import { QUERY_LANGUAGES, profileQueryLanguages } from './data/query-languages.js'

// Build the per-SIEM log-source map from a profile: prefer stored siem_log_sources,
// else fall back to the flat log_sources_deployed under the primary (first) SIEM.
function initSiemLogSources(profile) {
  const langs = profileQueryLanguages(profile)
  const src = (profile && typeof profile.siem_log_sources === 'object' && profile.siem_log_sources) || null
  const out = {}
  langs.forEach((k, i) => {
    out[k] = new Set(src && Array.isArray(src[k]) ? src[k] : (i === 0 ? (profile?.log_sources_deployed || []) : []))
  })
  return out
}

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

export default function Settings({ profile, onSave, onRerunSetup }) {
  const [orgName, setOrgName] = useState(profile?.org_name || '')
  const [queryLanguages, setQueryLanguages] = useState(
    () => new Set(profileQueryLanguages(profile))
  )
  // Per-SIEM log sources (#15): { queryLanguageKey: Set<logSourceId> }.
  const [siemLogSources, setSiemLogSources] = useState(() => initSiemLogSources(profile))
  const [saving, setSaving] = useState(false)
  const [savedAt, setSavedAt] = useState(null)
  const [error, setError] = useState(null)
  // Splunk lab URL — browser-local (per machine), drives the rule "Open in Splunk"
  // link. Not part of the org profile; saved to localStorage immediately.
  const [splunkUrl, setSplunkUrl] = useState(() => {
    try { return localStorage.getItem('tdl_splunk_url') || 'http://localhost:8100' }
    catch { return 'http://localhost:8100' }
  })
  const onSplunkUrlChange = (v) => {
    setSplunkUrl(v)
    try { localStorage.setItem('tdl_splunk_url', v.trim().replace(/\/+$/, '')) } catch { /* ignore */ }
  }

  const logSources = useMemo(() => {
    const u = new Set()
    for (const s of Object.values(siemLogSources)) for (const id of s) u.add(id)
    return u
  }, [siemLogSources])

  // Keep local form state in sync if the live org profile changes underneath us
  // (single source of truth lives at the App root). Without this, the form could
  // drift from what the matrix / other views render.
  useEffect(() => {
    setOrgName(profile?.org_name || '')
    setQueryLanguages(new Set(profileQueryLanguages(profile)))
    setSiemLogSources(initSiemLogSources(profile))
  }, [profile])

  const toggleLang = (key) => {
    const selecting = !queryLanguages.has(key)
    setQueryLanguages(prev => { const n = new Set(prev); selecting ? n.add(key) : n.delete(key); return n })
    setSiemLogSources(prev => {
      const out = { ...prev }
      if (selecting) { if (!out[key]) out[key] = new Set() } else { delete out[key] }
      return out
    })
  }

  const toggleSiemSource = (lang, id) => {
    setSiemLogSources(prev => {
      const set = new Set(prev[lang] || [])
      set.has(id) ? set.delete(id) : set.add(id)
      return { ...prev, [lang]: set }
    })
  }

  const submit = async (e) => {
    e.preventDefault()
    if (!orgName.trim() || queryLanguages.size === 0) return
    setSaving(true)
    setError(null)
    try {
      const orderedLangs = QUERY_LANGUAGES.filter((l) => queryLanguages.has(l.key)).map((l) => l.key)
      const primary = orderedLangs[0] || null
      const siemPayload = {}
      for (const k of orderedLangs) siemPayload[k] = [...(siemLogSources[k] || [])]
      await onSave({
        ...(profile || {}),
        version: 1,
        org_name: orgName.trim(),
        query_languages: orderedLangs,
        primary_query_language: primary,
        // keep the legacy key populated for any old reader
        primary_siem: primary,
        siem_log_sources: siemPayload,
        log_sources_deployed: Array.from(logSources),
        // Preserve any event-level inventory captured during onboarding; the
        // per-event UI lives in the onboarding "Re-run setup" flow.
        events_deployed: profile?.events_deployed || {},
        updated_at: new Date().toISOString(),
      })
      setSavedAt(new Date())
    } catch (err) {
      setError(err?.message || 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="view" style={S.page}>
      <form onSubmit={submit} style={S.card}>
        <h1 style={S.h1}>Organization Settings</h1>
        <p style={S.sub}>Drives recommendations and (later) per-org tier limits.</p>

        <label style={S.label}>
          Organization name
          <input
            type="text"
            value={orgName}
            onChange={(e) => setOrgName(e.target.value)}
            placeholder="Acme Security"
            required
            style={S.input}
          />
        </label>

        <label style={S.label}>
          Splunk lab URL
          <div style={S.sublabel}>
            Where your local Splunk test-lab is reachable — drives the “Open in Splunk”
            link on each rule. Saved to this browser instantly (no need to hit Save).
          </div>
          <input
            type="text"
            value={splunkUrl}
            onChange={(e) => onSplunkUrlChange(e.target.value)}
            placeholder="http://localhost:8100"
            style={S.input}
          />
        </label>

        <div style={S.label}>
          Query languages
          <div style={S.sublabel}>
            Detection Rules shows query logic for just these. The first selected is
            your primary/default language.
          </div>
          <div style={S.grid}>
            {QUERY_LANGUAGES.map((l) => {
              const checked = queryLanguages.has(l.key)
              return (
                <label key={l.key} style={{ ...S.chip, ...(checked ? S.chipOn : {}) }}>
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => toggleLang(l.key)}
                    style={S.checkbox}
                  />
                  {l.selectLabel}
                </label>
              )
            })}
          </div>
        </div>

        <div style={S.label}>
          Log sources per SIEM
          <div style={S.sublabel}>
            For each SIEM, the log sources you actually send to it — not aspirational.
          </div>
          {QUERY_LANGUAGES.filter((l) => queryLanguages.has(l.key)).map((l) => {
            const set = siemLogSources[l.key] || new Set()
            return (
              <div key={l.key} style={{ marginTop: 12 }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: '#A78BFA', marginBottom: 6 }}>
                  {l.selectLabel} <span style={{ color: '#6E6E7C', fontWeight: 400 }}>· {set.size} selected</span>
                </div>
                <div style={S.grid}>
                  {LOG_SOURCES.map((src) => {
                    const checked = set.has(src.id)
                    return (
                      <label key={src.id} style={{ ...S.chip, ...(checked ? S.chipOn : {}) }}>
                        <input type="checkbox" checked={checked}
                               onChange={() => toggleSiemSource(l.key, src.id)} style={S.checkbox} />
                        {src.name}
                      </label>
                    )
                  })}
                </div>
              </div>
            )
          })}
        </div>

        <div style={S.footer}>
          <span style={S.count}>
            {queryLanguages.size} {queryLanguages.size === 1 ? 'query language' : 'query languages'} · {logSources.size} of {LOG_SOURCES.length} log sources
            {queryLanguages.size === 0 && <span style={{ color: '#F87171', marginLeft: 12 }}>Pick at least one query language.</span>}
            {savedAt && <span style={{ color: '#7C5CFF', marginLeft: 12 }}>Saved.</span>}
            {error && <span style={{ color: '#F87171', marginLeft: 12 }}>{error}</span>}
          </span>
          <div style={{ display: 'flex', gap: 8 }}>
            {onRerunSetup && (
              <button type="button" onClick={onRerunSetup}
                      style={{ ...S.button, background: 'transparent', color: '#9598A8', border: '1px solid #262833', fontWeight: 500 }}>
                Re-run Setup
              </button>
            )}
            <button type="submit" disabled={saving || !orgName.trim() || queryLanguages.size === 0} style={S.button}>
              {saving ? 'Saving…' : 'Save Changes'}
            </button>
          </div>
        </div>
      </form>
    </div>
  )
}

const S = {
  page: {
    minHeight: '100%',
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
  h1: { margin: 0, fontSize: 22, fontWeight: 700 },
  sub: { margin: 0, color: '#9598A8', fontSize: 13 },
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
    gap: 12,
    flexWrap: 'wrap',
  },
  count: { color: '#9598A8', fontSize: 13 },
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
