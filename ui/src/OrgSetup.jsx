import React, { useState, useEffect, useMemo } from 'react'
import { QUERY_LANGUAGES } from './data/query-languages.js'
import { aggregateEventsBySource } from './data/requirements.js'

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

// Mirror of the canonical id mapping used elsewhere in the UI.
const ORG_TO_CANONICAL = {
  proxy_web_gateway: 'proxy', cloud_infrastructure: 'cloud',
  m365_audit: 'm365', linux_os: 'linux', saas_productivity: 'saas',
}
const toCanonical = (id) => ORG_TO_CANONICAL[id] || id

// Same keyword map App.jsx uses to bucket rules.requirements log_sources[].source
// into a canonical id. Kept in sync manually.
const LOG_SOURCE_KEYWORDS = {
  windows_security_events: ['windows','wineventlog','security event','event id','windows operating system'],
  sysmon: ['sysmon'],
  firewall: ['firewall','palo alto','fortinet','pfsense','network perimeter'],
  edr: ['edr','crowdstrike','sentinelone','mde','defender for endpoint','endpoint detection'],
  dns: ['dns'],
  identity_provider: ['okta','azure ad','aad','duo','identity provider','idp'],
  proxy: ['proxy','web gateway','swg','zscaler'],
  email_security: ['email','proofpoint','mimecast','defender for office'],
  cloud: ['cloudtrail','aws','azure activity','azure audit','gcp audit','cloud audit','cloud infrastructure'],
  m365: ['microsoft 365','m365','office 365','unified audit'],
  linux: ['linux','auditd','syslog'],
  vpn: ['vpn','remote access'],
  dlp: ['dlp','data loss'],
  waf: ['waf','web application firewall'],
  saas: ['saas','salesforce','slack','github'],
  kubernetes: ['kubernetes','k8s','container'],
  mfa: ['mfa','multi-factor','okta verify'],
}
function matchLogSourceId(text) {
  const t = (text || '').toLowerCase()
  if (!t.trim()) return null
  for (const id of Object.keys(LOG_SOURCE_KEYWORDS)) {
    for (const k of LOG_SOURCE_KEYWORDS[id]) if (t.includes(k)) return id
  }
  return null
}

export default function OrgSetup({ userId, onComplete }) {
  const [step, setStep] = useState('basics') // basics | events
  const [orgName, setOrgName] = useState('')
  const [primaryLanguage, setPrimaryLanguage] = useState('spl')
  const [logSources, setLogSources] = useState(new Set())
  const [eventsDeployed, setEventsDeployed] = useState({}) // {canonical_id: Set<event_id>}
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  // Pull the rule library so we can offer event-ID checklists per log source.
  const [rules, setRules] = useState([])
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const r = await fetch('/api/rules', { credentials: 'include' })
        if (r.ok) {
          const data = await r.json()
          if (!cancelled && Array.isArray(data)) setRules(data)
        }
      } catch { /* offline / first run — events step degrades gracefully */ }
    })()
    return () => { cancelled = true }
  }, [])

  const eventsBySource = useMemo(
    () => aggregateEventsBySource(rules, matchLogSourceId),
    [rules],
  )

  const toggle = (id) => {
    const next = new Set(logSources)
    next.has(id) ? next.delete(id) : next.add(id)
    setLogSources(next)
    // Default-on every event for any newly added source; clear out events for
    // sources the user just removed.
    setEventsDeployed(prev => {
      const out = { ...prev }
      const canonical = toCanonical(id)
      if (next.has(id)) {
        const events = eventsBySource[canonical] || {}
        out[canonical] = new Set(Object.keys(events))
      } else {
        delete out[canonical]
      }
      return out
    })
  }

  const toggleEvent = (canonicalSrc, eid) => {
    setEventsDeployed(prev => {
      const out = { ...prev }
      const cur = new Set(out[canonicalSrc] || [])
      cur.has(eid) ? cur.delete(eid) : cur.add(eid)
      out[canonicalSrc] = cur
      return out
    })
  }

  // Real-time impact estimate for the events step.
  const impact = useMemo(() => {
    if (!rules.length) return null
    let full = 0, partial = 0, blocked = 0
    for (const r of rules) {
      const reqs = r?.requirements?.log_sources
      if (!reqs || !reqs.length) { full += 1; continue }
      let total = 0, have = 0, anyHave = false
      for (const ls of reqs) {
        const c = matchLogSourceId(ls.source || '')
        if (!c) continue
        const deployedEvents = eventsDeployed[c]
        for (const ev of ls.events || []) {
          if (!ev.required) continue
          total += 1
          if (logSources.has(Object.keys(ORG_TO_CANONICAL).find(k => toCanonical(k) === c) || c)
              && deployedEvents?.has(ev.id)) {
            have += 1; anyHave = true
          }
        }
      }
      if (total === 0) full += 1
      else if (have === total) full += 1
      else if (have > 0) partial += 1
      else blocked += 1
    }
    return { full, partial, blocked }
  }, [rules, logSources, eventsDeployed])

  const submit = async (e) => {
    if (e) e.preventDefault()
    if (!orgName.trim()) return
    setSubmitting(true)
    setError(null)
    try {
      const eventsPayload = {}
      for (const [k, v] of Object.entries(eventsDeployed)) {
        eventsPayload[k] = [...v]
      }
      await onComplete({
        version: 1,
        org_name: orgName.trim(),
        primary_query_language: primaryLanguage,
        primary_siem: primaryLanguage,
        log_sources_deployed: Array.from(logSources),
        events_deployed: eventsPayload,
        created_at: new Date().toISOString(),
        created_by_user_id: userId,
      })
    } catch (err) {
      setError(err?.message || 'Save failed')
      setSubmitting(false)
    }
  }

  // Deployed sources mapped to their canonical IDs for the events step.
  const deployedCanonical = useMemo(() => {
    const out = []
    for (const id of logSources) {
      const canonical = toCanonical(id)
      const meta = LOG_SOURCES.find(s => s.id === id)
      const events = eventsBySource[canonical] || {}
      if (Object.keys(events).length) {
        out.push({ id: canonical, name: meta?.name || id, events })
      }
    }
    return out
  }, [logSources, eventsBySource])

  return (
    <div style={S.page}>
      <form onSubmit={(e) => { e.preventDefault(); step === 'basics' ? setStep('events') : submit() }} style={S.card}>
        {step === 'basics' && (
          <>
            <h1 style={S.h1}>Welcome to TDL Playbook</h1>
            <p style={S.sub}>One-time setup. You can change all of this later.</p>

            <label style={S.label}>
              Organization name
              <input type="text" value={orgName} onChange={(e) => setOrgName(e.target.value)}
                     placeholder="Acme Security" required style={S.input} autoFocus />
            </label>

            <label style={S.label}>
              Primary Query Language
              <select value={primaryLanguage} onChange={(e) => setPrimaryLanguage(e.target.value)} style={S.input}>
                {QUERY_LANGUAGES.map((l) => (
                  <option key={l.key} value={l.key}>{l.selectLabel}</option>
                ))}
              </select>
            </label>

            <div style={S.label}>
              Log sources currently deployed
              <div style={S.sublabel}>What you actually have running — not aspirational.</div>
              <div style={S.grid}>
                {LOG_SOURCES.map((src) => {
                  const checked = logSources.has(src.id)
                  return (
                    <label key={src.id} style={{ ...S.chip, ...(checked ? S.chipOn : {}) }}>
                      <input type="checkbox" checked={checked} onChange={() => toggle(src.id)} style={S.checkbox} />
                      {src.name}
                    </label>
                  )
                })}
              </div>
            </div>

            {error && <div style={S.error}>{error}</div>}

            <div style={S.footer}>
              <span style={S.count}>{logSources.size} of {LOG_SOURCES.length} log sources selected</span>
              <button type="submit" disabled={!orgName.trim()} style={S.button}>
                {deployedCanonical.length ? 'Next: pick event IDs →' : 'Continue to dashboard'}
              </button>
            </div>
          </>
        )}

        {step === 'events' && (
          <>
            <h1 style={S.h1}>What events do you have?</h1>
            <p style={S.sub}>
              For each deployed log source, check off the event IDs you actually collect.
              Pre-checked defaults assume you collect the common ones — uncheck anything you don't.
            </p>

            {deployedCanonical.length === 0 && (
              <div style={S.error}>
                None of your deployed log sources have event-ID metadata yet.
                You can finish setup and refine this later from Settings.
              </div>
            )}

            {deployedCanonical.map(src => {
              const have = eventsDeployed[src.id] || new Set()
              const eventIds = Object.keys(src.events).sort((a, b) =>
                (isNaN(+a) || isNaN(+b)) ? a.localeCompare(b) : +a - +b)
              return (
                <div key={src.id} style={S.eventGroup}>
                  <div style={S.eventGroupHeader}>{src.name}</div>
                  {eventIds.map(eid => {
                    const ev = src.events[eid]
                    const checked = have.has(eid)
                    return (
                      <label key={eid} style={S.eventRow}>
                        <input type="checkbox" checked={checked}
                               onChange={() => toggleEvent(src.id, eid)}
                               style={S.checkbox} />
                        <span style={{ fontFamily: 'var(--mono)', color: '#A78BFA', minWidth: 48 }}>{eid}</span>
                        <span style={{ flex: 1 }}>— {ev.name}</span>
                        <span style={{ fontSize: 11, color: ev.required ? '#F87171' : '#7E7E8C' }}>
                          {ev.required ? 'Required by' : 'Used by'} {ev.rule_ids.length} rule{ev.rule_ids.length === 1 ? '' : 's'}
                        </span>
                      </label>
                    )
                  })}
                </div>
              )
            })}

            {impact && (
              <div style={S.impact}>
                With your current selection: <strong>{impact.full}</strong> rules fully enabled,{' '}
                <strong>{impact.partial}</strong> partially enabled,{' '}
                <strong>{impact.blocked}</strong> require events you haven't enabled.
              </div>
            )}

            {error && <div style={S.error}>{error}</div>}

            <div style={S.footer}>
              <button type="button" onClick={() => setStep('basics')} style={S.buttonGhost}>← Back</button>
              <button type="submit" disabled={submitting} style={S.button}>
                {submitting ? 'Saving…' : 'Finish setup'}
              </button>
            </div>
          </>
        )}
      </form>
    </div>
  )
}

const S = {
  page: {
    minHeight: '100vh', background: '#0B0B11', color: '#E6E7EE',
    padding: '32px 16px', display: 'flex', justifyContent: 'center',
    alignItems: 'flex-start', fontFamily: 'system-ui, -apple-system, sans-serif',
  },
  card: {
    width: '100%', maxWidth: 720, background: '#15161D',
    border: '1px solid #262833', borderRadius: 12, padding: 32,
    display: 'flex', flexDirection: 'column', gap: 20,
  },
  h1: { margin: 0, fontSize: 24, fontWeight: 700 },
  sub: { margin: 0, color: '#9598A8', fontSize: 14 },
  label: { display: 'flex', flexDirection: 'column', gap: 6, fontSize: 13, fontWeight: 600 },
  sublabel: { fontWeight: 400, color: '#9598A8', fontSize: 12, marginTop: 2 },
  input: {
    background: '#0B0B11', border: '1px solid #262833', borderRadius: 6,
    padding: '10px 12px', color: '#E6E7EE', fontSize: 14,
    fontFamily: 'inherit', outline: 'none',
  },
  grid: {
    display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
    gap: 8, marginTop: 8,
  },
  chip: {
    display: 'flex', alignItems: 'center', gap: 8, padding: '8px 10px',
    background: '#0B0B11', border: '1px solid #262833', borderRadius: 6,
    fontWeight: 400, fontSize: 13, cursor: 'pointer', userSelect: 'none',
  },
  chipOn: { borderColor: '#7C5CFF', background: 'rgba(124,92,255,0.08)' },
  checkbox: { accentColor: '#7C5CFF' },
  eventGroup: {
    border: '1px solid #262833', borderRadius: 8, padding: 12, background: '#0B0B11',
  },
  eventGroupHeader: {
    fontSize: 13, fontWeight: 700, color: '#E6E7EE', marginBottom: 8,
  },
  eventRow: {
    display: 'flex', alignItems: 'center', gap: 10, padding: '4px 0',
    fontSize: 12, color: '#9598A8', cursor: 'pointer',
  },
  impact: {
    background: 'rgba(124,92,255,.08)', border: '1px solid rgba(124,92,255,.3)',
    color: '#A78BFA', borderRadius: 6, padding: '10px 12px', fontSize: 13,
  },
  footer: {
    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
    marginTop: 8, paddingTop: 16, borderTop: '1px solid #262833',
  },
  count: { color: '#9598A8', fontSize: 13 },
  error: {
    background: 'rgba(248,113,113,.08)', border: '1px solid rgba(248,113,113,.4)',
    color: '#F87171', borderRadius: 6, padding: '10px 12px', fontSize: 13,
  },
  button: {
    background: '#7C5CFF', color: '#fff', border: 'none', borderRadius: 6,
    padding: '10px 18px', fontSize: 14, fontWeight: 600, cursor: 'pointer',
  },
  buttonGhost: {
    background: 'transparent', color: '#9598A8', border: '1px solid #262833',
    borderRadius: 6, padding: '10px 18px', fontSize: 13, cursor: 'pointer',
  },
}
