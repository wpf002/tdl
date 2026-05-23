// Aggregation helpers over rule.requirements (the {log_sources:[{source,
// events:[{id,name,required}]}]} field on each rule).
//
// Free-form `source` strings are matched against the canonical log-source
// keyword map in App.jsx via the matchSource helper passed in, so different
// rules can reference "Windows Security Event Log" or "wineventlog" and still
// roll up to the same canonical log_source_id.

// Returns { [canonical_id]: { [event_id]: { name, required, rule_ids: [] } } }
export function aggregateEventsBySource(rules, matchSource) {
  const out = {}
  for (const r of rules || []) {
    const reqs = r?.requirements?.log_sources
    if (!reqs || !reqs.length) continue
    for (const ls of reqs) {
      const canonical = matchSource(ls.source || '')
      if (!canonical) continue
      const bucket = (out[canonical] = out[canonical] || {})
      for (const ev of ls.events || []) {
        if (!ev?.id) continue
        const slot = (bucket[ev.id] = bucket[ev.id] || {
          name: ev.name || `Event ${ev.id}`,
          required: false,
          rule_ids: [],
        })
        // Once required is true anywhere, stay true for that event globally.
        slot.required = slot.required || !!ev.required
        if (r.rule_id) slot.rule_ids.push(r.rule_id)
      }
    }
  }
  return out
}

// For a single rule, return { [canonical_id]: { required:[eid…], optional:[eid…] } }
export function rulePerSourceRequirements(rule, matchSource) {
  const out = {}
  const reqs = rule?.requirements?.log_sources
  if (!reqs) return out
  for (const ls of reqs) {
    const canonical = matchSource(ls.source || '')
    if (!canonical) continue
    const bucket = (out[canonical] = out[canonical] || { required: [], optional: [], _src: ls.source })
    for (const ev of ls.events || []) {
      if (!ev?.id) continue
      ;(ev.required ? bucket.required : bucket.optional).push({ id: ev.id, name: ev.name || `Event ${ev.id}` })
    }
  }
  return out
}

// Classify a single rule against an org's deployed events.
//   deployedSources: Set of canonical log_source_ids
//   eventsDeployed:  { canonical_id: [event_id, ...] }
// Returns 'full' | 'partial' | 'none'
export function ruleEventCoverage(rule, deployedSources, eventsDeployed, matchSource) {
  const perSrc = rulePerSourceRequirements(rule, matchSource)
  const sourceIds = Object.keys(perSrc)
  if (!sourceIds.length) {
    // Rule lacks requirements data — fall back to "covered if any deployed
    // source matches its data_sources keyword". Callers compute that.
    return null
  }
  let total = 0, covered = 0, anyCovered = false
  for (const sid of sourceIds) {
    const reqIds = perSrc[sid].required.map(e => e.id)
    if (!reqIds.length) { anyCovered = true; continue }
    if (!deployedSources.has(sid)) { total += reqIds.length; continue }
    const have = new Set(eventsDeployed?.[sid] || [])
    for (const id of reqIds) {
      total += 1
      if (have.has(id)) { covered += 1; anyCovered = true }
    }
  }
  if (total === 0) return anyCovered ? 'full' : 'none'
  if (covered === total) return 'full'
  if (covered === 0)     return 'none'
  return 'partial'
}

// Per-rule coverage detail for the rule-detail "Coverage Status" line.
export function ruleCoverageDetail(rule, deployedSources, eventsDeployed, matchSource) {
  const perSrc = rulePerSourceRequirements(rule, matchSource)
  const sources = Object.entries(perSrc).map(([sid, info]) => {
    const deployed = deployedSources.has(sid)
    const have = new Set(eventsDeployed?.[sid] || [])
    const missing = deployed ? info.required.filter(e => !have.has(e.id)) : info.required
    return { sourceId: sid, sourceName: info._src, deployed, required: info.required, missing }
  })
  return sources
}
