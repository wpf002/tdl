// Per-rule quality score (0–100) and breakdown.
// Surfaces on the rule list as a small badge and in the rule detail as a
// section. Tunable as the library matures.

const ALL_LANGUAGES = [
  'spl','kql','aql','yara_l','esql','leql','crowdstrike','xql','lucene','sumo',
]

export function ruleQualityScore(rule) {
  const r = rule || {}
  const breakdown = []

  const hasPseudo = !!(r.pseudo_logic && r.pseudo_logic.trim().length >= 20)
  breakdown.push({ key: 'pseudo_logic', label: 'Has pseudo-logic', weight: 20, ok: hasPseudo })

  const presentQs = ALL_LANGUAGES.filter(k => (r.queries || {})[k] && String(r.queries[k]).trim())
  const hasAllQs = presentQs.length >= ALL_LANGUAGES.length
  breakdown.push({
    key: 'queries', label: `All ${ALL_LANGUAGES.length} SIEM queries`,
    weight: 20, ok: hasAllQs,
    detail: hasAllQs ? `${presentQs.length}/${ALL_LANGUAGES.length}` : `${presentQs.length}/${ALL_LANGUAGES.length}`,
  })

  const hasReqs = !!(r.requirements?.log_sources?.length)
  breakdown.push({ key: 'requirements', label: 'Has requirements (log sources + event IDs)',
                   weight: 20, ok: hasReqs })

  const hasTriage = Array.isArray(r.triage_steps) && r.triage_steps.length >= 4
  breakdown.push({ key: 'triage_steps', label: 'Has ≥ 4 triage steps', weight: 20, ok: hasTriage })

  const hasFP = Array.isArray(r.false_positives) && r.false_positives.length > 0
  breakdown.push({ key: 'false_positives', label: 'Has false-positive notes', weight: 10, ok: hasFP })

  const hasTuning = !!(r.tuning_guidance && r.tuning_guidance.trim())
  breakdown.push({ key: 'tuning_guidance', label: 'Has tuning guidance', weight: 10, ok: hasTuning })

  const score = breakdown.reduce((acc, b) => acc + (b.ok ? b.weight : 0), 0)
  return { score, breakdown }
}

// Colour for a 0–100 quality score (matches the UI's purple / amber / red palette).
export function qualityColor(score) {
  if (score >= 80) return '#10B981' // green
  if (score >= 60) return '#A78BFA' // purple
  if (score >= 40) return '#FBBF24' // amber
  return '#F87171'                  // red
}
