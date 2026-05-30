// Canonical catalog of the 10 SIEM query languages TDL supports.
//
// Single source of truth for:
//   - the Settings / onboarding "Primary Query Language" dropdown (selectLabel)
//   - the Documentation page reference cards (cardName, cardSiem, docsUrl, desc)
//
// `key` matches the rule.queries.* keys and the backend QUERY_KEYS.

export const QUERY_LANGUAGES = [
  {
    key: 'spl',
    selectLabel: 'SPL (Splunk)',
    cardName: 'SPL',
    cardSiem: 'Splunk',
    docsUrl: 'https://docs.splunk.com/Documentation/Splunk/latest/SearchReference',
    desc: 'Search Processing Language — pipeline search over indexed events.',
  },
  {
    key: 'kql',
    selectLabel: 'KQL (Microsoft Sentinel / Defender)',
    cardName: 'KQL',
    cardSiem: 'Microsoft Sentinel',
    docsUrl: 'https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/',
    desc: 'Kusto Query Language for Sentinel and Defender advanced hunting.',
  },
  {
    key: 'aql',
    selectLabel: 'AQL (IBM QRadar)',
    cardName: 'AQL',
    cardSiem: 'IBM QRadar',
    docsUrl: 'https://www.ibm.com/docs/en/qradar-on-cloud?topic=reference-ariel-query-language',
    desc: 'Ariel Query Language — SQL-like queries over QRadar events and flows.',
  },
  {
    key: 'yara_l',
    selectLabel: 'YARA-L (Google Chronicle)',
    cardName: 'YARA-L',
    cardSiem: 'Google Chronicle',
    docsUrl: 'https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview',
    desc: 'YARA-L 2.0 detection rules over Chronicle UDM events.',
  },
  {
    key: 'esql',
    selectLabel: 'ES|QL (Elastic Security)',
    cardName: 'ES|QL',
    cardSiem: 'Elastic',
    docsUrl: 'https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html',
    desc: 'Elasticsearch piped query language over ECS data streams.',
  },
  {
    key: 'leql',
    selectLabel: 'LEQL (Rapid7 InsightIDR)',
    cardName: 'LEQL',
    cardSiem: 'Rapid7',
    docsUrl: 'https://docs.rapid7.com/insightidr/log-search/',
    desc: 'Log Entry Query Language for InsightIDR log search.',
  },
  {
    key: 'crowdstrike',
    selectLabel: 'CQL (CrowdStrike Falcon)',
    cardName: 'CrowdStrike LogScale',
    cardSiem: 'CrowdStrike Falcon',
    docsUrl: 'https://library.humio.com/falcon-logscale/docs-search-cql.html',
    desc: 'Falcon LogScale (Humio) CQL pipeline search over EDR telemetry.',
  },
  {
    key: 'xql',
    selectLabel: 'XQL (Palo Alto XSIAM)',
    cardName: 'XQL',
    cardSiem: 'Palo Alto XSIAM',
    docsUrl: 'https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-XQL-Language-Reference',
    desc: 'Cortex XQL pipeline language over XSIAM / XDR datasets.',
  },
  {
    key: 'lucene',
    selectLabel: 'Lucene (Exabeam / Graylog / OpenSearch)',
    cardName: 'Lucene',
    cardSiem: 'OpenSearch / Graylog',
    docsUrl: 'https://opensearch.org/docs/latest/query-dsl/full-text/query-string/',
    desc: 'Generic Lucene query-string syntax for OpenSearch, Graylog, Exabeam.',
  },
  {
    key: 'sumo',
    selectLabel: 'Sumo Logic Search (Sumo Logic)',
    cardName: 'Sumo Logic',
    cardSiem: 'Sumo Logic',
    docsUrl: 'https://help.sumologic.com/docs/search/search-query-language/',
    desc: 'Sumo Logic search query language — scoped, parsed, piped operators.',
  },
]

export const QUERY_LANGUAGE_BY_KEY = Object.fromEntries(
  QUERY_LANGUAGES.map((l) => [l.key, l]),
)

const QUERY_LANGUAGE_ORDER = QUERY_LANGUAGES.map((l) => l.key)

// Canonical list of the org's selected query languages, in catalog order.
// Reads the new `query_languages` array, falling back to the legacy single
// `primary_query_language` / `primary_siem` value so older profiles (DB rows or
// localStorage) keep working. Returns [] when nothing is configured.
export function profileQueryLanguages(profile) {
  if (!profile) return []
  const raw = Array.isArray(profile.query_languages)
    ? profile.query_languages.filter((k) => k && QUERY_LANGUAGE_BY_KEY[k])
    : []
  const keys = raw.length
    ? raw
    : (() => {
        const single = profile.primary_query_language || profile.primary_siem
        return single && QUERY_LANGUAGE_BY_KEY[single] ? [single] : []
      })()
  // De-dupe and sort into catalog order for deterministic tab/primary ordering.
  const set = new Set(keys)
  return QUERY_LANGUAGE_ORDER.filter((k) => set.has(k))
}
