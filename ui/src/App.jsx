import React, { useState, useMemo, useCallback, useEffect, useRef } from 'react'
import {
  Shield, Search, ChevronRight, X, AlertTriangle, CheckCircle,
  Activity, Database, Target, Filter, Tag, Copy, Check,
  BarChart3, Layers, Crosshair, Clock, TrendingUp, ChevronDown,
  Terminal, Zap, GitBranch, Map as MapIcon, Award, Eye, Lock, Cpu,
  ArrowRight, Circle, Minus, Download, Edit3, Trash2, Sliders, Sparkles
} from 'lucide-react'
import { UserButton, useAuth } from '@clerk/react'
import RULES_RAW from './data/rules.json'
import { ATTACK_MATRIX, KILL_CHAIN, TACTIC_ORDER_MATRIX } from './data/attack-matrix.js'
import Settings from './Settings.jsx'

// ─── HOOKS ──────────────────────────────────────────────────────────────────

function useMediaQuery(query) {
  const [matches, setMatches] = useState(() =>
    typeof window !== 'undefined' ? window.matchMedia(query).matches : false
  )
  useEffect(() => {
    const mql = window.matchMedia(query)
    const handler = (e) => setMatches(e.matches)
    mql.addEventListener('change', handler)
    setMatches(mql.matches)
    return () => mql.removeEventListener('change', handler)
  }, [query])
  return matches
}

// ─── CONSTANTS ──────────────────────────────────────────────────────────────

const TACTIC_ORDER = [
  'Initial Access','Execution','Persistence','Privilege Escalation',
  'Defense Evasion','Credential Access','Discovery','Lateral Movement',
  'Command and Control','Collection','Exfiltration','Impact'
]

// Tactic → rule-id prefix (e.g. "Initial Access" → "AUTH" since rule IDs look
// like TDL-AUTH-000289). Surfaced in the UI as "Initial Access (AUTH)".
const TACTIC_PREFIX = {
  'Initial Access':       'AUTH',
  'Execution':            'EXE',
  'Persistence':          'PER',
  'Privilege Escalation': 'PE',
  'Defense Evasion':      'DE',
  'Credential Access':    'CA',
  'Discovery':            'DIS',
  'Lateral Movement':     'LM',
  'Command and Control':  'C2',
  'Collection':           'COL',
  'Exfiltration':         'EXF',
  'Impact':               'IMP',
}

const tacticLabel = (t) => TACTIC_PREFIX[t] ? `${t} (${TACTIC_PREFIX[t]})` : t

// Kill Chain stages that have ATT&CK tactic mappings (pre-attack stages —
// Reconnaissance, Weaponization — are excluded since the rule library has no
// rules for them). Order mirrors KILL_CHAIN.
const KC_FILTER_STAGES = KILL_CHAIN.filter(s => s.attack_tactics.length > 0).map(s => s.name)

// Reverse map: ATT&CK tactic name → Kill Chain stage name (the stage whose
// attack_tactics list contains the tactic). Each tactic maps to exactly one
// stage in the current data model.
const TACTIC_TO_KC = (() => {
  const m = {}
  KILL_CHAIN.forEach(s => s.attack_tactics.forEach(t => { m[t] = s.name }))
  return m
})()

// Tactic palette — three bands across the kill-chain progression, tuned to
// read well on near-black panels:
//   red    = early-stage (gain access, execute, escalate)
//   purple = mid-stage   (evade, harvest, move)
//   blue   = late-stage  (control, collect, exfil, impact)
const TACTIC_COLOR = {
  'Initial Access':        '#EF4444',
  'Execution':             '#F87171',
  'Persistence':           '#FB7185',
  'Privilege Escalation':  '#E11D48',
  'Defense Evasion':       '#A855F7',
  'Credential Access':     '#C084FC',
  'Discovery':             '#B794F6',
  'Lateral Movement':      '#9F75F4',
  'Command and Control':   '#3B82F6',
  'Collection':            '#60A5FA',
  'Exfiltration':          '#2563EB',
  'Impact':                '#93C5FD',
}

const SEV_COLOR = { Critical:'#EF4444', High:'#F87171', Medium:'#A855F7', Low:'#3B82F6' }
const SEV_BG    = { Critical:'rgba(239,68,68,.18)', High:'rgba(248,113,113,.18)', Medium:'rgba(168,85,247,.18)', Low:'rgba(59,130,246,.18)' }

const PLATFORMS = ['Windows','Linux','macOS','AWS','Azure','GCP','Okta','Microsoft 365','Network','Kubernetes','SaaS']

const SIEM_LABELS = {
  spl:'Splunk SPL', kql:'Microsoft KQL', aql:'IBM QRadar AQL',
  yara_l:'Chronicle YARA-L', esql:'Elastic ES|QL', leql:'Rapid7 LEQL',
  crowdstrike:'CrowdStrike', xql:'XSIAM XQL', lucene:'Lucene',
  sumo:'Sumo Logic'
}

const ATTACK_TECHNIQUES = {
  'Initial Access':        ['T1566','T1078','T1133','T1190','T1195','T1199'],
  'Execution':             ['T1059','T1053','T1218','T1047','T1204','T1203'],
  'Persistence':           ['T1547','T1543','T1546','T1574','T1078','T1136'],
  'Privilege Escalation':  ['T1134','T1548','T1055','T1068','T1078','T1053'],
  'Defense Evasion':       ['T1070','T1036','T1027','T1562','T1140','T1218'],
  'Credential Access':     ['T1003','T1558','T1110','T1555','T1552','T1539'],
  'Discovery':             ['T1046','T1087','T1082','T1135','T1016','T1069'],
  'Lateral Movement':      ['T1550','T1021','T1563','T1534','T1570'],
  'Command and Control':   ['T1071','T1095','T1105','T1090','T1132','T1573'],
  'Collection':            ['T1560','T1074','T1056','T1113','T1114'],
  'Exfiltration':          ['T1041','T1048','T1567','T1020','T1030'],
  'Impact':                ['T1486','T1490','T1531','T1529','T1485'],
}

const CHAINS = [
  { id:'CHAIN-001', name:'Cobalt Strike Compromise', threat:'APT / Red Team', window:'4h', severity:'Critical', steps:['Staging (MSHTA/Regsvr32)','Process Injection','LSASS Dump','Pass-the-Hash','C2 Beacon'], active:true },
  { id:'CHAIN-002', name:'Ransomware Kill Chain', threat:'LockBit / BlackCat / Cl0p', window:'2h', severity:'Critical', steps:['AV Detection','Log Clearing','VSS Deletion','Mass File Encryption'], active:true },
  { id:'CHAIN-003', name:'AD Domain Takeover', threat:'Advanced Threat Actor', window:'8h', severity:'Critical', steps:['LDAP Enumeration','Kerberoasting / DCSync','Pass-the-Hash','Log Clearing'], active:true },
  { id:'CHAIN-004', name:'Insider Data Exfiltration', threat:'Insider Threat / Compromised Account', window:'24h', severity:'High', steps:['Bulk File Access','Archive Creation','Cloud Upload'], active:true },
  { id:'CHAIN-005', name:'Initial Access → Persistence', threat:'General Threat Actor', window:'4h', severity:'High', steps:['Encoded PowerShell / WSH','Registry / Service / WMI Persist','C2 Beacon'], active:true },
]

const LOG_SOURCES = [
  { id:'windows_security_events', name:'Windows Security Events', criticality:'Critical', tier:1, deployed:true,  rules_unlocked:287 },
  { id:'sysmon',                  name:'Sysmon',                  criticality:'Critical', tier:1, deployed:true,  rules_unlocked:210 },
  { id:'edr',                     name:'EDR (CrowdStrike/S1/MDE)',criticality:'Critical', tier:1, deployed:true,  rules_unlocked:195 },
  { id:'firewall',                name:'Firewall Logs',           criticality:'Critical', tier:1, deployed:true,  rules_unlocked:140 },
  { id:'dns',                     name:'DNS Logs',                criticality:'High',     tier:1, deployed:true,  rules_unlocked:89  },
  { id:'identity_provider',       name:'Identity Provider (IdP)', criticality:'Critical', tier:1, deployed:true,  rules_unlocked:156 },
  { id:'proxy',                   name:'Web Proxy / SWG',        criticality:'High',     tier:2, deployed:false, rules_unlocked:63  },
  { id:'email_security',          name:'Email Security Gateway',  criticality:'High',     tier:2, deployed:true,  rules_unlocked:44  },
  { id:'cloud',                   name:'Cloud Infrastructure',    criticality:'High',     tier:2, deployed:true,  rules_unlocked:98  },
  { id:'m365',                    name:'Microsoft 365 Audit',     criticality:'High',     tier:2, deployed:true,  rules_unlocked:71  },
  { id:'linux',                   name:'Linux / auditd',          criticality:'High',     tier:2, deployed:false, rules_unlocked:55  },
  { id:'vpn',                     name:'VPN / Remote Access',     criticality:'High',     tier:2, deployed:true,  rules_unlocked:38  },
  { id:'dlp',                     name:'DLP',                     criticality:'Medium',   tier:3, deployed:false, rules_unlocked:29  },
  { id:'waf',                     name:'WAF',                     criticality:'Medium',   tier:3, deployed:true,  rules_unlocked:22  },
  { id:'saas',                    name:'SaaS / Productivity Apps',criticality:'Medium',   tier:3, deployed:false, rules_unlocked:47  },
  { id:'kubernetes',              name:'Kubernetes',              criticality:'Medium',   tier:3, deployed:false, rules_unlocked:18  },
  { id:'mfa',                     name:'MFA Logs',                criticality:'Medium',   tier:3, deployed:true,  rules_unlocked:31  },
]

// ─── CSS ─────────────────────────────────────────────────────────────────────

const CSS = `
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600;700&display=swap');

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  /* Surfaces — grey page; cards sit *above* it as a lighter shade.
     Sidebar / code blocks sit *below* it as a darker shade. */
  --bg0:      #16161D;   /* page background (grey, mid-tone) */
  --bg1:      #0B0B11;   /* sidebar / code / dark recess (BELOW page) */
  --bg2:      #23232C;   /* elevated cards (ABOVE page) */
  --bg3:      #2C2C36;   /* hover state on cards / interactive elevated */
  --border:   #2A2A35;
  --border2:  #3A3A47;

  /* Text — white on dark, all WCAG AAA */
  --text:     #F2F2F7;
  --text2:    #B8B8C8;
  --text3:    #80808E;

  /* Restricted palette: red / blue / purple / grey / white / black */
  --red:      #EF4444;
  --red-dk:   #DC2626;
  --red-lt:   rgba(239,68,68,.14);
  --blue:     #3B82F6;
  --blue-dk:  #2563EB;
  --blue-lt:  rgba(59,130,246,.14);
  --purple:   #A855F7;
  --purple-dk:#9333EA;
  --purple-lt:rgba(168,85,247,.14);

  /* Aliases — primary accent is purple, secondary is blue */
  --accent:   var(--purple);
  --accent2:  var(--blue);

  --shadow-sm: 0 1px 2px rgba(0,0,0,.40);
  --shadow:    0 2px 12px rgba(0,0,0,.45);
  --shadow-lg: 0 12px 40px rgba(0,0,0,.55);

  --mono:    'IBM Plex Mono', monospace;
  --sans:    'IBM Plex Sans', sans-serif;
}

html, body, #root { height: 100%; background: var(--bg0); color: var(--text); font-family: var(--sans); overflow: hidden; -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; }

::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--text3); }

button { font-family: var(--sans); cursor: pointer; border: none; background: none; }
input  { font-family: var(--sans); }

/* ── APP SHELL ── */
.shell { display: flex; height: 100vh; }

/* ── SIDEBAR ── */
.sidebar {
  width: 220px; flex-shrink: 0; background: var(--bg1);
  border-right: 1px solid var(--border);
  display: flex; flex-direction: column;
}
.sidebar-logo {
  padding: 20px 18px 16px;
  border-bottom: 1px solid var(--border);
}
.logo-mark { display: flex; align-items: center; gap: 10px; }
.logo-icon {
  width: 32px; height: 32px;
  background: linear-gradient(135deg, var(--purple) 0%, var(--blue) 100%);
  border-radius: 8px; display: flex; align-items: center; justify-content: center;
  flex-shrink: 0; box-shadow: var(--shadow-sm);
}
.logo-text { font-size: 14px; font-weight: 700; letter-spacing: .06em; }
.logo-ver  { font-size: 10px; font-family: var(--mono); color: var(--text3); margin-top: 1px; }

.sidebar-nav { flex: 1; overflow-y: auto; padding: 8px 0; }
.nav-label {
  padding: 10px 18px 4px;
  font-size: 9px; font-weight: 600; letter-spacing: .12em;
  text-transform: uppercase; color: var(--text3);
}
.nav-item {
  display: flex; align-items: center; gap: 9px;
  padding: 8px 18px; font-size: 13px; font-weight: 500;
  color: var(--text2); cursor: pointer; transition: all .12s;
  border-left: 2px solid transparent;
  user-select: none;
}
.nav-item:hover { color: var(--text); background: var(--bg2); }
.nav-item.active { color: var(--purple); background: var(--purple-lt); border-left-color: var(--purple); font-weight: 600; }
.nav-badge {
  margin-left: auto; font-size: 10px; font-family: var(--mono);
  background: var(--bg3); color: var(--text3);
  padding: 1px 7px; border-radius: 10px; font-weight: 600;
}
.nav-item.active .nav-badge { background: var(--purple); color: #fff; }

.sidebar-stats { border-top: 1px solid var(--border); padding: 12px 18px; }
.stat-row { display: flex; justify-content: space-between; padding: 2px 0; }
.stat-k { font-size: 11px; color: var(--text2); }
.stat-v { font-size: 11px; font-family: var(--mono); color: var(--text); font-weight: 600; }

/* ── MAIN ── */
.main { flex: 1; display: flex; flex-direction: column; min-width: 0; overflow: hidden; }

.topbar {
  height: 54px; background: var(--bg0); border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 14px; padding: 0 24px; flex-shrink: 0;
}
.topbar-title { font-size: 15px; font-weight: 700; letter-spacing: -.01em; color: var(--text); }
.topbar-sub   { font-size: 11px; color: var(--text2); font-family: var(--mono); }
.topbar-link  { margin-left: auto; font-size: 11px; font-family: var(--mono); color: var(--purple); text-decoration: none; font-weight: 600; padding: 5px 10px; border: 1px solid var(--border); border-radius: 5px; transition: all .12s; }
.topbar-link:hover { border-color: var(--purple); background: var(--purple-lt); }

.export-menu { position: relative; display: inline-block; }
.export-btn { margin-left: 0; cursor: pointer; background: transparent; }
.export-btn:disabled { opacity: 0.6; cursor: default; }
.export-pop {
  position: absolute; right: 0; top: calc(100% + 4px); z-index: 30;
  min-width: 200px; background: var(--bg0); border: 1px solid var(--border);
  border-radius: 6px; box-shadow: 0 6px 24px rgba(0,0,0,.35); padding: 4px;
  display: flex; flex-direction: column;
}
.export-section-label {
  padding: 7px 10px 4px; font-size: 9.5px; font-family: var(--mono);
  color: var(--text3); font-weight: 700; letter-spacing: .08em; text-transform: uppercase;
}
.export-divider { height: 1px; background: var(--border); margin: 4px 0; }
.export-item {
  text-align: left; padding: 7px 10px; font-size: 12px; color: var(--text);
  background: transparent; border: 0; border-radius: 4px; cursor: pointer;
  font-family: inherit;
}
.export-item:hover:not(:disabled) { background: var(--purple-lt); color: var(--purple); }
.export-item:disabled { opacity: 0.6; cursor: default; }
.export-err {
  padding: 6px 10px; font-size: 11px; color: var(--danger, #EF4444);
  font-family: var(--mono); border-top: 1px solid var(--border); margin-top: 4px;
}

.search-wrap { position: relative; margin-left: auto; }
.search-icon { position: absolute; left: 10px; top: 50%; transform: translateY(-50%); color: var(--text3); pointer-events: none; }
.search-input {
  background: var(--bg1); border: 1px solid var(--border); border-radius: 6px;
  color: var(--text); padding: 7px 12px 7px 32px; font-size: 12px;
  width: 280px; outline: none; transition: border-color .15s, box-shadow .15s, background .15s;
}
.search-input:focus { border-color: var(--purple); background: var(--bg0); box-shadow: 0 0 0 3px var(--purple-lt); }
.search-input::placeholder { color: var(--text3); }

.filterbar {
  display: flex; flex-direction: column; gap: 6px; padding: 10px 24px;
  border-bottom: 1px solid var(--border); flex-shrink: 0;
  background: var(--bg1);
}
.filter-row {
  display: flex; align-items: center; gap: 6px;
  flex-wrap: nowrap; overflow-x: auto;
  scrollbar-width: none;            /* Firefox */
  -ms-overflow-style: none;          /* IE / old Edge */
}
.filter-row::-webkit-scrollbar { display: none; width: 0; height: 0; }
.filter-sep { width: 1px; height: 22px; background: var(--border2); margin: 0 18px; flex-shrink: 0; }
.chip {
  padding: 4px 11px; border-radius: 4px; font-size: 11px; font-weight: 600;
  border: 1px solid var(--border); background: var(--bg0); color: var(--text2);
  cursor: pointer; transition: all .12s; white-space: nowrap; flex-shrink: 0;
}
.chip:hover { border-color: var(--purple); color: var(--purple); }
.chip.on    { border-color: var(--purple); background: var(--purple); color: #fff; }
.chip.clear { border-color: var(--red); color: var(--red); background: var(--red-lt); }
.chip-label { font-size: 10px; color: var(--text3); font-weight: 600; text-transform: uppercase; letter-spacing: .06em; flex-shrink: 0; min-width: 56px; }

/* ── RULE LIST ── */
.rule-list { width: 380px; flex-shrink: 0; border-right: 1px solid var(--border); overflow-y: auto; background: var(--bg0); }
.list-count { padding: 10px 16px; font-size: 10px; font-family: var(--mono); color: var(--text3); border-bottom: 1px solid var(--border); font-weight: 600; }
.rule-row {
  padding: 12px 16px; border-bottom: 1px solid var(--border);
  cursor: pointer; transition: background .1s; position: relative;
}
.rule-row:hover  { background: var(--bg1); }
.rule-row.active { background: var(--purple-lt); }
.rule-row.active::before { content:''; position:absolute; left:0; top:0; bottom:0; width:3px; background: var(--purple); }
.rule-rid  { font-family: var(--mono); font-size: 10px; color: var(--text3); margin-bottom: 4px; font-weight: 600; }
.rule-name { font-size: 13px; font-weight: 500; line-height: 1.35; margin-bottom: 7px; color: var(--text); }
.rule-meta { display: flex; align-items: center; gap: 5px; flex-wrap: wrap; }

/* ── PILLS ── */
.pill {
  font-size: 10px; padding: 2px 7px; border-radius: 3px;
  font-weight: 600; border: 1px solid transparent; white-space: nowrap; font-family: var(--mono);
}
.pill-sev { }
.pill-tactic { background: var(--bg3); color: var(--text2); border-color: var(--border); font-family: var(--sans); font-size: 10px; }
.pill-fid-High   { background: var(--purple-lt); color: #C084FC; border-color: rgba(168,85,247,.35); }
.pill-fid-Medium { background: var(--blue-lt);   color: #60A5FA; border-color: rgba(59,130,246,.35); }
.pill-fid-Low    { background: var(--bg3);       color: var(--text2); border-color: var(--border); }
.pill-lc { background: var(--bg3); color: var(--text2); font-family: var(--sans); font-size: 10px; }

/* ── RULE DETAIL ── */
.content { flex: 1; display: flex; overflow: hidden; }
.detail  { flex: 1; overflow-y: auto; padding: 24px; }
.empty-state { display: flex; align-items: center; justify-content: center; }
.empty-inner { text-align: center; opacity: .2; }
.empty-inner svg { margin-bottom: 12px; }
.empty-inner p { font-size: 13px; }

.detail-rid  { font-family: var(--mono); font-size: 11px; color: var(--text3); margin-bottom: 5px; }
.detail-name { font-size: 20px; font-weight: 700; margin-bottom: 10px; line-height: 1.2; }
.detail-badges { display: flex; gap: 7px; flex-wrap: wrap; margin-bottom: 20px; }

.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 20px; }
.card {
  background: var(--bg2); border: 1px solid var(--border);
  border-radius: 8px; padding: 14px;
}
.card-label { font-size: 9px; font-weight: 600; text-transform: uppercase; letter-spacing: .1em; color: var(--text3); margin-bottom: 5px; }
.card-value { font-size: 15px; font-weight: 700; font-family: var(--mono); }
.risk-bar { height: 3px; background: var(--bg3); border-radius: 2px; margin-top: 6px; overflow: hidden; }
.risk-fill { height: 100%; border-radius: 2px; }

.section { margin-bottom: 20px; }
.section-title {
  font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: .1em;
  color: var(--text3); margin-bottom: 8px; display: flex; align-items: center; gap: 5px;
}
.desc-box {
  background: var(--bg1); border: 1px solid var(--border); border-radius: 6px;
  padding: 14px; font-size: 13px; color: var(--text2); line-height: 1.65;
}

/* Query tabs */
.qtabs { display: flex; gap: 4px; margin-bottom: 0; flex-wrap: wrap; }
.qtab {
  padding: 4px 10px; border-radius: 4px 4px 0 0; font-size: 10px; font-weight: 600;
  font-family: var(--mono); cursor: pointer; border: 1px solid var(--border);
  border-bottom: none; background: var(--bg2); color: var(--text3);
  transition: all .12s;
}
.qtab:hover { color: var(--text); }
.qtab.active { background: var(--bg0); color: var(--purple); border-color: var(--border2); }
.qblock { background: var(--bg0); border: 1px solid var(--border2); border-radius: 0 8px 8px 8px; overflow: hidden; }
.qblock-head {
  display: flex; align-items: center; justify-content: space-between;
  padding: 8px 14px; background: var(--bg1); border-bottom: 1px solid var(--border);
}
.qblock-lang { font-size: 11px; font-family: var(--mono); color: var(--purple); font-weight: 700; letter-spacing: .03em; }
.copy-btn {
  display: flex; align-items: center; gap: 5px; font-size: 10px;
  border: 1px solid var(--border); border-radius: 5px; padding: 4px 9px;
  color: var(--text2); background: var(--bg0); transition: all .12s; font-weight: 600;
}
.copy-btn:hover { border-color: var(--purple); color: var(--purple); background: var(--purple-lt); }
.qcode { font-family: var(--mono); font-size: 11.5px; padding: 14px; overflow-x: auto; white-space: pre; color: var(--text); line-height: 1.7; max-height: 360px; overflow-y: auto; background: var(--bg1); }

.tags-row { display: flex; gap: 5px; flex-wrap: wrap; }
.tag { font-size: 10px; font-family: var(--mono); padding: 2px 8px; background: var(--bg2); border: 1px solid var(--border); border-radius: 3px; color: var(--text3); }

.list-items { display: flex; flex-direction: column; gap: 4px; }
.list-item { display: flex; align-items: flex-start; gap: 8px; font-size: 12px; color: var(--text2); padding: 6px 10px; background: var(--bg1); border: 1px solid var(--border); border-radius: 4px; }
.list-dot { width: 4px; height: 4px; border-radius: 50%; background: var(--text3); margin-top: 5px; flex-shrink: 0; }

.triage-list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 6px; }
.triage-item { display: flex; align-items: flex-start; gap: 10px; padding: 8px 12px; background: var(--bg1); border: 1px solid var(--border); border-radius: 4px; }
.triage-num { flex-shrink: 0; width: 18px; height: 18px; border-radius: 50%; background: rgba(168,85,247,.18); color: #A855F7; font-size: 10px; font-weight: 700; font-family: var(--mono); display: flex; align-items: center; justify-content: center; margin-top: 1px; }
.triage-text { font-size: 12px; line-height: 1.55; color: var(--text2); }

/* ── INLINE RULE EDITOR ── */
.rule-actions { display: flex; gap: 6px; align-items: center; margin: 6px 0 14px; flex-wrap: wrap; }
.rule-btn {
  display: inline-flex; align-items: center; gap: 4px;
  font-size: 11px; font-family: var(--mono); font-weight: 600;
  padding: 5px 10px; border-radius: 5px;
  background: var(--bg0); color: var(--text2);
  border: 1px solid var(--border);
  cursor: pointer; transition: all .12s;
}
.rule-btn:hover:not(:disabled) { border-color: var(--purple); color: var(--purple); background: var(--purple-lt); }
.rule-btn:disabled { opacity: .45; cursor: not-allowed; }
.rule-btn-primary { background: var(--purple); color: #fff; border-color: var(--purple); }
.rule-btn-primary:hover:not(:disabled) { background: var(--purple); color: #fff; opacity: .9; }
.rule-btn-danger:hover:not(:disabled) { border-color: #F87171; color: #F87171; background: rgba(248,113,113,.08); }
.rule-err { font-size: 11px; color: #F87171; font-family: var(--mono); margin-left: 6px; }

.edit-input, .edit-textarea {
  width: 100%; box-sizing: border-box;
  background: var(--bg1); border: 1px solid var(--border); border-radius: 5px;
  color: var(--text); font-size: 13px; font-family: var(--sans);
  padding: 8px 10px; outline: none; transition: border-color .12s;
}
.edit-input:focus, .edit-textarea:focus { border-color: var(--purple); }
.edit-input-lg { font-size: 18px; font-weight: 600; padding: 8px 10px; }
.edit-textarea { resize: vertical; min-height: 56px; line-height: 1.5; }
.edit-mono { font-family: var(--mono); font-size: 12px; }

/* ── VIEWS ── */
.view { flex: 1; overflow-y: auto; padding: 28px; background: var(--bg0); }

/* Dashboard */
.dash-metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 28px; }
.metric-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 10px; padding: 18px; box-shadow: var(--shadow-sm); transition: box-shadow .15s, transform .15s, border-color .15s; }
.metric-card:hover { box-shadow: var(--shadow); transform: translateY(-1px); border-color: var(--border2); }
.metric-icon { width: 36px; height: 36px; border-radius: 8px; display: flex; align-items: center; justify-content: center; margin-bottom: 12px; }
.metric-num  { font-size: 30px; font-weight: 700; font-family: var(--mono); line-height: 1; letter-spacing: -.02em; }
.metric-lbl  { font-size: 11px; color: var(--text2); margin-top: 5px; font-weight: 500; }

.section-header { font-size: 13px; font-weight: 700; margin-bottom: 14px; display: flex; align-items: center; gap: 8px; color: var(--text); letter-spacing: -.01em; }

/* Tactic grid */
.tactic-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; }
.tactic-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 14px; cursor: pointer; transition: border-color .15s, box-shadow .15s; }
.tactic-card:hover { border-color: var(--border2); box-shadow: var(--shadow-sm); }
.tactic-dot  { width: 8px; height: 8px; border-radius: 50%; margin-bottom: 8px; }
.tactic-name { font-size: 11px; font-weight: 600; margin-bottom: 6px; }
.tactic-bar  { height: 3px; border-radius: 2px; background: var(--bg3); overflow: hidden; margin-bottom: 5px; }
.tactic-fill { height: 100%; border-radius: 2px; }
.tactic-stat { font-size: 10px; font-family: var(--mono); color: var(--text2); }

/* Sev dist */
.sev-bars { display: flex; flex-direction: column; gap: 10px; }
.sev-bars-tall { gap: 18px; }
.sev-bars-tall .sev-bar-bg { height: 32px; border-radius: 6px; }
.sev-bars-tall .sev-bar-fill { border-radius: 6px; padding: 0 14px; font-size: 12px; }
.sev-bars-tall .sev-lbl { font-size: 12px; width: 78px; }
.sev-row  { display: flex; align-items: center; gap: 12px; }
.sev-row-clickable { cursor: pointer; padding: 4px 6px; border-radius: 6px; transition: background .15s; }
.sev-row-clickable:hover { background: rgba(168,85,247,.06); }
.tactic-card-clickable { outline: none; }
.tactic-card-clickable:hover { border-color: rgba(168,85,247,.45); }
.sev-lbl  { font-size: 11px; font-weight: 700; width: 70px; }
.sev-bar-bg { flex: 1; height: 20px; background: var(--bg1); border-radius: 4px; overflow: hidden; }
.sev-bar-fill { height: 100%; border-radius: 4px; display: flex; align-items: center; padding: 0 10px; font-size: 11px; font-family: var(--mono); font-weight: 700; color: white; min-width: 30px; }
.panel-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 10px; padding: 22px; box-shadow: var(--shadow-sm); }
.panel-card-fill { display: flex; flex-direction: column; justify-content: center; flex: 1; }

/* ATT&CK Matrix — column-per-tactic grid mirroring attack.mitre.org */
.matrix-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; padding: 18px 24px; border-bottom: 1px solid var(--border); background: var(--bg0); }
.matrix-stat { background: var(--bg2); border: 1px solid var(--border); border-radius: 10px; padding: 14px 18px; }
.matrix-stat-num { font-size: 32px; font-weight: 700; font-family: var(--mono); line-height: 1; letter-spacing: -.02em; color: var(--text); }
.matrix-stat-pct { font-size: 18px; font-weight: 700; color: var(--text2); margin-left: 1px; }
.matrix-stat-lbl { font-size: 11px; color: var(--text2); margin-top: 8px; line-height: 1.4; }
.matrix-stat-sub { color: var(--text3); font-size: 10px; }
.matrix-legend { display: flex; align-items: center; gap: 14px; padding: 10px 24px; border-bottom: 1px solid var(--border); flex-shrink: 0; flex-wrap: wrap; font-size: 10px; color: var(--text2); font-family: var(--mono); background: var(--bg1); font-weight: 500; }
.matrix-legend-item { display: inline-flex; align-items: center; gap: 5px; }
.matrix-legend-swatch { display: inline-block; width: 12px; height: 12px; border-radius: 2px; border: 1px solid; }
.matrix-legend-label { font-size: 10px; color: var(--text3); font-weight: 600; text-transform: uppercase; letter-spacing: .08em; margin-right: 4px; }
.matrix-scroll { flex: 1; overflow: auto; padding: 12px; }
.attack-grid { display: grid; grid-auto-flow: column; grid-auto-columns: minmax(168px, 1fr); gap: 6px; min-width: max-content; }
.attack-col { display: flex; flex-direction: column; min-width: 168px; }
.attack-col-head { padding: 8px 10px 7px; background: var(--bg1); border: 1px solid var(--border); border-top: 3px solid; border-radius: 4px 4px 0 0; }
.attack-col-tactic { font-size: 11px; font-weight: 700; line-height: 1.2; margin-bottom: 2px; }
.attack-col-meta { font-size: 9px; font-family: var(--mono); color: var(--text2); letter-spacing: .04em; }
.attack-col-body { display: flex; flex-direction: column; gap: 3px; padding-top: 4px; }
.attack-cell {
  display: flex; flex-direction: column; gap: 1px; padding: 6px 8px;
  border: 1px solid; border-radius: 3px; text-decoration: none;
  cursor: pointer; transition: filter .12s, transform .08s;
  position: relative;
}
.attack-cell:hover { transform: translateX(2px); box-shadow: var(--shadow-sm); }
.attack-cell-id { font-size: 10px; font-family: var(--mono); font-weight: 700; letter-spacing: .02em; }
.attack-cell-name { font-size: 10.5px; line-height: 1.3; }
.attack-cell-count {
  position: absolute; top: 5px; right: 22px; font-size: 9px; font-family: var(--mono); font-weight: 700;
  color: #fff; background: var(--purple); padding: 1px 6px; border-radius: 8px;
}
.attack-cell-link { display: flex; flex-direction: column; gap: 1px; text-decoration: none; padding-right: 18px; }
.attack-cell-toggle {
  position: absolute; top: 4px; right: 4px; width: 16px; height: 16px; padding: 0;
  display: flex; align-items: center; justify-content: center;
  background: rgba(255,255,255,.04); border: 1px solid rgba(168,85,247,.30);
  border-radius: 3px; cursor: pointer; color: #C084FC;
  transition: background .12s, transform .15s;
}
.attack-cell-toggle:hover { background: rgba(168,85,247,.18); }
.attack-cell-toggle.open { transform: rotate(180deg); background: rgba(168,85,247,.22); }
.attack-cell-wrap { display: flex; flex-direction: column; gap: 0; }
.attack-cell-wrap.open .attack-cell { border-radius: 3px 3px 0 0; }
.attack-cell-rules {
  background: var(--bg2); border: 1px solid rgba(168,85,247,.36); border-top: none;
  border-radius: 0 0 3px 3px; padding: 6px 8px; display: flex; flex-direction: column; gap: 4px;
  max-height: 260px; overflow-y: auto;
}
.attack-cell-rules-head { font-size: 9px; font-family: var(--mono); color: var(--text3); letter-spacing: .04em; padding-bottom: 4px; border-bottom: 1px solid var(--border); margin-bottom: 2px; }
.attack-cell-rule {
  display: grid; grid-template-columns: auto 1fr auto; gap: 6px; align-items: center;
  padding: 4px 6px; background: var(--bg1); border: 1px solid var(--border); border-radius: 3px;
  cursor: pointer; transition: border-color .12s;
}
.attack-cell-rule:hover { border-color: rgba(168,85,247,.55); background: rgba(168,85,247,.06); }
.attack-cell-rule-rid { font-size: 9px; font-family: var(--mono); color: #A855F7; font-weight: 700; }
.attack-cell-rule-name { font-size: 10.5px; color: var(--text2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

/* Lockheed Cyber Kill Chain — horizontal 7-stage flow */
.killchain { display: flex; align-items: stretch; gap: 6px; flex-wrap: wrap; margin-bottom: 8px; }
.kc-wrap { display: flex; align-items: center; flex: 1 1 230px; min-width: 220px; }
.kc-stage {
  flex: 1; padding: 14px 14px 12px; border-radius: 8px; border: 1px solid;
  display: flex; flex-direction: column; gap: 8px; min-height: 168px; min-width: 0;
  background: var(--bg2); transition: border-color .15s, box-shadow .15s, transform .15s;
}
.kc-stage:hover { box-shadow: var(--shadow); transform: translateY(-1px); }
.kc-stage-clickable { cursor: pointer; outline: none; }
.kc-stage-clickable:hover { border-color: rgba(168,85,247,.55); }
.kc-stage-clickable:focus-visible { box-shadow: 0 0 0 2px var(--purple); }
.kc-stage.kc-cov { border-color: rgba(124,58,237,.50); background: linear-gradient(180deg, var(--purple-lt) 0%, var(--bg0) 70%); }
.kc-stage.kc-gap { border-color: rgba(220,38,38,.40); background: linear-gradient(180deg, var(--red-lt) 0%, var(--bg0) 70%); }
.kc-stage.kc-pre { border-color: var(--border); background: var(--bg1); opacity: .80; }
.kc-stage-num { font-size: 9px; font-family: var(--mono); color: var(--text3); letter-spacing: .18em; font-weight: 700; }
.kc-stage-name { font-size: 13.5px; font-weight: 700; color: var(--text); line-height: 1.15; letter-spacing: -.01em; }
.kc-stage-desc { font-size: 10.5px; color: var(--text2); line-height: 1.5; flex: 1; }
.kc-stage-meta { display: flex; flex-direction: column; gap: 6px; padding-top: 8px; border-top: 1px solid var(--border); }
.kc-tactics { display: flex; flex-wrap: wrap; gap: 4px; }
.kc-tactic-pill { font-size: 9px; padding: 2px 7px; border-radius: 3px; border: 1px solid; font-weight: 600; }
.kc-count { font-size: 11px; font-family: var(--mono); font-weight: 700; }
.kc-pre-cluster {
  display: flex; flex-direction: column;
  flex: 2 1 460px; min-width: 440px;
  gap: 8px;
}
.kc-pre-row { display: flex; align-items: stretch; gap: 6px; }
.kc-pre-row .kc-stage { flex: 1 1 0; min-width: 0; }
.kc-pre-callout {
  background: var(--bg1); border: 1px solid var(--border);
  border-radius: 8px; padding: 14px 16px;
}
.kc-pre-callout-tag { font-size: 10.5px; color: var(--text3); font-weight: 700; letter-spacing: .04em; margin-bottom: 5px; text-transform: uppercase; }
.kc-pre-callout-body { font-size: 11.5px; color: var(--text2); line-height: 1.55; }
.kc-arrow { color: var(--text3); flex-shrink: 0; margin: 0 -2px; align-self: center; }

/* Chains */
.chains-grid { display: flex; flex-direction: column; gap: 14px; }
.chain-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; transition: box-shadow .15s; }
.chain-card:hover { box-shadow: var(--shadow); }
.chain-head { display: flex; align-items: center; gap: 14px; padding: 16px 18px; }
.chain-active { width: 9px; height: 9px; border-radius: 50%; flex-shrink: 0; }
.chain-id   { font-family: var(--mono); font-size: 11px; color: var(--text3); font-weight: 600; }
.chain-name { font-size: 14px; font-weight: 600; flex: 1; color: var(--text); }
.chain-threat { font-size: 11px; color: var(--text2); margin-left: auto; }
.chain-steps { display: flex; align-items: center; gap: 0; padding: 0 18px 16px; flex-wrap: wrap; }
.chain-step {
  font-size: 11px; padding: 5px 11px; background: var(--bg1);
  border: 1px solid var(--border); border-radius: 5px; color: var(--text2);
  white-space: nowrap; font-weight: 500;
}
.chain-arrow { color: var(--text3); margin: 0 5px; flex-shrink: 0; }
.chain-meta  { display: flex; gap: 16px; padding: 11px 18px; background: var(--bg1); border-top: 1px solid var(--border); }
.chain-meta-item { font-size: 11px; color: var(--text2); display: flex; align-items: center; gap: 6px; font-family: var(--mono); font-weight: 500; }

/* Recommend — demo banner makes the mock framing impossible to miss */
.demo-banner {
  display: flex; align-items: flex-start; gap: 14px; padding: 16px 18px;
  background: linear-gradient(135deg, rgba(239,68,68,.10) 0%, rgba(168,85,247,.08) 100%);
  border: 1px solid rgba(239,68,68,.30); border-radius: 10px;
}
.demo-banner-icon {
  width: 32px; height: 32px; border-radius: 8px; flex-shrink: 0;
  background: rgba(239,68,68,.15); color: var(--red);
  display: flex; align-items: center; justify-content: center;
}
.demo-banner-title { font-size: 13px; font-weight: 700; color: var(--text); margin-bottom: 4px; letter-spacing: -.01em; }
.demo-banner-body  { font-size: 12px; color: var(--text2); line-height: 1.55; }
.demo-banner-body code { font-family: var(--mono); font-size: 11px; padding: 1px 5px; background: var(--bg3); border-radius: 3px; color: var(--text); }
.demo-banner-body strong { color: var(--text); font-weight: 700; }

.rec-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 24px; }
.log-source-table { width: 100%; border-collapse: collapse; }
.log-source-table th { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: .10em; color: var(--text3); padding: 10px 14px; border-bottom: 1px solid var(--border); text-align: left; background: var(--bg1); }
.log-source-table td { font-size: 12px; padding: 11px 14px; border-bottom: 1px solid var(--border); color: var(--text2); }
.log-source-table tr:last-child td { border-bottom: none; }
.log-source-table tr:hover td { background: var(--bg1); }
.status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 7px; }

.two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; align-items: stretch; }
.two-col > div { display: flex; flex-direction: column; min-width: 0; }

/* ── BOTTOM TAB BAR (mobile only — hidden by default, shown via media query) ── */
.bottom-tabs {
  display: none;
  position: fixed; bottom: 0; left: 0; right: 0;
  height: calc(60px + env(safe-area-inset-bottom));
  padding-bottom: env(safe-area-inset-bottom);
  background: var(--bg1); border-top: 1px solid var(--border);
  z-index: 50;
}
.bottom-tab {
  flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center;
  gap: 3px; padding: 8px 4px 0;
  color: var(--text3); background: none; border: none; cursor: pointer;
  position: relative; transition: color .12s;
  min-width: 0;
}
.bottom-tab.active { color: var(--purple); }
.bottom-tab.active::before {
  content: ''; position: absolute; top: 0; left: 28%; right: 28%;
  height: 2px; background: var(--purple); border-radius: 0 0 2px 2px;
}
.bottom-tab-icon { display: flex; align-items: center; justify-content: center; }
.bottom-tab-label {
  font-size: 10px; font-weight: 600; letter-spacing: -.01em;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  max-width: 100%;
}

/* Mobile-only status dot (hidden on desktop, inline-block on mobile) */
.status-dot-mobile { display: none; }

/* Mobile-only matrix tactic picker (rendered conditionally; styled here) */
.matrix-tactic-picker {
  display: flex; flex-wrap: nowrap; overflow-x: auto;
  gap: 6px; padding: 10px 12px;
  background: var(--bg1); border-bottom: 1px solid var(--border);
  scrollbar-width: none;
}
.matrix-tactic-picker::-webkit-scrollbar { display: none; }
.matrix-tactic-pill {
  flex-shrink: 0; font-size: 11px; font-weight: 600;
  padding: 6px 12px; border-radius: 16px; border: 1px solid;
  white-space: nowrap; cursor: pointer; background: transparent;
  font-family: var(--sans);
}
.matrix-tactic-pill .mt-pill-count {
  font-family: var(--mono); font-size: 10px; opacity: .7; margin-left: 6px;
}

/* Mobile rule-detail overlay (slides up full-screen) */
.mobile-detail-overlay {
  position: fixed; inset: 0; z-index: 100;
  display: flex; flex-direction: column;
  background: var(--bg0);
  animation: mobileDetailSlideUp .25s ease-out;
}
@keyframes mobileDetailSlideUp {
  from { transform: translateY(100%); }
  to   { transform: translateY(0); }
}
.mobile-detail-header {
  height: 48px; flex-shrink: 0;
  display: flex; align-items: center; padding: 0 8px;
  background: var(--bg0); border-bottom: 1px solid var(--border);
}
.mobile-detail-back {
  display: inline-flex; align-items: center; gap: 6px;
  font-size: 14px; font-weight: 600; color: var(--text);
  background: none; border: none; padding: 8px 10px; cursor: pointer;
}
.mobile-detail-back:hover { color: var(--purple); }
.mobile-detail-body { flex: 1; overflow-y: auto; }

/* ─────────────────────── MOBILE LAYOUT (≤ 768px) ─────────────────────── */
@media (max-width: 768px) {
  html, body, #root { overflow-x: hidden; }

  .shell { flex-direction: column; height: 100vh; }

  /* Sidebar fully hidden — replaced by bottom tabs */
  .sidebar { display: none !important; }

  /* Bottom tabs visible */
  .bottom-tabs { display: flex; }

  /* Main pane: leave room for bottom tabs */
  .main { padding-bottom: calc(60px + env(safe-area-inset-bottom)); }

  /* Topbar: 44px slim, title only — search wraps to its own row when present */
  .topbar {
    height: auto; min-height: 44px;
    padding: 0 12px; gap: 6px;
    flex-wrap: wrap; align-items: center;
  }
  .topbar-title { font-size: 14px; line-height: 44px; }
  .topbar-sub, .topbar-link { display: none; }
  .search-wrap { width: 100%; margin: 0 0 8px; order: 2; }
  .search-input { width: 100%; padding: 8px 12px 8px 32px; font-size: 13px; }

  /* Filterbar: single horizontal scrollable strip */
  .filterbar {
    flex-direction: row; flex-wrap: nowrap;
    overflow-x: auto; overflow-y: hidden;
    padding: 8px 12px; gap: 6px;
    scrollbar-width: none;
  }
  .filterbar::-webkit-scrollbar { display: none; }
  .filter-row { flex-shrink: 0; gap: 4px; overflow: visible; }
  .filter-sep { display: none; }
  .chip-label { min-width: 0; padding-right: 2px; }

  /* Views: tighter padding */
  .view { padding: 16px 12px; }

  /* Dashboard: 2x2 metric grid, single-column tactic list, stacked two-col */
  .dash-metrics { grid-template-columns: repeat(2, 1fr); gap: 10px; margin-bottom: 20px; }
  .metric-card { padding: 14px; }
  .metric-num  { font-size: 24px; }
  .two-col { grid-template-columns: 1fr; gap: 18px; }

  /* Tactic grid (Dashboard): full-width single-column rows  — name + bar + count */
  .tactic-grid { grid-template-columns: 1fr !important; gap: 6px; }
  .tactic-card {
    display: grid; grid-template-columns: 8px 1fr 1.2fr auto;
    align-items: center; gap: 10px; padding: 10px 12px;
  }
  .tactic-dot  { margin-bottom: 0; }
  .tactic-name { margin-bottom: 0; font-size: 12px; }
  .tactic-bar  { margin-bottom: 0; }
  .tactic-stat { white-space: nowrap; }

  /* Rules: list takes full width, detail goes to fullscreen overlay */
  .content { flex-direction: column; overflow: visible; }
  .rule-list {
    width: 100%; flex-shrink: 1;
    border-right: none; border-bottom: 1px solid var(--border);
  }
  .detail { padding: 18px 14px; }
  .detail-name { font-size: 17px; }
  .grid2 { grid-template-columns: 1fr 1fr; gap: 8px; }
  .qcode { font-size: 11px; max-height: 280px; }
  .qtabs { overflow-x: auto; flex-wrap: nowrap; scrollbar-width: none; }
  .qtabs::-webkit-scrollbar { display: none; }
  .qtab { flex-shrink: 0; }

  /* Matrix: stats 2-col, picker visible (rendered by component) */
  .matrix-stats { grid-template-columns: repeat(2, 1fr); gap: 8px; padding: 12px; }
  .matrix-stat  { padding: 12px 14px; }
  .matrix-stat-num { font-size: 24px; }
  .matrix-stat-pct { font-size: 14px; }
  .matrix-stat-lbl { font-size: 10px; }
  .matrix-legend { padding: 8px 12px; gap: 8px; overflow-x: auto; flex-wrap: nowrap; scrollbar-width: none; }
  .matrix-legend::-webkit-scrollbar { display: none; }
  .matrix-legend-item, .matrix-legend-label { flex-shrink: 0; }
  .matrix-scroll { padding: 12px; }
  /* Mobile single-tactic body uses one full-width column */
  .attack-grid { grid-auto-flow: row; grid-auto-columns: auto; min-width: 0; }
  .attack-col { min-width: 0; width: 100%; }

  /* Kill Chain: vertical stack with 90° rotated arrows */
  .killchain { flex-direction: column; gap: 0; margin-bottom: 4px; }
  .kc-wrap   { flex-direction: column; flex: 0 0 auto; min-width: 0; width: 100%; align-items: stretch; }
  .kc-stage  { min-height: auto; padding: 12px 14px; }
  .kc-arrow  { transform: rotate(90deg); margin: 6px auto; }
  .kc-pre-cluster { flex: 0 0 auto; min-width: 0; width: 100%; gap: 6px; }
  .kc-pre-row { flex-direction: column; gap: 0; }
  .kc-pre-row .kc-arrow { transform: rotate(90deg); margin: 6px auto; }

  /* Attack chains: vertical step list */
  .chain-head { flex-wrap: wrap; padding: 14px 16px; }
  .chain-threat { margin-left: 0; width: 100%; margin-top: 4px; }
  .chain-steps { flex-direction: column; align-items: flex-start; padding: 0 16px 14px; gap: 0; }
  .chain-step  { width: 100%; }
  .chain-arrow { transform: rotate(90deg); margin: 4px 12px; }
  .chain-meta  { padding: 10px 16px; flex-wrap: wrap; gap: 12px; }

  /* Log Sources: hide Tier column, sticky header, show status dot */
  .log-source-table th:nth-child(2),
  .log-source-table td:nth-child(2) { display: none; }
  .log-source-table thead th { position: sticky; top: 0; z-index: 1; }
  .log-source-table th, .log-source-table td { padding: 10px 12px; }
  .status-dot-mobile { display: inline-block; }
}
`

// ─── HELPERS ─────────────────────────────────────────────────────────────────

function SevBadge({ s }) {
  const c = SEV_COLOR[s] || '#888'
  const bg = SEV_BG[s]   || 'rgba(128,128,128,.1)'
  return (
    <span className="pill pill-sev" style={{ background: bg, color: c, borderColor: c + '44' }}>
      {s === 'Critical' && <AlertTriangle size={9} style={{ display:'inline', marginRight:3, verticalAlign:'middle' }} />}
      {s}
    </span>
  )
}

function CopyBtn({ text }) {
  const [ok, setOk] = useState(false)
  const copy = () => { navigator.clipboard.writeText(text); setOk(true); setTimeout(()=>setOk(false),1400) }
  return (
    <button className="copy-btn" onClick={copy}>
      {ok ? <><Check size={10} />Copied</> : <><Copy size={10} />Copy</>}
    </button>
  )
}

// ─── RULE DETAIL ─────────────────────────────────────────────────────────────

const SIEM_KEYS = ['spl','kql','aql','yara_l','esql','leql','crowdstrike','xql','lucene','sumo']

const linesToList = (s) => (s || '').split('\n').map(x => x.trim()).filter(Boolean)
const listToLines = (xs) => (xs || []).join('\n')

function RuleDetail({ rule, onUpdated, onDuplicated, onDeleted }) {
  const { getToken } = useAuth()
  const [tab, setTab] = useState('spl')
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  const platforms = Object.keys(rule.queries || {}).filter(k => rule.queries[k])
  const rc = SEV_COLOR[rule.severity] || '#888'

  const startEdit = () => {
    setDraft({
      name: rule.name || '',
      description: rule.description || '',
      severity: rule.severity || 'Medium',
      fidelity: rule.fidelity || 'Medium',
      lifecycle: rule.lifecycle || 'Proposed',
      risk_score: rule.risk_score ?? 0,
      pseudo_logic: rule.pseudo_logic || '',
      tuning_guidance: rule.tuning_guidance || '',
      tags: listToLines(rule.tags),
      false_positives: listToLines(rule.false_positives),
      triage_steps: listToLines(rule.triage_steps),
      queries: { ...(rule.queries || {}) },
    })
    setError(null)
    setEditing(true)
  }

  const cancelEdit = () => {
    setEditing(false)
    setDraft(null)
    setError(null)
  }

  const updateDraft = (k, v) => setDraft(d => ({ ...d, [k]: v }))
  const updateQuery = (key, v) => setDraft(d => ({ ...d, queries: { ...d.queries, [key]: v } }))

  const apiCall = async (path, opts = {}) => {
    const token = await getToken()
    return fetch(path, {
      ...opts,
      headers: {
        ...(opts.headers || {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    })
  }

  const save = async () => {
    if (!draft) return
    setBusy(true)
    setError(null)
    try {
      const payload = {
        name: draft.name,
        description: draft.description,
        severity: draft.severity,
        fidelity: draft.fidelity,
        lifecycle: draft.lifecycle,
        risk_score: Number.isFinite(+draft.risk_score) ? +draft.risk_score : 0,
        pseudo_logic: draft.pseudo_logic,
        tuning_guidance: draft.tuning_guidance,
        tags: linesToList(draft.tags),
        false_positives: linesToList(draft.false_positives),
        triage_steps: linesToList(draft.triage_steps),
        queries: draft.queries,
      }
      const r = await apiCall(`/api/rules/${encodeURIComponent(rule.rule_id)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const updated = await r.json()
      onUpdated && onUpdated(updated)
      setEditing(false)
      setDraft(null)
    } catch (e) {
      setError(e.message || 'Save failed')
    } finally {
      setBusy(false)
    }
  }

  const remove = async () => {
    if (!confirm(`Permanently delete ${rule.rule_id}?\n\nThis can't be undone — the rule will be removed from the library and won't come back on re-seed.`)) return
    setBusy(true)
    setError(null)
    try {
      const r = await apiCall(`/api/rules/${encodeURIComponent(rule.rule_id)}`, { method: 'DELETE' })
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      onDeleted && onDeleted(rule.rule_id)
    } catch (e) {
      setError(e.message || 'Delete failed')
      setBusy(false)
    }
  }

  const duplicate = async () => {
    setBusy(true)
    setError(null)
    try {
      const r = await apiCall(`/api/rules/${encodeURIComponent(rule.rule_id)}/duplicate`, { method: 'POST' })
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const created = await r.json()
      onDuplicated && onDuplicated(created)
    } catch (e) {
      setError(e.message || 'Duplicate failed')
    } finally {
      setBusy(false)
    }
  }

  const queryTab = editing ? (draft.queries[tab] ?? '') : (rule.queries?.[tab] ?? '')

  return (
    <div className="detail">
      <div className="detail-rid">{rule.rule_id} · {rule.technique_id}</div>

      {editing ? (
        <input className="edit-input edit-input-lg" value={draft.name}
               onChange={e => updateDraft('name', e.target.value)} />
      ) : (
        <div className="detail-name">{rule.name}</div>
      )}

      <div className="detail-badges">
        <SevBadge s={rule.severity} />
        <span className="pill pill-tactic">{tacticLabel(rule.tactic)}</span>
        <span className="pill pill-lc">{(rule.platform||[]).join(' · ')}</span>
        {rule.is_custom && <span className="pill" style={{background:'rgba(124,92,255,.18)', color:'#C4B5FD'}}>Custom</span>}
      </div>

      <div className="rule-actions">
        {!editing && (
          <>
            <button className="rule-btn" onClick={startEdit} disabled={busy}>
              <Edit3 size={11} /> Edit
            </button>
            <button className="rule-btn" onClick={duplicate} disabled={busy}>
              <Copy size={11} /> Duplicate
            </button>
          </>
        )}
        {editing && (
          <>
            <button className="rule-btn rule-btn-primary" onClick={save} disabled={busy}>
              {busy ? 'Saving…' : 'Save'}
            </button>
            <button className="rule-btn" onClick={cancelEdit} disabled={busy}>Cancel</button>
          </>
        )}
        {error && <span className="rule-err">{error}</span>}
      </div>

      <div className="grid2">
        <div className="card">
          <div className="card-label">Risk Score</div>
          {editing ? (
            <input type="number" min="0" max="100" className="edit-input"
                   value={draft.risk_score}
                   onChange={e => updateDraft('risk_score', e.target.value)} />
          ) : (
            <>
              <div className="card-value" style={{ color: rc }}>{rule.risk_score}/100</div>
              <div className="risk-bar"><div className="risk-fill" style={{ width:`${rule.risk_score}%`, background:rc }} /></div>
            </>
          )}
        </div>
        <div className="card">
          <div className="card-label">Severity</div>
          {editing ? (
            <select className="edit-input" value={draft.severity}
                    onChange={e => updateDraft('severity', e.target.value)}>
              {['Critical','High','Medium','Low'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          ) : (
            <div className="card-value" style={{ color: rc }}>{rule.severity}</div>
          )}
        </div>
        <div className="card">
          <div className="card-label">Fidelity</div>
          {editing ? (
            <select className="edit-input" value={draft.fidelity}
                    onChange={e => updateDraft('fidelity', e.target.value)}>
              {['High','Medium','Low'].map(f => <option key={f} value={f}>{f}</option>)}
            </select>
          ) : (
            <div className="card-value" style={{ color: rule.fidelity==='High'?'#7C3AED':rule.fidelity==='Medium'?'#2563EB':'#6E6E7C' }}>{rule.fidelity}</div>
          )}
        </div>
        <div className="card">
          <div className="card-label">Lifecycle</div>
          {editing ? (
            <select className="edit-input" value={draft.lifecycle}
                    onChange={e => updateDraft('lifecycle', e.target.value)}>
              {['Deployed','Proposed','Tested','Retired'].map(l => <option key={l} value={l}>{l}</option>)}
            </select>
          ) : (
            <div className="card-value" style={{ fontSize:12, color:'#aaa' }}>{rule.lifecycle}</div>
          )}
        </div>
      </div>

      <div className="section">
        <div className="section-title"><Activity size={11} />Description</div>
        {editing ? (
          <textarea className="edit-textarea" rows={3}
                    value={draft.description}
                    onChange={e => updateDraft('description', e.target.value)} />
        ) : (
          <div className="desc-box">{rule.description || 'No description available.'}</div>
        )}
      </div>

      {(platforms.length > 0 || editing) && (
        <div className="section">
          <div className="section-title"><Terminal size={11} />Detection Queries</div>
          <div className="qtabs">
            {(editing ? SIEM_KEYS : platforms).map(p => (
              <button key={p} className={`qtab${tab===p?' active':''}`} onClick={()=>setTab(p)}>
                {p}
              </button>
            ))}
          </div>
          <div className="qblock">
            <div className="qblock-head">
              <span className="qblock-lang">{SIEM_LABELS[tab] || tab.toUpperCase()}</span>
              {!editing && <CopyBtn text={queryTab} />}
            </div>
            {editing ? (
              <textarea className="edit-textarea edit-mono" rows={8}
                        value={queryTab}
                        onChange={e => updateQuery(tab, e.target.value)}
                        placeholder={`${SIEM_LABELS[tab] || tab} query…`} />
            ) : (
              <div className="qcode">{queryTab}</div>
            )}
          </div>
        </div>
      )}

      {(rule.pseudo_logic || editing) && (
        <div className="section">
          <div className="section-title"><Cpu size={11} />Pseudo Logic</div>
          {editing ? (
            <textarea className="edit-textarea edit-mono" rows={4}
                      value={draft.pseudo_logic}
                      onChange={e => updateDraft('pseudo_logic', e.target.value)} />
          ) : (
            <div className="qcode">{rule.pseudo_logic}</div>
          )}
        </div>
      )}

      {rule.data_sources?.length > 0 && !editing && (
        <div className="section">
          <div className="section-title"><Database size={11} />Data Sources</div>
          <div className="list-items">
            {rule.data_sources.map((s,i) => <div key={i} className="list-item"><div className="list-dot" />{s}</div>)}
          </div>
        </div>
      )}

      {(rule.false_positives?.length > 0 || editing) && (
        <div className="section">
          <div className="section-title"><AlertTriangle size={11} />False Positives</div>
          {editing ? (
            <textarea className="edit-textarea" rows={3}
                      placeholder="One per line"
                      value={draft.false_positives}
                      onChange={e => updateDraft('false_positives', e.target.value)} />
          ) : (
            <div className="list-items">
              {rule.false_positives.map((fp,i) => <div key={i} className="list-item"><div className="list-dot" />{fp}</div>)}
            </div>
          )}
        </div>
      )}

      {(rule.tags?.length > 0 || editing) && (
        <div className="section">
          <div className="section-title"><Tag size={11} />Tags</div>
          {editing ? (
            <textarea className="edit-textarea" rows={2}
                      placeholder="One tag per line"
                      value={draft.tags}
                      onChange={e => updateDraft('tags', e.target.value)} />
          ) : (
            <div className="tags-row">{rule.tags.map(t=><span key={t} className="tag">{t}</span>)}</div>
          )}
        </div>
      )}

      {(rule.triage_steps?.length > 0 || editing) && (
        <div className="section">
          <div className="section-title"><Crosshair size={11} />Triage Steps</div>
          {editing ? (
            <textarea className="edit-textarea" rows={4}
                      placeholder="One step per line"
                      value={draft.triage_steps}
                      onChange={e => updateDraft('triage_steps', e.target.value)} />
          ) : (
            <ol className="triage-list">
              {rule.triage_steps.map((s,i) => (
                <li key={i} className="triage-item">
                  <span className="triage-num">{i+1}</span>
                  <span className="triage-text">{s}</span>
                </li>
              ))}
            </ol>
          )}
        </div>
      )}

      {(rule.tuning_guidance || editing) && (
        <div className="section">
          <div className="section-title"><Sliders size={11} />Tuning Guidance</div>
          {editing ? (
            <textarea className="edit-textarea" rows={3}
                      value={draft.tuning_guidance}
                      onChange={e => updateDraft('tuning_guidance', e.target.value)} />
          ) : (
            <div className="desc-box">{rule.tuning_guidance}</div>
          )}
        </div>
      )}

      <div style={{ marginTop:8, paddingTop:10, borderTop:'1px solid var(--border)', display:'flex', gap:16, flexWrap:'wrap' }}>
        <span style={{ fontSize:11, color:'var(--text3)', fontFamily:'var(--mono)' }}>Author: {rule.author}</span>
        <span style={{ fontSize:11, color:'var(--text3)', fontFamily:'var(--mono)' }}>Created: {rule.created}</span>
        {rule.last_modified && rule.last_modified !== rule.created && (
          <span style={{ fontSize:11, color:'var(--text3)', fontFamily:'var(--mono)' }}>Modified: {rule.last_modified}</span>
        )}
      </div>

      {!editing && (
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 24 }}>
          <button
            className="rule-btn rule-btn-danger"
            onClick={remove}
            disabled={busy}
            style={{ fontSize: 11 }}
            title="Permanently delete this rule from the library"
          >
            <Trash2 size={11} /> Delete
          </button>
        </div>
      )}
    </div>
  )
}

// ─── RULES VIEW ──────────────────────────────────────────────────────────────

// ─── AI RULE BUILDER MODAL (Phase 4) ────────────────────────────────────────

// Extract a readable error from a non-OK fetch response, regardless of whether
// the server returned JSON ({error: "..."}) or HTML (Flask's default abort).
async function readErr(r) {
  const ct = r.headers.get('Content-Type') || ''
  if (ct.includes('application/json')) {
    try {
      const j = await r.json()
      if (j && j.error) return j.error
    } catch { /* fall through */ }
  }
  try {
    const t = await r.text()
    // Flask's HTML errors look like "<p>Description</p>"; pull the message out.
    const m = t.match(/<p>([\s\S]*?)<\/p>/)
    if (m) return `HTTP ${r.status}: ${m[1].trim()}`
    if (t && t.length < 200) return `HTTP ${r.status}: ${t.trim()}`
  } catch { /* ignore */ }
  return `HTTP ${r.status}`
}

function GenerateRuleModal({ open, onClose, onSaved, primarySiem }) {
  const { getToken } = useAuth()
  const [prompt, setPrompt] = useState('')
  const [techniqueId, setTechniqueId] = useState('')
  const [platforms, setPlatforms] = useState([])
  const [phase, setPhase] = useState('compose') // compose | generating | preview | saving
  const [error, setError] = useState(null)
  const [preview, setPreview] = useState(null) // { rule, usage }

  useEffect(() => {
    if (!open) return
    setPrompt(''); setTechniqueId(''); setPlatforms([])
    setPhase('compose'); setError(null); setPreview(null)
  }, [open])

  if (!open) return null

  const togglePlatform = (p) => {
    setPlatforms(prev => prev.includes(p) ? prev.filter(x => x !== p) : [...prev, p])
  }

  const generate = async () => {
    if (!prompt.trim()) { setError('Describe what you want to detect'); return }
    setPhase('generating'); setError(null)
    try {
      const token = await getToken()
      const r = await fetch('/api/rules/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          prompt: prompt.trim(),
          technique_id: techniqueId || null,
          platforms: platforms.length ? platforms : null,
          primary_siem: primarySiem || null,
        }),
      })
      if (!r.ok) {
        throw new Error(await readErr(r))
      }
      const data = await r.json()
      setPreview(data)
      setPhase('preview')
    } catch (e) {
      setError(e.message || 'Generation failed')
      setPhase('compose')
    }
  }

  const save = async () => {
    if (!preview) return
    setPhase('saving'); setError(null)
    try {
      const token = await getToken()
      const r = await fetch('/api/rules', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ rule: preview.rule }),
      })
      if (!r.ok) {
        throw new Error(await readErr(r))
      }
      const saved = await r.json()
      onSaved && onSaved(saved)
      onClose()
    } catch (e) {
      setError(e.message || 'Save failed')
      setPhase('preview')
    }
  }

  const overlayStyle = {
    position: 'fixed', inset: 0, background: 'rgba(0,0,0,.6)', zIndex: 50,
    display: 'grid', placeItems: 'center', padding: 24,
  }
  const modalStyle = {
    width: '100%', maxWidth: 720, maxHeight: '90vh', overflow: 'auto',
    background: '#15161D', border: '1px solid #262833', borderRadius: 8,
    color: '#E6E7EE', padding: 20,
  }
  const labelStyle = { fontSize: 11, color: '#9598A8', textTransform: 'uppercase', letterSpacing: '.04em', marginBottom: 6 }
  const fieldStyle = {
    width: '100%', background: '#0B0B11', border: '1px solid #262833',
    color: '#E6E7EE', borderRadius: 6, padding: '8px 10px', fontSize: 13,
    fontFamily: 'inherit',
  }

  const r = preview?.rule

  return (
    <div style={overlayStyle} onClick={onClose} role="dialog" aria-modal="true">
      <div style={modalStyle} onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Sparkles size={16} color="#7C5CFF" />
            <span style={{ fontWeight: 600 }}>Generate Rule with AI</span>
          </div>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: '#9598A8', cursor: 'pointer' }}>
            <X size={16} />
          </button>
        </div>

        {phase === 'compose' && (
          <>
            <div style={labelStyle}>Describe the detection</div>
            <textarea
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              placeholder="e.g. Detect lateral movement via SMB admin shares using compromised credentials, focus on Windows event 5140 and 4624 type 3"
              rows={5}
              style={{ ...fieldStyle, marginBottom: 14 }}
              maxLength={2000}
            />

            <div style={labelStyle}>MITRE Technique (optional)</div>
            <input
              value={techniqueId}
              onChange={(e) => setTechniqueId(e.target.value.trim())}
              placeholder="T1078, T1021.002…"
              style={{ ...fieldStyle, marginBottom: 14 }}
            />

            <div style={labelStyle}>Platforms (optional)</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 18 }}>
              {PLATFORMS.map(p => (
                <button
                  key={p}
                  type="button"
                  className={`chip${platforms.includes(p) ? ' on' : ''}`}
                  onClick={() => togglePlatform(p)}
                  style={{ fontSize: 11 }}
                >
                  {p}
                </button>
              ))}
            </div>

            {error && <div style={{ color: '#F87171', fontSize: 12, marginBottom: 12 }}>{error}</div>}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button onClick={onClose} className="chip">Cancel</button>
              <button onClick={generate} className="chip on" style={{ background: '#7C5CFF', color: '#fff', borderColor: '#7C5CFF' }}>
                Generate
              </button>
            </div>
          </>
        )}

        {phase === 'generating' && (
          <div style={{ padding: '40px 0', textAlign: 'center', color: '#9598A8' }}>
            Generating rule with Claude Sonnet 4.6…
          </div>
        )}

        {phase === 'preview' && r && (
          <>
            <div style={{ background: '#0B0B11', border: '1px solid #262833', borderRadius: 6, padding: 14, marginBottom: 14 }}>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 4 }}>{r.name}</div>
              <div style={{ fontSize: 12, color: '#9598A8', marginBottom: 10 }}>{r.description}</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, fontSize: 11 }}>
                <span className="pill pill-tactic">{tacticLabel(r.tactic)}</span>
                <SevBadge s={r.severity} />
                <span className={`pill pill-fid-${r.fidelity}`}>{r.fidelity}</span>
                <span className="pill" style={{ background: 'rgba(124,92,255,.15)', color: '#A78BFA' }}>{r.technique_id}</span>
              </div>
            </div>

            <details style={{ marginBottom: 12 }}>
              <summary style={{ cursor: 'pointer', fontSize: 12, color: '#9598A8' }}>Pseudo logic</summary>
              <pre style={{ background: '#0B0B11', border: '1px solid #262833', borderRadius: 6, padding: 10, fontSize: 11, whiteSpace: 'pre-wrap', marginTop: 6 }}>{r.pseudo_logic}</pre>
            </details>

            <details style={{ marginBottom: 14 }}>
              <summary style={{ cursor: 'pointer', fontSize: 12, color: '#9598A8' }}>SIEM queries ({Object.keys(r.queries || {}).length})</summary>
              {Object.entries(r.queries || {}).map(([k, v]) => (
                <div key={k} style={{ marginTop: 8 }}>
                  <div style={{ fontSize: 10, color: '#7C5CFF', textTransform: 'uppercase', marginBottom: 2 }}>{SIEM_LABELS[k] || k}</div>
                  <pre style={{ background: '#0B0B11', border: '1px solid #262833', borderRadius: 6, padding: 10, fontSize: 11, whiteSpace: 'pre-wrap', overflow: 'auto' }}>{v}</pre>
                </div>
              ))}
            </details>

            {error && <div style={{ color: '#F87171', fontSize: 12, marginBottom: 12 }}>{error}</div>}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button onClick={() => setPhase('compose')} className="chip">Discard & retry</button>
              <button onClick={save} className="chip on" style={{ background: '#7C5CFF', color: '#fff', borderColor: '#7C5CFF' }}>
                Save to library
              </button>
            </div>
          </>
        )}

        {phase === 'saving' && (
          <div style={{ padding: '40px 0', textAlign: 'center', color: '#9598A8' }}>Saving…</div>
        )}
      </div>
    </div>
  )
}

// ─── IMPORT RULES MODAL (Phase 5) ───────────────────────────────────────────

const SOURCE_TYPES = [
  { id: 'sigma',       label: 'Sigma YAML' },
  { id: 'spl',         label: 'Splunk SPL' },
  { id: 'kql',         label: 'Microsoft KQL' },
  { id: 'aql',         label: 'IBM QRadar AQL' },
  { id: 'yara_l',      label: 'Chronicle YARA-L' },
  { id: 'esql',        label: 'Elastic ES|QL' },
  { id: 'leql',        label: 'Rapid7 LEQL' },
  { id: 'crowdstrike', label: 'CrowdStrike' },
  { id: 'xql',         label: 'Palo XSIAM XQL' },
  { id: 'lucene',      label: 'Lucene' },
  { id: 'sumo',        label: 'Sumo Logic' },
]

function ImportRulesModal({ open, onClose, onApplied }) {
  const { getToken } = useAuth()
  const [sourceType, setSourceType] = useState('sigma')
  const [content, setContent] = useState('')
  const [phase, setPhase] = useState('compose') // compose | running | review | applying
  const [error, setError] = useState(null)
  const [job, setJob] = useState(null) // { id, status, total_rules, completed_rules, staged_rules, ... }
  const [selected, setSelected] = useState(new Set()) // indexes the user wants to apply

  useEffect(() => {
    if (!open) return
    setContent(''); setSourceType('sigma')
    setPhase('compose'); setError(null); setJob(null); setSelected(new Set())
  }, [open])

  // Poll the job while it's running
  useEffect(() => {
    if (!job?.id || phase !== 'running') return
    let cancelled = false
    const tick = async () => {
      try {
        const token = await getToken()
        const r = await fetch(`/api/import-jobs/${job.id}`, {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        })
        if (!r.ok) throw new Error(await readErr(r))
        const data = await r.json()
        if (cancelled) return
        setJob(data)
        if (data.status === 'awaiting_review') {
          setSelected(new Set(data.staged_rules.map((_, i) => i)))
          setPhase('review')
        } else if (data.status === 'failed') {
          setError(data.error || 'Import failed')
          setPhase('compose')
        }
      } catch (e) {
        if (!cancelled) {
          setError(e.message || 'Polling failed')
          setPhase('compose')
        }
      }
    }
    const id = setInterval(tick, 3000)
    tick()
    return () => { cancelled = true; clearInterval(id) }
  }, [job?.id, phase, getToken])

  if (!open) return null

  const submit = async () => {
    if (!content.trim()) { setError('Paste content to import'); return }
    setError(null); setPhase('running')
    try {
      const token = await getToken()
      const r = await fetch('/api/rules/import', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ source_type: sourceType, content }),
      })
      if (!r.ok) throw new Error(await readErr(r))
      setJob(await r.json())
    } catch (e) {
      setError(e.message || 'Import failed to start')
      setPhase('compose')
    }
  }

  const toggleIndex = (i) => {
    setSelected(prev => {
      const next = new Set(prev)
      next.has(i) ? next.delete(i) : next.add(i)
      return next
    })
  }

  const apply = async () => {
    if (!job || selected.size === 0) return
    setPhase('applying'); setError(null)
    try {
      const token = await getToken()
      const r = await fetch(`/api/import-jobs/${job.id}/apply`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ selected_indexes: Array.from(selected).sort((a,b) => a-b) }),
      })
      if (!r.ok) throw new Error(await readErr(r))
      const finished = await r.json()
      // Pull the saved rule rows so the parent list updates
      const ids = finished.created_rule_ids || []
      const fetched = await Promise.all(ids.map(async (rid) => {
        const tok = await getToken()
        const rr = await fetch(`/api/rules/${rid}?full=1`, {
          headers: tok ? { Authorization: `Bearer ${tok}` } : {},
        })
        return rr.ok ? rr.json() : null
      }))
      onApplied && onApplied(fetched.filter(Boolean))
      onClose()
    } catch (e) {
      setError(e.message || 'Apply failed')
      setPhase('review')
    }
  }

  const overlayStyle = {
    position: 'fixed', inset: 0, background: 'rgba(0,0,0,.6)', zIndex: 50,
    display: 'grid', placeItems: 'center', padding: 24,
  }
  const modalStyle = {
    width: '100%', maxWidth: 760, maxHeight: '90vh', overflow: 'auto',
    background: '#15161D', border: '1px solid #262833', borderRadius: 8,
    color: '#E6E7EE', padding: 20,
  }
  const labelStyle = { fontSize: 11, color: '#9598A8', textTransform: 'uppercase', letterSpacing: '.04em', marginBottom: 6 }
  const fieldStyle = {
    width: '100%', background: '#0B0B11', border: '1px solid #262833',
    color: '#E6E7EE', borderRadius: 6, padding: '8px 10px', fontSize: 13,
    fontFamily: 'inherit',
  }

  return (
    <div style={overlayStyle} onClick={onClose} role="dialog" aria-modal="true">
      <div style={modalStyle} onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Download size={16} color="#7C5CFF" style={{ transform: 'rotate(180deg)' }} />
            <span style={{ fontWeight: 600 }}>Import Rules</span>
          </div>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: '#9598A8', cursor: 'pointer' }}>
            <X size={16} />
          </button>
        </div>

        {phase === 'compose' && (
          <>
            <div style={labelStyle}>Source format</div>
            <select
              value={sourceType}
              onChange={(e) => setSourceType(e.target.value)}
              style={{ ...fieldStyle, marginBottom: 14 }}
            >
              {SOURCE_TYPES.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}
            </select>

            <div style={labelStyle}>
              {sourceType === 'sigma'
                ? 'Paste Sigma YAML (one or more rules, separated by ---)'
                : 'Paste detection queries (separate multiple with --- on its own line)'}
            </div>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              rows={14}
              style={{ ...fieldStyle, marginBottom: 14, fontFamily: 'ui-monospace, monospace', fontSize: 12 }}
              placeholder={
                sourceType === 'sigma'
                  ? 'title: Suspicious Process\ndescription: ...\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith: \\\\powershell.exe\n  condition: selection\nlevel: medium'
                  : 'index=windows EventCode=4625 | stats count by user, src_ip | where count > 5'
              }
            />

            {error && <div style={{ color: '#F87171', fontSize: 12, marginBottom: 12 }}>{error}</div>}

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 11, color: '#9598A8' }}>≤50 rules per import</span>
              <div style={{ display: 'flex', gap: 8 }}>
                <button onClick={onClose} className="chip">Cancel</button>
                <button onClick={submit} className="chip on" style={{ background: '#7C5CFF', color: '#fff', borderColor: '#7C5CFF' }}>
                  Import
                </button>
              </div>
            </div>
          </>
        )}

        {phase === 'running' && (
          <div style={{ padding: '40px 0', textAlign: 'center', color: '#9598A8' }}>
            <div style={{ marginBottom: 8 }}>Translating with Claude Sonnet 4.6…</div>
            {job && (
              <div style={{ fontSize: 12 }}>
                {job.completed_rules} / {job.total_rules} rules done
              </div>
            )}
          </div>
        )}

        {phase === 'review' && job && (
          <>
            <div style={{ fontSize: 12, color: '#9598A8', marginBottom: 12 }}>
              Translated {(job.staged_rules || []).length} of {job.total_rules} rules.
              Pick which to save to the library.
              {job.error && <div style={{ color: '#F87171', marginTop: 4 }}>{job.error}</div>}
            </div>

            <div style={{ maxHeight: 360, overflow: 'auto', border: '1px solid #262833', borderRadius: 6, marginBottom: 14 }}>
              {(job.staged_rules || []).map((rule, i) => (
                <label
                  key={i}
                  style={{
                    display: 'flex', alignItems: 'flex-start', gap: 10, padding: 12,
                    borderBottom: '1px solid #262833', cursor: 'pointer',
                  }}
                >
                  <input
                    type="checkbox"
                    checked={selected.has(i)}
                    onChange={() => toggleIndex(i)}
                    style={{ accentColor: '#7C5CFF', marginTop: 2 }}
                  />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 2 }}>{rule.name}</div>
                    <div style={{ fontSize: 11, color: '#9598A8', marginBottom: 6 }}>{rule.description}</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, fontSize: 10 }}>
                      <span className="pill pill-tactic">{tacticLabel(rule.tactic)}</span>
                      <SevBadge s={rule.severity} />
                      <span className={`pill pill-fid-${rule.fidelity}`}>{rule.fidelity}</span>
                      <span className="pill" style={{ background: 'rgba(124,92,255,.15)', color: '#A78BFA' }}>{rule.technique_id}</span>
                    </div>
                  </div>
                </label>
              ))}
            </div>

            {error && <div style={{ color: '#F87171', fontSize: 12, marginBottom: 12 }}>{error}</div>}

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 11, color: '#9598A8' }}>{selected.size} selected</span>
              <div style={{ display: 'flex', gap: 8 }}>
                <button onClick={() => setPhase('compose')} className="chip">Discard</button>
                <button
                  onClick={apply}
                  disabled={selected.size === 0}
                  className="chip on"
                  style={{
                    background: selected.size === 0 ? '#3a3a4a' : '#7C5CFF',
                    color: '#fff',
                    borderColor: selected.size === 0 ? '#3a3a4a' : '#7C5CFF',
                  }}
                >
                  Save {selected.size > 0 ? `${selected.size} ` : ''}to library
                </button>
              </div>
            </div>
          </>
        )}

        {phase === 'applying' && (
          <div style={{ padding: '40px 0', textAlign: 'center', color: '#9598A8' }}>Saving…</div>
        )}
      </div>
    </div>
  )
}

function RulesView({ rules, pendingFilter, clearPendingFilter, isMobile, onRuleUpdated, onRuleAdded, onRuleDeleted, primarySiem }) {
  const [selected, setSelected]   = useState(null)
  const [search, setSearch]       = useState('')
  const [fTactic, setFTactic]     = useState('All')
  const [fSev, setFSev]           = useState('All')
  const [fFid, setFid]            = useState('All')
  const [fKc, setFKc]             = useState('All')
  const [aiOpen, setAiOpen]       = useState(false)
  const [importOpen, setImportOpen] = useState(false)

  // Apply a cross-view handoff (e.g., dashboard tile click) once, then clear it.
  useEffect(() => {
    if (!pendingFilter) return
    if (pendingFilter.tactic) setFTactic(pendingFilter.tactic)
    if (pendingFilter.severity) setFSev(pendingFilter.severity)
    if (pendingFilter.killChain) setFKc(pendingFilter.killChain)
    if (pendingFilter.ruleId) {
      const r = rules.find(x => x.rule_id === pendingFilter.ruleId)
      if (r) setSelected(r)
    }
    clearPendingFilter && clearPendingFilter()
  }, [pendingFilter, rules, clearPendingFilter])

  const filtered = useMemo(() => rules.filter(r => {
    const q = search.toLowerCase()
    const mq = !q || r.name.toLowerCase().includes(q) || r.rule_id.toLowerCase().includes(q) ||
               (r.technique_id||'').toLowerCase().includes(q) || (r.tags||[]).some(t=>t.includes(q))
    return mq &&
      (fTactic==='All'||r.tactic===fTactic) &&
      (fSev==='All'||r.severity===fSev) &&
      (fFid==='All'||r.fidelity===fFid) &&
      (fKc==='All'||TACTIC_TO_KC[r.tactic]===fKc)
  }), [rules, search, fTactic, fSev, fFid, fKc])

  const clearAll = () => { setSearch(''); setFTactic('All'); setFSev('All'); setFid('All'); setFKc('All') }
  const dirty = search||fTactic!=='All'||fSev!=='All'||fFid!=='All'||fKc!=='All'

  const handleUpdated = (updated) => {
    onRuleUpdated && onRuleUpdated(updated)
    setSelected(updated)
  }
  const handleDuplicated = (added) => {
    onRuleAdded && onRuleAdded(added)
    setSelected(added)
  }
  const handleDeleted = (rule_id) => {
    onRuleDeleted && onRuleDeleted(rule_id)
    setSelected(null)
  }

  return (
    <>
      <div className="topbar">
        <span className="topbar-title">Detection Rules</span>
        <span className="topbar-sub">{rules.length} Rules · 9 SIEM Platforms</span>
        <div className="search-wrap">
          <Search size={13} className="search-icon" />
          <input className="search-input" placeholder="Search rules, IDs, techniques, tags…"
            value={search} onChange={e=>setSearch(e.target.value)} />
        </div>
        <button
          type="button"
          className="topbar-link"
          onClick={() => setAiOpen(true)}
          title="Generate a new rule with AI"
          style={{ marginLeft: 8 }}
        >
          <Sparkles size={12} style={{ marginRight: 6, verticalAlign: '-2px', color: '#7C5CFF' }} />
          Generate with AI
        </button>
        <button
          type="button"
          className="topbar-link"
          onClick={() => setImportOpen(true)}
          title="Import Sigma or SIEM-dialect detection rules"
          style={{ marginLeft: 6 }}
        >
          <Download size={12} style={{ marginRight: 6, verticalAlign: '-2px', color: '#7C5CFF', transform: 'rotate(180deg)' }} />
          Import
        </button>
      </div>
      <div className="filterbar">
        <div className="filter-row">
          <span className="chip-label">Tactic</span>
          <button className={`chip${fTactic==='All'?' on':''}`} onClick={()=>setFTactic('All')} style={{ fontSize:10 }}>All</button>
          {TACTIC_ORDER.slice(0, 8).map(t=>(
            <button key={t} className={`chip${fTactic===t?' on':''}`} onClick={()=>setFTactic(t)} style={{ fontSize:10 }}>{tacticLabel(t)}</button>
          ))}
        </div>
        <div className="filter-row">
          {/* Invisible spacers align "Command and Control" vertically under "Initial Access". */}
          <span className="chip-label" aria-hidden="true" style={{ visibility: 'hidden' }}>Tactic</span>
          <button aria-hidden="true" tabIndex={-1} className="chip" style={{ fontSize:10, visibility: 'hidden' }}>All</button>
          {TACTIC_ORDER.slice(8).map(t=>(
            <button key={t} className={`chip${fTactic===t?' on':''}`} onClick={()=>setFTactic(t)} style={{ fontSize:10 }}>{tacticLabel(t)}</button>
          ))}
        </div>
        <div className="filter-row">
          <span className="chip-label">Kill Chain</span>
          <button className={`chip${fKc==='All'?' on':''}`} onClick={()=>setFKc('All')}>All</button>
          {KC_FILTER_STAGES.map(s=>(
            <button key={s} className={`chip${fKc===s?' on':''}`} onClick={()=>setFKc(s)} style={{ fontSize:10 }}>{s}</button>
          ))}
        </div>
        <div className="filter-row">
          <span className="chip-label">Severity</span>
          {['All','Critical','High','Medium','Low'].map(s=>(
            <button key={s} className={`chip${fSev===s?' on':''}`} onClick={()=>setFSev(s)}>{s}</button>
          ))}
          <span className="filter-sep" aria-hidden="true" />
          <span className="chip-label">Fidelity</span>
          {['All','High','Medium','Low'].map(f=>(
            <button key={f} className={`chip${fFid===f?' on':''}`} onClick={()=>setFid(f)}>{f}</button>
          ))}
          {dirty && <button className="chip clear" style={{marginLeft:'auto'}} onClick={clearAll}><X size={10} style={{marginRight:3}} />Clear</button>}
        </div>
      </div>
      <div className="content">
        <div className="rule-list">
          <div className="list-count">{filtered.length} rules</div>
          {filtered.map(r => (
            <div key={r.rule_id} className={`rule-row${selected?.rule_id===r.rule_id?' active':''}`}
              onClick={()=>setSelected(r)}>
              <div className="rule-rid">{r.rule_id} · {r.technique_id}</div>
              <div className="rule-name">{r.name}</div>
              <div className="rule-meta">
                <span className="pill pill-tactic" style={{fontSize:9}}>{tacticLabel(r.tactic)}</span>
                <SevBadge s={r.severity} />
                <span className={`pill pill-fid-${r.fidelity}`}>{r.fidelity}</span>
              </div>
            </div>
          ))}
        </div>
        {!isMobile && (selected
          ? <RuleDetail rule={selected} onUpdated={handleUpdated} onDuplicated={handleDuplicated} onDeleted={handleDeleted} />
          : <div className="detail empty-state">
              <div className="empty-inner">
                <Shield size={48} />
                <p style={{marginTop:12}}>Select a rule</p>
              </div>
            </div>
        )}
      </div>

      {isMobile && selected && (
        <div className="mobile-detail-overlay" role="dialog" aria-modal="true" aria-label="Rule detail">
          <div className="mobile-detail-header">
            <button type="button" className="mobile-detail-back" onClick={() => setSelected(null)} aria-label="Back to rule list">
              <ChevronRight size={16} style={{ transform: 'rotate(180deg)' }} />
              Back
            </button>
          </div>
          <div className="mobile-detail-body">
            <RuleDetail rule={selected} onUpdated={handleUpdated} onDuplicated={handleDuplicated} onDeleted={handleDeleted} />
          </div>
        </div>
      )}

      <GenerateRuleModal
        open={aiOpen}
        onClose={() => setAiOpen(false)}
        primarySiem={primarySiem}
        onSaved={(saved) => {
          onRuleAdded && onRuleAdded(saved)
          setSelected(saved)
        }}
      />

      <ImportRulesModal
        open={importOpen}
        onClose={() => setImportOpen(false)}
        onApplied={(savedRules) => {
          savedRules.forEach(r => onRuleAdded && onRuleAdded(r))
          if (savedRules.length) setSelected(savedRules[0])
        }}
      />
    </>
  )
}

// ─── COVERAGE EXPORT MENU ───────────────────────────────────────────────────

function CoverageExportMenu() {
  const { getToken } = useAuth()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(null)
  const [error, setError] = useState(null)
  const wrapRef = useRef(null)

  useEffect(() => {
    if (!open) return
    const onDoc = (e) => { if (wrapRef.current && !wrapRef.current.contains(e.target)) setOpen(false) }
    const onKey = (e) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onDoc)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDoc)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  const download = async (key, url, fallbackFilename) => {
    setBusy(key)
    setError(null)
    try {
      const token = await getToken()
      const r = await fetch(url, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const blob = await r.blob()
      const cd = r.headers.get('Content-Disposition') || ''
      const m = /filename="([^"]+)"/.exec(cd)
      const filename = m ? m[1] : fallbackFilename
      const objUrl = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = objUrl
      a.download = filename
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(objUrl)
      setOpen(false)
    } catch (e) {
      setError(e.message || 'Export failed')
    } finally {
      setBusy(null)
    }
  }

  const COVERAGE = [
    { key: 'cov-pdf',  label: 'PDF',  url: '/api/coverage/export?format=pdf',  fallback: 'tdl-coverage.pdf'  },
    { key: 'cov-csv',  label: 'CSV',  url: '/api/coverage/export?format=csv',  fallback: 'tdl-coverage.csv'  },
    { key: 'cov-json', label: 'JSON', url: '/api/coverage/export?format=json', fallback: 'tdl-coverage.json' },
  ]
  const LIBRARY = [
    { key: 'rules-yaml', label: 'YAML', url: '/api/rules/export?format=yaml', fallback: 'tdl-rules.zip' },
  ]

  const renderItem = (opt) => (
    <button
      key={opt.key}
      type="button"
      role="menuitem"
      className="export-item"
      disabled={busy !== null}
      onClick={() => download(opt.key, opt.url, opt.fallback)}
    >
      {busy === opt.key ? 'Downloading…' : opt.label}
    </button>
  )

  return (
    <div ref={wrapRef} className="export-menu">
      <button
        type="button"
        className="topbar-link export-btn"
        onClick={() => setOpen(o => !o)}
        aria-haspopup="menu"
        aria-expanded={open}
        title="Export"
      >
        <Download size={12} style={{ marginRight: 6, verticalAlign: '-2px' }} />
        Export
        <ChevronDown size={12} style={{ marginLeft: 6, verticalAlign: '-2px' }} />
      </button>
      {open && (
        <div className="export-pop" role="menu">
          <div className="export-section-label">Coverage report</div>
          {COVERAGE.map(renderItem)}
          <div className="export-divider" />
          <div className="export-section-label">Rule library · DaaC</div>
          {LIBRARY.map(renderItem)}
          {error && <div className="export-err">{error}</div>}
        </div>
      )}
    </div>
  )
}

// ─── DASHBOARD VIEW ─────────────────────────────────────────────────────────

function DashboardView({ rules, onNavigate }) {
  const byTactic   = useMemo(() => TACTIC_ORDER.reduce((a,t) => ({...a,[t]:rules.filter(r=>r.tactic===t).length}), {}), [rules])
  const bySev      = useMemo(() => ['Critical','High','Medium','Low'].reduce((a,s) => ({...a,[s]:rules.filter(r=>r.severity===s).length}), {}), [rules])
  const techniques = useMemo(() => new Set(rules.map(r => (r.technique_id||'').split('.')[0]).filter(Boolean)), [rules])
  const critical   = rules.filter(r=>r.severity==='Critical').length
  const highFid    = rules.filter(r=>r.fidelity==='High').length
  const maxTactic  = Math.max(...Object.values(byTactic))

  return (
    <div className="view">
      <div className="dash-metrics">
        {[
          { icon:<Shield size={16} />, num:rules.length, lbl:'Total Rules',       color:'#F2F2F7', bg:'rgba(255,255,255,.06)' },
          { icon:<Crosshair size={16} />, num:techniques.size, lbl:'ATT&CK Techniques', color:'#A855F7', bg:'rgba(168,85,247,.18)' },
          { icon:<AlertTriangle size={16} />, num:critical, lbl:'Critical Severity', color:'#EF4444', bg:'rgba(239,68,68,.18)' },
          { icon:<TrendingUp size={16} />, num:highFid,     lbl:'High Fidelity',   color:'#3B82F6', bg:'rgba(59,130,246,.18)' },
        ].map((m,i) => (
          <div key={i} className="metric-card">
            <div className="metric-icon" style={{background:m.bg}}>{React.cloneElement(m.icon, {color:m.color})}</div>
            <div className="metric-num" style={{color:m.color}}>{m.num}</div>
            <div className="metric-lbl">{m.lbl}</div>
          </div>
        ))}
      </div>

      <div className="two-col">
        <div>
          <div className="section-header"><Crosshair size={13} />MITRE ATT&CK Tactics</div>
          <div className="tactic-grid" style={{gridTemplateColumns:'repeat(3,1fr)'}}>
            {TACTIC_ORDER.map(t => {
              const c = byTactic[t]||0, color = TACTIC_COLOR[t]
              return (
                <div key={t} className="tactic-card tactic-card-clickable" onClick={() => onNavigate && onNavigate({ tactic: t })} role="button" tabIndex={0}
                     title={`Show ${c} ${t} rule${c===1?'':'s'}`}>
                  <div className="tactic-dot" style={{background:color}} />
                  <div className="tactic-name" style={{color}}>{tacticLabel(t)}</div>
                  <div className="tactic-bar"><div className="tactic-fill" style={{width:`${maxTactic?c/maxTactic*100:0}%`,background:color}} /></div>
                  <div className="tactic-stat">{c} rules</div>
                </div>
              )
            })}
          </div>
        </div>

        <div>
          <div className="section-header"><BarChart3 size={13} />Severity Distribution</div>
          <div className="panel-card panel-card-fill">
            <div className="sev-bars sev-bars-tall">
              {['Critical','High','Medium','Low'].map(s => {
                const c = bySev[s]||0
                const pct = rules.length ? Math.max(c/rules.length*100,2) : 2
                return (
                  <div key={s} className="sev-row sev-row-clickable" onClick={() => onNavigate && onNavigate({ severity: s })} role="button" tabIndex={0}
                       title={`Show ${c} ${s} rule${c===1?'':'s'}`}>
                    <div className="sev-lbl" style={{color:SEV_COLOR[s]}}>{s}</div>
                    <div className="sev-bar-bg"><div className="sev-bar-fill" style={{width:`${pct}%`,background:SEV_COLOR[s]}}>{c}</div></div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── ATT&CK MATRIX VIEW ──────────────────────────────────────────────────────
// Column-per-tactic grid mirroring https://attack.mitre.org/matrices/enterprise.

function MatrixView({ rules, onSelectRule, isMobile }) {
  // Map technique_id (top-level) → number of rules covering it.
  const ruleCount = useMemo(() => {
    const m = new Map()
    rules.forEach(r => {
      const tid = (r.technique_id || '').split('.')[0]
      if (tid) m.set(tid, (m.get(tid) || 0) + 1)
    })
    return m
  }, [rules])

  // Expansion: which (tactic|techniqueId) cell currently shows its rule list.
  const [expandedKey, setExpandedKey] = useState(null)
  // Mobile: which tactic the picker has selected. Desktop ignores this.
  const [pickedTactic, setPickedTactic] = useState(TACTIC_ORDER_MATRIX[0])
  // For an expanded cell, list rules whose tactic+technique match. Falls back
  // to "any tactic" if there are no rules with that exact tactic+technique
  // pair (handles cells where the technique exists in the library but under a
  // sibling tactic — still useful to show those).
  const rulesForCell = (tactic, techId) => {
    const exact = rules.filter(r => r.tactic === tactic && (r.technique_id || '').split('.')[0] === techId)
    if (exact.length) return exact
    return rules.filter(r => (r.technique_id || '').split('.')[0] === techId)
  }

  // Coverage shading buckets — purple density on dark.
  const shade = (count) => {
    if (!count) return { background:'var(--bg1)', border:'var(--border)', color:'var(--text3)', name:'var(--text3)' }
    if (count >= 10) return { background:'rgba(168,85,247,.32)', border:'rgba(168,85,247,.65)', color:'#E9D5FF', name:'var(--text)' }
    if (count >= 5)  return { background:'rgba(168,85,247,.22)', border:'rgba(168,85,247,.50)', color:'#D8B4FE', name:'var(--text)' }
    if (count >= 2)  return { background:'rgba(168,85,247,.13)', border:'rgba(168,85,247,.36)', color:'#C084FC', name:'var(--text)' }
    return { background:'rgba(168,85,247,.06)', border:'rgba(168,85,247,.22)', color:'#A855F7', name:'var(--text2)' }
  }

  const totalTactics = TACTIC_ORDER_MATRIX.length
  // Unique top-level techniques in canonical Enterprise (some techniques span
  // multiple tactic columns — count each technique once to match the sidebar).
  const canonicalTechs = useMemo(() => {
    const s = new Set()
    TACTIC_ORDER_MATRIX.forEach(t => (ATTACK_MATRIX[t]?.techniques || []).forEach(x => s.add(x.id)))
    return s
  }, [])
  const totalTechs = canonicalTechs.size
  const coveredTechs = useMemo(() => {
    let n = 0
    canonicalTechs.forEach(tid => { if (ruleCount.has(tid)) n++ })
    return n
  }, [canonicalTechs, ruleCount])

  const totalRules = rules.length
  const pctCovered = totalTechs ? Math.round(coveredTechs / totalTechs * 100) : 0

  const renderCell = (tactic, t) => {
    const c = ruleCount.get(t.id) || 0
    const s = shade(c)
    const key = `${tactic}|${t.id}`
    const expanded = expandedKey === key
    const cellRules = expanded ? rulesForCell(tactic, t.id) : []
    return (
      <div key={t.id} className={`attack-cell-wrap${expanded?' open':''}`}>
        <div className="attack-cell" style={{background:s.background, borderColor:s.border}}
             title={`${t.id} ${t.name}${c ? ` · ${c} rule${c>1?'s':''}` : ' · not covered'}`}>
          <a className="attack-cell-link" href={`https://attack.mitre.org/techniques/${t.id}/`} target="_blank" rel="noreferrer">
            <span className="attack-cell-id" style={{color:s.color}}>{t.id}</span>
            <span className="attack-cell-name" style={{color:s.name}}>{t.name}</span>
          </a>
          {c > 0 && <span className="attack-cell-count">{c}</span>}
          {c > 0 && (
            <button type="button" className={`attack-cell-toggle${expanded?' open':''}`}
                    aria-label={expanded ? 'Hide rules' : 'Show rules'}
                    onClick={(e) => { e.stopPropagation(); setExpandedKey(expanded ? null : key) }}>
              <ChevronDown size={11} />
            </button>
          )}
        </div>
        {expanded && (
          <div className="attack-cell-rules">
            <div className="attack-cell-rules-head">{cellRules.length} rule{cellRules.length===1?'':'s'} · {t.id}</div>
            {cellRules.map(r => (
              <div key={r.rule_id} className="attack-cell-rule" onClick={() => onSelectRule && onSelectRule(r.rule_id)}>
                <div className="attack-cell-rule-rid">{r.rule_id}</div>
                <div className="attack-cell-rule-name">{r.name}</div>
                <SevBadge s={r.severity} />
              </div>
            ))}
          </div>
        )}
      </div>
    )
  }

  return (
    <>
      <div className="matrix-stats">
        <div className="matrix-stat">
          <div className="matrix-stat-num" style={{color:'#A855F7'}}>{coveredTechs}</div>
          <div className="matrix-stat-lbl">Techniques covered <span className="matrix-stat-sub">/ {totalTechs} in ATT&CK Enterprise</span></div>
        </div>
        <div className="matrix-stat">
          <div className="matrix-stat-num">{pctCovered}<span className="matrix-stat-pct">%</span></div>
          <div className="matrix-stat-lbl">Of the matrix covered by TDL</div>
        </div>
        <div className="matrix-stat">
          <div className="matrix-stat-num" style={{color:'#3B82F6'}}>{totalTactics}</div>
          <div className="matrix-stat-lbl">Tactics with coverage <span className="matrix-stat-sub">/ {totalTactics} total</span></div>
        </div>
        <div className="matrix-stat">
          <div className="matrix-stat-num">{totalRules}</div>
          <div className="matrix-stat-lbl">Detection rules backing this</div>
        </div>
      </div>
      <div className="matrix-legend">
        <span className="matrix-legend-label">Coverage:</span>
        <span className="matrix-legend-item"><span className="matrix-legend-swatch" style={{background:'var(--bg1)',borderColor:'var(--border)'}}/>0</span>
        <span className="matrix-legend-item"><span className="matrix-legend-swatch" style={{background:'rgba(168,85,247,.06)',borderColor:'rgba(168,85,247,.22)'}}/>1</span>
        <span className="matrix-legend-item"><span className="matrix-legend-swatch" style={{background:'rgba(168,85,247,.13)',borderColor:'rgba(168,85,247,.36)'}}/>2-4</span>
        <span className="matrix-legend-item"><span className="matrix-legend-swatch" style={{background:'rgba(168,85,247,.22)',borderColor:'rgba(168,85,247,.50)'}}/>5-9</span>
        <span className="matrix-legend-item"><span className="matrix-legend-swatch" style={{background:'rgba(168,85,247,.32)',borderColor:'rgba(168,85,247,.65)'}}/>10+</span>
        <span className="matrix-legend-item" style={{color:'var(--text3)'}}>rules per technique</span>
      </div>
      {isMobile && (
        <div className="matrix-tactic-picker" role="tablist" aria-label="ATT&CK tactic">
          {TACTIC_ORDER_MATRIX.map(tactic => {
            const col = ATTACK_MATRIX[tactic]
            if (!col) return null
            const covered = col.techniques.filter(t => ruleCount.has(t.id)).length
            const color = TACTIC_COLOR[tactic]
            const on = pickedTactic === tactic
            return (
              <button
                key={tactic}
                type="button"
                role="tab"
                aria-selected={on}
                className="matrix-tactic-pill"
                style={{
                  borderColor: color,
                  color: on ? '#fff' : color,
                  background: on ? color : 'transparent',
                }}
                onClick={() => { setPickedTactic(tactic); setExpandedKey(null) }}
              >
                {tacticLabel(tactic)}<span className="mt-pill-count">{covered}/{col.techniques.length}</span>
              </button>
            )
          })}
        </div>
      )}
      <div className="matrix-scroll">
        {isMobile ? (() => {
          const tactic = pickedTactic
          const col = ATTACK_MATRIX[tactic]
          if (!col) return null
          const techs = col.techniques
          const covered = techs.filter(t => ruleCount.has(t.id)).length
          const color = TACTIC_COLOR[tactic]
          return (
            <div className="attack-col">
              <div className="attack-col-head" style={{borderTopColor:color}}>
                <div className="attack-col-tactic" style={{color}}>{tactic}</div>
                <div className="attack-col-meta">{col.id} · {covered}/{techs.length}</div>
              </div>
              <div className="attack-col-body">
                {techs.map(t => renderCell(tactic, t))}
              </div>
            </div>
          )
        })() : (
          <div className="attack-grid">
            {TACTIC_ORDER_MATRIX.map(tactic => {
              const col = ATTACK_MATRIX[tactic]
              if (!col) return null
              const techs = col.techniques
              const covered = techs.filter(t => ruleCount.has(t.id)).length
              const color = TACTIC_COLOR[tactic]
              return (
                <div key={tactic} className="attack-col">
                  <div className="attack-col-head" style={{borderTopColor:color}}>
                    <div className="attack-col-tactic" style={{color}}>{tacticLabel(tactic)}</div>
                    <div className="attack-col-meta">{col.id} · {covered}/{techs.length}</div>
                  </div>
                  <div className="attack-col-body">
                    {techs.map(t => renderCell(tactic, t))}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </>
  )
}

// ─── CHAINS VIEW ─────────────────────────────────────────────────────────────

function ChainsView({ rules, onNavigate }) {
  // Per-tactic rule counts for Kill Chain stage coverage
  const byTactic = useMemo(() => {
    const m = new Map()
    rules.forEach(r => { if(r.tactic) m.set(r.tactic, (m.get(r.tactic)||0) + 1) })
    return m
  }, [rules])

  const stageCoverage = (stage) => {
    if (stage.attack_tactics.length === 0) return { count: 0, status: 'pre' }
    const count = stage.attack_tactics.reduce((a, t) => a + (byTactic.get(t) || 0), 0)
    return { count, status: count > 0 ? 'covered' : 'gap' }
  }

  return (
    <div className="view">
      <div className="section-header" style={{marginBottom:6}}>
        <Crosshair size={13} />Lockheed Martin Cyber Kill Chain®
      </div>
      <div style={{fontSize:11,color:'var(--text2)',marginBottom:14,lineHeight:1.55,whiteSpace:'nowrap'}}>
        The 7-stage adversary lifecycle from Lockheed Martin. Each stage shows the ATT&CK tactic(s) that map to it and the number of TDL rules covering that adversary behavior. <a href="https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html" target="_blank" rel="noreferrer" style={{color:'var(--accent2)'}}>Reference ↗</a>
      </div>

      <div className="killchain">
        <div className="kc-pre-cluster">
          <div className="kc-pre-row">
            {KILL_CHAIN.slice(0, 2).map((stage, i) => (
              <React.Fragment key={stage.id}>
                <div className="kc-stage kc-pre">
                  <div className="kc-stage-num">{stage.stage}</div>
                  <div className="kc-stage-name">{stage.name}</div>
                  <div className="kc-stage-desc">{stage.description}</div>
                </div>
                {i === 0 && <ArrowRight size={16} className="kc-arrow" />}
              </React.Fragment>
            ))}
          </div>
          <div className="kc-pre-callout">
            <div className="kc-pre-callout-tag">Pre-compromise · external to your network</div>
            <div className="kc-pre-callout-body">Adversary acts on their own infrastructure. Detection requires threat intel feeds, not endpoint logs — outside the scope of this rule library.</div>
          </div>
        </div>
        <ArrowRight size={16} className="kc-arrow" />
        {KILL_CHAIN.slice(2).map((stage, idx) => {
          const i = idx + 2
          const { count, status } = stageCoverage(stage)
          const isGap = status === 'gap'
          const clickable = count > 0
          const goToFiltered = () => onNavigate && onNavigate({ killChain: stage.name })
          return (
            <div key={stage.id} className="kc-wrap">
              <div
                className={`kc-stage ${isGap?'kc-gap':'kc-cov'}${clickable?' kc-stage-clickable':''}`}
                role={clickable ? 'button' : undefined}
                tabIndex={clickable ? 0 : undefined}
                onClick={clickable ? goToFiltered : undefined}
                onKeyDown={clickable ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); goToFiltered() } } : undefined}
                title={clickable ? `Show ${count} rule${count===1?'':'s'} in ${stage.name}` : undefined}
              >
                <div className="kc-stage-num">{stage.stage}</div>
                <div className="kc-stage-name">{stage.name}</div>
                <div className="kc-stage-desc">{stage.description}</div>
                <div className="kc-stage-meta">
                  <div className="kc-tactics">{stage.attack_tactics.map(t => (
                    <span key={t} className="kc-tactic-pill" style={{borderColor: TACTIC_COLOR[t]+'66', color:TACTIC_COLOR[t]}}>{t}</span>
                  ))}</div>
                  <div className="kc-count" style={{color: isGap?'var(--red)':'var(--purple)'}}>
                    {count} rule{count===1?'':'s'}
                  </div>
                </div>
              </div>
              {i < KILL_CHAIN.length - 1 && <ArrowRight size={16} className="kc-arrow" />}
            </div>
          )
        })}
      </div>

      <div style={{marginTop:32}}>
        <div className="section-header" style={{marginBottom:6}}>
          <GitBranch size={13} />TDL Internal Attack Chains
        </div>
        <div style={{fontSize:11,color:'var(--text2)',marginBottom:14}}>
          Multi-rule correlation chains specific to this rule library. Each chain
          fires when its required rules trigger within the time window.
        </div>
        <div className="chains-grid">
          {CHAINS.map(chain => {
            const sc = SEV_COLOR[chain.severity]
            const sb = SEV_BG[chain.severity]
            return (
              <div key={chain.id} className="chain-card">
                <div className="chain-head">
                  <div className="chain-active" style={{background: chain.active ? '#7C3AED' : '#DC2626'}} />
                  <div>
                    <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:3}}>
                      <span className="chain-id">{chain.id}</span>
                      <span className="pill pill-sev" style={{background:sb,color:sc,borderColor:sc+'44'}}>{chain.severity}</span>
                      <span style={{fontSize:10,fontFamily:'var(--mono)',color:'var(--text3)'}}>window: {chain.window}</span>
                    </div>
                    <div className="chain-name">{chain.name}</div>
                  </div>
                  <span className="chain-threat">{chain.threat}</span>
                </div>
                <div className="chain-steps">
                  {chain.steps.map((s,i) => (
                    <React.Fragment key={i}>
                      <span className="chain-step">{s}</span>
                      {i < chain.steps.length-1 && <ArrowRight size={12} className="chain-arrow" />}
                    </React.Fragment>
                  ))}
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

// ─── RECOMMEND VIEW ──────────────────────────────────────────────────────────

function RecommendView({ rules }) {
  const cCrit = { Critical:'#DC2626', High:'#7C3AED', Medium:'#2563EB', Low:'#6E6E7C' }
  const critOrder = { Critical:0, High:1, Medium:2, Low:3 }
  const byCriticality = [...LOG_SOURCES].sort((a,b) =>
    (critOrder[a.criticality] ?? 9) - (critOrder[b.criticality] ?? 9) || a.tier - b.tier || b.rules_unlocked - a.rules_unlocked
  )

  return (
    <div className="view">
      <div className="section-header"><Database size={13} />Log Source Criticality Assessment</div>
      <table className="log-source-table">
        <thead><tr>
          <th>Criticality</th><th>Tier</th><th>Log Source</th><th>Rules</th>
        </tr></thead>
        <tbody>
          {byCriticality.map(ls => (
            <tr key={ls.id}>
              <td style={{color:cCrit[ls.criticality]||'var(--text2)'}}>{ls.criticality}</td>
              <td style={{fontFamily:'var(--mono)',fontSize:11}}>T{ls.tier}</td>
              <td>
                <span
                  className="status-dot status-dot-mobile"
                  style={{background: ls.deployed ? '#7C3AED' : '#DC2626'}}
                  aria-label={ls.deployed ? 'Deployed' : 'Not deployed'}
                />
                {ls.name}
              </td>
              <td style={{fontFamily:'var(--mono)',fontSize:12,color:'#7C3AED',fontWeight:700}}>{ls.rules_unlocked}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ─── APP ─────────────────────────────────────────────────────────────────────

const buildViews = (ruleCount, techCount, chainCount) => [
  { id:'dashboard', label:'Dashboard',        icon:<BarChart3 size={14} /> },
  { id:'rules',     label:'Detection Rules',  icon:<Shield size={14} />,   badge:ruleCount },
  { id:'matrix',    label:'MITRE ATT&CK',     icon:<MapIcon size={14} />,   badge:techCount },
  { id:'chains',    label:'Kill Chain',       icon:<GitBranch size={14} />, badge:chainCount },
  { id:'recommend', label:'Log Sources',      icon:<TrendingUp size={14} /> },
  { id:'settings',  label:'Settings',         icon:<Sliders size={14} /> },
]

export default function App({ orgProfile = null, onProfileChange }) {
  const isMobile = useMediaQuery('(max-width: 768px)')
  const { getToken } = useAuth()
  const [view, setView] = useState('dashboard')
  const [rules, setRules] = useState(RULES_RAW)
  const [source, setSource] = useState('bundled')
  // Cross-view filter handoff: dashboard tile / matrix tile click → Rules view
  // pre-filtered. Shape: { tactic?, severity?, ruleId? }. Cleared after Rules
  // applies it so subsequent in-view filter changes aren't overwritten.
  const [pendingRulesFilter, setPendingRulesFilter] = useState(null)
  const navigateToRules = (filter) => {
    setPendingRulesFilter(filter || {})
    setView('rules')
  }

  const removeRule = useCallback((rule_id) => {
    setRules(prev => prev.filter(r => r.rule_id !== rule_id))
  }, [])

  const replaceRule = useCallback((updated) => {
    setRules(prev => prev.map(r => r.rule_id === updated.rule_id ? updated : r))
  }, [])
  const addRule = useCallback((added) => {
    setRules(prev => [...prev, added])
  }, [])

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const token = await getToken()
        const r = await fetch('/api/rules', {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        })
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        const data = await r.json()
        if (cancelled) return
        if (Array.isArray(data) && data.length) {
          setRules(data)
          setSource('api')
        }
      } catch {
        /* keep bundled fallback */
      }
    })()
    return () => { cancelled = true }
  }, [getToken])

  // Unique top-level techniques *in the canonical ATT&CK Enterprise matrix*
  // that have at least one rule. Matches the matrix view's coverage stat so
  // the sidebar badge and the matrix headline always agree.
  const techCount = useMemo(() => {
    const canonical = new Set()
    TACTIC_ORDER_MATRIX.forEach(t => (ATTACK_MATRIX[t]?.techniques || []).forEach(x => canonical.add(x.id)))
    const libTechs = new Set(rules.map(r => (r.technique_id||'').split('.')[0]).filter(Boolean))
    let n = 0
    canonical.forEach(tid => { if (libTechs.has(tid)) n++ })
    return n
  }, [rules])
  const chainCount = 5

  return (
    <>
      <style>{CSS}</style>
      <div className="shell">
        <aside className="sidebar">
          <div className="sidebar-logo">
            <div className="logo-mark">
              <div className="logo-icon"><Shield size={15} color="white" /></div>
              <div>
                <div className="logo-text">TDL PLAYBOOK</div>
              </div>
            </div>
          </div>
          <nav className="sidebar-nav">
            <div className="nav-label">Navigation</div>
            {buildViews(rules.length, techCount, chainCount).map(v => (
              <div key={v.id} className={`nav-item${view===v.id?' active':''}`} onClick={()=>setView(v.id)}>
                {v.icon}{v.label}
                {v.badge && <span className="nav-badge">{v.badge}</span>}
              </div>
            ))}
          </nav>
          <div style={{
            borderTop: '1px solid var(--border)',
            padding: '12px 18px',
            display: 'flex',
            alignItems: 'center',
            gap: 10,
          }}>
            <UserButton afterSignOutUrl="/" />
            {orgProfile?.org_name && (
              <div style={{ overflow: 'hidden' }}>
                <div style={{ fontSize: 12, color: 'var(--muted)' }}>Organization</div>
                <div style={{
                  fontSize: 13,
                  fontWeight: 600,
                  color: 'var(--text)',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}>{orgProfile.org_name}</div>
              </div>
            )}
          </div>
        </aside>

        <div className="main">
          {view === 'rules'     && <RulesView rules={rules} pendingFilter={pendingRulesFilter} clearPendingFilter={() => setPendingRulesFilter(null)} isMobile={isMobile} onRuleUpdated={replaceRule} onRuleAdded={addRule} onRuleDeleted={removeRule} primarySiem={orgProfile?.primary_siem} />}
          {view === 'dashboard' && (
            <>
              <div className="topbar">
                <span className="topbar-title">Dashboard</span>
                <div style={{ marginLeft: 'auto' }}>
                  <CoverageExportMenu />
                </div>
              </div>
              <DashboardView rules={rules} onNavigate={navigateToRules} />
            </>
          )}
          {view === 'matrix' && (
            <>
              <div className="topbar">
                <span className="topbar-title">MITRE ATT&CK</span>
                <a className="topbar-link" href="https://attack.mitre.org/matrices/enterprise/" target="_blank" rel="noreferrer">attack.mitre.org ↗</a>
              </div>
              <MatrixView rules={rules} onSelectRule={(rid) => navigateToRules({ ruleId: rid })} isMobile={isMobile} />
            </>
          )}
          {view === 'chains' && (
            <>
              <div className="topbar">
                <span className="topbar-title">Kill Chain &amp; Attack Chains</span>
              </div>
              <ChainsView rules={rules} onNavigate={navigateToRules} />
            </>
          )}
          {view === 'recommend' && (
            <>
              <div className="topbar">
                <span className="topbar-title">Recommendations</span>
              </div>
              <RecommendView rules={rules} />
            </>
          )}
          {view === 'settings' && (
            <>
              <div className="topbar">
                <span className="topbar-title">Settings</span>
              </div>
              <Settings profile={orgProfile} onSave={onProfileChange} />
            </>
          )}
        </div>

        <nav className="bottom-tabs" role="tablist" aria-label="Primary">
          {buildViews(rules.length, techCount, chainCount).map(v => (
            <button
              key={v.id}
              type="button"
              role="tab"
              aria-selected={view === v.id}
              className={`bottom-tab${view === v.id ? ' active' : ''}`}
              onClick={() => setView(v.id)}
            >
              <span className="bottom-tab-icon">{v.icon}</span>
              <span className="bottom-tab-label">{v.label === 'Detection Rules' ? 'Rules' : v.label === 'MITRE ATT&CK' ? 'Matrix' : v.label === 'Kill Chain' ? 'Kill Chain' : v.label === 'Log Sources' ? 'Log Sources' : v.label}</span>
            </button>
          ))}
        </nav>
      </div>
    </>
  )
}
