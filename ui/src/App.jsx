import { useState, useMemo, useCallback, useEffect } from 'react'
import {
  Shield, Search, ChevronRight, X, AlertTriangle, CheckCircle,
  Activity, Database, Target, Filter, Tag, Copy, Check,
  BarChart3, Layers, Crosshair, Clock, TrendingUp, ChevronDown,
  Terminal, Zap, GitBranch, Map, Award, Eye, Lock, Cpu,
  ArrowRight, Circle, Minus
} from 'lucide-react'
import RULES_RAW from './data/rules.json'

// ─── CONSTANTS ──────────────────────────────────────────────────────────────

const TACTIC_ORDER = [
  'Initial Access','Execution','Persistence','Privilege Escalation',
  'Defense Evasion','Credential Access','Discovery','Lateral Movement',
  'Command and Control','Collection','Exfiltration','Impact'
]

const TACTIC_COLOR = {
  'Initial Access':        '#FF6B35',
  'Execution':             '#F7C59F',
  'Persistence':           '#EFEFD0',
  'Privilege Escalation':  '#FF4757',
  'Defense Evasion':       '#A855F7',
  'Credential Access':     '#EC4899',
  'Discovery':             '#3B82F6',
  'Lateral Movement':      '#06B6D4',
  'Command and Control':   '#10B981',
  'Collection':            '#84CC16',
  'Exfiltration':          '#EAB308',
  'Impact':                '#EF4444',
}

const SEV_COLOR = { Critical:'#EF4444', High:'#F97316', Medium:'#EAB308', Low:'#22C55E' }
const SEV_BG    = { Critical:'rgba(239,68,68,.12)', High:'rgba(249,115,22,.12)', Medium:'rgba(234,179,8,.12)', Low:'rgba(34,197,94,.12)' }

const PLATFORMS = ['Windows','Linux','macOS','AWS','Azure','GCP','Okta','Microsoft 365','Network','Kubernetes','SaaS']

const SIEM_LABELS = {
  spl:'Splunk SPL', kql:'Microsoft KQL', aql:'IBM QRadar AQL',
  yara_l:'Chronicle YARA-L', esql:'Elastic ES|QL', leql:'Rapid7 LEQL',
  crowdstrike:'CrowdStrike', xql:'XSIAM XQL', lucene:'Lucene'
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
  --bg0:     #0a0a0b;
  --bg1:     #111113;
  --bg2:     #18181c;
  --bg3:     #222228;
  --border:  #2a2a32;
  --border2: #363640;
  --text:    #e8e8f0;
  --text2:   #8888a0;
  --text3:   #4a4a5a;
  --accent:  #FF6B35;
  --accent2: #3B82F6;
  --green:   #22C55E;
  --red:     #EF4444;
  --yellow:  #EAB308;
  --purple:  #A855F7;
  --mono:    'IBM Plex Mono', monospace;
  --sans:    'IBM Plex Sans', sans-serif;
}

html, body, #root { height: 100%; background: var(--bg0); color: var(--text); font-family: var(--sans); overflow: hidden; }

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
  width: 30px; height: 30px; background: var(--accent);
  border-radius: 6px; display: flex; align-items: center; justify-content: center;
  flex-shrink: 0;
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
.nav-item.active { color: var(--accent); background: rgba(255,107,53,.07); border-left-color: var(--accent); }
.nav-badge {
  margin-left: auto; font-size: 10px; font-family: var(--mono);
  background: var(--bg3); color: var(--text3);
  padding: 1px 6px; border-radius: 10px;
}
.nav-item.active .nav-badge { background: rgba(255,107,53,.15); color: var(--accent); }

.sidebar-stats { border-top: 1px solid var(--border); padding: 12px 18px; }
.stat-row { display: flex; justify-content: space-between; padding: 2px 0; }
.stat-k { font-size: 11px; color: var(--text2); }
.stat-v { font-size: 11px; font-family: var(--mono); color: var(--text); font-weight: 600; }

/* ── MAIN ── */
.main { flex: 1; display: flex; flex-direction: column; min-width: 0; overflow: hidden; }

.topbar {
  height: 50px; background: var(--bg1); border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 12px; padding: 0 20px; flex-shrink: 0;
}
.topbar-title { font-size: 15px; font-weight: 600; letter-spacing: -.01em; }
.topbar-sub   { font-size: 11px; color: var(--text2); font-family: var(--mono); }

.search-wrap { position: relative; margin-left: auto; }
.search-icon { position: absolute; left: 10px; top: 50%; transform: translateY(-50%); color: var(--text3); pointer-events: none; }
.search-input {
  background: var(--bg2); border: 1px solid var(--border); border-radius: 6px;
  color: var(--text); padding: 7px 12px 7px 32px; font-size: 12px;
  width: 260px; outline: none; transition: border-color .15s;
}
.search-input:focus { border-color: var(--accent2); }
.search-input::placeholder { color: var(--text3); }

.filterbar {
  display: flex; align-items: center; gap: 6px; padding: 8px 20px;
  border-bottom: 1px solid var(--border); flex-shrink: 0; flex-wrap: wrap;
}
.chip {
  padding: 3px 10px; border-radius: 3px; font-size: 11px; font-weight: 600;
  border: 1px solid var(--border2); background: var(--bg2); color: var(--text2);
  cursor: pointer; transition: all .12s; white-space: nowrap;
}
.chip:hover { border-color: var(--accent); color: var(--text); }
.chip.on    { border-color: var(--accent); background: rgba(255,107,53,.1); color: var(--accent); }
.chip.clear { border-color: var(--red); color: var(--red); margin-left: auto; }
.chip-label { font-size: 10px; color: var(--text3); }

/* ── RULE LIST ── */
.rule-list { width: 360px; flex-shrink: 0; border-right: 1px solid var(--border); overflow-y: auto; }
.list-count { padding: 8px 14px; font-size: 10px; font-family: var(--mono); color: var(--text3); border-bottom: 1px solid var(--border); }
.rule-row {
  padding: 11px 14px; border-bottom: 1px solid var(--border);
  cursor: pointer; transition: background .1s; position: relative;
}
.rule-row:hover  { background: var(--bg2); }
.rule-row.active { background: rgba(59,130,246,.07); }
.rule-row.active::before { content:''; position:absolute; left:0; top:0; bottom:0; width:2px; background: var(--accent2); }
.rule-rid  { font-family: var(--mono); font-size: 10px; color: var(--text3); margin-bottom: 3px; }
.rule-name { font-size: 13px; font-weight: 500; line-height: 1.3; margin-bottom: 6px; }
.rule-meta { display: flex; align-items: center; gap: 5px; flex-wrap: wrap; }

/* ── PILLS ── */
.pill {
  font-size: 10px; padding: 2px 7px; border-radius: 3px;
  font-weight: 600; border: 1px solid transparent; white-space: nowrap; font-family: var(--mono);
}
.pill-sev { }
.pill-tactic { background: rgba(59,130,246,.1); color: var(--accent2); border-color: rgba(59,130,246,.2); font-family: var(--sans); font-size: 10px; }
.pill-fid-High   { background: rgba(34,197,94,.1);  color: var(--green);  border-color: rgba(34,197,94,.2);  }
.pill-fid-Medium { background: rgba(234,179,8,.1);  color: var(--yellow); border-color: rgba(234,179,8,.2);  }
.pill-fid-Low    { background: rgba(239,68,68,.1);  color: var(--red);    border-color: rgba(239,68,68,.2);  }
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
  background: var(--bg1); border: 1px solid var(--border);
  border-radius: 6px; padding: 12px;
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
.qtab.active { background: var(--bg1); color: var(--accent); border-color: var(--border2); }
.qblock { background: var(--bg1); border: 1px solid var(--border2); border-radius: 0 6px 6px 6px; overflow: hidden; }
.qblock-head {
  display: flex; align-items: center; justify-content: space-between;
  padding: 7px 14px; background: var(--bg2); border-bottom: 1px solid var(--border);
}
.qblock-lang { font-size: 11px; font-family: var(--mono); color: var(--accent); font-weight: 600; }
.copy-btn {
  display: flex; align-items: center; gap: 4px; font-size: 10px;
  border: 1px solid var(--border2); border-radius: 4px; padding: 3px 8px;
  color: var(--text2); background: var(--bg3); transition: all .12s;
}
.copy-btn:hover { border-color: var(--accent); color: var(--accent); }
.qcode { font-family: var(--mono); font-size: 11.5px; padding: 14px; overflow-x: auto; white-space: pre; color: var(--text); line-height: 1.7; max-height: 320px; overflow-y: auto; }

.tags-row { display: flex; gap: 5px; flex-wrap: wrap; }
.tag { font-size: 10px; font-family: var(--mono); padding: 2px 8px; background: var(--bg2); border: 1px solid var(--border); border-radius: 3px; color: var(--text3); }

.list-items { display: flex; flex-direction: column; gap: 4px; }
.list-item { display: flex; align-items: flex-start; gap: 8px; font-size: 12px; color: var(--text2); padding: 6px 10px; background: var(--bg1); border: 1px solid var(--border); border-radius: 4px; }
.list-dot { width: 4px; height: 4px; border-radius: 50%; background: var(--text3); margin-top: 5px; flex-shrink: 0; }

/* ── VIEWS ── */
.view { flex: 1; overflow-y: auto; padding: 24px; }

/* Dashboard */
.dash-metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
.metric-card { background: var(--bg1); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
.metric-icon { width: 34px; height: 34px; border-radius: 7px; display: flex; align-items: center; justify-content: center; margin-bottom: 10px; }
.metric-num  { font-size: 28px; font-weight: 700; font-family: var(--mono); line-height: 1; }
.metric-lbl  { font-size: 11px; color: var(--text2); margin-top: 3px; }

.section-header { font-size: 13px; font-weight: 600; margin-bottom: 12px; display: flex; align-items: center; gap: 7px; }

/* Tactic grid */
.tactic-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-bottom: 24px; }
.tactic-card { background: var(--bg1); border: 1px solid var(--border); border-radius: 6px; padding: 12px; cursor: pointer; transition: border-color .15s; }
.tactic-card:hover { border-color: var(--border2); }
.tactic-dot  { width: 8px; height: 8px; border-radius: 50%; margin-bottom: 8px; }
.tactic-name { font-size: 11px; font-weight: 600; margin-bottom: 6px; }
.tactic-bar  { height: 3px; border-radius: 2px; background: var(--bg3); overflow: hidden; margin-bottom: 5px; }
.tactic-fill { height: 100%; border-radius: 2px; }
.tactic-stat { font-size: 10px; font-family: var(--mono); color: var(--text2); }

/* Sev dist */
.sev-bars { display: flex; flex-direction: column; gap: 8px; }
.sev-row  { display: flex; align-items: center; gap: 10px; }
.sev-lbl  { font-size: 11px; font-weight: 700; width: 65px; }
.sev-bar-bg { flex: 1; height: 18px; background: var(--bg3); border-radius: 3px; overflow: hidden; }
.sev-bar-fill { height: 100%; border-radius: 3px; display: flex; align-items: center; padding: 0 8px; font-size: 11px; font-family: var(--mono); font-weight: 700; color: white; }

/* ATT&CK Matrix */
.matrix-grid { display: grid; gap: 8px; }
.matrix-tactic { }
.matrix-header { font-size: 11px; font-weight: 600; padding: 6px 0; margin-bottom: 6px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
.matrix-techs { display: flex; flex-wrap: wrap; gap: 4px; }
.tech-chip {
  font-size: 10px; font-family: var(--mono); padding: 3px 8px;
  border-radius: 3px; cursor: pointer; transition: all .12s;
  white-space: nowrap;
}
.tech-chip.covered   { background: rgba(34,197,94,.12); color: var(--green); border: 1px solid rgba(34,197,94,.25); }
.tech-chip.uncovered { background: var(--bg2); color: var(--text3); border: 1px solid var(--border); }
.tech-chip.covered:hover { background: rgba(34,197,94,.2); }

/* Chains */
.chains-grid { display: flex; flex-direction: column; gap: 12px; }
.chain-card { background: var(--bg1); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
.chain-head { display: flex; align-items: center; gap: 12px; padding: 14px 16px; }
.chain-active { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.chain-id   { font-family: var(--mono); font-size: 11px; color: var(--text3); }
.chain-name { font-size: 14px; font-weight: 600; flex: 1; }
.chain-threat { font-size: 11px; color: var(--text2); margin-left: auto; }
.chain-steps { display: flex; align-items: center; gap: 0; padding: 0 16px 14px; flex-wrap: wrap; }
.chain-step {
  font-size: 11px; padding: 4px 10px; background: var(--bg2);
  border: 1px solid var(--border); border-radius: 4px; color: var(--text2);
  white-space: nowrap;
}
.chain-arrow { color: var(--text3); margin: 0 4px; flex-shrink: 0; }
.chain-meta  { display: flex; gap: 16px; padding: 10px 16px; background: var(--bg0); border-top: 1px solid var(--border); }
.chain-meta-item { font-size: 11px; color: var(--text2); display: flex; align-items: center; gap: 5px; font-family: var(--mono); }

/* Recommend */
.rec-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 24px; }
.log-source-table { width: 100%; border-collapse: collapse; }
.log-source-table th { font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: .08em; color: var(--text3); padding: 8px 12px; border-bottom: 1px solid var(--border); text-align: left; }
.log-source-table td { font-size: 12px; padding: 10px 12px; border-bottom: 1px solid var(--border); color: var(--text2); }
.log-source-table tr:last-child td { border-bottom: none; }
.log-source-table tr:hover td { background: var(--bg2); }
.status-dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 6px; }

.two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
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

function LcBadge({ lc }) {
  const colors = { Deployed:'#22C55E', Tested:'#3B82F6', Proposed:'#666', Tuned:'#A855F7', Retired:'#333' }
  return <span className="pill pill-lc" style={{ color: colors[lc] || '#666', borderColor: (colors[lc]||'#333')+'33' }}>{lc}</span>
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

function RuleDetail({ rule }) {
  const [tab, setTab] = useState('spl')
  const platforms = Object.keys(rule.queries || {}).filter(k => rule.queries[k])

  const rc = SEV_COLOR[rule.severity] || '#888'

  return (
    <div className="detail">
      <div className="detail-rid">{rule.rule_id} · {rule.technique_id}</div>
      <div className="detail-name">{rule.name}</div>
      <div className="detail-badges">
        <SevBadge s={rule.severity} />
        <LcBadge lc={rule.lifecycle} />
        <span className="pill pill-tactic">{rule.tactic}</span>
        <span className="pill pill-lc">{(rule.platform||[]).join(' · ')}</span>
      </div>

      <div className="grid2">
        <div className="card">
          <div className="card-label">Risk Score</div>
          <div className="card-value" style={{ color: rc }}>{rule.risk_score}/100</div>
          <div className="risk-bar"><div className="risk-fill" style={{ width:`${rule.risk_score}%`, background:rc }} /></div>
        </div>
        <div className="card">
          <div className="card-label">Fidelity</div>
          <div className="card-value" style={{ color: rule.fidelity==='High'?'#22C55E':rule.fidelity==='Medium'?'#EAB308':'#EF4444' }}>{rule.fidelity}</div>
        </div>
        <div className="card">
          <div className="card-label">Technique</div>
          <div className="card-value" style={{ fontSize:12, color:'#aaa' }}>{rule.technique_name}</div>
        </div>
        <div className="card">
          <div className="card-label">Test Method</div>
          <div className="card-value" style={{ fontSize:12, color:'#aaa' }}>{rule.test_method}</div>
        </div>
      </div>

      <div className="section">
        <div className="section-title"><Activity size={11} />Description</div>
        <div className="desc-box">{rule.description || 'No description available.'}</div>
      </div>

      {platforms.length > 0 && (
        <div className="section">
          <div className="section-title"><Terminal size={11} />Detection Queries</div>
          <div className="qtabs">
            {platforms.map(p => (
              <button key={p} className={`qtab${tab===p?' active':''}`} onClick={()=>setTab(p)}>
                {p}
              </button>
            ))}
          </div>
          <div className="qblock">
            <div className="qblock-head">
              <span className="qblock-lang">{SIEM_LABELS[tab] || tab.toUpperCase()}</span>
              <CopyBtn text={rule.queries[tab]} />
            </div>
            <div className="qcode">{rule.queries[tab]}</div>
          </div>
        </div>
      )}

      {rule.data_sources?.length > 0 && (
        <div className="section">
          <div className="section-title"><Database size={11} />Data Sources</div>
          <div className="list-items">
            {rule.data_sources.map((s,i) => <div key={i} className="list-item"><div className="list-dot" />{s}</div>)}
          </div>
        </div>
      )}

      {rule.false_positives?.length > 0 && (
        <div className="section">
          <div className="section-title"><AlertTriangle size={11} />False Positives</div>
          <div className="list-items">
            {rule.false_positives.map((fp,i) => <div key={i} className="list-item"><div className="list-dot" />{fp}</div>)}
          </div>
        </div>
      )}

      {rule.tags?.length > 0 && (
        <div className="section">
          <div className="section-title"><Tag size={11} />Tags</div>
          <div className="tags-row">{rule.tags.map(t=><span key={t} className="tag">{t}</span>)}</div>
        </div>
      )}

      <div style={{ marginTop:8, paddingTop:10, borderTop:'1px solid var(--border)', display:'flex', gap:16 }}>
        <span style={{ fontSize:11, color:'var(--text3)', fontFamily:'var(--mono)' }}>Author: {rule.author}</span>
        <span style={{ fontSize:11, color:'var(--text3)', fontFamily:'var(--mono)' }}>Created: {rule.created}</span>
      </div>
    </div>
  )
}

// ─── RULES VIEW ──────────────────────────────────────────────────────────────

function RulesView({ rules }) {
  const [selected, setSelected]   = useState(null)
  const [search, setSearch]       = useState('')
  const [fTactic, setFTactic]     = useState('All')
  const [fSev, setFSev]           = useState('All')
  const [fFid, setFid]            = useState('All')
  const [fLc, setFLc]             = useState('All')

  const filtered = useMemo(() => rules.filter(r => {
    const q = search.toLowerCase()
    const mq = !q || r.name.toLowerCase().includes(q) || r.rule_id.toLowerCase().includes(q) ||
               (r.technique_id||'').toLowerCase().includes(q) || (r.tags||[]).some(t=>t.includes(q))
    return mq &&
      (fTactic==='All'||r.tactic===fTactic) &&
      (fSev==='All'||r.severity===fSev) &&
      (fFid==='All'||r.fidelity===fFid) &&
      (fLc==='All'||r.lifecycle===fLc)
  }), [rules, search, fTactic, fSev, fFid, fLc])

  const clearAll = () => { setSearch(''); setFTactic('All'); setFSev('All'); setFid('All'); setFLc('All') }
  const dirty = search||fTactic!=='All'||fSev!=='All'||fFid!=='All'||fLc!=='All'

  return (
    <>
      <div className="topbar">
        <span className="topbar-title">Detection Rules</span>
        <span className="topbar-sub">{rules.length} rules · 9 SIEM platforms</span>
        <div className="search-wrap">
          <Search size={13} className="search-icon" />
          <input className="search-input" placeholder="Search rules, IDs, techniques, tags…"
            value={search} onChange={e=>setSearch(e.target.value)} />
        </div>
      </div>
      <div className="filterbar">
        <span className="chip-label">Tactic:</span>
        {['All',...TACTIC_ORDER].map(t=>(
          <button key={t} className={`chip${fTactic===t?' on':''}`} onClick={()=>setFTactic(t)} style={{ fontSize:10 }}>{t}</button>
        ))}
        <span className="chip-label" style={{marginLeft:6}}>Sev:</span>
        {['All','Critical','High','Medium','Low'].map(s=>(
          <button key={s} className={`chip${fSev===s?' on':''}`} onClick={()=>setFSev(s)}>{s}</button>
        ))}
        <span className="chip-label" style={{marginLeft:6}}>Lifecycle:</span>
        {['All','Deployed','Proposed','Tested'].map(l=>(
          <button key={l} className={`chip${fLc===l?' on':''}`} onClick={()=>setFLc(l)}>{l}</button>
        ))}
        {dirty && <button className="chip clear" onClick={clearAll}><X size={10} style={{marginRight:3}} />Clear</button>}
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
                <span className="pill pill-tactic" style={{fontSize:9}}>{r.tactic}</span>
                <SevBadge s={r.severity} />
                <span className={`pill pill-fid-${r.fidelity}`}>{r.fidelity}</span>
              </div>
            </div>
          ))}
        </div>
        {selected
          ? <RuleDetail rule={selected} />
          : <div className="detail empty-state">
              <div className="empty-inner">
                <Shield size={48} />
                <p style={{marginTop:12}}>Select a rule</p>
              </div>
            </div>
        }
      </div>
    </>
  )
}

// ─── DASHBOARD VIEW ─────────────────────────────────────────────────────────

function DashboardView({ rules }) {
  const byTactic   = useMemo(() => TACTIC_ORDER.reduce((a,t) => ({...a,[t]:rules.filter(r=>r.tactic===t).length}), {}), [rules])
  const bySev      = useMemo(() => ['Critical','High','Medium','Low'].reduce((a,s) => ({...a,[s]:rules.filter(r=>r.severity===s).length}), {}), [rules])
  const deployed   = rules.filter(r=>r.lifecycle==='Deployed').length
  const critical   = rules.filter(r=>r.severity==='Critical').length
  const highFid    = rules.filter(r=>r.fidelity==='High').length
  const maxTactic  = Math.max(...Object.values(byTactic))

  return (
    <div className="view">
      <div className="dash-metrics">
        {[
          { icon:<Shield size={16} />, num:rules.length, lbl:'Total Rules',       color:'#3B82F6', bg:'rgba(59,130,246,.15)' },
          { icon:<CheckCircle size={16} />, num:deployed,   lbl:'Deployed',        color:'#22C55E', bg:'rgba(34,197,94,.15)' },
          { icon:<AlertTriangle size={16} />, num:critical, lbl:'Critical Severity', color:'#EF4444', bg:'rgba(239,68,68,.15)' },
          { icon:<TrendingUp size={16} />, num:highFid,     lbl:'High Fidelity',   color:'#FF6B35', bg:'rgba(255,107,53,.15)' },
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
          <div className="section-header"><Crosshair size={13} />ATT&CK Tactic Coverage</div>
          <div className="tactic-grid" style={{gridTemplateColumns:'repeat(3,1fr)'}}>
            {TACTIC_ORDER.map(t => {
              const c = byTactic[t]||0, color = TACTIC_COLOR[t]
              return (
                <div key={t} className="tactic-card">
                  <div className="tactic-dot" style={{background:color}} />
                  <div className="tactic-name" style={{color}}>{t}</div>
                  <div className="tactic-bar"><div className="tactic-fill" style={{width:`${maxTactic?c/maxTactic*100:0}%`,background:color}} /></div>
                  <div className="tactic-stat">{c} rules</div>
                </div>
              )
            })}
          </div>
        </div>

        <div>
          <div className="section-header"><BarChart3 size={13} />Severity Distribution</div>
          <div className="sev-bars" style={{marginBottom:24}}>
            {['Critical','High','Medium','Low'].map(s => {
              const c = bySev[s]||0
              const pct = rules.length ? Math.max(c/rules.length*100,2) : 2
              return (
                <div key={s} className="sev-row">
                  <div className="sev-lbl" style={{color:SEV_COLOR[s]}}>{s}</div>
                  <div className="sev-bar-bg"><div className="sev-bar-fill" style={{width:`${pct}%`,background:SEV_COLOR[s]}}>{c}</div></div>
                </div>
              )
            })}
          </div>

          <div className="section-header"><Activity size={13} />Lifecycle Split</div>
          <div className="sev-bars">
            {[['Deployed','#22C55E'],['Proposed','#666'],['Tested','#3B82F6']].map(([lc,color]) => {
              const c = rules.filter(r=>r.lifecycle===lc).length
              const pct = rules.length ? Math.max(c/rules.length*100,1) : 1
              return (
                <div key={lc} className="sev-row">
                  <div className="sev-lbl" style={{color}}>{lc}</div>
                  <div className="sev-bar-bg"><div className="sev-bar-fill" style={{width:`${pct}%`,background:color}}>{c}</div></div>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── ATT&CK MATRIX VIEW ──────────────────────────────────────────────────────

function MatrixView({ rules }) {
  const coveredIds = useMemo(() => {
    const s = new Set()
    rules.forEach(r => { if(r.technique_id) s.add(r.technique_id.slice(0,5)) })
    return s
  }, [rules])

  return (
    <div className="view">
      <div className="topbar" style={{marginBottom:0,borderBottom:'1px solid var(--border)'}}>
        <span className="topbar-title">ATT&CK Coverage Matrix</span>
        <span className="topbar-sub">{coveredIds.size} techniques covered</span>
      </div>
      <div style={{padding:20,overflowY:'auto',height:'calc(100% - 0px)'}}>
        {TACTIC_ORDER.map(tactic => {
          const techs = ATTACK_TECHNIQUES[tactic] || []
          const covered = techs.filter(t => coveredIds.has(t))
          const color = TACTIC_COLOR[tactic]
          return (
            <div key={tactic} className="matrix-tactic" style={{marginBottom:20}}>
              <div className="matrix-header" style={{color}}>
                <span>{tactic}</span>
                <span style={{fontSize:10,fontFamily:'var(--mono)',color:'var(--text3)'}}>{covered.length}/{techs.length} covered</span>
              </div>
              <div className="matrix-techs">
                {techs.map(t => (
                  <span key={t} className={`tech-chip ${coveredIds.has(t)?'covered':'uncovered'}`}>{t}</span>
                ))}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─── CHAINS VIEW ─────────────────────────────────────────────────────────────

function ChainsView() {
  return (
    <div className="view">
      <div className="section-header" style={{marginBottom:16}}><GitBranch size={13} />Attack Chain Correlation</div>
      <div className="chains-grid">
        {CHAINS.map(chain => {
          const sc = SEV_COLOR[chain.severity]
          const sb = SEV_BG[chain.severity]
          return (
            <div key={chain.id} className="chain-card">
              <div className="chain-head">
                <div className="chain-active" style={{background: chain.active ? '#22C55E' : '#EF4444'}} />
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
              <div className="chain-meta">
                <span className="chain-meta-item">
                  <span style={{color:chain.active?'#22C55E':'#EF4444'}}>●</span>
                  {chain.active ? 'ACTIVE — all required rules present' : 'INACTIVE — missing required rules'}
                </span>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─── RECOMMEND VIEW ──────────────────────────────────────────────────────────

function RecommendView({ rules }) {
  const deployed    = LOG_SOURCES.filter(l=>l.deployed)
  const undeployed  = LOG_SOURCES.filter(l=>!l.deployed).sort((a,b)=>b.rules_unlocked-a.rules_unlocked)
  const deployable  = useMemo(() => {
    const depIds = new Set(deployed.map(l=>l.id))
    return rules.filter(r => {
      const src = (r.data_sources||[]).join(' ').toLowerCase()
      return depIds.has('windows_security_events') && (src.includes('windows') || src.includes('sysmon'))
        || depIds.has('firewall') && src.includes('firewall')
        || depIds.has('dns') && src.includes('dns')
        || depIds.has('edr') && src.includes('edr')
        || depIds.has('identity_provider') && (src.includes('azure ad')||src.includes('okta'))
        || depIds.has('cloud') && (src.includes('aws')||src.includes('azure')||src.includes('cloudtrail'))
    }).length
  }, [rules, deployed])

  const cCrit = { Critical:'#EF4444', High:'#F97316', Medium:'#EAB308' }

  return (
    <div className="view">
      <div className="section-header" style={{marginBottom:4}}><Map size={13} />Environment Profile</div>
      <div style={{fontSize:12,color:'var(--text2)',marginBottom:20}}>Default Enterprise — Windows + M365 + Cloud. Edit <code style={{fontFamily:'var(--mono)',fontSize:11}}>profiles/default.yaml</code> to customize.</div>

      <div className="dash-metrics" style={{gridTemplateColumns:'repeat(3,1fr)',marginBottom:24}}>
        {[
          { icon:<CheckCircle size={15}/>, num:deployed.length,     lbl:'Log Sources Deployed',  color:'#22C55E', bg:'rgba(34,197,94,.15)' },
          { icon:<Shield size={15}/>,      num:deployable,           lbl:'Rules Deployable Now',  color:'#3B82F6', bg:'rgba(59,130,246,.15)' },
          { icon:<TrendingUp size={15}/>,  num:undeployed.reduce((a,l)=>a+l.rules_unlocked,0), lbl:'Rules Unlockable', color:'#FF6B35', bg:'rgba(255,107,53,.15)' },
        ].map((m,i)=>(
          <div key={i} className="metric-card">
            <div className="metric-icon" style={{background:m.bg}}>{React.cloneElement(m.icon,{color:m.color})}</div>
            <div className="metric-num" style={{color:m.color}}>{m.num}</div>
            <div className="metric-lbl">{m.lbl}</div>
          </div>
        ))}
      </div>

      <div className="two-col">
        <div>
          <div className="section-header"><Database size={13} />Log Source Criticality Assessment</div>
          <table className="log-source-table">
            <thead><tr>
              <th>Status</th><th>Criticality</th><th>Tier</th><th>Log Source</th>
            </tr></thead>
            <tbody>
              {LOG_SOURCES.map(ls => (
                <tr key={ls.id}>
                  <td>
                    <span className="status-dot" style={{background:ls.deployed?'#22C55E':'#EF4444'}} />
                    {ls.deployed ? 'Deployed' : 'Missing'}
                  </td>
                  <td style={{color:cCrit[ls.criticality]||'var(--text2)'}}>{ls.criticality}</td>
                  <td style={{fontFamily:'var(--mono)',fontSize:11}}>T{ls.tier}</td>
                  <td>{ls.name}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div>
          <div className="section-header"><TrendingUp size={13} />Log Source ROI — Deploy These Next</div>
          <table className="log-source-table">
            <thead><tr>
              <th>Log Source</th><th>Tier</th><th>Rules Unlocked</th>
            </tr></thead>
            <tbody>
              {undeployed.map(ls => (
                <tr key={ls.id}>
                  <td style={{fontWeight:500,color:'var(--text)'}}>{ls.name}</td>
                  <td style={{fontFamily:'var(--mono)',fontSize:11}}>T{ls.tier}</td>
                  <td style={{fontFamily:'var(--mono)',fontSize:12,color:'#FF6B35',fontWeight:700}}>+{ls.rules_unlocked}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// ─── APP ─────────────────────────────────────────────────────────────────────

const buildViews = (ruleCount, chainCount) => [
  { id:'dashboard', label:'Dashboard',        icon:<BarChart3 size={14} /> },
  { id:'rules',     label:'Detection Rules',  icon:<Shield size={14} />,   badge:ruleCount },
  { id:'matrix',    label:'ATT&CK Matrix',    icon:<Map size={14} /> },
  { id:'chains',    label:'Attack Chains',    icon:<GitBranch size={14} />, badge:chainCount },
  { id:'recommend', label:'Recommendations',  icon:<TrendingUp size={14} /> },
]

export default function App() {
  const [view, setView] = useState('dashboard')
  const [rules, setRules] = useState(RULES_RAW)
  const [source, setSource] = useState('bundled')

  useEffect(() => {
    let cancelled = false
    fetch('/api/rules')
      .then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
      .then(data => {
        if (cancelled) return
        if (Array.isArray(data) && data.length) {
          setRules(data)
          setSource('api')
        }
      })
      .catch(() => { /* keep bundled fallback */ })
    return () => { cancelled = true }
  }, [])

  const deployed = rules.filter(r => r.lifecycle === 'Deployed').length
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
                <div className="logo-ver">v2.0.0 · DaaC</div>
              </div>
            </div>
          </div>
          <nav className="sidebar-nav">
            <div className="nav-label">Navigation</div>
            {buildViews(rules.length, chainCount).map(v => (
              <div key={v.id} className={`nav-item${view===v.id?' active':''}`} onClick={()=>setView(v.id)}>
                {v.icon}{v.label}
                {v.badge && <span className="nav-badge">{v.badge}</span>}
              </div>
            ))}
          </nav>
          <div className="sidebar-stats">
            <div className="stat-row"><span className="stat-k">Total Rules</span><span className="stat-v">{rules.length}</span></div>
            <div className="stat-row"><span className="stat-k">Deployed</span><span className="stat-v" style={{color:'#22C55E'}}>{deployed}</span></div>
            <div className="stat-row"><span className="stat-k">SIEM Platforms</span><span className="stat-v" style={{color:'#FF6B35'}}>9</span></div>
            <div className="stat-row"><span className="stat-k">Attack Chains</span><span className="stat-v" style={{color:'#3B82F6'}}>{chainCount}</span></div>
            <div className="stat-row"><span className="stat-k">Data source</span><span className="stat-v" style={{color: source==='api' ? '#22C55E' : '#94A3B8', fontSize:9}}>{source==='api' ? '● live API' : '○ bundled'}</span></div>
          </div>
        </aside>

        <div className="main">
          {view === 'rules'     && <RulesView rules={rules} />}
          {view === 'dashboard' && (
            <>
              <div className="topbar">
                <span className="topbar-title">Dashboard</span>
                <span className="topbar-sub">TDL Playbook · Threat Detection Library</span>
              </div>
              <DashboardView rules={rules} />
            </>
          )}
          {view === 'matrix' && (
            <>
              <div className="topbar">
                <span className="topbar-title">ATT&CK Coverage Matrix</span>
              </div>
              <MatrixView rules={rules} />
            </>
          )}
          {view === 'chains' && (
            <>
              <div className="topbar">
                <span className="topbar-title">Attack Chain Correlation</span>
                <span className="topbar-sub">{chainCount} chains · all active</span>
              </div>
              <ChainsView />
            </>
          )}
          {view === 'recommend' && (
            <>
              <div className="topbar">
                <span className="topbar-title">Recommendations</span>
                <span className="topbar-sub">Log source ROI · Coverage gaps</span>
              </div>
              <RecommendView rules={rules} />
            </>
          )}
        </div>
      </div>
    </>
  )
}
