import React, { useState, useMemo, useCallback, useEffect } from 'react'
import {
  Shield, Search, ChevronRight, X, AlertTriangle, CheckCircle,
  Activity, Database, Target, Filter, Tag, Copy, Check,
  BarChart3, Layers, Crosshair, Clock, TrendingUp, ChevronDown,
  Terminal, Zap, GitBranch, Map as MapIcon, Award, Eye, Lock, Cpu,
  ArrowRight, Circle, Minus
} from 'lucide-react'
import RULES_RAW from './data/rules.json'
import { ATTACK_MATRIX, KILL_CHAIN, TACTIC_ORDER_MATRIX } from './data/attack-matrix.js'

// ─── CONSTANTS ──────────────────────────────────────────────────────────────

const TACTIC_ORDER = [
  'Initial Access','Execution','Persistence','Privilege Escalation',
  'Defense Evasion','Credential Access','Discovery','Lateral Movement',
  'Command and Control','Collection','Exfiltration','Impact'
]

// Tactic palette — three bands across the kill-chain progression:
//   red   = early-stage (gain access, execute, escalate)
//   purple = mid-stage  (evade, harvest, move)
//   blue  = late-stage  (control, collect, exfil, impact)
const TACTIC_COLOR = {
  'Initial Access':        '#B91C1C',
  'Execution':             '#DC2626',
  'Persistence':           '#E11D48',
  'Privilege Escalation':  '#9F1239',
  'Defense Evasion':       '#7C3AED',
  'Credential Access':     '#6D28D9',
  'Discovery':             '#8B5CF6',
  'Lateral Movement':      '#5B21B6',
  'Command and Control':   '#1D4ED8',
  'Collection':            '#2563EB',
  'Exfiltration':          '#1E40AF',
  'Impact':                '#3B82F6',
}

const SEV_COLOR = { Critical:'#B91C1C', High:'#DC2626', Medium:'#7C3AED', Low:'#2563EB' }
const SEV_BG    = { Critical:'rgba(185,28,28,.10)', High:'rgba(220,38,38,.10)', Medium:'rgba(124,58,237,.10)', Low:'rgba(37,99,235,.10)' }

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
  /* Surfaces — pure white page, soft greys for chrome */
  --bg0:      #FFFFFF;
  --bg1:      #FAFAFB;
  --bg2:      #F4F4F7;
  --bg3:      #ECECF0;
  --border:   #E4E4EA;
  --border2:  #D0D0D9;

  /* Text — near-black on white, all WCAG AAA */
  --text:     #0B0B12;
  --text2:    #4A4A57;
  --text3:    #6E6E7C;

  /* Restricted palette: red / blue / purple / grey / white / black */
  --red:      #DC2626;
  --red-dk:   #B91C1C;
  --red-lt:   #FEE2E2;
  --blue:     #2563EB;
  --blue-dk:  #1D4ED8;
  --blue-lt:  #DBEAFE;
  --purple:   #7C3AED;
  --purple-dk:#6D28D9;
  --purple-lt:#EDE9FE;

  /* Aliases — primary accent is purple, secondary is blue */
  --accent:   var(--purple);
  --accent2:  var(--blue);

  --shadow-sm: 0 1px 2px rgba(11,11,18,.04);
  --shadow:    0 2px 8px rgba(11,11,18,.06);
  --shadow-lg: 0 8px 24px rgba(11,11,18,.08);

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
.topbar-title { font-size: 15px; font-weight: 600; letter-spacing: -.01em; }
.topbar-sub   { font-size: 11px; color: var(--text2); font-family: var(--mono); }

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
  display: flex; align-items: center; gap: 6px; padding: 10px 24px;
  border-bottom: 1px solid var(--border); flex-shrink: 0; flex-wrap: wrap;
  background: var(--bg1);
}
.chip {
  padding: 4px 11px; border-radius: 4px; font-size: 11px; font-weight: 600;
  border: 1px solid var(--border); background: var(--bg0); color: var(--text2);
  cursor: pointer; transition: all .12s; white-space: nowrap;
}
.chip:hover { border-color: var(--purple); color: var(--purple); }
.chip.on    { border-color: var(--purple); background: var(--purple); color: #fff; }
.chip.clear { border-color: var(--red); color: var(--red); margin-left: auto; background: var(--red-lt); }
.chip-label { font-size: 10px; color: var(--text3); font-weight: 600; text-transform: uppercase; letter-spacing: .06em; }

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
.pill-tactic { background: var(--bg2); color: var(--text2); border-color: var(--border); font-family: var(--sans); font-size: 10px; }
.pill-fid-High   { background: var(--purple-lt); color: var(--purple-dk); border-color: rgba(124,58,237,.25); }
.pill-fid-Medium { background: var(--blue-lt);   color: var(--blue-dk);   border-color: rgba(37,99,235,.25); }
.pill-fid-Low    { background: var(--bg2);       color: var(--text2);     border-color: var(--border); }
.pill-lc { background: var(--bg2); color: var(--text2); font-family: var(--sans); font-size: 10px; }

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

/* ── VIEWS ── */
.view { flex: 1; overflow-y: auto; padding: 28px; background: var(--bg0); }

/* Dashboard */
.dash-metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 28px; }
.metric-card { background: var(--bg0); border: 1px solid var(--border); border-radius: 10px; padding: 18px; box-shadow: var(--shadow-sm); transition: box-shadow .15s, transform .15s; }
.metric-card:hover { box-shadow: var(--shadow); transform: translateY(-1px); }
.metric-icon { width: 36px; height: 36px; border-radius: 8px; display: flex; align-items: center; justify-content: center; margin-bottom: 12px; }
.metric-num  { font-size: 30px; font-weight: 700; font-family: var(--mono); line-height: 1; letter-spacing: -.02em; }
.metric-lbl  { font-size: 11px; color: var(--text2); margin-top: 5px; font-weight: 500; }

.section-header { font-size: 13px; font-weight: 700; margin-bottom: 14px; display: flex; align-items: center; gap: 8px; color: var(--text); letter-spacing: -.01em; }

/* Tactic grid */
.tactic-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-bottom: 24px; }
.tactic-card { background: var(--bg0); border: 1px solid var(--border); border-radius: 8px; padding: 14px; cursor: pointer; transition: border-color .15s, box-shadow .15s; }
.tactic-card:hover { border-color: var(--border2); box-shadow: var(--shadow-sm); }
.tactic-dot  { width: 8px; height: 8px; border-radius: 50%; margin-bottom: 8px; }
.tactic-name { font-size: 11px; font-weight: 600; margin-bottom: 6px; }
.tactic-bar  { height: 3px; border-radius: 2px; background: var(--bg3); overflow: hidden; margin-bottom: 5px; }
.tactic-fill { height: 100%; border-radius: 2px; }
.tactic-stat { font-size: 10px; font-family: var(--mono); color: var(--text2); }

/* Sev dist */
.sev-bars { display: flex; flex-direction: column; gap: 10px; }
.sev-row  { display: flex; align-items: center; gap: 12px; }
.sev-lbl  { font-size: 11px; font-weight: 700; width: 70px; }
.sev-bar-bg { flex: 1; height: 20px; background: var(--bg2); border-radius: 4px; overflow: hidden; }
.sev-bar-fill { height: 100%; border-radius: 4px; display: flex; align-items: center; padding: 0 10px; font-size: 11px; font-family: var(--mono); font-weight: 700; color: white; min-width: 30px; }

/* ATT&CK Matrix — column-per-tactic grid mirroring attack.mitre.org */
.matrix-legend { display: flex; align-items: center; gap: 12px; padding: 8px 20px; border-bottom: 1px solid var(--border); flex-shrink: 0; flex-wrap: wrap; font-size: 10px; color: var(--text2); font-family: var(--mono); }
.matrix-legend-item { display: inline-flex; align-items: center; gap: 5px; }
.matrix-legend-swatch { display: inline-block; width: 12px; height: 12px; border-radius: 2px; border: 1px solid; }
.matrix-legend-link { margin-left: auto; }
.matrix-legend-link a { color: var(--purple); text-decoration: none; font-weight: 600; }
.matrix-legend-link a:hover { text-decoration: underline; }
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
  position: absolute; top: 5px; right: 6px; font-size: 9px; font-family: var(--mono); font-weight: 700;
  color: #fff; background: var(--purple); padding: 1px 6px; border-radius: 8px;
}

/* Lockheed Cyber Kill Chain — horizontal 7-stage flow */
.killchain { display: flex; align-items: stretch; gap: 6px; flex-wrap: wrap; margin-bottom: 8px; }
.kc-wrap { display: flex; align-items: center; flex: 1 1 230px; min-width: 220px; }
.kc-stage {
  flex: 1; padding: 14px 14px 12px; border-radius: 8px; border: 1px solid;
  display: flex; flex-direction: column; gap: 8px; min-height: 168px; min-width: 0;
  background: var(--bg0); transition: border-color .15s, box-shadow .15s, transform .15s;
}
.kc-stage:hover { box-shadow: var(--shadow); transform: translateY(-1px); }
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
.kc-pre-tag { font-size: 9px; font-family: var(--mono); color: var(--text3); letter-spacing: .04em; font-weight: 600; }
.kc-arrow { color: var(--text3); flex-shrink: 0; margin: 0 -2px; }

/* Chains */
.chains-grid { display: flex; flex-direction: column; gap: 14px; }
.chain-card { background: var(--bg0); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; transition: box-shadow .15s; }
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

/* Recommend */
.rec-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 24px; }
.log-source-table { width: 100%; border-collapse: collapse; }
.log-source-table th { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: .10em; color: var(--text3); padding: 10px 14px; border-bottom: 1px solid var(--border); text-align: left; background: var(--bg1); }
.log-source-table td { font-size: 12px; padding: 11px 14px; border-bottom: 1px solid var(--border); color: var(--text2); }
.log-source-table tr:last-child td { border-bottom: none; }
.log-source-table tr:hover td { background: var(--bg1); }
.status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 7px; }

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
          <div className="card-value" style={{ color: rule.fidelity==='High'?'#7C3AED':rule.fidelity==='Medium'?'#2563EB':'#6E6E7C' }}>{rule.fidelity}</div>
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

  const filtered = useMemo(() => rules.filter(r => {
    const q = search.toLowerCase()
    const mq = !q || r.name.toLowerCase().includes(q) || r.rule_id.toLowerCase().includes(q) ||
               (r.technique_id||'').toLowerCase().includes(q) || (r.tags||[]).some(t=>t.includes(q))
    return mq &&
      (fTactic==='All'||r.tactic===fTactic) &&
      (fSev==='All'||r.severity===fSev) &&
      (fFid==='All'||r.fidelity===fFid)
  }), [rules, search, fTactic, fSev, fFid])

  const clearAll = () => { setSearch(''); setFTactic('All'); setFSev('All'); setFid('All') }
  const dirty = search||fTactic!=='All'||fSev!=='All'||fFid!=='All'

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
        <span className="chip-label" style={{marginLeft:6}}>Fidelity:</span>
        {['All','High','Medium','Low'].map(f=>(
          <button key={f} className={`chip${fFid===f?' on':''}`} onClick={()=>setFid(f)}>{f}</button>
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
  const techniques = useMemo(() => new Set(rules.map(r => (r.technique_id||'').split('.')[0]).filter(Boolean)), [rules])
  const critical   = rules.filter(r=>r.severity==='Critical').length
  const highFid    = rules.filter(r=>r.fidelity==='High').length
  const maxTactic  = Math.max(...Object.values(byTactic))

  return (
    <div className="view">
      <div className="dash-metrics">
        {[
          { icon:<Shield size={16} />, num:rules.length, lbl:'Total Rules',       color:'#0B0B12', bg:'#F4F4F7' },
          { icon:<Crosshair size={16} />, num:techniques.size, lbl:'ATT&CK Techniques', color:'#7C3AED', bg:'#EDE9FE' },
          { icon:<AlertTriangle size={16} />, num:critical, lbl:'Critical Severity', color:'#DC2626', bg:'#FEE2E2' },
          { icon:<TrendingUp size={16} />, num:highFid,     lbl:'High Fidelity',   color:'#2563EB', bg:'#DBEAFE' },
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

        </div>
      </div>
    </div>
  )
}

// ─── ATT&CK MATRIX VIEW ──────────────────────────────────────────────────────
// Column-per-tactic grid mirroring https://attack.mitre.org/matrices/enterprise.

function MatrixView({ rules }) {
  // Map technique_id (top-level) → number of rules covering it.
  const ruleCount = useMemo(() => {
    const m = new Map()
    rules.forEach(r => {
      const tid = (r.technique_id || '').split('.')[0]
      if (tid) m.set(tid, (m.get(tid) || 0) + 1)
    })
    return m
  }, [rules])

  // Coverage shading buckets — purple density based on rules-per-technique.
  const shade = (count) => {
    if (!count) return { background:'#FFFFFF', border:'var(--border)', color:'var(--text3)', name:'var(--text3)' }
    if (count >= 10) return { background:'rgba(124,58,237,.22)', border:'rgba(124,58,237,.55)', color:'#5B21B6', name:'var(--text)' }
    if (count >= 5)  return { background:'rgba(124,58,237,.15)', border:'rgba(124,58,237,.45)', color:'#6D28D9', name:'var(--text)' }
    if (count >= 2)  return { background:'rgba(124,58,237,.09)', border:'rgba(124,58,237,.32)', color:'#6D28D9', name:'var(--text)' }
    return { background:'rgba(124,58,237,.05)', border:'rgba(124,58,237,.20)', color:'#7C3AED', name:'var(--text)' }
  }

  const totalTactics = TACTIC_ORDER_MATRIX.length
  const totalTechs = TACTIC_ORDER_MATRIX.reduce((a,t) => a + (ATTACK_MATRIX[t]?.techniques.length || 0), 0)
  const coveredTechs = TACTIC_ORDER_MATRIX.reduce((a,t) => {
    const techs = ATTACK_MATRIX[t]?.techniques || []
    return a + techs.filter(x => ruleCount.has(x.id)).length
  }, 0)

  return (
    <>
      <div className="topbar">
        <span className="topbar-title">ATT&CK Coverage Matrix</span>
        <span className="topbar-sub">Enterprise · {coveredTechs}/{totalTechs} techniques covered across {totalTactics} tactics</span>
      </div>
      <div className="matrix-legend">
        <span className="matrix-legend-item"><span className="matrix-legend-swatch" style={{background:'#FFFFFF',borderColor:'var(--border)'}}/>Not covered</span>
        <span className="matrix-legend-item"><span className="matrix-legend-swatch" style={{background:'rgba(124,58,237,.05)',borderColor:'rgba(124,58,237,.20)'}}/>1 rule</span>
        <span className="matrix-legend-item"><span className="matrix-legend-swatch" style={{background:'rgba(124,58,237,.09)',borderColor:'rgba(124,58,237,.32)'}}/>2-4</span>
        <span className="matrix-legend-item"><span className="matrix-legend-swatch" style={{background:'rgba(124,58,237,.15)',borderColor:'rgba(124,58,237,.45)'}}/>5-9</span>
        <span className="matrix-legend-item"><span className="matrix-legend-swatch" style={{background:'rgba(124,58,237,.22)',borderColor:'rgba(124,58,237,.55)'}}/>10+</span>
        <span className="matrix-legend-link"><a href="https://attack.mitre.org/matrices/enterprise/" target="_blank" rel="noreferrer">attack.mitre.org ↗</a></span>
      </div>
      <div className="matrix-scroll">
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
                  <div className="attack-col-tactic" style={{color}}>{tactic}</div>
                  <div className="attack-col-meta">{col.id} · {covered}/{techs.length}</div>
                </div>
                <div className="attack-col-body">
                  {techs.map(t => {
                    const c = ruleCount.get(t.id) || 0
                    const s = shade(c)
                    return (
                      <a key={t.id} href={`https://attack.mitre.org/techniques/${t.id}/`} target="_blank" rel="noreferrer"
                         className="attack-cell" style={{background:s.background, borderColor:s.border}}
                         title={`${t.id} ${t.name}${c ? ` · ${c} rule${c>1?'s':''}` : ' · not covered'}`}>
                        <span className="attack-cell-id" style={{color:s.color}}>{t.id}</span>
                        <span className="attack-cell-name" style={{color:s.name}}>{t.name}</span>
                        {c > 0 && <span className="attack-cell-count">{c}</span>}
                      </a>
                    )
                  })}
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </>
  )
}

// ─── CHAINS VIEW ─────────────────────────────────────────────────────────────

function ChainsView({ rules }) {
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
      <div style={{fontSize:11,color:'var(--text2)',marginBottom:14,maxWidth:780,lineHeight:1.55}}>
        The 7-stage adversary lifecycle from Lockheed Martin. Each stage shows the
        ATT&CK tactic(s) that map to it and the number of TDL rules covering that
        adversary behavior. <a href="https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html" target="_blank" rel="noreferrer" style={{color:'var(--accent2)'}}>Reference ↗</a>
      </div>

      <div className="killchain">
        {KILL_CHAIN.map((stage, i) => {
          const { count, status } = stageCoverage(stage)
          const isPre = status === 'pre'
          const isGap = status === 'gap'
          return (
            <div key={stage.id} className="kc-wrap">
              <div className={`kc-stage ${isPre?'kc-pre':isGap?'kc-gap':'kc-cov'}`}>
                <div className="kc-stage-num">{stage.stage}</div>
                <div className="kc-stage-name">{stage.name}</div>
                <div className="kc-stage-desc">{stage.description}</div>
                <div className="kc-stage-meta">
                  {isPre
                    ? <span className="kc-pre-tag">{stage.pre_attack[0]} (PRE-ATT&CK)</span>
                    : <>
                        <div className="kc-tactics">{stage.attack_tactics.map(t => (
                          <span key={t} className="kc-tactic-pill" style={{borderColor: TACTIC_COLOR[t]+'66', color:TACTIC_COLOR[t]}}>{t}</span>
                        ))}</div>
                        <div className="kc-count" style={{color: isGap?'var(--red)':'var(--purple)'}}>
                          {count} rule{count===1?'':'s'}
                        </div>
                      </>
                  }
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
                <div className="chain-meta">
                  <span className="chain-meta-item">
                    <span style={{color:chain.active?'#7C3AED':'#DC2626'}}>●</span>
                    {chain.active ? 'ACTIVE — all required rules present' : 'INACTIVE — missing required rules'}
                  </span>
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

  const cCrit = { Critical:'#DC2626', High:'#7C3AED', Medium:'#2563EB' }

  return (
    <div className="view">
      <div className="section-header" style={{marginBottom:4}}><MapIcon size={13} />Environment Profile <span style={{fontSize:10,fontWeight:600,color:'#B91C1C',marginLeft:8,padding:'2px 8px',background:'#FEE2E2',border:'1px solid rgba(220,38,38,.25)',borderRadius:4,letterSpacing:0,textTransform:'none'}}>SAMPLE — not your environment</span></div>
      <div style={{fontSize:12,color:'var(--text2)',marginBottom:20}}>This view shows the <em>default</em> enterprise profile (Windows + M365 + Cloud) as a worked example. Edit <code style={{fontFamily:'var(--mono)',fontSize:11}}>profiles/default.yaml</code> with your real log sources for accurate recommendations.</div>

      <div className="dash-metrics" style={{gridTemplateColumns:'repeat(3,1fr)',marginBottom:24}}>
        {[
          { icon:<CheckCircle size={15}/>, num:deployed.length,     lbl:'Sources in sample profile', color:'#0B0B12', bg:'#F4F4F7' },
          { icon:<Shield size={15}/>,      num:deployable,           lbl:'Rules runnable on these',   color:'#2563EB', bg:'#DBEAFE' },
          { icon:<TrendingUp size={15}/>,  num:undeployed.reduce((a,l)=>a+l.rules_unlocked,0), lbl:'Rules unlocked by adding the rest', color:'#7C3AED', bg:'#EDE9FE' },
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
                    <span className="status-dot" style={{background:ls.deployed?'#7C3AED':'#DC2626'}} />
                    {ls.deployed ? 'In profile' : 'Not in profile'}
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
                  <td style={{fontFamily:'var(--mono)',fontSize:12,color:'#7C3AED',fontWeight:700}}>+{ls.rules_unlocked}</td>
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
  { id:'matrix',    label:'ATT&CK Matrix',    icon:<MapIcon size={14} /> },
  { id:'chains',    label:'Kill Chain',       icon:<GitBranch size={14} />, badge:chainCount },
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

  const techCount = useMemo(() => new Set(rules.map(r => (r.technique_id||'').split('.')[0]).filter(Boolean)).size, [rules])
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
            <div className="stat-row"><span className="stat-k">Techniques</span><span className="stat-v" style={{color:'#7C3AED'}}>{techCount}</span></div>
            <div className="stat-row"><span className="stat-k">SIEM Platforms</span><span className="stat-v">9</span></div>
            <div className="stat-row"><span className="stat-k">Attack Chains</span><span className="stat-v" style={{color:'#2563EB'}}>{chainCount}</span></div>
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
                <span className="topbar-title">Kill Chain &amp; Attack Chains</span>
                <span className="topbar-sub">Lockheed Cyber Kill Chain · {chainCount} TDL internal chains</span>
              </div>
              <ChainsView rules={rules} />
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
