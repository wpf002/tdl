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
  position: absolute; top: 5px; right: 6px; font-size: 9px; font-family: var(--mono); font-weight: 700;
  color: #fff; background: var(--purple); padding: 1px 6px; border-radius: 8px;
}

/* Lockheed Cyber Kill Chain — horizontal 7-stage flow */
.killchain { display: flex; align-items: stretch; gap: 6px; flex-wrap: wrap; margin-bottom: 8px; }
.kc-wrap { display: flex; align-items: center; flex: 1 1 230px; min-width: 220px; }
.kc-stage {
  flex: 1; padding: 14px 14px 12px; border-radius: 8px; border: 1px solid;
  display: flex; flex-direction: column; gap: 8px; min-height: 168px; min-width: 0;
  background: var(--bg2); transition: border-color .15s, box-shadow .15s, transform .15s;
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
.kc-pre-tag { font-size: 10px; color: var(--text3); font-weight: 600; line-height: 1.3; }
.kc-pre-sub { font-size: 9.5px; color: var(--text3); line-height: 1.45; opacity: .85; }
.kc-arrow { color: var(--text3); flex-shrink: 0; margin: 0 -2px; }

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
          <div className="card-value" style={{ fontSize:12, color:'#aaa' }}>{(rule.test_method||'').replace(/_/g,' ').replace(/\b\w/g, c => c.toUpperCase())}</div>
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
        <div className="filter-row">
          <span className="chip-label">Tactic</span>
          {['All',...TACTIC_ORDER].map(t=>(
            <button key={t} className={`chip${fTactic===t?' on':''}`} onClick={()=>setFTactic(t)} style={{ fontSize:10 }}>{t}</button>
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
          <div className="panel-card panel-card-fill">
            <div className="sev-bars sev-bars-tall">
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

  // Coverage shading buckets — purple density on dark.
  const shade = (count) => {
    if (!count) return { background:'var(--bg1)', border:'var(--border)', color:'var(--text3)', name:'var(--text3)' }
    if (count >= 10) return { background:'rgba(168,85,247,.32)', border:'rgba(168,85,247,.65)', color:'#E9D5FF', name:'var(--text)' }
    if (count >= 5)  return { background:'rgba(168,85,247,.22)', border:'rgba(168,85,247,.50)', color:'#D8B4FE', name:'var(--text)' }
    if (count >= 2)  return { background:'rgba(168,85,247,.13)', border:'rgba(168,85,247,.36)', color:'#C084FC', name:'var(--text)' }
    return { background:'rgba(168,85,247,.06)', border:'rgba(168,85,247,.22)', color:'#A855F7', name:'var(--text2)' }
  }

  const totalTactics = TACTIC_ORDER_MATRIX.length
  const totalTechs = TACTIC_ORDER_MATRIX.reduce((a,t) => a + (ATTACK_MATRIX[t]?.techniques.length || 0), 0)
  const coveredTechs = TACTIC_ORDER_MATRIX.reduce((a,t) => {
    const techs = ATTACK_MATRIX[t]?.techniques || []
    return a + techs.filter(x => ruleCount.has(x.id)).length
  }, 0)

  const totalRules = rules.length
  const pctCovered = totalTechs ? Math.round(coveredTechs / totalTechs * 100) : 0

  return (
    <>
      <div className="topbar">
        <span className="topbar-title">MITRE ATT&CK</span>
        <span className="topbar-sub">Enterprise · v15</span>
        <a className="topbar-link" href="https://attack.mitre.org/matrices/enterprise/" target="_blank" rel="noreferrer">attack.mitre.org ↗</a>
      </div>
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
      <div style={{fontSize:11,color:'var(--text2)',marginBottom:14,lineHeight:1.55,whiteSpace:'nowrap'}}>
        The 7-stage adversary lifecycle from Lockheed Martin. Each stage shows the ATT&CK tactic(s) that map to it and the number of TDL rules covering that adversary behavior. <a href="https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html" target="_blank" rel="noreferrer" style={{color:'var(--accent2)'}}>Reference ↗</a>
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
                    ? <>
                        <span className="kc-pre-tag">Pre-compromise · external to your network</span>
                        <span className="kc-pre-sub">Adversary acts on their own infrastructure. Detection requires threat intel feeds, not endpoint logs — outside the scope of this rule library.</span>
                      </>
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
              <td>{ls.name}</td>
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
            {buildViews(rules.length, techCount, chainCount).map(v => (
              <div key={v.id} className={`nav-item${view===v.id?' active':''}`} onClick={()=>setView(v.id)}>
                {v.icon}{v.label}
                {v.badge && <span className="nav-badge">{v.badge}</span>}
              </div>
            ))}
          </nav>
          <div className="sidebar-stats">
            <div className="stat-row"><span className="stat-k">Total Rules</span><span className="stat-v">{rules.length}</span></div>
            <div className="stat-row"><span className="stat-k">Techniques</span><span className="stat-v" style={{color:'#A855F7'}}>{techCount}</span></div>
            <div className="stat-row"><span className="stat-k">SIEM Platforms</span><span className="stat-v">9</span></div>
            <div className="stat-row"><span className="stat-k">Attack Chains</span><span className="stat-v" style={{color:'#A855F7'}}>{chainCount}</span></div>
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
                <span className="topbar-title">MITRE ATT&CK</span>
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
