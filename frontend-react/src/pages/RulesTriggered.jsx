import React, { useState, useEffect, useCallback } from 'react';
import { Zap, AlertTriangle, CheckCircle, Filter, ExternalLink, Shield } from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer,
} from 'recharts';
import Header from '../components/Header';
import Modal from '../components/common/Modal';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { getRulesTriggered } from '../utils/api';
import { fmtDateTime, severityBg } from '../utils/formatters';

/* ─── static meta ─── */
const RULE_META = {
  PORT_SCAN: {
    rule_id: 9001, rule_name: 'Unauthorized Port Scan Detected',
    severity: 'HIGH', detection_method: 'statistical_analysis',
    mitre_technique: 'T1046 – Network Service Scanning',
    mitre_tactic: 'Discovery',
    description: 'Multiple TCP connection attempts to different ports in rapid succession from a single source.',
    remediation: 'Block source IP at the perimeter firewall. Enable IDS signatures for port scanning. Review access control lists.',
  },
  UNAUTHORIZED_READ: {
    rule_id: 9002, rule_name: 'Unauthorized Modbus Read',
    severity: 'HIGH', detection_method: 'behavioral_profiling',
    mitre_technique: 'T1557 – Adversary-in-the-Middle',
    mitre_tactic: 'Collection',
    description: 'Unauthorized Modbus read request from a non-HMI source to PLC registers.',
    remediation: 'Review PLC access logs. Implement network segmentation and whitelist authorized HMI IPs for Modbus access.',
  },
  MALICIOUS_WRITE: {
    rule_id: 9003, rule_name: 'Malicious PLC Write Attempt',
    severity: 'CRITICAL', detection_method: 'anomaly_detection',
    mitre_technique: 'T1561 – Disk Wipe / Control System Sabotage',
    mitre_tactic: 'Impact',
    description: 'Unauthorized write operation to PLC holding registers with anomalous values. May indicate sabotage.',
    remediation: 'Isolate device immediately. Restore PLC from known-good backup. Investigate root cause.',
  },
  LATERAL_MOVEMENT: {
    rule_id: 9004, rule_name: 'Lateral Movement in OT Network',
    severity: 'CRITICAL', detection_method: 'behavioral_profiling',
    mitre_technique: 'T1021 – Remote Services',
    mitre_tactic: 'Lateral Movement',
    description: 'Suspicious lateral connections to multiple OT/IoT devices across network zones.',
    remediation: 'Activate network segmentation. Isolate threat source IP. Review cross-zone firewall rules.',
  },
  DATA_EXFIL: {
    rule_id: 9005, rule_name: 'Data Exfiltration Detected',
    severity: 'CRITICAL', detection_method: 'statistical_analysis',
    mitre_technique: 'T1030 – Data Transfer Size Limits',
    mitre_tactic: 'Exfiltration',
    description: 'Anomalous outbound data volume detected from OT network host to external destination.',
    remediation: 'Block outbound connection immediately. Preserve packet captures as forensic evidence.',
  },
};

const METHOD_BADGE = {
  statistical_analysis: 'bg-cyan-900/40 text-cyan-400',
  behavioral_profiling:  'bg-purple-900/40 text-purple-400',
  anomaly_detection:     'bg-orange-900/40 text-orange-400',
  ensemble_voting:       'bg-green-900/40 text-green-400',
  rule_based:            'bg-blue-900/40 text-blue-400',
};

const SEV_LEVELS = ['ALL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const METHODS    = ['ALL', 'statistical_analysis', 'behavioral_profiling', 'anomaly_detection', 'ensemble_voting', 'rule_based'];

const relTime = (ts) => {
  if (!ts) return '—';
  const diff = Date.now() - new Date((ts || '').replace(' ', 'T')).getTime();
  const m = Math.floor(diff / 60000);
  if (m <  1)   return 'just now';
  if (m <  60)  return `${m}m ago`;
  if (m < 1440) return `${Math.floor(m / 60)}h ago`;
  return fmtDateTime(ts);
};

/* ─── Rule detail modal ─── */
function RuleDetail({ rule }) {
  if (!rule) return null;
  const meta = RULE_META[rule._action] || {};
  return (
    <div className="space-y-5">

      {/* Header strip */}
      <div className="flex items-start gap-4 bg-dark-bg rounded-xl p-4 border border-dark-border">
        <div className="w-10 h-10 rounded-xl bg-orange-900/30 flex items-center justify-center shrink-0">
          <Zap size={18} className="text-accent-orange" />
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-white font-semibold">{rule.rule_name}</p>
          <p className="text-dark-secondary text-xs mt-0.5">Rule #{rule.rule_id}</p>
          <div className="flex items-center gap-2 mt-2">
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${severityBg(rule.severity)}`}>{rule.severity}</span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${METHOD_BADGE[rule.detection_method || meta.detection_method] || 'bg-gray-800 text-gray-400'}`}>
              {rule.detection_method || meta.detection_method || '—'}
            </span>
          </div>
        </div>
        <div className="text-right shrink-0">
          <p className="text-2xl font-bold font-mono text-accent-orange">{rule.triggered_count}</p>
          <p className="text-dark-secondary text-xs">total fires</p>
        </div>
      </div>

      {/* Description */}
      <div>
        <p className="text-dark-secondary text-xs uppercase tracking-wider mb-1">Description</p>
        <p className="text-white text-sm leading-relaxed">{meta.description || rule.details || '—'}</p>
      </div>

      {/* MITRE */}
      <div className="bg-dark-bg rounded-xl border border-dark-border p-4">
        <p className="text-dark-secondary text-xs uppercase tracking-wider mb-3">MITRE ATT&CK for ICS</p>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <p className="text-dark-secondary text-[10px] mb-1">Technique</p>
            <p className="text-accent-cyan text-xs font-mono">{meta.mitre_technique || '—'}</p>
          </div>
          <div>
            <p className="text-dark-secondary text-[10px] mb-1">Tactic</p>
            <p className="text-accent-purple text-xs font-mono">{meta.mitre_tactic || '—'}</p>
          </div>
        </div>
      </div>

      {/* Traffic flow */}
      <div>
        <p className="text-dark-secondary text-xs uppercase tracking-wider mb-2">Traffic Flow</p>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <p className="text-dark-secondary text-[10px] mb-1">Source IPs</p>
            <div className="flex flex-wrap gap-1">
              {(rule.source_ips || rule.affected_devices || []).slice(0,5).map((ip, i) => (
                <span key={i} className="px-2 py-1 bg-red-900/20 border border-red-900/30 rounded-lg font-mono text-xs text-red-400">
                  {ip}
                </span>
              ))}
            </div>
          </div>
          <div>
            <p className="text-dark-secondary text-[10px] mb-1">Destination IPs</p>
            <div className="flex flex-wrap gap-1">
              {(rule.destination_ips || []).slice(0,5).map((ip, i) => (
                <span key={i} className="px-2 py-1 bg-orange-900/20 border border-orange-900/30 rounded-lg font-mono text-xs text-orange-400">
                  {ip}
                </span>
              ))}
              {(!rule.destination_ips || rule.destination_ips.length === 0) && (
                <span className="text-dark-secondary text-xs">—</span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Timeline mini bar */}
      <div>
        <p className="text-dark-secondary text-xs uppercase tracking-wider mb-2">Last Triggered</p>
        <p className="text-white text-sm font-mono">{fmtDateTime(rule.last_triggered)}</p>
        <p className="text-dark-secondary text-xs">{relTime(rule.last_triggered)}</p>
      </div>

      {/* Remediation */}
      <div className="bg-green-900/10 border border-green-900/30 rounded-xl p-4">
        <p className="text-accent-green text-xs font-semibold uppercase tracking-wider mb-2">🛡 Remediation Steps</p>
        <p className="text-white text-sm leading-relaxed">{meta.remediation || 'Review affected devices and apply appropriate containment.'}</p>
      </div>

    </div>
  );
}

/* ─── Main page ─── */
export default function RulesTriggered() {
  const [all,      setAll]      = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState(null);
  const [sevFilter,setSevFilter]= useState('ALL');
  const [methFilter,setMethFilter] = useState('ALL');
  const [selected, setSelected] = useState(null);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const res = await getRulesTriggered();
      const rows = (res.data?.rules_triggered || []).map(r => {
        // Derive action key from rule_id to look up meta
        const actionMap = { 9001:'PORT_SCAN', 9002:'UNAUTHORIZED_READ', 9003:'MALICIOUS_WRITE', 9004:'LATERAL_MOVEMENT', 9005:'DATA_EXFIL' };
        const meta = RULE_META[actionMap[r.rule_id]] || {};
        return { ...r, _action: actionMap[r.rule_id] || '', detection_method: r.detection_method || meta.detection_method || '' };
      });
      setAll(rows);
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const rows = all.filter(r => {
    if (sevFilter !== 'ALL'  && r.severity !== sevFilter)         return false;
    if (methFilter !== 'ALL' && r.detection_method !== methFilter) return false;
    return true;
  });

  const highSev   = all.filter(r => ['HIGH','CRITICAL'].includes(r.severity)).length;
  const totalFired = all.reduce((a, r) => a + (r.triggered_count || 1), 0);

  // Bar chart data
  const chartData = rows.map(r => ({ name: r.rule_name.split(' ').slice(0,2).join(' '), count: r.triggered_count, severity: r.severity }));

  const FilterBtn = ({ value, current, onChange, children }) => (
    <button onClick={() => onChange(value)}
      className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-all
        ${current === value ? 'bg-accent-cyan text-dark-sidebar' : 'bg-dark-card border border-dark-border text-dark-secondary hover:text-white'}`}>
      {children}
    </button>
  );

  const severityColor = (s) => ({ CRITICAL:'#ff0055', HIGH:'#ff6600', MEDIUM:'#ffaa00', LOW:'#00ff88' })[s] || '#aaa';

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <Header title="Detection Rules Triggered" subtitle="Active rules that have detected anomalies in the network" onRefresh={load} loading={loading} />
      <div className="flex-1 overflow-y-auto p-6 space-y-5">

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Rules Triggered', value: all.length,   color: '#ffaa00', icon: Zap },
            { label: 'High / Critical', value: highSev,      color: '#ff0055', icon: AlertTriangle },
            { label: 'Total Fires',     value: totalFired,   color: '#00d4ff', icon: CheckCircle },
            { label: 'MITRE Mapped',    value: all.length,   color: '#b066ff', icon: Shield },
          ].map(({ label, value, color, icon: Icon }) => (
            <div key={label} className="bg-dark-card border border-dark-border rounded-xl p-5 card-hover relative overflow-hidden">
              <div className="absolute inset-0 opacity-5 rounded-xl" style={{ background: `radial-gradient(circle at top right, ${color}, transparent)` }} />
              <div className="relative flex items-start justify-between mb-2">
                <p className="text-dark-secondary text-xs uppercase tracking-wider">{label}</p>
                <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ background: `${color}18` }}>
                  <Icon size={14} style={{ color }} />
                </div>
              </div>
              <p className="text-2xl font-bold font-mono" style={{ color }}>{value}</p>
            </div>
          ))}
        </div>

        {/* Bar chart */}
        {rows.length > 0 && (
          <div className="bg-dark-card border border-dark-border rounded-xl p-5">
            <p className="text-white text-sm font-semibold mb-4">Rule Trigger Counts</p>
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={chartData} margin={{ left: -10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis dataKey="name" stroke="#555" tick={{ fontSize: 10 }} />
                <YAxis stroke="#555" tick={{ fontSize: 10 }} />
                <Tooltip contentStyle={{ background: '#151b28', border: '1px solid #1f2937', borderRadius: 8, fontSize: 11 }} />
                <Bar dataKey="count" radius={[4,4,0,0]}>
                  {chartData.map((entry, i) => (
                    <rect key={i} fill={severityColor(entry.severity)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Filters */}
        <div className="bg-dark-card border border-dark-border rounded-xl p-4 space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-dark-secondary text-xs uppercase tracking-wider mr-1 flex items-center gap-1"><Filter size={11} />Severity</span>
            {SEV_LEVELS.map(v => <FilterBtn key={v} value={v} current={sevFilter} onChange={setSevFilter}>{v}</FilterBtn>)}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-dark-secondary text-xs uppercase tracking-wider mr-1 flex items-center gap-1"><Filter size={11} />Method</span>
            {METHODS.map(v => <FilterBtn key={v} value={v} current={methFilter} onChange={setMethFilter}>{v === 'ALL' ? 'All' : v.replace(/_/g,' ')}</FilterBtn>)}
          </div>
          <p className="text-dark-secondary text-xs">{rows.length} rule{rows.length !== 1 ? 's' : ''} shown</p>
        </div>

        {/* Table */}
        <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden">
          {loading && <LoadingSpinner text="Loading rules…" />}
          {error   && <p className="text-accent-red p-6 text-sm">{error}</p>}
          {!loading && !error && rows.length === 0 && (
            <div className="flex flex-col items-center justify-center py-16">
              <Zap size={40} className="text-dark-secondary mb-3" />
              <p className="text-dark-secondary">No rules match current filters</p>
            </div>
          )}
          {!loading && !error && rows.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead className="bg-dark-sidebar sticky top-0">
                  <tr>
                    {['Rule ID','Rule Name','Severity','Fires','Last Triggered','Source IP','Destination IP','Method','Actions'].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-dark-secondary font-semibold uppercase tracking-wider whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rows.map((rule, i) => (
                    <tr key={i} className="border-t border-dark-border tr-hover">
                      <td className="px-4 py-3 font-mono text-dark-secondary">#{rule.rule_id}</td>
                      <td className="px-4 py-3">
                        <button onClick={() => setSelected(rule)} className="font-semibold text-white hover:text-accent-cyan transition-colors text-left">
                          {rule.rule_name}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${severityBg(rule.severity)}`}>{rule.severity}</span>
                      </td>
                      <td className="px-4 py-3 font-mono font-bold text-accent-orange">{rule.triggered_count}</td>
                      <td className="px-4 py-3 text-dark-secondary font-mono" title={fmtDateTime(rule.last_triggered)}>{relTime(rule.last_triggered)}</td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {(rule.source_ips || rule.affected_devices || []).slice(0,2).map((ip, j) => (
                            <span key={j} className="px-1.5 py-0.5 bg-red-900/20 rounded font-mono text-[10px] text-red-400">{ip}</span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {(rule.destination_ips || []).slice(0,3).map((ip, j) => (
                            <span key={j} className="px-1.5 py-0.5 bg-orange-900/20 rounded font-mono text-[10px] text-orange-400">{ip}</span>
                          ))}
                          {(!rule.destination_ips || rule.destination_ips.length === 0) && (
                            <span className="text-dark-secondary text-[10px]">—</span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${METHOD_BADGE[rule.detection_method] || 'bg-gray-800 text-gray-400'}`}>
                          {(rule.detection_method || '—').replace(/_/g,' ')}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <button onClick={() => setSelected(rule)} className="text-accent-cyan hover:text-white text-xs transition-colors">
                          Details →
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

      </div>

      <Modal isOpen={!!selected} onClose={() => setSelected(null)}
        title={selected ? `Rule #${selected.rule_id} — ${selected.rule_name}` : ''}
        width="max-w-2xl">
        <RuleDetail rule={selected} />
      </Modal>
    </div>
  );
}
