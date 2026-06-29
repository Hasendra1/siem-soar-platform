import React, { useState, useEffect, useCallback } from 'react';
import { ShieldOff, Clock, Network, Shield, RefreshCw, Filter, Activity } from 'lucide-react';
import Header from '../components/Header';
import Modal from '../components/common/Modal';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { useWebSocket } from '../hooks/useWebSocket';
import { getIsolations } from '../utils/api';
import { fmtDateTime } from '../utils/formatters';

/* ─── State helpers ─── */
const getStateColor = (state) => {
  const map = {
    'THREAT_SOURCE': 'bg-red-500/20 text-red-500 border border-red-500/30',
    'COMPROMISED':   'bg-orange-500/20 text-orange-400 border border-orange-500/30',
    'PROPAGATED':    'bg-purple-500/20 text-purple-400 border border-purple-500/30',
    'NORMAL':        'bg-gray-500/20 text-gray-400',
  };
  return map[state] || map['NORMAL'];
};

const isIsolated = (state) =>
  ['THREAT_SOURCE', 'COMPROMISED', 'PROPAGATED'].includes(state);

const REASON_META = {
  ATTACKER_IDENTIFIED: { label: 'Attacker Identified', cls: 'bg-red-900/40 text-red-400 border border-red-900/60' },
  COMPROMISED_DEVICE:  { label: 'Compromised Device',  cls: 'bg-orange-900/40 text-orange-400 border border-orange-900/60' },
  MANUAL_CONTAINMENT:  { label: 'Manual Containment',  cls: 'bg-cyan-900/40 text-cyan-400 border border-cyan-900/60' },
};

const NET_ZONE = (net) => {
  const n = (net || '').toLowerCase();
  if (n.includes('ot'))  return { label: 'OT',  cls: 'bg-yellow-900/40 text-yellow-400' };
  if (n.includes('iot')) return { label: 'IoT', cls: 'bg-cyan-900/40 text-cyan-400' };
  if (n.includes('dmz')) return { label: 'DMZ', cls: 'bg-purple-900/40 text-purple-400' };
  return { label: net.slice(-8), cls: 'bg-gray-800 text-gray-400' };
};

const relTime = (ts) => {
  if (!ts) return '—';
  const diff = Date.now() - new Date(ts.replace(' ', 'T')).getTime();
  const m = Math.floor(diff / 60000);
  if (m <  1)   return 'just now';
  if (m <  60)  return `${m}m ago`;
  if (m < 1440) return `${Math.floor(m / 60)}h ago`;
  return fmtDateTime(ts);
};

const inTimeRange = (ts, range) => {
  if (range === 'all') return true;
  const ms = { '24h': 86400000, '7d': 604800000, '30d': 2592000000 }[range] || Infinity;
  return Date.now() - new Date((ts || '').replace(' ', 'T')).getTime() <= ms;
};

/* ─── Detail Modal content ─── */
function IsolationDetail({ iso }) {
  if (!iso) return null;
  const nets = Array.isArray(iso.networks_disconnected)
    ? iso.networks_disconnected
    : iso.network_name ? [iso.network_name] : [];

  const fields = [
    ['Device IP',    <span className="font-mono text-accent-cyan">{iso.ip_address}</span>],
    ['Container',    iso.container_name || '—'],
    ['State',        (
      <span className={`px-2 py-0.5 rounded text-xs font-bold ${getStateColor(iso.state || '')}`}>
        {iso.state || '—'}
      </span>
    )],
    ['Reason',       (
      <span className={`px-2 py-0.5 rounded text-xs font-bold ${(REASON_META[iso.isolation_reason] || {}).cls || 'bg-gray-800 text-gray-300'}`}>
        {iso.isolation_reason?.replace(/_/g, ' ') || '—'}
      </span>
    )],
    ['ML Score',     (
      <span className="font-mono text-white">{(iso.ensemble_score || 0).toFixed(3)}</span>
    )],
    ['Method',       <span className="font-mono text-accent-purple">{iso.automation_method || '—'}</span>],
    ['Isolated At',  fmtDateTime(iso.isolation_timestamp)],
    ['Status',       (
      <span className={isIsolated(iso.state) ? 'text-accent-red font-bold' : 'text-accent-green font-bold'}>
        {isIsolated(iso.state) ? '🔒 ISOLATED' : 'NORMAL'}
      </span>
    )],
  ];

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4">
        {fields.map(([label, val], i) => (
          <div key={i} className={i >= 6 ? 'col-span-2' : ''}>
            <p className="text-dark-secondary text-xs uppercase tracking-wider mb-1">{label}</p>
            <p className="text-white text-sm">{val}</p>
          </div>
        ))}
      </div>

      {/* Networks disconnected */}
      <div>
        <p className="text-dark-secondary text-xs uppercase tracking-wider mb-2">Networks Disconnected</p>
        {nets.length > 0 ? (
          <div className="flex flex-wrap gap-2">
            {nets.map((net, i) => {
              const z = NET_ZONE(net);
              return (
                <div key={i} className="flex items-center gap-2 bg-dark-hover rounded-lg px-3 py-2 border border-dark-border">
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${z.cls}`}>{z.label}</span>
                  <span className="font-mono text-xs text-dark-secondary">{net}</span>
                </div>
              );
            })}
          </div>
        ) : <p className="text-dark-secondary text-sm">No network data</p>}
      </div>

      {/* Threat assessment */}
      <div className="bg-dark-bg rounded-xl border border-dark-border p-4">
        <p className="text-white text-xs font-semibold uppercase tracking-wider mb-3">Threat Assessment</p>
        <div className="space-y-2">
          {[
            { label: 'Ensemble ML Score', value: Math.round((iso.ensemble_score || 0) * 100) },
            { label: 'Threat Containment', value: isIsolated(iso.state) ? 100 : 0 },
            { label: 'Risk Reduction', value: isIsolated(iso.state) ? 92 : 0 },
          ].map(({ label, value }) => (
            <div key={label} className="flex items-center gap-3">
              <p className="text-dark-secondary text-xs w-40 shrink-0">{label}</p>
              <div className="flex-1 h-2 bg-dark-border rounded-full overflow-hidden">
                <div className="h-full rounded-full bg-accent-cyan transition-all duration-700"
                     style={{ width: `${value}%` }} />
              </div>
              <span className="text-xs font-mono text-white w-10 text-right">{value}%</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ─── Main page ─── */
export default function IsolatedDevices() {
  const [all,      setAll]      = useState([]);
  const [mlDevices, setMlDevices] = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState(null);
  const [filter,   setFilter]   = useState({ status: 'all', reason: 'all', timeRange: 'all' });
  const [selected, setSelected] = useState(null);
  const [viewMode, setViewMode] = useState('states'); // 'states' or 'isolations'

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      // Load both isolation records and ML device states
      const [isoRes, mlRes] = await Promise.allSettled([
        getIsolations(),
        fetch('http://localhost:5000/api/data/ml/device-states').then(r => r.json()),
      ]);

      if (isoRes.status === 'fulfilled') {
        const data = Array.isArray(isoRes.value.data) ? isoRes.value.data : isoRes.value.data?.isolations || [];
        setAll(data.sort((a, b) => new Date(b.isolation_timestamp) - new Date(a.isolation_timestamp)));
      }

      if (mlRes.status === 'fulfilled') {
        setMlDevices(mlRes.value.devices || []);
      }
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  // real-time
  useWebSocket({ onIsolation: (iso) => setAll(p => [iso, ...p]) });

  /* apply filters for isolation view */
  const rows = all.filter(r => {
    if (filter.status !== 'all') {
      const active = r.success;
      if (filter.status === 'active'   && !active)  return false;
      if (filter.status === 'resolved' &&  active)  return false;
    }
    if (filter.reason !== 'all' && r.isolation_reason !== filter.reason) return false;
    if (!inTimeRange(r.isolation_timestamp, filter.timeRange)) return false;
    return true;
  });

  const sel = () => 'bg-accent-cyan text-dark-sidebar';
  const unsel = () => 'bg-dark-card border border-dark-border text-dark-secondary hover:text-white';

  const FilterBtn = ({ value, current, onChange, children }) => (
    <button
      onClick={() => onChange(value)}
      className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${current === value ? sel() : unsel()}`}
    >
      {children}
    </button>
  );

  // Count states from ML devices
  const stateCount = (s) => mlDevices.filter(d => d.state === s).length;
  const isolatedCount = mlDevices.filter(d => isIsolated(d.state)).length;

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <Header title="Isolated Devices" subtitle="Real-time isolation status and containment details" onRefresh={load} loading={loading} />
      <div className="flex-1 overflow-y-auto p-6 space-y-5">

        {/* ── State Legend ── */}
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
          <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-3">
            <div className="flex items-center justify-between">
              <p className="text-red-500 font-bold text-sm">THREAT SOURCE</p>
              <span className="text-red-500 font-mono text-lg font-bold">{stateCount('THREAT_SOURCE')}</span>
            </div>
            <p className="text-dark-text-secondary text-xs mt-1">Compromised device identified by ML — isolated</p>
          </div>
          <div className="bg-orange-500/10 border border-orange-500/30 rounded-xl p-3">
            <div className="flex items-center justify-between">
              <p className="text-orange-400 font-bold text-sm">COMPROMISED</p>
              <span className="text-orange-400 font-mono text-lg font-bold">{stateCount('COMPROMISED')}</span>
            </div>
            <p className="text-dark-text-secondary text-xs mt-1">High risk — scanned or received malicious write — isolated</p>
          </div>
          <div className="bg-purple-500/10 border border-purple-500/30 rounded-xl p-3">
            <div className="flex items-center justify-between">
              <p className="text-purple-400 font-bold text-sm">PROPAGATED</p>
              <span className="text-purple-400 font-mono text-lg font-bold">{stateCount('PROPAGATED')}</span>
            </div>
            <p className="text-dark-text-secondary text-xs mt-1">Compromised device now attacking — isolated</p>
          </div>
        </div>

        {/* Summary cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Total Isolated',     value: isolatedCount,                                        color: '#ff0055', icon: ShieldOff },
            { label: 'Active Records',     value: all.filter(r => r.success).length,                    color: '#ff6600', icon: Shield },
            { label: 'Networks Affected',  value: new Set(all.map(r => r.network_name).filter(Boolean)).size, color: '#b066ff', icon: Network },
            { label: 'Last Isolation',     value: relTime(all[0]?.isolation_timestamp) || '—',          color: '#ffaa00', icon: Clock },
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

        {/* ── View Mode Toggle ── */}
        <div className="flex gap-2">
          <button
            onClick={() => setViewMode('states')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all ${viewMode === 'states' ? sel() : unsel()}`}
          >
            <Activity size={12} className="inline mr-1" /> ML Device States
          </button>
          <button
            onClick={() => setViewMode('isolations')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all ${viewMode === 'isolations' ? sel() : unsel()}`}
          >
            <ShieldOff size={12} className="inline mr-1" /> Isolation Records
          </button>
        </div>

        {/* ── ML Device States View ── */}
        {viewMode === 'states' && (
          <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden">
            {loading && <LoadingSpinner text="Loading device states…" />}
            {!loading && mlDevices.length === 0 && (
              <div className="flex flex-col items-center justify-center py-16">
                <Shield size={48} className="text-dark-secondary mb-3" />
                <p className="text-dark-secondary">No device state data — start the API server</p>
              </div>
            )}
            {!loading && mlDevices.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead className="bg-dark-sidebar sticky top-0">
                    <tr>
                      {['Device IP', 'Name', 'Type', 'Zone', 'State', 'ML Score', 'Isolation'].map(h => (
                        <th key={h} className="px-4 py-3 text-left text-dark-secondary font-semibold uppercase tracking-wider whitespace-nowrap">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {mlDevices.map((device, i) => (
                      <tr key={i} className="border-t border-dark-border tr-hover cursor-pointer" onClick={() => setSelected({
                        ...device, ip_address: device.device_ip, container_name: device.device_name,
                      })}>
                        {/* IP */}
                        <td className="px-4 py-3">
                          <span className="font-mono text-accent-cyan">{device.device_ip}</span>
                        </td>
                        {/* Name */}
                        <td className="px-4 py-3 text-white font-semibold">{device.device_name}</td>
                        {/* Type */}
                        <td className="px-4 py-3 text-dark-secondary">{device.device_type}</td>
                        {/* Zone */}
                        <td className="px-4 py-3">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            device.zone === 'OT' ? 'bg-yellow-900/40 text-yellow-400' :
                            device.zone === 'IoT' ? 'bg-cyan-900/40 text-cyan-400' :
                            'bg-purple-900/40 text-purple-400'
                          }`}>{device.zone}</span>
                        </td>
                        {/* State */}
                        <td className="px-4 py-3">
                          <div>
                            <span className={`px-2 py-1 rounded text-xs font-bold ${getStateColor(device.state)}`}>
                              {device.state}
                            </span>
                            {isIsolated(device.state) && (
                              <p className="text-xs text-red-400 mt-1">🔒 ISOLATED</p>
                            )}
                          </div>
                        </td>
                        {/* ML Score */}
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="w-16 bg-dark-bg rounded h-2">
                              <div
                                className={`h-full rounded ${
                                  device.ensemble_score > 0.7 ? 'bg-red-500' :
                                  device.ensemble_score > 0.4 ? 'bg-orange-400' : 'bg-green-500'
                                }`}
                                style={{ width: `${Math.min(device.ensemble_score * 100, 100)}%` }}
                              />
                            </div>
                            <span className="text-white text-xs font-mono">
                              {(device.ensemble_score || 0).toFixed(3)}
                            </span>
                          </div>
                        </td>
                        {/* Isolation info */}
                        <td className="px-4 py-3">
                          {device.isolation_reason ? (
                            <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                              (REASON_META[device.isolation_reason] || {}).cls || 'bg-gray-800 text-gray-400'
                            }`}>
                              {(REASON_META[device.isolation_reason] || {}).label || device.isolation_reason}
                            </span>
                          ) : (
                            <span className="text-dark-secondary text-xs">—</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ── Isolation Records View ── */}
        {viewMode === 'isolations' && (
          <>
            {/* Filters */}
            <div className="bg-dark-card border border-dark-border rounded-xl p-4 space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-dark-secondary text-xs uppercase tracking-wider flex items-center gap-1.5 mr-1">
                  <Filter size={12} /> Status
                </span>
                {['all', 'active', 'resolved'].map(v => (
                  <FilterBtn key={v} value={v} current={filter.status} onChange={s => setFilter(f => ({ ...f, status: s }))}>
                    {v === 'all' ? 'All' : v === 'active' ? 'Active (Isolated)' : 'Released'}
                  </FilterBtn>
                ))}
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-dark-secondary text-xs uppercase tracking-wider flex items-center gap-1.5 mr-1">
                  <Filter size={12} /> Reason
                </span>
                {[['all','All'], ['ATTACKER_IDENTIFIED','Attacker'], ['COMPROMISED_DEVICE','Compromised'], ['MANUAL_CONTAINMENT','Manual']].map(([v, label]) => (
                  <FilterBtn key={v} value={v} current={filter.reason} onChange={r => setFilter(f => ({ ...f, reason: r }))}>
                    {label}
                  </FilterBtn>
                ))}
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-dark-secondary text-xs uppercase tracking-wider flex items-center gap-1.5 mr-1">
                  <Clock size={12} /> Range
                </span>
                {[['24h','Last 24h'], ['7d','Last 7d'], ['30d','Last 30d'], ['all','All Time']].map(([v, label]) => (
                  <FilterBtn key={v} value={v} current={filter.timeRange} onChange={t => setFilter(f => ({ ...f, timeRange: t }))}>
                    {label}
                  </FilterBtn>
                ))}
              </div>
              <p className="text-dark-secondary text-xs mt-1">{rows.length} record{rows.length !== 1 ? 's' : ''} shown</p>
            </div>

            {/* Table */}
            <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden">
              {loading && <LoadingSpinner text="Loading isolation records…" />}
              {error   && <p className="text-accent-red p-6 text-sm">{error}</p>}
              {!loading && !error && rows.length === 0 && (
                <div className="flex flex-col items-center justify-center py-16">
                  <Shield size={48} className="text-dark-secondary mb-3" />
                  <p className="text-dark-secondary">No records match the selected filters</p>
                </div>
              )}
              {!loading && !error && rows.length > 0 && (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead className="bg-dark-sidebar sticky top-0">
                      <tr>
                        {['Device IP','Container','Reason','Isolated','Networks','Method','Status','Actions'].map(h => (
                          <th key={h} className="px-4 py-3 text-left text-dark-secondary font-semibold uppercase tracking-wider whitespace-nowrap">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {rows.map((iso, i) => {
                        const rm = REASON_META[iso.isolation_reason] || { label: iso.isolation_reason, cls: 'bg-gray-800 text-gray-400' };
                        const nets = Array.isArray(iso.networks_disconnected) ? iso.networks_disconnected : iso.network_name ? [iso.network_name] : [];
                        return (
                          <tr key={i} className="border-t border-dark-border tr-hover">
                            <td className="px-4 py-3">
                              <button onClick={() => setSelected(iso)} className="font-mono text-accent-cyan hover:underline">{iso.ip_address}</button>
                            </td>
                            <td className="px-4 py-3 text-white font-semibold">{iso.container_name || '—'}</td>
                            <td className="px-4 py-3">
                              <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${rm.cls}`}>{rm.label}</span>
                            </td>
                            <td className="px-4 py-3">
                              <span className="text-dark-secondary font-mono" title={fmtDateTime(iso.isolation_timestamp)}>{relTime(iso.isolation_timestamp)}</span>
                            </td>
                            <td className="px-4 py-3">
                              <div className="flex flex-wrap gap-1">
                                {nets.length > 0 ? nets.map((net, j) => {
                                  const z = NET_ZONE(net);
                                  return <span key={j} className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${z.cls}`}>{z.label}</span>;
                                }) : <span className="text-dark-secondary">—</span>}
                              </div>
                            </td>
                            <td className="px-4 py-3">
                              <span className="font-mono text-accent-purple text-[11px]">{iso.automation_method || '—'}</span>
                            </td>
                            <td className="px-4 py-3">
                              <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${iso.success ? 'bg-red-900/40 text-red-400' : 'bg-green-900/40 text-green-400'}`}>
                                {iso.success ? 'ISOLATED' : 'RELEASED'}
                              </span>
                            </td>
                            <td className="px-4 py-3">
                              <button onClick={() => setSelected(iso)}
                                className="flex items-center gap-1 text-accent-cyan hover:text-white text-xs transition-colors">
                                Details →
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </>
        )}

      </div>

      {/* Detail Modal */}
      <Modal
        isOpen={!!selected}
        onClose={() => setSelected(null)}
        title={selected ? `Isolation — ${selected.ip_address || selected.device_ip} (${selected.container_name || selected.device_name || '—'})` : ''}
        width="max-w-2xl"
      >
        <IsolationDetail iso={selected} />
      </Modal>
    </div>
  );
}
