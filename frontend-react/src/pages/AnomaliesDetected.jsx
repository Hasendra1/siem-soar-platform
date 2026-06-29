import React, { useState, useEffect, useCallback } from 'react';
import {
  AlertCircle, TrendingUp, Filter, ChevronDown, ChevronUp,
} from 'lucide-react';
import {
  BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts';
import Header from '../components/Header';
import Modal from '../components/common/Modal';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { useWebSocket } from '../hooks/useWebSocket';
import { getAnomaliesDetailed } from '../utils/api';
import { fmtDateTime, severityBg } from '../utils/formatters';

/* ─── helpers ─── */
const SCORE_CLS = (s) => {
  if (s < 0.3) return 'bg-green-900/40 text-green-400';
  if (s < 0.6) return 'bg-yellow-900/40 text-yellow-400';
  if (s < 0.9) return 'bg-orange-900/40 text-orange-400';
  return 'bg-red-900/40 text-red-400';
};
const SCORE_CLR = (s) => {
  if (s < 0.3) return '#00ff88';
  if (s < 0.6) return '#ffaa00';
  if (s < 0.9) return '#ff6600';
  return '#ff0055';
};

const TYPE_CLS = {
  PORT_SCAN:          'bg-purple-900/40 text-purple-400',
  UNAUTHORIZED_READ:  'bg-orange-900/40 text-orange-400',
  MALICIOUS_WRITE:    'bg-red-900/40 text-red-400',
  LATERAL_MOVEMENT:   'bg-yellow-900/40 text-yellow-400',
  DATA_EXFIL:         'bg-pink-900/40 text-pink-400',
  BEHAVIORAL_DEVIATION:'bg-blue-900/40 text-blue-400',
  UNKNOWN:            'bg-gray-800 text-gray-400',
};

const STATUS_CLS = {
  DETECTED:     'bg-red-900/40 text-red-400',
  INVESTIGATING:'bg-orange-900/40 text-orange-400',
  CONTAINED:    'bg-cyan-900/40 text-cyan-400',
  RESOLVED:     'bg-green-900/40 text-green-400',
};

const METHOD_CLS = {
  isolation_forest: 'bg-cyan-900/40 text-cyan-400',
  dbscan:           'bg-green-900/40 text-green-400',
  '2_model_ensemble':'bg-accent-cyan bg-opacity-20 text-accent-cyan',
  ensemble_voting:  'bg-accent-cyan bg-opacity-20 text-accent-cyan',
};

const PIE_COLORS = ['#00d4ff','#00ff88','#ff0055','#ffaa00','#b066ff','#ff6600','#ff9900'];

const TYPES    = ['all','PORT_SCAN','UNAUTHORIZED_READ','MALICIOUS_WRITE','LATERAL_MOVEMENT','DATA_EXFIL'];
const SEVS     = ['all','LOW','MEDIUM','HIGH','CRITICAL'];
const METHODS  = ['all','isolation_forest','dbscan','2_model_ensemble','ensemble_voting'];
const STATUSES = ['all','DETECTED','INVESTIGATING','CONTAINED','RESOLVED'];

const relTime = (ts) => {
  if (!ts) return '—';
  const diff = Date.now() - new Date((ts||'').replace(' ','T')).getTime();
  const m = Math.floor(diff / 60000);
  if (m <  1)   return 'just now';
  if (m <  60)  return `${m}m ago`;
  if (m < 1440) return `${Math.floor(m/60)}h ago`;
  return fmtDateTime(ts);
};

/* Score bar */
const ScoreBar = ({ value, max = 1 }) => {
  const pct = Math.round((value / max) * 100);
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 bg-dark-border rounded-full overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: SCORE_CLR(value) }} />
      </div>
      <span className="font-mono text-[11px] text-white">{value.toFixed(2)}</span>
    </div>
  );
};

/* Model scores panel */
function ModelScores({ scores = {} }) {
  const models = [
    { key: 'isolation_forest', label: 'Isolation Forest' },
    { key: 'dbscan',           label: 'DBSCAN' },
  ].filter(m => scores[m.key] != null);

  if (models.length === 0) return <p className="text-dark-secondary text-xs">Individual model scores not available</p>;

  return (
    <div className="space-y-2">
      {models.map(m => (
        <div key={m.key} className="flex items-center gap-3">
          <p className="text-dark-secondary text-xs w-32 shrink-0">{m.label}</p>
          <div className="flex-1">
            <div className="h-2 bg-dark-border rounded-full overflow-hidden">
              <div className="h-full rounded-full" style={{ width: `${Math.round(scores[m.key]*100)}%`, background: SCORE_CLR(scores[m.key]) }} />
            </div>
          </div>
          <span className="font-mono text-xs text-white w-10 text-right">{scores[m.key].toFixed(2)}</span>
        </div>
      ))}
    </div>
  );
}

/* Detail modal */
function AnomalyDetail({ anomaly }) {
  if (!anomaly) return null;
  return (
    <div className="space-y-5">
      {/* Top strip */}
      <div className="flex items-start gap-4 bg-dark-bg rounded-xl p-4 border border-dark-border">
        <div className="flex-1">
          <div className="flex items-center gap-2 flex-wrap mb-2">
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${TYPE_CLS[anomaly.anomaly_type] || TYPE_CLS.UNKNOWN}`}>{anomaly.anomaly_type}</span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${severityBg(anomaly.severity)}`}>{anomaly.severity}</span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${STATUS_CLS[anomaly.status] || 'bg-gray-800 text-gray-400'}`}>{anomaly.status}</span>
          </div>
          <p className="font-mono text-accent-cyan text-sm">{anomaly.src_ip}</p>
          <p className="text-dark-secondary text-xs mt-1">{relTime(anomaly.timestamp)} — {fmtDateTime(anomaly.timestamp)}</p>
        </div>
        <div className="text-right shrink-0">
          <p className="text-2xl font-bold font-mono" style={{ color: SCORE_CLR(anomaly.anomaly_score) }}>{anomaly.anomaly_score.toFixed(2)}</p>
          <p className="text-dark-secondary text-xs">anomaly score</p>
        </div>
      </div>

      {/* Details */}
      <div>
        <p className="text-dark-secondary text-xs uppercase tracking-wider mb-1">Detection Details</p>
        <p className="text-white text-sm leading-relaxed">{anomaly.details || '—'}</p>
      </div>

      {anomaly.affected_device && (
        <div>
          <p className="text-dark-secondary text-xs uppercase tracking-wider mb-1">Affected Device</p>
          <p className="text-white text-sm font-mono">{anomaly.affected_device}</p>
        </div>
      )}

      {/* Model scores */}
      <div className="bg-dark-bg rounded-xl border border-dark-border p-4">
        <p className="text-dark-secondary text-xs uppercase tracking-wider mb-3">Individual Model Scores</p>
        <ModelScores scores={anomaly.model_scores || {}} />
        <div className="mt-3 pt-3 border-t border-dark-border flex items-center gap-3">
          <p className="text-dark-secondary text-xs">Ensemble Confidence</p>
          <ScoreBar value={anomaly.confidence || anomaly.anomaly_score} />
        </div>
      </div>

      {/* Detection method */}
      <div className="grid grid-cols-2 gap-4">
        <div>
          <p className="text-dark-secondary text-xs uppercase tracking-wider mb-1">Primary Method</p>
          <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${METHOD_CLS[anomaly.detection_method] || 'bg-gray-800 text-gray-400'}`}>
            {anomaly.detection_method || '—'}
          </span>
        </div>
        {anomaly.related_incident_id && (
          <div>
            <p className="text-dark-secondary text-xs uppercase tracking-wider mb-1">Related Incident</p>
            <p className="text-accent-cyan font-mono text-sm">#{anomaly.related_incident_id}</p>
          </div>
        )}
      </div>
    </div>
  );
}

/* ─── Main page ─── */
export default function AnomaliesDetected() {
  const [all,       setAll]      = useState([]);
  const [loading,   setLoading]  = useState(true);
  const [error,     setError]    = useState(null);
  const [filter,    setFilter]   = useState({ type:'all', severity:'all', method:'all', status:'all' });
  const [expanded,  setExpanded] = useState(new Set());
  const [selected,  setSelected] = useState(null);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const res = await getAnomaliesDetailed();
      const data = (res.data?.anomalies || []).sort((a,b) => new Date(b.timestamp) - new Date(a.timestamp));
      setAll(data);
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  useWebSocket({ onAnomalyDetected: (a) => setAll(p => [a, ...p]) });

  /* apply filters */
  const rows = all.filter(r => {
    if (filter.type     !== 'all' && r.anomaly_type       !== filter.type)     return false;
    if (filter.severity !== 'all' && r.severity           !== filter.severity) return false;
    if (filter.method   !== 'all' && r.detection_method   !== filter.method)   return false;
    if (filter.status   !== 'all' && r.status             !== filter.status)   return false;
    return true;
  });

  /* stats */
  const critical  = all.filter(r => r.severity === 'CRITICAL').length;
  const avgScore  = all.length ? (all.reduce((a,r) => a + (r.anomaly_score||0), 0) / all.length).toFixed(3) : '—';
  const avgConf   = all.length ? (all.reduce((a,r) => a + (r.confidence||0),    0) / all.length).toFixed(3) : '—';

  /* chart data */
  const typeCount = Object.entries(
    all.reduce((acc, r) => { acc[r.anomaly_type] = (acc[r.anomaly_type]||0)+1; return acc; }, {})
  ).map(([name, value]) => ({ name: name.replace(/_/g,' '), value }));

  const methodCount = Object.entries(
    all.reduce((acc, r) => { acc[r.detection_method||'unknown'] = (acc[r.detection_method||'unknown']||0)+1; return acc; }, {})
  ).map(([method, count]) => ({ method: method.replace(/_/g,' '), count }));

  const toggleExpand = (id) => setExpanded(p => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n; });

  const FilterBtn = ({ k, value, current, label }) => (
    <button onClick={() => setFilter(f => ({ ...f, [k]: value }))}
      className={`px-2.5 py-1 rounded-lg text-[10px] font-semibold transition-all whitespace-nowrap
        ${current === value ? 'bg-accent-cyan text-dark-sidebar' : 'bg-dark-card border border-dark-border text-dark-secondary hover:text-white'}`}>
      {label}
    </button>
  );

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <Header title="Anomalies Detected" subtitle="ML ensemble anomaly detection with individual model scoring" onRefresh={load} loading={loading} />
      <div className="flex-1 overflow-y-auto p-6 space-y-5">

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label:'Total Anomalies', value: all.length, color:'#ff0055', icon: AlertCircle },
            { label:'Critical',        value: critical,   color:'#ff0055', icon: AlertCircle },
            { label:'Avg Score',       value: avgScore,   color:'#ffaa00', icon: TrendingUp },
            { label:'Avg Confidence',  value: avgConf,    color:'#00ff88', icon: TrendingUp },
          ].map(({ label, value, color, icon: Icon }) => (
            <div key={label} className="bg-dark-card border border-dark-border rounded-xl p-5 card-hover relative overflow-hidden">
              <div className="absolute inset-0 opacity-5 rounded-xl" style={{ background: `radial-gradient(circle at top right,${color},transparent)` }} />
              <div className="relative flex items-start justify-between mb-2">
                <p className="text-dark-secondary text-xs uppercase tracking-wider">{label}</p>
                <Icon size={14} style={{ color }} />
              </div>
              <p className="text-2xl font-bold font-mono" style={{ color }}>{value}</p>
            </div>
          ))}
        </div>

        {/* Charts */}
        {all.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-dark-card border border-dark-border rounded-xl p-5">
              <p className="text-white text-sm font-semibold mb-3">Anomaly Type Distribution</p>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={typeCount} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80}
                    label={({ name, percent }) => `${(percent*100).toFixed(0)}%`} labelLine={false}>
                    {typeCount.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                  </Pie>
                  <Tooltip contentStyle={{ background:'#151b28', border:'1px solid #1f2937', borderRadius:8, fontSize:11 }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="bg-dark-card border border-dark-border rounded-xl p-5">
              <p className="text-white text-sm font-semibold mb-3">Detection Method Usage</p>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={methodCount} margin={{ left:-10 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                  <XAxis dataKey="method" stroke="#555" tick={{ fontSize:9 }} />
                  <YAxis stroke="#555" tick={{ fontSize:9 }} />
                  <Tooltip contentStyle={{ background:'#151b28', border:'1px solid #1f2937', borderRadius:8, fontSize:11 }} />
                  <Bar dataKey="count" fill="#00d4ff" radius={[4,4,0,0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* Filters */}
        <div className="bg-dark-card border border-dark-border rounded-xl p-4 space-y-2.5">
          {[
            { k:'type',     label:'Type',     opts: TYPES,    labels: ['All',...TYPES.slice(1).map(v=>v.replace(/_/g,' '))] },
            { k:'severity', label:'Severity', opts: SEVS,     labels: SEVS.map(v=>v==='all'?'All':v) },
            { k:'method',   label:'Method',   opts: METHODS,  labels: METHODS.map(v=>v==='all'?'All':v.replace(/_/g,' ')) },
            { k:'status',   label:'Status',   opts: STATUSES, labels: STATUSES.map(v=>v==='all'?'All':v) },
          ].map(({ k, label, opts, labels }) => (
            <div key={k} className="flex flex-wrap items-center gap-2">
              <span className="text-dark-secondary text-[10px] uppercase tracking-wider w-14 shrink-0 flex items-center gap-1">
                <Filter size={10} />{label}
              </span>
              {opts.map((v, i) => (
                <FilterBtn key={v} k={k} value={v} current={filter[k]} label={labels[i]} />
              ))}
            </div>
          ))}
          <p className="text-dark-secondary text-xs">{rows.length} anomal{rows.length !== 1 ? 'ies' : 'y'} shown</p>
        </div>

        {/* Table */}
        <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden">
          {loading && <LoadingSpinner text="Loading anomalies…" />}
          {error   && <p className="text-accent-red p-6 text-sm">{error}</p>}
          {!loading && !error && rows.length === 0 && (
            <div className="flex flex-col items-center justify-center py-16">
              <AlertCircle size={40} className="text-dark-secondary mb-3" />
              <p className="text-dark-secondary">No anomalies match the current filters</p>
            </div>
          )}
          {!loading && !error && rows.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead className="bg-dark-sidebar sticky top-0">
                  <tr>
                    <th className="w-8 px-2 py-3" />
                    {['Timestamp','Source IP','Type','Score','Confidence','Method','Severity','Status',''].map(h => (
                      <th key={h} className="px-3 py-3 text-left text-dark-secondary font-semibold uppercase tracking-wider whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rows.map((a) => {
                    const isExp = expanded.has(a.anomaly_id);
                    return (
                      <React.Fragment key={a.anomaly_id}>
                        {/* Main row */}
                        <tr className="border-t border-dark-border tr-hover cursor-pointer" onClick={() => toggleExpand(a.anomaly_id)}>
                          <td className="px-2 py-3 text-center">
                            {isExp ? <ChevronUp size={14} className="text-accent-cyan mx-auto" /> : <ChevronDown size={14} className="text-dark-secondary mx-auto" />}
                          </td>
                          <td className="px-3 py-3 text-dark-secondary font-mono whitespace-nowrap">{fmtDateTime(a.timestamp)}</td>
                          <td className="px-3 py-3 font-mono text-accent-cyan">{a.src_ip}</td>
                          <td className="px-3 py-3">
                            <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${TYPE_CLS[a.anomaly_type] || TYPE_CLS.UNKNOWN}`}>
                              {(a.anomaly_type||'').replace(/_/g,' ')}
                            </span>
                          </td>
                          <td className="px-3 py-3">
                            <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${SCORE_CLS(a.anomaly_score||0)}`}>
                              {(a.anomaly_score||0).toFixed(2)}
                            </span>
                          </td>
                          <td className="px-3 py-3">
                            <ScoreBar value={a.confidence || a.anomaly_score || 0} />
                          </td>
                          <td className="px-3 py-3">
                            <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${METHOD_CLS[a.detection_method] || 'bg-gray-800 text-gray-400'}`}>
                              {(a.detection_method||'—').replace(/_/g,' ')}
                            </span>
                          </td>
                          <td className="px-3 py-3">
                            <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${severityBg(a.severity)}`}>{a.severity}</span>
                          </td>
                          <td className="px-3 py-3">
                            <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${STATUS_CLS[a.status] || 'bg-gray-800 text-gray-400'}`}>{a.status}</span>
                          </td>
                          <td className="px-3 py-3">
                            <button onClick={(e) => { e.stopPropagation(); setSelected(a); }}
                              className="text-accent-cyan hover:text-white text-xs transition-colors">Details →</button>
                          </td>
                        </tr>

                        {/* Expanded row: inline model scores */}
                        {isExp && (
                          <tr className="bg-dark-hover border-t border-dark-border">
                            <td colSpan={10} className="px-6 py-4">
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div>
                                  <p className="text-dark-secondary text-xs uppercase tracking-wider mb-2">Detection Details</p>
                                  <p className="text-white text-xs leading-relaxed">{a.details || '—'}</p>
                                  {a.affected_device && (
                                    <p className="text-dark-secondary text-xs mt-2">Affected: <span className="text-white font-mono">{a.affected_device}</span></p>
                                  )}
                                </div>
                                <div>
                                  <p className="text-dark-secondary text-xs uppercase tracking-wider mb-2">Model Scores</p>
                                  <ModelScores scores={a.model_scores || {}} />
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

      </div>

      <Modal isOpen={!!selected} onClose={() => setSelected(null)}
        title={selected ? `Anomaly #${selected.anomaly_id} — ${selected.anomaly_type}` : ''}
        width="max-w-2xl">
        <AnomalyDetail anomaly={selected} />
      </Modal>
    </div>
  );
}
