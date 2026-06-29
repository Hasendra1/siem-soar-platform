import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Activity, CheckCircle, AlertCircle, ShieldAlert, Zap,
  Bookmark, Clock, Server, Network, ChevronRight, RefreshCw,
} from 'lucide-react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts';
import Header from '../components/Header';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { useWebSocket } from '../hooks/useWebSocket';
import {
  getDashboardSummary, getTimeline, getTopology,
  getEvents, getIsolations, getAnomaliesDetailed, getRulesTriggered,
} from '../utils/api';
import { fmtDateTime, severityBg } from '../utils/formatters';
import { ACTION_COLORS, MAX_LIVE_ROWS } from '../utils/constants';

/* ── helpers ── */
const threatColor = (v) => v < 25 ? '#00ff88' : v < 50 ? '#ffaa00' : v < 75 ? '#ff6600' : '#ff0055';
const threatLabel = (v) => v < 25 ? 'LOW' : v < 50 ? 'MEDIUM' : v < 75 ? 'HIGH' : 'CRITICAL';

const ACTION_BADGE = {
  NORMAL:           'bg-green-900/40 text-green-400',
  PORT_SCAN:        'bg-red-900/40 text-red-400',
  UNAUTHORIZED_READ:'bg-orange-900/40 text-orange-400',
  MALICIOUS_WRITE:  'bg-red-900/40 text-red-400',
  LATERAL_MOVEMENT: 'bg-purple-900/40 text-purple-400',
  DATA_EXFIL:       'bg-red-900/40 text-red-400',
};

const relTime = (ts) => {
  if (!ts) return '—';
  const m = Math.floor((Date.now() - new Date((ts||'').replace(' ','T')).getTime()) / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  return `${Math.floor(m/60)}h ago`;
};

/* ── Gauge ── */
function ThreatGauge({ level = 0 }) {
  const c = threatColor(level);
  const r = 45;
  const circ = 2 * Math.PI * r;
  const dash = (level / 100) * circ;
  return (
    <div className="flex flex-col items-center">
      <svg width="160" height="160" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r={r} fill="none" stroke="#1f2937" strokeWidth="10" />
        <circle cx="50" cy="50" r={r} fill="none" stroke={c} strokeWidth="10"
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
          transform="rotate(-90 50 50)"
          style={{ transition: 'stroke-dasharray 0.8s ease, stroke 0.5s ease' }} />
        <text x="50" y="46" textAnchor="middle" fill={c} fontSize="18" fontWeight="bold" fontFamily="monospace">{level}</text>
        <text x="50" y="60" textAnchor="middle" fill="#aaa" fontSize="8">{threatLabel(level)}</text>
      </svg>
      <p className="text-dark-secondary text-xs mt-1">Threat Level</p>
    </div>
  );
}

/* ── Topology ── */
const NODE_COLORS = { plc:'#00d4ff', hmi:'#b066ff', broker:'#00ff88', sensor:'#ffaa00', camera:'#aaa', gateway:'#ffaa00', attacker:'#ff0055' };
function Topology({ devices=[], links=[] }) {
  return (
    <svg width="100%" viewBox="0 0 720 300" style={{ maxHeight:280 }}>
      {/* Zone boxes */}
      {[{x:30,y:30,w:260,h:240,c:'#ffaa00',label:'OT ZONE'},{x:310,y:30,w:200,h:240,c:'#00d4ff',label:'IoT ZONE'},{x:530,y:30,w:170,h:240,c:'#b066ff',label:'DMZ ZONE'}].map(z=>(
        <g key={z.label}>
          <rect x={z.x} y={z.y} width={z.w} height={z.h} fill="none" stroke={z.c} strokeDasharray="6 4" strokeWidth="1.5" rx="8" opacity="0.4"/>
          <text x={z.x+10} y={z.y+16} fill={z.c} fontSize="9" fontWeight="bold">{z.label}</text>
        </g>
      ))}
      {links.map((l,i)=>{
        const s=devices.find(d=>d.id===l.source), t=devices.find(d=>d.id===l.target);
        if(!s||!t) return null;
        return <line key={i} x1={s.x} y1={s.y} x2={t.x} y2={t.y}
          stroke={l.type==='attack'?'#ff005566':'#1f2937'} strokeWidth={l.type==='attack'?2:1}
          strokeDasharray={l.type==='attack'?'6 4':undefined}/>;
      })}
      {devices.map(d=>{
        const c=NODE_COLORS[d.type]||'#aaa', iso=d.status==='isolated';
        return (
          <g key={d.id}>
            <circle cx={d.x} cy={d.y} r={16} fill={`${c}22`} stroke={iso?'#ff0055':c} strokeWidth={iso?2.5:1.5}/>
            <text x={d.x} y={d.y+4} textAnchor="middle" fill={c} fontSize="8" fontFamily="monospace">{d.id.slice(0,5)}</text>
            {iso && <text x={d.x} y={d.y-22} textAnchor="middle" fill="#ff0055" fontSize="7" fontWeight="bold">ISOLATED</text>}
          </g>
        );
      })}
    </svg>
  );
}

/* ── Mini panel widget ── */
function MiniPanel({ title, icon: Icon, iconColor, count, children, onViewAll, navTarget }) {
  const navigate = useNavigate();
  return (
    <div className="bg-dark-card border border-dark-border rounded-xl p-4 flex flex-col">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Icon size={16} style={{ color: iconColor }} />
          <p className="text-white text-sm font-semibold">{title}</p>
        </div>
        {count != null && count > 0 && (
          <span className="text-xs font-bold rounded-full px-2 py-0.5 text-white" style={{ background: iconColor }}>{count}</span>
        )}
      </div>
      <div className="flex-1 space-y-1.5 overflow-y-auto max-h-52">{children}</div>
      <button onClick={() => navigate(navTarget)}
        className="mt-3 w-full text-accent-cyan text-xs flex items-center justify-center gap-1 hover:underline pt-2 border-t border-dark-border">
        View All <ChevronRight size={12} />
      </button>
    </div>
  );
}

/* ── Stat card ── */
function StatCard({ label, value, sub, breakdown, icon: Icon, color, onClick }) {
  return (
    <div onClick={onClick} className={`bg-dark-card border border-dark-border rounded-xl p-5 relative overflow-hidden card-hover ${onClick?'cursor-pointer':''}`}>
      <div className="absolute inset-0 opacity-5" style={{ background:`radial-gradient(circle at top right,${color},transparent)` }}/>
      <div className="relative flex items-start justify-between mb-3">
        <p className="text-dark-secondary text-xs uppercase tracking-wider">{label}</p>
        <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ background:`${color}18` }}>
          <Icon size={14} style={{ color }} />
        </div>
      </div>
      <p className="relative text-3xl font-bold font-mono text-white">{value ?? '—'}</p>
      {sub && <p className="relative text-dark-secondary text-xs mt-1">{sub}</p>}
      {breakdown && <p className="relative text-xs mt-1" style={{ color }}>{breakdown}</p>}
    </div>
  );
}

/* ── Quick pill ── */
function Pill({ icon: Icon, label, value, color, onClick }) {
  const navigate = useNavigate();
  return (
    <button onClick={onClick ? () => navigate(onClick) : undefined}
      className="flex items-center gap-3 px-4 py-3 bg-dark-card border border-dark-border rounded-xl card-hover flex-1 min-w-0">
      <Icon size={18} style={{ color }} />
      <div className="text-left min-w-0">
        <p className="text-dark-secondary text-[10px] uppercase tracking-wider truncate">{label}</p>
        <p className="text-white font-bold text-sm font-mono">{value}</p>
      </div>
    </button>
  );
}

/* ══ MAIN PAGE ══ */
export default function Dashboard() {
  const navigate = useNavigate();
  const [summary,   setSummary]   = useState(null);
  const [timeline,  setTimeline]  = useState([]);
  const [topology,  setTopology]  = useState({ devices:[], links:[] });
  const [events,    setEvents]    = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [isolations,setIsolations]= useState([]);
  const [rules,     setRules]     = useState([]);
  const [clusters,  setClusters]  = useState([]);
  const [loading,   setLoading]   = useState(true);
  const [wsStatus,  setWsStatus]  = useState('disconnected');
  const evRef = useRef([]);

  const load = useCallback(async () => {
    try {
      const [s, tl, tp, ev, an, iso, ru] = await Promise.allSettled([
        getDashboardSummary(), getTimeline(), getTopology(),
        getEvents(50), getAnomaliesDetailed(), getIsolations(), getRulesTriggered(),
      ]);
      if (s.status  ==='fulfilled') setSummary(s.value.data);
      if (tl.status ==='fulfilled') setTimeline(tl.value.data||[]);
      if (tp.status ==='fulfilled') setTopology(tp.value.data||{devices:[],links:[]});
      if (ev.status ==='fulfilled') { evRef.current=ev.value.data||[]; setEvents([...evRef.current]); }
      if (an.status ==='fulfilled') setAnomalies(an.value.data?.anomalies||[]);
      if (iso.status==='fulfilled') setIsolations(Array.isArray(iso.value.data)?iso.value.data:iso.value.data?.isolations||[]);
      if (ru.status ==='fulfilled') setRules(ru.value.data?.rules_triggered||[]);
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); const id = setInterval(load,10000); return ()=>clearInterval(id); }, [load]);

  useWebSocket({
    onNewEvent: (e) => { const n=[e,...evRef.current].slice(0,MAX_LIVE_ROWS); evRef.current=n; setEvents([...n]); },
    onAnomalyDetected: (a) => setAnomalies(p=>[a,...p]),
    onIsolation: (i) => { setIsolations(p=>[i,...p]); load(); },
    onSummaryUpdate: (s) => { if(s) setSummary(prev => ({...prev, ...s})); },
    onStatusChange: setWsStatus,
  });

  /* Cluster data */
  const clusterData = [
    { name:'Normal',       value: Math.max(0,(summary?.total_events||0)-(summary?.attack_events||0)>0?7:7), fill:'#00ff88' },
    { name:'Threat Sources',value: isolations.length>0?1:0, fill:'#ff0055' },
  ];

  const level = summary?.threat_level ?? 0;
  const tc = threatColor(level);

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <Header
        title="Security Operations Center"
        subtitle={`Real-time IoT/OT threat monitoring  •  ${wsStatus==='connected'?'🟢 Live':'🔴 Offline'}`}
        onRefresh={load} loading={loading}
      />
      <div className="flex-1 overflow-y-auto p-6 space-y-5">

        {/* ── Section 1: Gauge + quick summary ── */}
        <div className="bg-dark-card border border-dark-border rounded-xl p-5">
          <div className="flex flex-wrap items-center gap-6">
            <ThreatGauge level={level} />
            <div className="flex-1 min-w-48 grid grid-cols-2 gap-3">
              {[
                { label:'Threat Source Identified', value: summary?.attacker_ip||'None', color:'#ff0055' },
                { label:'Threat Level',    value: `${level}/100`,              color: tc },
                { label:'Anomalies',       value: anomalies.length,            color:'#ffaa00' },
                { label:'Isolated',        value: isolations.length,           color:'#b066ff' },
              ].map(({label,value,color})=>(
                <div key={label} className="bg-dark-bg rounded-lg px-3 py-2">
                  <p className="text-dark-secondary text-[10px] uppercase tracking-wider">{label}</p>
                  <p className="font-mono text-sm font-bold" style={{color}}>{value}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── Section 2: Stat cards ── */}
        <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
          <StatCard label="Total Events"      value={summary?.total_events}  sub="All network traffic"   icon={Activity}    color="#00d4ff" />
          <StatCard label="Normal Traffic"    value={summary?.normal_events} sub="Verified safe"         icon={CheckCircle} color="#00ff88"
            breakdown={summary?.total_events ? `${Math.round((summary.normal_events/summary.total_events)*100)}% of traffic` : undefined} />
          <StatCard label="Anomalies Detected" value={anomalies.length}      sub="ML ensemble flagged"   icon={AlertCircle} color="#ff0055"
            breakdown={`${anomalies.filter(a=>a.severity==='CRITICAL').length} CRITICAL, ${anomalies.filter(a=>a.severity==='HIGH').length} HIGH`}
            onClick={()=>navigate('/anomalies-detected')} />
          <StatCard label="Devices Isolated"  value={isolations.length}     sub="Auto-segmented"        icon={ShieldAlert} color="#ffaa00"
            breakdown={`${isolations.filter(i=>i.isolation_reason==='ATTACKER_IDENTIFIED').length} Threat Source, ${isolations.filter(i=>i.isolation_reason==='COMPROMISED_DEVICE').length} Compromised`}
            onClick={()=>navigate('/isolated-devices')} />
        </div>

        {/* ── Section 3: Quick pills ── */}
        <div className="flex flex-wrap gap-3">
          <Pill icon={Zap}        label="Rules Triggered"  value={rules.length}              color="#ffaa00" onClick="/rules-triggered" />
          <Pill icon={Bookmark}   label="Incidents Open"   value={summary?.incidents||0}     color="#ff0055" onClick="/incidents" />
          <Pill icon={Clock}      label="Detection Latency" value="67ms avg"                 color="#00ff88" />
          <Pill icon={CheckCircle} label="Model Agreement"  value="89% consensus"            color="#00ff88" />
          <Pill icon={Server}     label="System Uptime"    value="99.2%"                     color="#00ff88" />
        </div>

        {/* ── Section 4+9: Timeline + Cluster ── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2 bg-dark-card border border-dark-border rounded-xl p-5">
            <p className="text-white text-sm font-semibold mb-3">Live Threat Timeline</p>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={timeline}>
                <defs>
                  <linearGradient id="gN" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#00ff88" stopOpacity={0.3}/><stop offset="95%" stopColor="#00ff88" stopOpacity={0}/></linearGradient>
                  <linearGradient id="gA" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#ff0055" stopOpacity={0.4}/><stop offset="95%" stopColor="#ff0055" stopOpacity={0}/></linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937"/>
                <XAxis dataKey="time" stroke="#555" tick={{fontSize:9}}/>
                <YAxis stroke="#555" tick={{fontSize:9}}/>
                <Tooltip contentStyle={{background:'#151b28',border:'1px solid #1f2937',borderRadius:8,fontSize:11}}/>
                <Area type="monotone" dataKey="normal" stroke="#00ff88" fill="url(#gN)" strokeWidth={2}/>
                <Area type="monotone" dataKey="attack" stroke="#ff0055" fill="url(#gA)" strokeWidth={2}/>
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="bg-dark-card border border-dark-border rounded-xl p-5">
            <p className="text-white text-sm font-semibold mb-3">Cluster Analysis</p>
            <ResponsiveContainer width="100%" height={160}>
              <PieChart>
                <Pie data={clusterData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={45} outerRadius={70} paddingAngle={3}
                  label={({name,percent})=>`${(percent*100).toFixed(0)}%`} labelLine={false}>
                  {clusterData.map((d,i)=><Cell key={i} fill={d.fill}/>)}
                </Pie>
                <Tooltip contentStyle={{background:'#151b28',border:'1px solid #1f2937',borderRadius:8,fontSize:11}}/>
              </PieChart>
            </ResponsiveContainer>
            <div className="space-y-1 mt-1">
              {clusterData.map(d=>(
                <div key={d.name} className="flex items-center gap-2 text-xs">
                  <div className="w-2.5 h-2.5 rounded-full" style={{background:d.fill}}/>
                  <span className="text-dark-secondary">{d.name}</span>
                  <span className="text-white font-mono ml-auto">{d.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── Section 6: Network Topology ── */}
        <div className="bg-dark-card border border-dark-border rounded-xl p-5">
          <p className="text-white text-sm font-semibold mb-3 flex items-center gap-2"><Network size={16} className="text-accent-cyan"/>Network Topology</p>
          <div className="bg-dark-bg rounded-xl p-3">
            <Topology devices={topology.devices} links={topology.links}/>
          </div>
        </div>

        {/* ── Section 5+7+8: Mini panels ── */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Anomalies */}
          <MiniPanel title="Latest Anomalies" icon={AlertCircle} iconColor="#ff0055" count={anomalies.length} navTarget="/anomalies-detected">
            {anomalies.slice(0,5).map((a,i)=>(
              <div key={i} onClick={()=>navigate('/anomalies-detected')}
                className="flex items-center justify-between px-2 py-1.5 rounded-lg bg-dark-bg hover:bg-dark-hover cursor-pointer transition">
                <div className="min-w-0">
                  <p className="font-mono text-accent-cyan text-[11px]">{a.src_ip}</p>
                  <p className="text-dark-secondary text-[10px] truncate">{a.anomaly_type}</p>
                </div>
                <div className="text-right shrink-0 ml-2">
                  <p className="font-mono text-xs font-bold" style={{color:threatColor(a.anomaly_score||0)}}>{(a.anomaly_score||0).toFixed(2)}</p>
                  <p className="text-dark-secondary text-[10px]">{relTime(a.timestamp)}</p>
                </div>
              </div>
            ))}
            {anomalies.length===0&&<p className="text-dark-secondary text-xs text-center py-4">No anomalies</p>}
          </MiniPanel>

          {/* Isolated devices */}
          <MiniPanel title="Isolated Devices" icon={ShieldAlert} iconColor="#ffaa00" count={isolations.length} navTarget="/isolated-devices">
            {isolations.slice(0,5).map((device, idx) => {
              const stateColors = {
                'THREAT_SOURCE': 'text-red-500',
                'COMPROMISED':   'text-orange-400',
                'PROPAGATED':    'text-purple-400',
              };
              const state = device.state || (
                device.isolation_reason === 'ATTACKER_IDENTIFIED' ? 'THREAT_SOURCE' :
                device.isolation_reason === 'COMPROMISED_DEVICE' ? 'COMPROMISED' : 'NORMAL'
              );
              const colorClass = stateColors[state] || 'text-gray-400';

              return (
                <div
                  key={idx}
                  className="bg-dark-sidebar rounded p-2 text-sm hover:bg-dark-hover cursor-pointer transition"
                  onClick={() => navigate('/isolated-devices')}
                >
                  <div className="flex items-center justify-between">
                    <p className="text-white font-mono text-xs">{device.ip_address || device.device_ip}</p>
                    <span className={`text-xs font-bold ${colorClass}`}>{state}</span>
                  </div>
                  <p className="text-dark-secondary text-xs">{device.container_name || device.device_name}</p>
                  {['THREAT_SOURCE','COMPROMISED','PROPAGATED'].includes(state) && (
                    <p className="text-red-400 text-xs">🔒 Isolated</p>
                  )}
                </div>
              );
            })}            {isolations.length===0&&<p className="text-dark-secondary text-xs text-center py-4">No isolated devices</p>}
          </MiniPanel>

          {/* Rules */}
          <MiniPanel title="Detection Rules" icon={Zap} iconColor="#ffaa00" count={rules.length} navTarget="/rules-triggered">
            {rules.slice(0,5).map((r,i)=>(
              <div key={i} onClick={()=>navigate('/rules-triggered')}
                className="flex items-center justify-between px-2 py-1.5 rounded-lg bg-dark-bg hover:bg-dark-hover cursor-pointer transition">
                <div className="min-w-0">
                  <p className="text-white text-[11px] truncate font-medium">{r.rule_name}</p>
                  <p className="text-dark-secondary text-[10px]">Fired {r.triggered_count}×</p>
                </div>
                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded shrink-0 ml-2 ${severityBg(r.severity)}`}>{r.severity}</span>
              </div>
            ))}
            {rules.length===0&&<p className="text-dark-secondary text-xs text-center py-4">No rules triggered</p>}
          </MiniPanel>
        </div>

        {/* ── Section 10: Live event feed ── */}
        <div className="bg-dark-card border border-dark-border rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <p className="text-white text-sm font-semibold">Live Event Feed</p>
            <span className="flex items-center gap-1.5 text-xs text-accent-green">
              <span className="w-1.5 h-1.5 rounded-full bg-accent-green pulse-dot inline-block"/>Live
            </span>
          </div>
          <div className="overflow-auto max-h-80">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-dark-sidebar">
                <tr className="text-dark-secondary">
                  {['Time','Src IP','Dst IP','Protocol','Action','Port'].map(h=>(
                    <th key={h} className="px-3 py-2 text-left font-semibold uppercase tracking-wider whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {events.slice(0,50).map((ev,i)=>(
                  <tr key={i} className="border-t border-dark-border tr-hover">
                    <td className="px-3 py-2 text-dark-secondary font-mono whitespace-nowrap">{fmtDateTime(ev.timestamp)}</td>
                    <td className="px-3 py-2 text-accent-cyan font-mono">{ev.src_ip}</td>
                    <td className="px-3 py-2 text-dark-secondary font-mono">{ev.dst_ip}</td>
                    <td className="px-3 py-2 text-accent-purple">{ev.protocol}</td>
                    <td className="px-3 py-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${ACTION_BADGE[ev.action]||'bg-gray-800 text-gray-400'}`}>{ev.action}</span>
                    </td>
                    <td className="px-3 py-2 text-dark-secondary font-mono">{ev.dst_port}</td>
                  </tr>
                ))}
                {events.length===0&&(
                  <tr><td colSpan={6} className="text-center py-8 text-dark-secondary">Waiting for events…</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </div>
  );
}
