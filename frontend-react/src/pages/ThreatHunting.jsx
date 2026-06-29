import React, { useState, useCallback } from 'react';
import { Search, Plus, Trash2, Download, Filter, ChevronDown, ChevronUp, Zap } from 'lucide-react';
import { BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import Header from '../components/Header';
import Modal from '../components/common/Modal';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { queryEvents } from '../utils/api';
import { fmtDateTime, severityBg } from '../utils/formatters';

const SEV_CLR = { LOW:'#00ff88', MEDIUM:'#ffaa00', HIGH:'#ff6600', CRITICAL:'#ff0055' };
const PIE_COLORS = ['#00d4ff','#b066ff','#ffaa00','#ff6600','#00ff88','#ff0055'];
const ACTION_CLS = {
  NORMAL:           'bg-green-900/40 text-green-400',
  PORT_SCAN:        'bg-purple-900/40 text-purple-400',
  UNAUTHORIZED_READ:'bg-orange-900/40 text-orange-400',
  MALICIOUS_WRITE:  'bg-red-900/40 text-red-400',
  LATERAL_MOVEMENT: 'bg-yellow-900/40 text-yellow-400',
  DATA_EXFIL:       'bg-red-900/40 text-red-400',
};

const EMPTY_FILTERS = { src_ip:'', dst_ip:'', protocol:'all', action:'all', severity:[], zone:[], timeStart:'', timeEnd:'' };
const QUICK_PRESETS = [
  { label:'Port Scans',         f:{ action:'PORT_SCAN' } },
  { label:'Eng-WS Activity',    f:{ src_ip:'192.168.10.50' } },
  { label:'Modbus Traffic',     f:{ protocol:'Modbus' } },
  { label:'High Severity',      f:{ severity:['HIGH','CRITICAL'] } },
  { label:'Unauthorized Access',f:{ action:'UNAUTHORIZED_READ' } },
  { label:'OT Zone',            f:{ zone:['OT'] } },
];

function ExportBtn({ results }) {
  const csv = () => {
    const rows = [['Timestamp','Src IP','Dst IP','Protocol','Action','Severity','Zone'],
      ...results.map(r=>[r.timestamp,r.src_ip,r.dst_ip,r.protocol,r.action,r.severity,r.zone||''])];
    const blob = new Blob([rows.map(r=>r.join(',')).join('\n')], {type:'text/csv'});
    const a = document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=`hunt-${Date.now()}.csv`; a.click();
  };
  const json = () => {
    const blob = new Blob([JSON.stringify(results,null,2)], {type:'application/json'});
    const a = document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=`hunt-${Date.now()}.json`; a.click();
  };
  return (
    <div className="flex items-center gap-2">
      <Download size={13} className="text-dark-secondary"/>
      <button onClick={csv}  className="text-accent-cyan text-xs hover:underline">CSV</button>
      <span className="text-dark-border">|</span>
      <button onClick={json} className="text-accent-cyan text-xs hover:underline">JSON</button>
    </div>
  );
}

export default function ThreatHunting() {
  const [filters,   setFilters]   = useState(EMPTY_FILTERS);
  const [results,   setResults]   = useState([]);
  const [loading,   setLoading]   = useState(false);
  const [done,      setDone]      = useState(false);
  const [elapsed,   setElapsed]   = useState(0);
  const [expanded,  setExpanded]  = useState(new Set());
  const [saved,     setSaved]     = useState([]);
  const [saveModal, setSaveModal] = useState(false);
  const [qName,     setQName]     = useState('');

  const execSearch = useCallback(async () => {
    setLoading(true);
    const t0 = Date.now();
    try {
      const body = { filters, limit: 1000 };
      const res = await queryEvents(body);
      setResults(res.data?.results || res.data?.events || []);
      setDone(true);
    } catch(e) {
      console.error(e);
      setResults([]);
      setDone(true);
    } finally {
      setElapsed(Date.now()-t0);
      setLoading(false);
    }
  }, [filters]);

  const applyPreset = (preset) => setFilters(f=>({...EMPTY_FILTERS,...f,...preset.f}));

  const toggleExpand = (i) => setExpanded(p=>{const n=new Set(p);n.has(i)?n.delete(i):n.add(i);return n;});

  const saveQuery = () => {
    if (!qName.trim()) return;
    setSaved(p=>[...p,{id:Date.now(),name:qName,filters:{...filters},ts:new Date().toLocaleString()}]);
    setQName(''); setSaveModal(false);
  };

  /* chart data */
  const protoDist = Object.entries(results.reduce((a,r)=>{a[r.protocol||'?']=(a[r.protocol||'?']||0)+1;return a;},{}))
    .map(([name,value])=>({name,value}));
  const sevDist = ['LOW','MEDIUM','HIGH','CRITICAL'].map(s=>({name:s,value:results.filter(r=>r.severity===s).length})).filter(x=>x.value>0);

  const F = ({label, children}) => (
    <div>
      <label className="text-dark-secondary text-[10px] uppercase tracking-wider block mb-1">{label}</label>
      {children}
    </div>
  );

  const inp = "w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-1.5 text-white text-xs focus:border-accent-cyan outline-none";
  const sel = "w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-1.5 text-white text-xs";

  const chk = (arr, val, field) => {
    const next = arr.includes(val) ? arr.filter(x=>x!==val) : [...arr,val];
    setFilters(f=>({...f,[field]:next}));
  };

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <Header title="Threat Hunting" subtitle="Advanced search across all network events"/>
      <div className="flex-1 overflow-y-auto p-6 space-y-5">

        {/* Quick presets */}
        <div className="flex flex-wrap gap-2">
          {QUICK_PRESETS.map(p=>(
            <button key={p.label} onClick={()=>applyPreset(p)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-dark-card border border-dark-border rounded-lg text-xs text-dark-secondary hover:text-accent-cyan hover:border-accent-cyan transition">
              <Zap size={11}/>{p.label}
            </button>
          ))}
          <button onClick={()=>setFilters(EMPTY_FILTERS)}
            className="px-3 py-1.5 bg-dark-card border border-dark-border rounded-lg text-xs text-dark-secondary hover:text-white transition ml-auto">
            Clear All
          </button>
        </div>

        {/* Search builder */}
        <div className="bg-dark-card border border-dark-border rounded-xl p-5 space-y-4">
          <p className="text-white text-sm font-semibold flex items-center gap-2"><Filter size={14} className="text-accent-cyan"/>Build Query</p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <F label="Source IP"><input className={inp} value={filters.src_ip} onChange={e=>setFilters(f=>({...f,src_ip:e.target.value}))} placeholder="192.168.10.50"/></F>
            <F label="Destination IP"><input className={inp} value={filters.dst_ip} onChange={e=>setFilters(f=>({...f,dst_ip:e.target.value}))} placeholder="192.168.10.10"/></F>
            <F label="Protocol">
              <select className={sel} value={filters.protocol} onChange={e=>setFilters(f=>({...f,protocol:e.target.value}))}>
                {['all','TCP','UDP','Modbus','MQTT','HTTP'].map(v=><option key={v} value={v}>{v==='all'?'All Protocols':v}</option>)}
              </select>
            </F>
            <F label="Action">
              <select className={sel} value={filters.action} onChange={e=>setFilters(f=>({...f,action:e.target.value}))}>
                {['all','NORMAL','PORT_SCAN','UNAUTHORIZED_READ','MALICIOUS_WRITE','LATERAL_MOVEMENT','DATA_EXFIL'].map(v=>(
                  <option key={v} value={v}>{v==='all'?'All Actions':v.replace(/_/g,' ')}</option>
                ))}
              </select>
            </F>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <F label="Time Start"><input type="datetime-local" className={inp} value={filters.timeStart} onChange={e=>setFilters(f=>({...f,timeStart:e.target.value}))}/></F>
            <F label="Time End"><input type="datetime-local" className={inp} value={filters.timeEnd} onChange={e=>setFilters(f=>({...f,timeEnd:e.target.value}))}/></F>
            <F label="Severity">
              <div className="flex flex-wrap gap-2 pt-0.5">
                {['LOW','MEDIUM','HIGH','CRITICAL'].map(s=>(
                  <label key={s} className="flex items-center gap-1 text-white text-[11px] cursor-pointer">
                    <input type="checkbox" checked={filters.severity.includes(s)} onChange={()=>chk(filters.severity,s,'severity')} className="w-3 h-3 accent-accent-cyan"/>
                    <span style={{color:SEV_CLR[s]}}>{s}</span>
                  </label>
                ))}
              </div>
            </F>
            <F label="Zone">
              <div className="flex flex-wrap gap-2 pt-0.5">
                {['OT','IoT','DMZ'].map(z=>(
                  <label key={z} className="flex items-center gap-1 text-white text-[11px] cursor-pointer">
                    <input type="checkbox" checked={filters.zone.includes(z)} onChange={()=>chk(filters.zone,z,'zone')} className="w-3 h-3 accent-accent-cyan"/>
                    {z}
                  </label>
                ))}
              </div>
            </F>
          </div>
          <div className="flex items-center gap-3 pt-2">
            <button onClick={execSearch} disabled={loading}
              className="flex items-center gap-2 bg-accent-cyan text-dark-sidebar px-5 py-2 rounded-lg text-sm font-bold hover:opacity-90 disabled:opacity-50 transition">
              <Search size={16}/>{loading?'Searching…':'Search'}
            </button>
            <button onClick={()=>setSaveModal(true)} disabled={!done}
              className="flex items-center gap-1.5 px-4 py-2 border border-dark-border rounded-lg text-xs text-dark-secondary hover:text-white hover:bg-dark-hover disabled:opacity-40 transition">
              <Plus size={13}/>Save Query
            </button>
            {done && <ExportBtn results={results}/>}
            {done && <span className="text-dark-secondary text-xs font-mono ml-auto">{results.length} results · {elapsed}ms</span>}
          </div>
        </div>

        {/* Saved queries */}
        {saved.length>0 && (
          <div className="bg-dark-card border border-dark-border rounded-xl p-4">
            <p className="text-white text-sm font-semibold mb-3">Saved Queries ({saved.length})</p>
            <div className="space-y-2">
              {saved.map(q=>(
                <div key={q.id} className="flex items-center justify-between bg-dark-bg rounded-lg px-3 py-2 border border-dark-border">
                  <button onClick={()=>{setFilters(q.filters);}} className="text-accent-cyan text-xs hover:underline text-left">{q.name}</button>
                  <div className="flex items-center gap-3">
                    <span className="text-dark-secondary text-[10px]">{q.ts}</span>
                    <button onClick={()=>setSaved(p=>p.filter(x=>x.id!==q.id))} className="text-red-400 hover:text-white"><Trash2 size={13}/></button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Loading */}
        {loading && <LoadingSpinner text="Executing query…"/>}

        {/* Results */}
        {!loading && done && (
          <>
            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[['Total Results',results.length,'#00d4ff'],['Critical',results.filter(r=>r.severity==='CRITICAL').length,'#ff0055'],['Unique Src IPs',[...new Set(results.map(r=>r.src_ip))].length,'#ffaa00'],['Query Time',`${elapsed}ms`,'#00ff88']].map(([l,v,c])=>(
                <div key={l} className="bg-dark-card border border-dark-border rounded-xl p-4">
                  <p className="text-dark-secondary text-xs uppercase tracking-wider mb-1">{l}</p>
                  <p className="text-2xl font-bold font-mono" style={{color:c}}>{v}</p>
                </div>
              ))}
            </div>

            {/* Charts */}
            {results.length>0 && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-dark-card border border-dark-border rounded-xl p-5">
                  <p className="text-white text-sm font-semibold mb-3">Protocol Distribution</p>
                  <ResponsiveContainer width="100%" height={180}>
                    <PieChart>
                      <Pie data={protoDist} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={70}
                        label={({name,percent})=>`${name} ${(percent*100).toFixed(0)}%`} labelLine={false}>
                        {protoDist.map((_,i)=><Cell key={i} fill={PIE_COLORS[i%PIE_COLORS.length]}/>)}
                      </Pie>
                      <Tooltip contentStyle={{background:'#151b28',border:'1px solid #1f2937',borderRadius:8,fontSize:11}}/>
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="bg-dark-card border border-dark-border rounded-xl p-5">
                  <p className="text-white text-sm font-semibold mb-3">Severity Distribution</p>
                  <ResponsiveContainer width="100%" height={180}>
                    <BarChart data={sevDist} margin={{left:-10}}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1f2937"/>
                      <XAxis dataKey="name" stroke="#555" tick={{fontSize:10}}/>
                      <YAxis stroke="#555" tick={{fontSize:10}}/>
                      <Tooltip contentStyle={{background:'#151b28',border:'1px solid #1f2937',borderRadius:8,fontSize:11}}/>
                      <Bar dataKey="value" radius={[4,4,0,0]}>
                        {sevDist.map((d,i)=><Cell key={i} fill={SEV_CLR[d.name]||'#aaa'}/>)}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}

            {/* Results table */}
            <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden">
              <div className="overflow-x-auto max-h-[480px] overflow-y-auto">
                <table className="w-full text-xs">
                  <thead className="bg-dark-sidebar sticky top-0">
                    <tr>
                      <th className="w-8 px-2 py-3"/>
                      {['Timestamp','Src IP','Dst IP','Protocol','Action','Severity','Zone','Port'].map(h=>(
                        <th key={h} className="px-3 py-3 text-left text-dark-secondary font-semibold uppercase tracking-wider whitespace-nowrap">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {results.length===0?(
                      <tr><td colSpan={9} className="text-center py-12 text-dark-secondary">No results found — try adjusting your filters</td></tr>
                    ):results.slice(0,500).map((r,i)=>(
                      <React.Fragment key={i}>
                        <tr className="border-t border-dark-border tr-hover cursor-pointer" onClick={()=>toggleExpand(i)}>
                          <td className="px-2 py-2 text-center">{expanded.has(i)?<ChevronUp size={13} className="text-accent-cyan mx-auto"/>:<ChevronDown size={13} className="text-dark-secondary mx-auto"/>}</td>
                          <td className="px-3 py-2 text-dark-secondary font-mono whitespace-nowrap">{fmtDateTime(r.timestamp)}</td>
                          <td className="px-3 py-2">
                            <button className="text-accent-cyan font-mono hover:underline" onClick={e=>{e.stopPropagation();setFilters(f=>({...f,src_ip:r.src_ip}));}}>
                              {r.src_ip}
                            </button>
                          </td>
                          <td className="px-3 py-2 text-dark-secondary font-mono">{r.dst_ip}</td>
                          <td className="px-3 py-2 text-accent-purple">{r.protocol}</td>
                          <td className="px-3 py-2">
                            <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${ACTION_CLS[r.action]||'bg-gray-800 text-gray-400'}`}>{r.action}</span>
                          </td>
                          <td className="px-3 py-2"><span className={`px-2 py-0.5 rounded font-bold text-[10px] ${severityBg(r.severity)}`}>{r.severity}</span></td>
                          <td className="px-3 py-2 text-dark-secondary">{r.zone||'—'}</td>
                          <td className="px-3 py-2 text-dark-secondary font-mono">{r.dst_port||'—'}</td>
                        </tr>
                        {expanded.has(i)&&(
                          <tr className="bg-dark-hover border-t border-dark-border">
                            <td colSpan={9} className="px-6 py-3">
                              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                                {[['Event ID',r.event_id||'—'],['Payload Size',(r.payload_size||r.length||'—')+' bytes'],['Dst Port',r.dst_port||'—'],['Zone',r.zone||'—']].map(([l,v])=>(
                                  <div key={l}><p className="text-dark-secondary uppercase tracking-wider text-[10px]">{l}</p><p className="text-white font-mono">{v}</p></div>
                                ))}
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
              {results.length>500&&<p className="text-dark-secondary text-xs text-center py-2">Showing 500 of {results.length} results</p>}
            </div>
          </>
        )}

      </div>

      <Modal isOpen={saveModal} onClose={()=>{setSaveModal(false);setQName('');}} title="Save Query" width="max-w-sm">
        <div className="space-y-4">
          <div>
            <label className="text-dark-secondary text-xs uppercase tracking-wider block mb-1">Query Name</label>
            <input value={qName} onChange={e=>setQName(e.target.value)} placeholder="e.g., Suspicious lateral movement"
              className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white text-sm focus:border-accent-cyan outline-none"/>
          </div>
          <div className="flex gap-3 justify-end">
            <button onClick={()=>{setSaveModal(false);setQName('');}} className="px-4 py-2 border border-dark-border rounded-lg text-dark-secondary hover:text-white text-sm transition">Cancel</button>
            <button onClick={saveQuery} disabled={!qName.trim()} className="px-4 py-2 bg-accent-cyan text-dark-sidebar rounded-lg font-bold text-sm hover:opacity-90 disabled:opacity-50 transition">Save</button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
