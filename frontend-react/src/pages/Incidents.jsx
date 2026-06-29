import React, { useState, useEffect, useCallback } from 'react';
import { Bookmark, Plus, Trash2, Eye, AlertCircle, Clock, FileText, Filter, Search } from 'lucide-react';
import Header from '../components/Header';
import Modal from '../components/common/Modal';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { getIncidentList, getIncidentById, createIncident, updateIncident, deleteIncident } from '../utils/api';
import { fmtDateTime, severityBg } from '../utils/formatters';

const STATUS_CLS = {
  OPEN:          'bg-red-900/40 text-red-400',
  INVESTIGATING: 'bg-orange-900/40 text-orange-400',
  CONTAINED:     'bg-cyan-900/40 text-cyan-400',
  RESOLVED:      'bg-green-900/40 text-green-400',
};
const EVT_CLR = { PORT_SCAN:'#b066ff', UNAUTHORIZED_READ:'#ffaa00', MALICIOUS_WRITE:'#ff0055', LATERAL_MOVEMENT:'#ff6600', DATA_EXFIL:'#ff0055', ISOLATION:'#00ff88' };
const relTime = (ts) => { if(!ts) return '—'; const m=Math.floor((Date.now()-new Date((ts||'').replace(' ','T')).getTime())/60000); return m<1?'just now':m<60?`${m}m ago`:m<1440?`${Math.floor(m/60)}h ago`:fmtDateTime(ts); };
const EMPTY = { incident_name:'', severity:'HIGH', description:'', assigned_to:'Security Team', status:'OPEN' };

function IncidentTimeline({ events=[] }) {
  if (!events.length) return <p className="text-dark-secondary text-xs text-center py-4">No events recorded</p>;
  return (
    <div className="relative pl-5">
      <div className="absolute left-1.5 top-0 bottom-0 w-px bg-dark-border"/>
      {events.map((ev,i) => {
        const c = EVT_CLR[ev.event_type]||'#aaa';
        return (
          <div key={i} className="relative mb-3 last:mb-0">
            <div className="absolute -left-3.5 w-2.5 h-2.5 rounded-full border-2 border-dark-card" style={{background:c,top:'0.3rem'}}/>
            <div className="bg-dark-bg rounded-lg border border-dark-border p-3">
              <div className="flex items-start justify-between mb-1">
                <span className="text-[10px] font-bold px-1.5 py-0.5 rounded" style={{background:`${c}22`,color:c}}>{ev.event_type}</span>
                <span className="text-dark-secondary text-[10px] font-mono">{fmtDateTime(ev.timestamp)}</span>
              </div>
              <p className="text-white text-xs">{ev.details}</p>
              {ev.src_ip && <p className="text-accent-cyan font-mono text-[10px] mt-0.5">{ev.src_ip}</p>}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function IncidentDetail({ detail, onUpdate }) {
  if (!detail) return null;
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <p className="text-dark-secondary text-xs uppercase tracking-wider mb-1">Severity</p>
          <select value={detail.severity} onChange={e=>onUpdate('severity',e.target.value)}
            className={`w-full px-3 py-2 rounded text-xs font-bold border border-dark-border bg-dark-bg ${severityBg(detail.severity)}`}>
            {['LOW','MEDIUM','HIGH','CRITICAL'].map(v=><option key={v}>{v}</option>)}
          </select>
        </div>
        <div>
          <p className="text-dark-secondary text-xs uppercase tracking-wider mb-1">Status</p>
          <select value={detail.status} onChange={e=>onUpdate('status',e.target.value)}
            className={`w-full px-3 py-2 rounded text-xs font-bold border border-dark-border bg-dark-bg ${STATUS_CLS[detail.status]||''}`}>
            {['OPEN','INVESTIGATING','CONTAINED','RESOLVED'].map(v=><option key={v}>{v}</option>)}
          </select>
        </div>
      </div>
      <div>
        <p className="text-dark-secondary text-xs uppercase tracking-wider mb-1">Description</p>
        <p className="text-white text-sm leading-relaxed">{detail.description||'—'}</p>
      </div>
      <div className="grid grid-cols-2 gap-3">
        {[['Assigned To',detail.assigned_to||'—'],['Created',fmtDateTime(detail.created_timestamp)],['Updated',fmtDateTime(detail.updated_timestamp)],['Evidence',detail.evidence_count??0]].map(([l,v])=>(
          <div key={l} className="bg-dark-bg rounded-lg p-3">
            <p className="text-dark-secondary text-[10px] uppercase tracking-wider">{l}</p>
            <p className="text-white text-sm mt-0.5">{v}</p>
          </div>
        ))}
      </div>
      {detail.related_device_ips?.length>0 && (
        <div>
          <p className="text-dark-secondary text-xs uppercase tracking-wider mb-2">Related Devices</p>
          <div className="flex flex-wrap gap-2">
            {detail.related_device_ips.map((ip,i)=>(
              <span key={i} className="px-2.5 py-1 bg-dark-bg border border-dark-border rounded-lg font-mono text-xs text-accent-cyan">{ip}</span>
            ))}
          </div>
        </div>
      )}
      <div>
        <p className="text-white text-sm font-semibold mb-3">Event Timeline</p>
        <div className="max-h-56 overflow-y-auto pr-1"><IncidentTimeline events={detail.related_events||[]}/></div>
      </div>
      {detail.evidence?.length>0 && (
        <div>
          <p className="text-white text-sm font-semibold mb-3">Evidence ({detail.evidence.length})</p>
          <div className="space-y-2 max-h-40 overflow-y-auto">
            {detail.evidence.map((ev,i)=>(
              <div key={i} className="flex items-start gap-3 bg-dark-bg border border-dark-border rounded-xl p-3">
                <FileText size={14} className="text-accent-cyan mt-0.5 shrink-0"/>
                <div className="flex-1 min-w-0">
                  <p className="text-white text-xs font-semibold">{ev.description}</p>
                  <p className="text-dark-secondary text-[10px]">{fmtDateTime(ev.timestamp)} · {ev.type}</p>
                </div>
                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded shrink-0 ${severityBg(ev.severity)}`}>{ev.severity}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function Incidents() {
  const [all, setAll]           = useState([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);
  const [detail, setDetail]     = useState(null);
  const [form, setForm]         = useState(EMPTY);
  const [filters, setFilters]   = useState({ severity:'all', status:'all', search:'' });
  const [showCreate, setShowCreate] = useState(false);
  const [saving, setSaving]     = useState(false);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const res = await getIncidentList();
      setAll((res.data?.incidents||[]).sort((a,b)=>new Date(b.created_timestamp)-new Date(a.created_timestamp)));
    } catch(e) { setError(e.message); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const rows = all.filter(r => {
    if (filters.severity!=='all' && r.severity!==filters.severity) return false;
    if (filters.status!=='all'   && r.status!==filters.status)     return false;
    if (filters.search) { const q=filters.search.toLowerCase(); return r.incident_name?.toLowerCase().includes(q)||String(r.incident_id).includes(q); }
    return true;
  });

  const openDetail = async (inc) => {
    try { const res=await getIncidentById(inc.incident_id); setDetail(res.data?.incident||inc); }
    catch { setDetail(inc); }
  };

  const handleUpdate = async (field, value) => {
    if (!detail) return;
    setDetail(d=>({...d,[field]:value}));
    try { await updateIncident(detail.incident_id,{[field]:value}); setAll(p=>p.map(i=>i.incident_id===detail.incident_id?{...i,[field]:value}:i)); }
    catch(e) { console.error(e); }
  };

  const handleCreate = async () => {
    if (!form.incident_name.trim()) return;
    setSaving(true);
    try {
      const res = await createIncident(form);
      const inc = res.data?.incident||res.data;
      if (inc) setAll(p=>[inc,...p]);
      setForm(EMPTY); setShowCreate(false); load();
    } catch(e) { alert('Create failed: '+e.message); }
    finally { setSaving(false); }
  };

  const handleDelete = async (id, e) => {
    e.stopPropagation();
    if (!window.confirm('Delete this incident?')) return;
    try { await deleteIncident(id); setAll(p=>p.filter(i=>i.incident_id!==id)); }
    catch(e) { alert('Delete failed: '+e.message); }
  };

  const FB = ({k,value,label,cur}) => (
    <button onClick={()=>setFilters(f=>({...f,[k]:value}))}
      className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-all ${cur===value?'bg-accent-cyan text-dark-sidebar':'bg-dark-card border border-dark-border text-dark-secondary hover:text-white'}`}>{label}</button>
  );

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <Header title="Incidents" subtitle="Security incident management and tracking" onRefresh={load} loading={loading}/>
      <div className="flex-1 overflow-y-auto p-6 space-y-5">

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[['Total',all.length,'#00d4ff',Bookmark],['Open',all.filter(i=>i.status==='OPEN').length,'#ff0055',AlertCircle],['Critical',all.filter(i=>i.severity==='CRITICAL').length,'#ff0055',AlertCircle],['Resolved',all.filter(i=>i.status==='RESOLVED').length,'#00ff88',Clock]].map(([l,v,c,Ic])=>(
            <div key={l} className="bg-dark-card border border-dark-border rounded-xl p-5 card-hover relative overflow-hidden">
              <div className="absolute inset-0 opacity-5 rounded-xl" style={{background:`radial-gradient(circle at top right,${c},transparent)`}}/>
              <div className="relative flex items-start justify-between mb-2">
                <p className="text-dark-secondary text-xs uppercase tracking-wider">{l}</p>
                <Ic size={14} style={{color:c}}/>
              </div>
              <p className="relative text-2xl font-bold font-mono" style={{color:c}}>{v}</p>
            </div>
          ))}
        </div>

        <div className="bg-dark-card border border-dark-border rounded-xl p-4 space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-2 flex-1 min-w-40">
              <Search size={13} className="text-dark-secondary shrink-0"/>
              <input value={filters.search} onChange={e=>setFilters(f=>({...f,search:e.target.value}))}
                placeholder="Search by name or ID…"
                className="flex-1 bg-dark-bg border border-dark-border rounded-lg px-3 py-1.5 text-white text-xs outline-none focus:border-accent-cyan"/>
            </div>
            <button onClick={()=>setShowCreate(true)} className="flex items-center gap-1.5 bg-accent-cyan text-dark-sidebar px-4 py-1.5 rounded-lg text-xs font-bold hover:opacity-90 transition">
              <Plus size={13}/> Create Incident
            </button>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-dark-secondary text-[10px] uppercase tracking-wider mr-1"><Filter size={10} className="inline mr-0.5"/>Severity</span>
            {[['all','All'],['LOW','Low'],['MEDIUM','Med'],['HIGH','High'],['CRITICAL','Critical']].map(([v,l])=><FB key={v} k="severity" value={v} label={l} cur={filters.severity}/>)}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-dark-secondary text-[10px] uppercase tracking-wider mr-1"><Filter size={10} className="inline mr-0.5"/>Status</span>
            {[['all','All'],['OPEN','Open'],['INVESTIGATING','Investigating'],['CONTAINED','Contained'],['RESOLVED','Resolved']].map(([v,l])=><FB key={v} k="status" value={v} label={l} cur={filters.status}/>)}
          </div>
          <p className="text-dark-secondary text-xs">{rows.length} incident{rows.length!==1?'s':''} shown</p>
        </div>

        <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden">
          {loading && <LoadingSpinner text="Loading incidents…"/>}
          {error   && <p className="text-accent-red p-6 text-sm">{error}</p>}
          {!loading && !error && rows.length===0 && (
            <div className="flex flex-col items-center justify-center py-16">
              <Bookmark size={40} className="text-dark-secondary mb-3"/>
              <p className="text-dark-secondary text-sm">No incidents found</p>
              <button onClick={()=>setShowCreate(true)} className="mt-4 flex items-center gap-1.5 text-accent-cyan text-sm hover:underline"><Plus size={14}/>Create one</button>
            </div>
          )}
          {!loading && !error && rows.length>0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead className="bg-dark-sidebar sticky top-0">
                  <tr>{['ID','Name','Severity','Status','Created','Assigned','Evidence','Actions'].map(h=>(
                    <th key={h} className="px-4 py-3 text-left text-dark-secondary font-semibold uppercase tracking-wider whitespace-nowrap">{h}</th>
                  ))}</tr>
                </thead>
                <tbody>
                  {rows.map(inc=>(
                    <tr key={inc.incident_id} className="border-t border-dark-border tr-hover cursor-pointer" onClick={()=>openDetail(inc)}>
                      <td className="px-4 py-3 font-mono text-accent-cyan">#{inc.incident_id}</td>
                      <td className="px-4 py-3 text-white font-medium max-w-xs truncate">{inc.incident_name}</td>
                      <td className="px-4 py-3"><span className={`px-2 py-0.5 rounded font-bold text-[10px] ${severityBg(inc.severity)}`}>{inc.severity}</span></td>
                      <td className="px-4 py-3"><span className={`px-2 py-0.5 rounded font-bold text-[10px] ${STATUS_CLS[inc.status]||'bg-gray-800 text-gray-400'}`}>{inc.status}</span></td>
                      <td className="px-4 py-3 text-dark-secondary font-mono whitespace-nowrap" title={fmtDateTime(inc.created_timestamp)}>{relTime(inc.created_timestamp)}</td>
                      <td className="px-4 py-3 text-white">{inc.assigned_to||'—'}</td>
                      <td className="px-4 py-3 text-white font-mono">{inc.evidence_count??0}</td>
                      <td className="px-4 py-3" onClick={e=>e.stopPropagation()}>
                        <div className="flex items-center gap-2">
                          <button onClick={()=>openDetail(inc)} className="text-accent-cyan hover:text-white transition"><Eye size={14}/></button>
                          <button onClick={e=>handleDelete(inc.incident_id,e)} className="text-red-400 hover:text-white transition"><Trash2 size={14}/></button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      <Modal isOpen={!!detail} onClose={()=>setDetail(null)} title={detail?`#${detail.incident_id} — ${detail.incident_name}`:''} width="max-w-2xl">
        <IncidentDetail detail={detail} onUpdate={handleUpdate}/>
      </Modal>

      <Modal isOpen={showCreate} onClose={()=>{setShowCreate(false);setForm(EMPTY);}} title="Create New Incident" width="max-w-lg">
        <div className="space-y-4">
          <div>
            <label className="text-dark-secondary text-xs uppercase tracking-wider block mb-1">Incident Name *</label>
            <input value={form.incident_name} onChange={e=>setForm(f=>({...f,incident_name:e.target.value}))}
              placeholder="e.g., Unauthorized Modbus Access"
              className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white text-sm focus:border-accent-cyan outline-none"/>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-dark-secondary text-xs uppercase tracking-wider block mb-1">Severity</label>
              <select value={form.severity} onChange={e=>setForm(f=>({...f,severity:e.target.value}))}
                className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white text-sm">
                {['LOW','MEDIUM','HIGH','CRITICAL'].map(v=><option key={v}>{v}</option>)}
              </select>
            </div>
            <div>
              <label className="text-dark-secondary text-xs uppercase tracking-wider block mb-1">Status</label>
              <select value={form.status} onChange={e=>setForm(f=>({...f,status:e.target.value}))}
                className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white text-sm">
                {['OPEN','INVESTIGATING','CONTAINED','RESOLVED'].map(v=><option key={v}>{v}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="text-dark-secondary text-xs uppercase tracking-wider block mb-1">Assigned To</label>
            <input value={form.assigned_to} onChange={e=>setForm(f=>({...f,assigned_to:e.target.value}))}
              className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white text-sm focus:border-accent-cyan outline-none"/>
          </div>
          <div>
            <label className="text-dark-secondary text-xs uppercase tracking-wider block mb-1">Description</label>
            <textarea value={form.description} onChange={e=>setForm(f=>({...f,description:e.target.value}))}
              rows={3} placeholder="Describe the incident…"
              className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white text-sm resize-none focus:border-accent-cyan outline-none"/>
          </div>
          <div className="flex gap-3 justify-end pt-2">
            <button onClick={()=>{setShowCreate(false);setForm(EMPTY);}} className="px-4 py-2 border border-dark-border rounded-lg text-dark-secondary hover:text-white hover:bg-dark-hover transition text-sm">Cancel</button>
            <button onClick={handleCreate} disabled={!form.incident_name.trim()||saving}
              className="px-4 py-2 bg-accent-cyan text-dark-sidebar rounded-lg font-bold text-sm hover:opacity-90 disabled:opacity-50 transition">
              {saving?'Creating…':'Create'}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
