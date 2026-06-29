import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Home, ShieldAlert, Zap, AlertCircle, Search,
  Bookmark, Settings, Menu, X, CheckCircle, XCircle,
  Activity,
} from 'lucide-react';
import { useWebSocket } from '../hooks/useWebSocket';
import { getIsolations, getAnomaliesDetailed, getIncidentList, getRulesTriggered } from '../utils/api';

export default function Sidebar({ isOpen, onToggle }) {
  const navigate  = useNavigate();
  const location  = useLocation();
  const [counts, setCounts] = useState({ isolated: 0, rules: 0, anomalies: 0, incidents: 0 });
  const [recentIncidents, setRecentIncidents] = useState([]);
  const [wsStatus, setWsStatus] = useState('disconnected');
  const [search, setSearch] = useState('');
  const [timer, setTimer]   = useState(null);

  // Fetch badge counts
  useEffect(() => {
    const load = async () => {
      try {
        const [iso, anom, inc, rules] = await Promise.allSettled([
          getIsolations(),
          getAnomaliesDetailed(),
          getIncidentList(),
          getRulesTriggered(),
        ]);
        setCounts({
          isolated: iso.status === 'fulfilled'   ? (Array.isArray(iso.value.data) ? iso.value.data.length : iso.value.data?.length || 0) : 0,
          rules:    rules.status === 'fulfilled'  ? (rules.value.data?.rules_triggered?.length || 0)                                        : 0,
          anomalies:anom.status === 'fulfilled'   ? (anom.value.data?.anomalies?.length || 0)                                              : 0,
          incidents:inc.status === 'fulfilled'    ? ((inc.value.data?.incidents || []).filter(i => i.status === 'OPEN').length)            : 0,
        });
        if (inc.status === 'fulfilled') {
          setRecentIncidents((inc.value.data?.incidents || []).slice(0, 5));
        }
      } catch {}
    };
    load();
    const id = setInterval(load, 15000);
    return () => clearInterval(id);
  }, []);

  useWebSocket({
    onAnomalyDetected: () => setCounts(p => ({ ...p, anomalies: p.anomalies + 1 })),
    onIsolation:       () => setCounts(p => ({ ...p, isolated:  p.isolated  + 1 })),
    onStatusChange:    setWsStatus,
  });

  const handleSearch = (q) => {
    setSearch(q);
    clearTimeout(timer);
    if (q.trim()) {
      setTimer(setTimeout(() => navigate(`/threat-hunting?search=${encodeURIComponent(q)}`), 400));
    }
  };

  const isActive = (route) => location.pathname === route;

  const navItems = [
    { label: 'Dashboard',          icon: Home,        route: '/dashboard',          badge: null,           badgeColor: '' },
    { label: 'Isolated Devices',   icon: ShieldAlert,  route: '/isolated-devices',   badge: counts.isolated,  badgeColor: 'bg-red-600' },
    { label: 'Rules Triggered',    icon: Zap,          route: '/rules-triggered',    badge: counts.rules,     badgeColor: 'bg-orange-600' },
    { label: 'Anomalies Detected', icon: AlertCircle,  route: '/anomalies-detected', badge: counts.anomalies, badgeColor: 'bg-red-600' },
    { label: 'Threat Hunting',     icon: Search,       route: '/threat-hunting',     badge: null,           badgeColor: '' },
    { label: 'Incidents',          icon: Bookmark,     route: '/incidents',          badge: counts.incidents, badgeColor: 'bg-orange-600' },
    { label: 'Settings',           icon: Settings,     route: '/settings',           badge: null,           badgeColor: '' },
  ];

  const go = (route) => {
    navigate(route);
    if (window.innerWidth < 1024) onToggle();
  };

  return (
    <>
      {/* Mobile hamburger */}
      <button
        id="sidebar-toggle"
        onClick={onToggle}
        className="fixed top-4 left-4 lg:hidden z-[1001] bg-dark-sidebar border border-dark-border rounded-lg p-2 text-white"
      >
        {isOpen ? <X size={20} /> : <Menu size={20} />}
      </button>

      {/* Mobile overlay */}
      {isOpen && (
        <div className="fixed inset-0 bg-black/60 lg:hidden z-[999]" onClick={onToggle} />
      )}

      {/* Sidebar */}
      <aside
        className={`
          fixed left-0 top-0 h-screen w-60 flex flex-col
          bg-dark-sidebar border-r border-dark-border
          transition-transform duration-300 ease-in-out z-[1000]
          ${isOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
        `}
      >
        {/* Logo */}
        <div className="h-16 flex items-center px-4 gap-3 border-b border-dark-border shrink-0">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-accent-cyan to-accent-purple flex items-center justify-center">
            <Activity size={16} className="text-dark-sidebar" />
          </div>
          <div>
            <div className="text-white font-bold text-sm leading-none">SIEM·SOAR</div>
            <div className="text-dark-secondary text-xs mt-0.5">IoT/OT Platform</div>
          </div>
        </div>

        {/* Search */}
        <div className="px-3 py-3 border-b border-dark-border shrink-0">
          <div className="relative">
            <Search size={14} className="absolute left-2.5 top-2.5 text-dark-secondary pointer-events-none" />
            <input
              id="sidebar-search"
              type="text"
              value={search}
              onChange={e => handleSearch(e.target.value)}
              placeholder="Search events..."
              className="w-full bg-dark-card border border-dark-border rounded-md pl-8 pr-3 py-2 text-xs text-white placeholder-dark-secondary focus:border-accent-cyan focus:outline-none transition-colors duration-200"
            />
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto px-2 py-3 space-y-0.5">
          {navItems.map(({ label, icon: Icon, route, badge, badgeColor }) => {
            const active = isActive(route);
            return (
              <button
                key={route}
                id={`nav-${route.replace('/', '').replace(/-/g, '_')}`}
                onClick={() => go(route)}
                className={`
                  w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-200 group
                  ${active
                    ? 'bg-dark-hover text-accent-cyan border-l-[3px] border-accent-cyan pl-[9px]'
                    : 'text-dark-secondary hover:bg-dark-hover hover:text-white border-l-[3px] border-transparent pl-[9px]'}
                `}
              >
                <Icon size={18} className={active ? 'text-accent-cyan' : 'text-dark-secondary group-hover:text-white'} />
                <span className="flex-1 text-left font-medium truncate">{label}</span>
                {badge != null && badge > 0 && (
                  <span className={`${badgeColor} text-white text-[10px] font-bold rounded-full min-w-[18px] px-1.5 py-0.5 text-center leading-none`}>
                    {badge > 99 ? '99+' : badge}
                  </span>
                )}
              </button>
            );
          })}

          {/* Divider */}
          <div className="border-t border-dark-border my-3 mx-1" />

          {/* Recent Incidents */}
          {recentIncidents.length > 0 && (
            <div>
              <p className="text-dark-secondary text-[10px] font-semibold uppercase tracking-widest px-3 mb-2">Recent</p>
              {recentIncidents.map((inc, i) => (
                <button
                  key={inc.incident_id || i}
                  onClick={() => go('/incidents')}
                  className="w-full text-left px-3 py-1.5 text-xs text-dark-secondary hover:text-white hover:bg-dark-hover rounded-lg transition-colors truncate"
                  title={inc.incident_name || inc.title}
                >
                  • {inc.incident_name || inc.title || `Incident #${inc.incident_id}`}
                </button>
              ))}
            </div>
          )}
        </nav>

        {/* Footer */}
        <div className="border-t border-dark-border px-4 py-3 shrink-0">
          <div className="flex items-center gap-2">
            {wsStatus === 'connected'
              ? <CheckCircle size={14} className="text-accent-green pulse-dot" />
              : <XCircle    size={14} className="text-accent-red" />
            }
            <span className={`text-xs font-medium ${wsStatus === 'connected' ? 'text-accent-green' : 'text-accent-red'}`}>
              {wsStatus === 'connected' ? 'Live Connected' : 'Offline'}
            </span>
          </div>
        </div>
      </aside>
    </>
  );
}
