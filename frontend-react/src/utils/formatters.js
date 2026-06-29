export const fmtTime = (ts) => {
  if (!ts) return '—';
  const d = new Date(ts.replace(' ', 'T'));
  return isNaN(d) ? ts : d.toLocaleTimeString();
};

export const fmtDateTime = (ts) => {
  if (!ts) return '—';
  const d = new Date(ts.replace(' ', 'T'));
  return isNaN(d) ? ts : d.toLocaleString();
};

export const severityColor = (sev) => {
  switch ((sev || '').toUpperCase()) {
    case 'CRITICAL': return '#ff0055';
    case 'HIGH':     return '#ff6600';
    case 'MEDIUM':   return '#ffaa00';
    case 'LOW':      return '#00d4ff';
    default:         return '#aaaaaa';
  }
};

export const severityBg = (sev) => {
  switch ((sev || '').toUpperCase()) {
    case 'CRITICAL': return 'bg-red-900/40 text-red-300';
    case 'HIGH':     return 'bg-orange-900/40 text-orange-300';
    case 'MEDIUM':   return 'bg-yellow-900/40 text-yellow-300';
    case 'LOW':      return 'bg-cyan-900/40 text-cyan-300';
    default:         return 'bg-gray-800 text-gray-400';
  }
};

export const fmtNum = (n) => (n ?? 0).toLocaleString();
export const pct = (v, total) => total ? Math.round((v / total) * 100) : 0;
