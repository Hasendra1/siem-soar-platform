import axios from 'axios';

const API_BASE = 'http://localhost:5000/api';

const api = axios.create({
  baseURL: API_BASE,
  headers: { 'Content-Type': 'application/json' },
  timeout: 10000,
});

// ── Dashboard ─────────────────────────────────────────────
export const getDashboardSummary  = ()            => api.get('/dashboard/summary');
export const getTimeline          = ()            => api.get('/dashboard/timeline');
export const getTopology          = ()            => api.get('/dashboard/topology');
export const getIsolations        = ()            => api.get('/dashboard/isolations');
export const getClusters          = ()            => api.get('/dashboard/clusters');
export const getRulesTriggered    = ()            => api.get('/dashboard/rules-triggered');
export const getAnomaliesDetailed = ()            => api.get('/dashboard/anomalies-detailed');

// ── Data ──────────────────────────────────────────────────
export const getEvents       = (limit = 50) => api.get(`/data/events?limit=${limit}`);
export const getAnomalies    = ()            => api.get('/data/anomalies');
export const queryEvents     = (body)        => api.post('/data/events/query', body);

// ── ML Device States ─────────────────────────────────────
export const getMLDeviceStates = ()          => api.get('/data/ml/device-states');
export const getMLScores       = ()          => api.get('/data/ml/scores');

// ── Investigation / Incidents ─────────────────────────────
export const getIncidentList   = ()      => api.get('/investigation/incidents');
export const getIncidentById   = (id)    => api.get(`/investigation/incidents/${id}`);
export const createIncident    = (body)  => api.post('/investigation/incidents', body);
export const updateIncident    = (id, b) => api.put(`/investigation/incidents/${id}`, b);
export const deleteIncident    = (id)    => api.delete(`/investigation/incidents/${id}`);

// ── System Control ────────────────────────────────────────
export const resetSystem        = ()     => api.post('/system/reset');
export const getSystemStatus    = ()     => api.get('/system/status');
export const startMLMonitor     = ()     => api.post('/system/monitor/start');
export const stopMLMonitor      = ()     => api.post('/system/monitor/stop');

export default api;
