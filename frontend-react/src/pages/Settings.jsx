import React, { useState } from 'react';
import { Save, Download, Eye, Plus } from 'lucide-react';

const Settings = () => {
  const [activeTab, setActiveTab] = useState('system');
  const [savedChanges, setSavedChanges] = useState(true);

  const [systemConfig, setSystemConfig] = useState({
    platform_name: 'IoT/OT Security Operations Center',
    version: '1.0.0',
    deployment_date: '2026-05-31',
    uptime_hours: 45.5,
    total_events_processed: 15234,
    database_size_mb: 234.5,
    log_level: 'info',
    alert_email: 'security@company.com',
  });

  const [mlConfig, setMlConfig] = useState({
    kmeans_k_range: [2, 5],
    kmeans_max_iter: 300,
    dbscan_eps: 'auto',
    voting_threshold: 0.6,
    confidence_threshold: 0.3,
    retraining_interval: 24,
    model_last_trained: '2026-05-31 12:00:00',
  });

  const [detectionRules, setDetectionRules] = useState([
    {
      rule_id: 9001,
      rule_name: 'Unauthorized Modbus Read',
      enabled: true,
      severity: 'HIGH',
      detection_method: 'behavioral_profiling',
      confidence_threshold: 0.95,
      action_on_trigger: 'alert',
      description: 'Unauthorized read attempt on PLC registers',
      trigger_count: 10,
    },
    {
      rule_id: 9002,
      rule_name: 'Malicious Modbus Write',
      enabled: true,
      severity: 'CRITICAL',
      detection_method: 'anomaly_detection',
      confidence_threshold: 0.99,
      action_on_trigger: 'auto_isolate',
      description: 'Write operation to PLC with malicious value 9999',
      trigger_count: 5,
    },
    {
      rule_id: 9003,
      rule_name: 'Port Scanning Activity',
      enabled: true,
      severity: 'HIGH',
      detection_method: 'statistical_analysis',
      confidence_threshold: 0.87,
      action_on_trigger: 'alert',
      description: 'Multiple TCP connection attempts to different ports',
      trigger_count: 50,
    },
    {
      rule_id: 9004,
      rule_name: 'Lateral Movement',
      enabled: true,
      severity: 'HIGH',
      detection_method: 'behavioral_profiling',
      confidence_threshold: 0.90,
      action_on_trigger: 'alert',
      description: 'Device communicating across zones',
      trigger_count: 8,
    },
  ]);

  const [threatScoring, setThreatScoring] = useState({
    anomaly_score_weight: 0.30,
    escalation_pattern_weight: 0.25,
    action_detection_weight: 0.25,
    zone_violations_weight: 0.10,
    protocol_abuse_weight: 0.10,
    attacker_identification_confidence: 98.5,
    normal_device_max_score: 0.8,
    critical_threshold: 0.9,
    high_threshold: 0.7,
    medium_threshold: 0.5,
    auto_isolation_confidence: 90,
    current_threat_level: 23,
  });

  const [latencyTargets] = useState({
    ml_inference: { target: 100, current: 67, label: 'ML Inference' },
    anomaly_detection: { target: 100, current: 78, label: 'Anomaly Detection' },
    auto_segmentation: { target: 125, current: 98, label: 'Auto-Segmentation' },
    event_indexing: { target: 50, current: 34, label: 'Event Indexing' },
    websocket_push: { target: 100, current: 87, label: 'WebSocket Push' },
    alert_generation: { target: 150, current: 112, label: 'Alert Generation' },
  });

  const [devices, setDevices] = useState([
    { id: 1, name: 'PLC1', ip: '192.168.10.10', type: 'PLC', zone: 'OT', critical: true, baseline: 'Modbus TCP port 502 only, 750-850 packets/hour' },
    { id: 2, name: 'PLC2', ip: '192.168.10.11', type: 'PLC', zone: 'OT', critical: true, baseline: 'Modbus TCP port 502 only, 750-850 packets/hour' },
    { id: 3, name: 'HMI', ip: '192.168.10.20', type: 'HMI', zone: 'OT', critical: true, baseline: 'Polls PLC1, PLC2 every 5 seconds' },
    { id: 4, name: 'MQTT Broker', ip: '192.168.20.100', type: 'BROKER', zone: 'IoT', critical: true, baseline: 'MQTT port 1883 listener' },
    { id: 5, name: 'Sensor-Temp', ip: '192.168.20.10', type: 'SENSOR', zone: 'IoT', critical: false, baseline: 'Publishes temperature 20-35°C every 3 seconds' },
    { id: 6, name: 'Sensor-Pressure', ip: '192.168.20.11', type: 'SENSOR', zone: 'IoT', critical: false, baseline: 'Publishes pressure 1-5 every 3 seconds' },
    { id: 7, name: 'CCTV-Camera', ip: '192.168.30.10', type: 'CAMERA', zone: 'DMZ', critical: false, baseline: 'Flask HTTP server port 80' },
    { id: 8, name: 'Cloud-Gateway', ip: '192.168.30.100', type: 'GATEWAY', zone: 'DMZ', critical: true, baseline: 'MQTT subscriber, receives from sensors' },
  ]);

  const [wazuhConfig, setWazuhConfig] = useState({
    enabled: true,
    manager_ip: '127.0.0.1',
    manager_port: 1514,
    alert_threshold: 3,
    log_level: 'info',
    active_response_enabled: true,
    monitored_containers: 9,
    agents_connected: 9,
  });

  const [databaseConfig, setDatabaseConfig] = useState({
    engine: 'SQLite',
    location: 'C:\\siem-soar-platform\\dataset\\siem_database.db',
    size_mb: 234.5,
    retention_days: 90,
    backup_frequency: 'daily',
    last_backup: '2026-05-31 23:00:00',
    auto_cleanup_enabled: true,
    cleanup_frequency: 'daily',
  });

  const dbTables = [
    { name: 'events', rows: 15234, size: '45.2 MB' },
    { name: 'devices', rows: 8, size: '0.1 MB' },
    { name: 'anomalies', rows: 127, size: '2.3 MB' },
    { name: 'clusters', rows: 2, size: '0.1 MB' },
    { name: 'incidents', rows: 3, size: '0.2 MB' },
    { name: 'isolations', rows: 4, size: '0.1 MB' },
    { name: 'investigations', rows: 1, size: '0.1 MB' },
    { name: 'behavior_profiles', rows: 8, size: '1.2 MB' },
  ];

  const handleUpdateRule = (ruleId, field, value) => {
    setDetectionRules(detectionRules.map(r =>
      r.rule_id === ruleId ? { ...r, [field]: value } : r
    ));
    setSavedChanges(false);
  };

  const getLatencyStatus = (current, target) => {
    if (current <= target * 0.7) return { label: 'EXCELLENT', color: 'text-green-400', bg: 'bg-green-500' };
    if (current <= target) return { label: 'GOOD', color: 'text-accent-cyan', bg: 'bg-accent-cyan' };
    if (current <= target * 1.2) return { label: 'WARNING', color: 'text-yellow-400', bg: 'bg-yellow-500' };
    return { label: 'CRITICAL', color: 'text-red-500', bg: 'bg-red-500' };
  };

  const getZoneColor = (zone) => {
    const colors = {
      'OT': 'bg-yellow-500/20 text-yellow-400',
      'IoT': 'bg-cyan-500/20 text-cyan-400',
      'DMZ': 'bg-purple-500/20 text-purple-400',
    };
    return colors[zone] || '';
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Settings & Configuration</h1>
          <p className="text-dark-text-secondary">System configuration, ML parameters, and detection rules</p>
        </div>
        <button
          onClick={() => setSavedChanges(true)}
          className="flex items-center gap-2 bg-accent-cyan text-dark-sidebar px-4 py-2 rounded font-bold hover:opacity-90 transition"
        >
          <Save size={18} />
          Save Changes
        </button>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-0 border-b border-dark-border overflow-x-auto">
        {[
          { id: 'system', label: 'System Information' },
          { id: 'ml', label: 'ML Configuration' },
          { id: 'rules', label: 'Detection Rules' },
          { id: 'threat', label: 'Threat Scoring' },
          { id: 'latency', label: 'Latency Targets' },
          { id: 'devices', label: 'Devices & Baseline' },
          { id: 'wazuh', label: 'Wazuh Integration' },
          { id: 'database', label: 'Database & Retention' },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-3 font-bold whitespace-nowrap border-b-2 transition ${
              activeTab === tab.id
                ? 'text-accent-cyan border-accent-cyan'
                : 'text-dark-text-secondary border-transparent hover:text-white'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="bg-dark-card border border-dark-border rounded-lg p-6">
        
        {/* SYSTEM TAB */}
        {activeTab === 'system' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-dark-sidebar rounded-lg p-4">
                <p className="text-dark-text-secondary text-sm mb-1">Platform Name</p>
                <p className="text-white font-bold">{systemConfig.platform_name}</p>
              </div>
              <div className="bg-dark-sidebar rounded-lg p-4">
                <p className="text-dark-text-secondary text-sm mb-1">Version</p>
                <p className="text-white font-bold">{systemConfig.version}</p>
              </div>
              <div className="bg-dark-sidebar rounded-lg p-4">
                <p className="text-dark-text-secondary text-sm mb-1">Deployment Date</p>
                <p className="text-white font-bold">{systemConfig.deployment_date}</p>
              </div>
              <div className="bg-dark-sidebar rounded-lg p-4">
                <p className="text-dark-text-secondary text-sm mb-1">Uptime</p>
                <p className="text-accent-green font-bold">{systemConfig.uptime_hours} hours</p>
              </div>
              <div className="bg-dark-sidebar rounded-lg p-4">
                <p className="text-dark-text-secondary text-sm mb-1">Events Processed</p>
                <p className="text-white font-bold">{systemConfig.total_events_processed.toLocaleString()}</p>
              </div>
              <div className="bg-dark-sidebar rounded-lg p-4">
                <p className="text-dark-text-secondary text-sm mb-1">Database Size</p>
                <p className="text-white font-bold">{systemConfig.database_size_mb} MB</p>
              </div>
            </div>

            <div className="border-t border-dark-border pt-6 space-y-4">
              <h3 className="text-white font-bold">Editable Settings</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-dark-text-secondary text-sm mb-2">Alert Email</label>
                  <input
                    type="email"
                    value={systemConfig.alert_email}
                    onChange={(e) => {
                      setSystemConfig({ ...systemConfig, alert_email: e.target.value });
                      setSavedChanges(false);
                    }}
                    className="w-full bg-dark-card border border-dark-border rounded px-3 py-2 text-white text-sm"
                  />
                </div>
                <div>
                  <label className="block text-dark-text-secondary text-sm mb-2">Log Level</label>
                  <select
                    value={systemConfig.log_level}
                    onChange={(e) => {
                      setSystemConfig({ ...systemConfig, log_level: e.target.value });
                      setSavedChanges(false);
                    }}
                    className="w-full bg-dark-card border border-dark-border rounded px-3 py-2 text-white text-sm"
                  >
                    <option value="debug">Debug</option>
                    <option value="info">Info</option>
                    <option value="warning">Warning</option>
                    <option value="error">Error</option>
                  </select>
                </div>
              </div>
            </div>

            <div className="border-t border-dark-border pt-6 space-y-3">
              <h3 className="text-white font-bold">System Actions</h3>
              <div className="flex gap-3">
                <button className="px-4 py-2 border border-dark-border rounded hover:bg-dark-hover transition flex items-center gap-2 text-sm">
                  <Download size={16} />
                  Export Configuration
                </button>
                <button className="px-4 py-2 border border-dark-border rounded hover:bg-dark-hover transition flex items-center gap-2 text-sm">
                  <Eye size={16} />
                  View System Logs
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ML TAB */}
        {activeTab === 'ml' && (
          <div className="space-y-6">
            <div>
              <h3 className="text-white font-bold mb-4">Clustering Algorithms (5 Methods)</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {[
                  { name: 'K-Means', params: ['K Range: 2-5', 'Max Iterations: 300', 'Silhouette: 0.78'] },
                  { name: 'DBSCAN', params: ['Eps: auto', 'Min Samples: 5', 'Outlier Detection: On'] },
                  { name: 'Hierarchical', params: ['Linkage: Ward', 'Distance: Euclidean'] },
                  { name: 'Spectral', params: ['Communities: 2', 'Affinity: neighbors'] },
                  { name: 'GMM', params: ['Components: Auto', 'Model: BIC'] },
                ].map((algo, idx) => (
                  <div key={idx} className="bg-dark-sidebar border border-dark-border rounded p-4">
                    <div className="flex items-center justify-between mb-3">
                      <p className="text-white font-bold">{algo.name}</p>
                      <input type="checkbox" defaultChecked className="w-4 h-4" />
                    </div>
                    <div className="space-y-1 text-sm text-dark-text-secondary">
                      {algo.params.map((param, pidx) => (
                        <p key={pidx}>{param}</p>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="border-t border-dark-border pt-6 space-y-4">
              <h3 className="text-white font-bold">Ensemble Settings</h3>
              <div>
                <label className="block text-dark-text-secondary text-sm mb-2">
                  Voting Threshold: {mlConfig.voting_threshold.toFixed(2)}
                </label>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.05"
                  value={mlConfig.voting_threshold}
                  onChange={(e) => {
                    setMlConfig({ ...mlConfig, voting_threshold: parseFloat(e.target.value) });
                    setSavedChanges(false);
                  }}
                  className="w-full accent-cyan-400"
                />
              </div>

              <div>
                <label className="block text-dark-text-secondary text-sm mb-2">
                  Confidence Threshold: {mlConfig.confidence_threshold.toFixed(2)}
                </label>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.05"
                  value={mlConfig.confidence_threshold}
                  onChange={(e) => {
                    setMlConfig({ ...mlConfig, confidence_threshold: parseFloat(e.target.value) });
                    setSavedChanges(false);
                  }}
                  className="w-full accent-cyan-400"
                />
              </div>

              <div>
                <label className="block text-dark-text-secondary text-sm mb-2">
                  Model Retraining Interval (hours)
                </label>
                <input
                  type="number"
                  value={mlConfig.retraining_interval}
                  onChange={(e) => {
                    setMlConfig({ ...mlConfig, retraining_interval: parseInt(e.target.value) });
                    setSavedChanges(false);
                  }}
                  className="w-full bg-dark-card border border-dark-border rounded px-3 py-2 text-white"
                />
              </div>
            </div>

            <div className="border-t border-dark-border pt-6 space-y-3">
              <p className="text-dark-text-secondary text-sm">
                Last Trained: {mlConfig.model_last_trained}
              </p>
              <button className="px-4 py-2 bg-accent-cyan text-dark-sidebar rounded font-bold hover:opacity-90 text-sm">
                Force Retrain Models
              </button>
            </div>
          </div>
        )}

        {/* DETECTION RULES TAB */}
        {activeTab === 'rules' && (
          <div className="space-y-4">
            <h3 className="text-white font-bold mb-4">Detection Rules (4 Custom Rules)</h3>
            {detectionRules.map(rule => (
              <div key={rule.rule_id} className="bg-dark-sidebar border border-dark-border rounded-lg p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <p className="text-white font-bold">{rule.rule_name}</p>
                    <p className="text-dark-text-secondary text-sm">{rule.description}</p>
                  </div>
                  <input
                    type="checkbox"
                    checked={rule.enabled}
                    onChange={(e) => handleUpdateRule(rule.rule_id, 'enabled', e.target.checked)}
                    className="w-5 h-5 ml-4"
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-sm">
                  <div>
                    <label className="text-dark-text-secondary text-xs mb-1 block">Severity</label>
                    <select
                      value={rule.severity}
                      onChange={(e) => handleUpdateRule(rule.rule_id, 'severity', e.target.value)}
                      className={`w-full bg-dark-card border border-dark-border rounded px-2 py-1 text-xs font-bold ${
                        rule.severity === 'CRITICAL' ? 'text-red-500' :
                        rule.severity === 'HIGH' ? 'text-orange-400' : 'text-yellow-400'
                      }`}
                    >
                      <option value="LOW">Low</option>
                      <option value="MEDIUM">Medium</option>
                      <option value="HIGH">High</option>
                      <option value="CRITICAL">Critical</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-dark-text-secondary text-xs mb-1 block">Confidence</label>
                    <input
                      type="number"
                      min="0"
                      max="1"
                      step="0.01"
                      value={rule.confidence_threshold}
                      onChange={(e) => handleUpdateRule(rule.rule_id, 'confidence_threshold', parseFloat(e.target.value))}
                      className="w-full bg-dark-card border border-dark-border rounded px-2 py-1 text-white text-xs"
                    />
                  </div>
                  <div>
                    <label className="text-dark-text-secondary text-xs mb-1 block">Method</label>
                    <p className="text-white text-xs pt-1">{rule.detection_method}</p>
                  </div>
                  <div>
                    <label className="text-dark-text-secondary text-xs mb-1 block">Action</label>
                    <select
                      value={rule.action_on_trigger}
                      onChange={(e) => handleUpdateRule(rule.rule_id, 'action_on_trigger', e.target.value)}
                      className="w-full bg-dark-card border border-dark-border rounded px-2 py-1 text-white text-xs"
                    >
                      <option value="alert">Alert</option>
                      <option value="auto_isolate">Auto Isolate</option>
                    </select>
                  </div>
                </div>

                <div className="text-xs text-dark-text-secondary">
                  Triggered {rule.trigger_count} times
                </div>
              </div>
            ))}

            <button className="mt-4 px-4 py-2 border border-dark-border rounded hover:bg-dark-hover transition flex items-center gap-2 text-accent-cyan text-sm">
              <Plus size={16} />
              Add Custom Rule
            </button>
          </div>
        )}

        {/* THREAT SCORING TAB */}
        {activeTab === 'threat' && (
          <div className="space-y-6">
            <div>
              <h3 className="text-white font-bold mb-4">Ensemble Weights (5-Method Scoring)</h3>
              <div className="space-y-4">
                {[
                  { label: 'Anomaly Score Ranking', key: 'anomaly_score_weight' },
                  { label: 'Escalation Pattern', key: 'escalation_pattern_weight' },
                  { label: 'Action Detection', key: 'action_detection_weight' },
                  { label: 'Zone Violations', key: 'zone_violations_weight' },
                  { label: 'Protocol Abuse', key: 'protocol_abuse_weight' },
                ].map(method => (
                  <div key={method.key}>
                    <label className="block text-dark-text-secondary text-sm mb-2">
                      {method.label}: {Math.round(threatScoring[method.key] * 100)}%
                    </label>
                    <input
                      type="range"
                      min="0"
                      max="1"
                      step="0.05"
                      value={threatScoring[method.key]}
                      onChange={(e) => {
                        setThreatScoring({ ...threatScoring, [method.key]: parseFloat(e.target.value) });
                        setSavedChanges(false);
                      }}
                      className="w-full accent-cyan-400"
                    />
                  </div>
                ))}
              </div>
            </div>

            <div className="border-t border-dark-border pt-6 space-y-4">
              <h3 className="text-white font-bold">Confidence & Thresholds</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-dark-text-secondary text-sm mb-2">
                    Threat Identification: {threatScoring.attacker_identification_confidence.toFixed(1)}%
                  </label>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    step="1"
                    value={threatScoring.attacker_identification_confidence}
                    onChange={(e) => {
                      setThreatScoring({ ...threatScoring, attacker_identification_confidence: parseFloat(e.target.value) });
                      setSavedChanges(false);
                    }}
                    className="w-full accent-cyan-400"
                  />
                </div>
                <div>
                  <label className="block text-dark-text-secondary text-sm mb-2">
                    Auto-Isolation Confidence: {threatScoring.auto_isolation_confidence.toFixed(0)}%
                  </label>
                  <input
                    type="range"
                    min="50"
                    max="100"
                    step="1"
                    value={threatScoring.auto_isolation_confidence}
                    onChange={(e) => {
                      setThreatScoring({ ...threatScoring, auto_isolation_confidence: parseFloat(e.target.value) });
                      setSavedChanges(false);
                    }}
                    className="w-full accent-cyan-400"
                  />
                </div>
              </div>
            </div>

            <div className="border-t border-dark-border pt-6 space-y-4">
              <h3 className="text-white font-bold">Score Thresholds</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="block text-dark-text-secondary text-sm mb-2">
                    Critical: {threatScoring.critical_threshold.toFixed(2)}
                  </label>
                  <input
                    type="range"
                    min="0"
                    max="1"
                    step="0.05"
                    value={threatScoring.critical_threshold}
                    onChange={(e) => {
                      setThreatScoring({ ...threatScoring, critical_threshold: parseFloat(e.target.value) });
                      setSavedChanges(false);
                    }}
                    className="w-full accent-cyan-400"
                  />
                </div>
                <div>
                  <label className="block text-dark-text-secondary text-sm mb-2">
                    High: {threatScoring.high_threshold.toFixed(2)}
                  </label>
                  <input
                    type="range"
                    min="0"
                    max="1"
                    step="0.05"
                    value={threatScoring.high_threshold}
                    onChange={(e) => {
                      setThreatScoring({ ...threatScoring, high_threshold: parseFloat(e.target.value) });
                      setSavedChanges(false);
                    }}
                    className="w-full accent-cyan-400"
                  />
                </div>
                <div>
                  <label className="block text-dark-text-secondary text-sm mb-2">
                    Medium: {threatScoring.medium_threshold.toFixed(2)}
                  </label>
                  <input
                    type="range"
                    min="0"
                    max="1"
                    step="0.05"
                    value={threatScoring.medium_threshold}
                    onChange={(e) => {
                      setThreatScoring({ ...threatScoring, medium_threshold: parseFloat(e.target.value) });
                      setSavedChanges(false);
                    }}
                    className="w-full accent-cyan-400"
                  />
                </div>
              </div>
            </div>

            <div className="border-t border-dark-border pt-6 bg-dark-sidebar rounded p-4">
              <p className="text-dark-text-secondary text-sm mb-2">Current Threat Level</p>
              <div className="flex items-center gap-4">
                <div className="text-3xl font-bold text-accent-orange">{threatScoring.current_threat_level}/100</div>
                <div className="flex-1 bg-dark-card rounded h-2">
                  <div 
                    className="bg-accent-orange h-full rounded" 
                    style={{ width: `${threatScoring.current_threat_level}%` }} 
                  />
                </div>
              </div>
            </div>
          </div>
        )}

        {/* LATENCY TARGETS TAB */}
        {activeTab === 'latency' && (
          <div className="space-y-6">
            <h3 className="text-white font-bold mb-4">
              Performance Targets vs Actual
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {Object.values(latencyTargets).map((metric) => {
                const status = getLatencyStatus(metric.current, metric.target);
                const pct = Math.min(100, Math.round((metric.current / metric.target) * 100));
                return (
                  <div key={metric.label} className="bg-dark-sidebar border border-dark-border rounded-lg p-4">
                    <div className="flex items-center justify-between mb-3">
                      <p className="text-white font-bold">{metric.label}</p>
                      <span className={`text-xs font-bold px-2 py-1 rounded ${status.color}`}>
                        {status.label}
                      </span>
                    </div>
                    <div className="flex items-center justify-between mb-2 text-sm">
                      <span className="text-dark-text-secondary">Target: {metric.target}ms</span>
                      <span className={`font-bold ${status.color}`}>Current: {metric.current}ms</span>
                    </div>
                    <div className="w-full bg-dark-card rounded-full h-2">
                      <div
                        className={`h-2 rounded-full transition-all ${status.bg}`}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="border-t border-dark-border pt-6 bg-dark-sidebar rounded-lg p-4">
              <h3 className="text-white font-bold mb-4">Percentile Distribution</h3>
              <div className="grid grid-cols-3 gap-4 text-center">
                <div>
                  <p className="text-dark-text-secondary text-sm mb-1">P50 (Median)</p>
                  <p className="text-2xl font-bold text-accent-green">78ms</p>
                  <p className="text-xs text-dark-text-secondary">Under all targets</p>
                </div>
                <div>
                  <p className="text-dark-text-secondary text-sm mb-1">P95</p>
                  <p className="text-2xl font-bold text-accent-orange">134ms</p>
                  <p className="text-xs text-dark-text-secondary">Within targets</p>
                </div>
                <div>
                  <p className="text-dark-text-secondary text-sm mb-1">P99</p>
                  <p className="text-2xl font-bold text-accent-orange">156ms</p>
                  <p className="text-xs text-dark-text-secondary">Within targets</p>
                </div>
              </div>
            </div>

            <div className="border-t border-dark-border pt-6 space-y-4">
              <h3 className="text-white font-bold">Performance Tuning</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="block text-dark-text-secondary text-sm mb-2">
                    Optimization Level
                  </label>
                  <select className="w-full bg-dark-card border border-dark-border rounded px-3 py-2 text-white text-sm">
                    <option value="fast">Fast</option>
                    <option value="balanced" selected>Balanced</option>
                    <option value="accurate">Accurate</option>
                  </select>
                </div>
                <div>
                  <label className="block text-dark-text-secondary text-sm mb-2">
                    Batch Processing Size
                  </label>
                  <input
                    type="number"
                    defaultValue={64}
                    className="w-full bg-dark-card border border-dark-border rounded px-3 py-2 text-white text-sm"
                  />
                </div>
                <div className="flex items-end pb-1">
                  <label className="flex items-center gap-3 cursor-pointer">
                    <input type="checkbox" defaultChecked className="w-4 h-4" />
                    <span className="text-white text-sm">Cache Enabled</span>
                  </label>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* DEVICES TAB */}
        {activeTab === 'devices' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-white font-bold">
                Devices & Baseline Behavior (8 Devices)
              </h3>
              <div className="flex gap-2">
                <span className="text-xs px-2 py-1 rounded bg-yellow-500/20 text-yellow-400">OT Zone</span>
                <span className="text-xs px-2 py-1 rounded bg-cyan-500/20 text-cyan-400">IoT Zone</span>
                <span className="text-xs px-2 py-1 rounded bg-purple-500/20 text-purple-400">DMZ Zone</span>
              </div>
            </div>

            {devices.map(device => (
              <div key={device.id} className="bg-dark-sidebar border border-dark-border rounded-lg p-4">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-4 flex-1">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <p className="text-white font-bold">{device.name}</p>
                        <span className={`text-xs px-2 py-0.5 rounded font-bold ${getZoneColor(device.zone)}`}>
                          {device.zone}
                        </span>
                        <span className="text-xs px-2 py-0.5 rounded bg-dark-card text-dark-text-secondary">
                          {device.type}
                        </span>
                        {device.critical && (
                          <span className="text-xs px-2 py-0.5 rounded bg-red-500/20 text-red-400">
                            CRITICAL
                          </span>
                        )}
                      </div>
                      <p className="text-accent-cyan font-mono text-sm">{device.ip}</p>
                      <p className="text-dark-text-secondary text-xs mt-1">{device.baseline}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 ml-4">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <span className="text-dark-text-secondary text-xs">Critical</span>
                      <input
                        type="checkbox"
                        checked={device.critical}
                        onChange={() => {
                          setDevices(devices.map(d =>
                            d.id === device.id ? { ...d, critical: !d.critical } : d
                          ));
                          setSavedChanges(false);
                        }}
                        className="w-4 h-4"
                      />
                    </label>
                  </div>
                </div>
              </div>
            ))}

            <div className="border-t border-dark-border pt-4 mt-4">
              <div className="grid grid-cols-3 gap-4 text-center">
                <div className="bg-dark-sidebar rounded p-3">
                  <p className="text-2xl font-bold text-yellow-400">3</p>
                  <p className="text-dark-text-secondary text-xs">OT Devices</p>
                </div>
                <div className="bg-dark-sidebar rounded p-3">
                  <p className="text-2xl font-bold text-cyan-400">3</p>
                  <p className="text-dark-text-secondary text-xs">IoT Devices</p>
                </div>
                <div className="bg-dark-sidebar rounded p-3">
                  <p className="text-2xl font-bold text-purple-400">2</p>
                  <p className="text-dark-text-secondary text-xs">DMZ Devices</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* WAZUH INTEGRATION TAB */}
        {activeTab === 'wazuh' && (
          <div className="space-y-6">

            {/* Connection Status Banner */}
            <div className="flex items-center gap-3 bg-green-500/10 border border-green-500/30 rounded-lg p-4">
              <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse" />
              <div>
                <p className="text-green-400 font-bold">Wazuh Manager Connected</p>
                <p className="text-dark-text-secondary text-sm">Last heartbeat: 2 seconds ago</p>
              </div>
            </div>

            {/* Manager Settings */}
            <div>
              <h3 className="text-white font-bold mb-4">Manager Settings</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="block text-dark-text-secondary text-sm mb-2">Manager IP</label>
                  <input
                    type="text"
                    value={wazuhConfig.manager_ip}
                    onChange={(e) => {
                      setWazuhConfig({ ...wazuhConfig, manager_ip: e.target.value });
                      setSavedChanges(false);
                    }}
                    className="w-full bg-dark-card border border-dark-border rounded px-3 py-2 text-white text-sm"
                  />
                </div>
                <div>
                  <label className="block text-dark-text-secondary text-sm mb-2">Manager Port</label>
                  <input
                    type="number"
                    value={wazuhConfig.manager_port}
                    onChange={(e) => {
                      setWazuhConfig({ ...wazuhConfig, manager_port: parseInt(e.target.value) });
                      setSavedChanges(false);
                    }}
                    className="w-full bg-dark-card border border-dark-border rounded px-3 py-2 text-white text-sm"
                  />
                </div>
                <div>
                  <label className="block text-dark-text-secondary text-sm mb-2">Alert Threshold</label>
                  <input
                    type="number"
                    value={wazuhConfig.alert_threshold}
                    onChange={(e) => {
                      setWazuhConfig({ ...wazuhConfig, alert_threshold: parseInt(e.target.value) });
                      setSavedChanges(false);
                    }}
                    className="w-full bg-dark-card border border-dark-border rounded px-3 py-2 text-white text-sm"
                  />
                </div>
                <div>
                  <label className="block text-dark-text-secondary text-sm mb-2">Log Level</label>
                  <select
                    value={wazuhConfig.log_level}
                    onChange={(e) => {
                      setWazuhConfig({ ...wazuhConfig, log_level: e.target.value });
                      setSavedChanges(false);
                    }}
                    className="w-full bg-dark-card border border-dark-border rounded px-3 py-2 text-white text-sm"
                  >
                    <option value="debug">Debug</option>
                    <option value="info">Info</option>
                    <option value="warning">Warning</option>
                    <option value="error">Error</option>
                  </select>
                </div>
                <div className="flex items-end pb-1">
                  <label className="flex items-center gap-3 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={wazuhConfig.active_response_enabled}
                      onChange={(e) => {
                        setWazuhConfig({ ...wazuhConfig, active_response_enabled: e.target.checked });
                        setSavedChanges(false);
                      }}
                      className="w-4 h-4"
                    />
                    <span className="text-white text-sm">Active Response Enabled</span>
                  </label>
                </div>
              </div>
            </div>

            {/* Custom Rules */}
            <div className="border-t border-dark-border pt-6">
              <h3 className="text-white font-bold mb-4">Custom Rules (4 Active)</h3>
              <div className="space-y-2">
                {[
                  { id: 9001, name: 'Unauthorized Modbus Read', severity: 'HIGH' },
                  { id: 9002, name: 'Malicious Modbus Write', severity: 'CRITICAL' },
                  { id: 9003, name: 'Port Scanning Activity', severity: 'HIGH' },
                  { id: 9004, name: 'Lateral Movement', severity: 'HIGH' },
                ].map(rule => (
                  <div key={rule.id} className="flex items-center justify-between bg-dark-sidebar rounded-lg p-3">
                    <div className="flex items-center gap-3">
                      <div className="w-2 h-2 bg-green-500 rounded-full" />
                      <span className="text-accent-cyan font-mono text-sm">Rule {rule.id}</span>
                      <span className="text-white text-sm">{rule.name}</span>
                    </div>
                    <span className={`text-xs px-2 py-1 rounded font-bold ${
                      rule.severity === 'CRITICAL'
                        ? 'bg-red-500/20 text-red-500'
                        : 'bg-orange-500/20 text-orange-400'
                    }`}>
                      {rule.severity}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Monitored Containers */}
            <div className="border-t border-dark-border pt-6">
              <h3 className="text-white font-bold mb-4">Monitored Containers</h3>
              <div className="grid grid-cols-3 gap-4">
                <div className="bg-dark-sidebar rounded-lg p-4 text-center">
                  <p className="text-3xl font-bold text-accent-green">{wazuhConfig.monitored_containers}</p>
                  <p className="text-dark-text-secondary text-sm">Total Containers</p>
                </div>
                <div className="bg-dark-sidebar rounded-lg p-4 text-center">
                  <p className="text-3xl font-bold text-accent-green">{wazuhConfig.agents_connected}</p>
                  <p className="text-dark-text-secondary text-sm">Agents Connected</p>
                </div>
                <div className="bg-dark-sidebar rounded-lg p-4 text-center">
                  <p className="text-3xl font-bold text-accent-green">100%</p>
                  <p className="text-dark-text-secondary text-sm">Coverage</p>
                </div>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="border-t border-dark-border pt-6 flex gap-3">
              <button className="px-4 py-2 bg-accent-cyan text-dark-sidebar rounded font-bold hover:opacity-90 text-sm">
                Test Connection
              </button>
              <button className="px-4 py-2 border border-dark-border rounded hover:bg-dark-hover transition text-sm">
                Sync Rules
              </button>
              <button className="px-4 py-2 border border-dark-border rounded hover:bg-dark-hover transition text-sm">
                View Raw Logs
              </button>
            </div>
          </div>
        )}

        {/* DATABASE & RETENTION TAB */}
        {activeTab === 'database' && (
          <div className="space-y-6">

            {/* DB Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-dark-sidebar rounded-lg p-4">
                <p className="text-dark-text-secondary text-sm mb-1">Engine</p>
                <p className="text-white font-bold">{databaseConfig.engine}</p>
              </div>
              <div className="bg-dark-sidebar rounded-lg p-4">
                <p className="text-dark-text-secondary text-sm mb-1">Size</p>
                <p className="text-white font-bold">{databaseConfig.size_mb} MB</p>
              </div>
              <div className="bg-dark-sidebar rounded-lg p-4">
                <p className="text-dark-text-secondary text-sm mb-1">Tables</p>
                <p className="text-white font-bold">8</p>
              </div>
              <div className="bg-dark-sidebar rounded-lg p-4">
                <p className="text-dark-text-secondary text-sm mb-1">Indexes</p>
                <p className="text-white font-bold">16</p>
              </div>
            </div>

            {/* DB Location */}
            <div className="bg-dark-sidebar rounded-lg p-4">
              <p className="text-dark-text-secondary text-sm mb-1">Database Location</p>
              <p className="text-accent-cyan font-mono text-sm break-all">{databaseConfig.location}</p>
            </div>

            {/* Table Breakdown */}
            <div>
              <h3 className="text-white font-bold mb-4">Table Breakdown</h3>
              <div className="overflow-hidden rounded-lg border border-dark-border">
                <table className="w-full text-sm">
                  <thead className="bg-dark-sidebar border-b border-dark-border">
                    <tr>
                      <th className="px-4 py-3 text-left text-dark-text-secondary font-bold">Table</th>
                      <th className="px-4 py-3 text-left text-dark-text-secondary font-bold">Rows</th>
                      <th className="px-4 py-3 text-left text-dark-text-secondary font-bold">Size</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-dark-border">
                    {dbTables.map(table => (
                      <tr key={table.name} className="hover:bg-dark-hover transition">
                        <td className="px-4 py-3 text-accent-cyan font-mono">{table.name}</td>
                        <td className="px-4 py-3 text-white">{table.rows.toLocaleString()}</td>
                        <td className="px-4 py-3 text-dark-text-secondary">{table.size}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Retention Settings */}
            <div className="border-t border-dark-border pt-6 space-y-4">
              <h3 className="text-white font-bold">Data Retention</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-dark-text-secondary text-sm mb-2">
                    Retention Period
                  </label>
                  <select
                    value={databaseConfig.retention_days}
                    onChange={(e) => {
                      setDatabaseConfig({ ...databaseConfig, retention_days: parseInt(e.target.value) });
                      setSavedChanges(false);
                    }}
                    className="w-full bg-dark-card border border-dark-border rounded px-3 py-2 text-white text-sm"
                  >
                    <option value={7}>7 days</option>
                    <option value={30}>30 days</option>
                    <option value={60}>60 days</option>
                    <option value={90}>90 days</option>
                    <option value={180}>180 days</option>
                    <option value={365}>1 year</option>
                  </select>
                </div>
                <div>
                  <label className="block text-dark-text-secondary text-sm mb-2">
                    Cleanup Frequency
                  </label>
                  <select
                    value={databaseConfig.cleanup_frequency}
                    onChange={(e) => {
                      setDatabaseConfig({ ...databaseConfig, cleanup_frequency: e.target.value });
                      setSavedChanges(false);
                    }}
                    className="w-full bg-dark-card border border-dark-border rounded px-3 py-2 text-white text-sm"
                  >
                    <option value="hourly">Every 4 hours</option>
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                  </select>
                </div>
              </div>
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={databaseConfig.auto_cleanup_enabled}
                  onChange={(e) => {
                    setDatabaseConfig({ ...databaseConfig, auto_cleanup_enabled: e.target.checked });
                    setSavedChanges(false);
                  }}
                  className="w-4 h-4"
                />
                <span className="text-white text-sm">Auto-cleanup enabled</span>
              </label>
            </div>

            {/* Backup */}
            <div className="border-t border-dark-border pt-6 space-y-4">
              <h3 className="text-white font-bold">Backup Management</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-dark-text-secondary text-sm mb-2">
                    Backup Frequency
                  </label>
                  <select
                    value={databaseConfig.backup_frequency}
                    onChange={(e) => {
                      setDatabaseConfig({ ...databaseConfig, backup_frequency: e.target.value });
                      setSavedChanges(false);
                    }}
                    className="w-full bg-dark-card border border-dark-border rounded px-3 py-2 text-white text-sm"
                  >
                    <option value="4h">Every 4 hours</option>
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                  </select>
                </div>
                <div className="bg-dark-sidebar rounded-lg p-4">
                  <p className="text-dark-text-secondary text-sm mb-1">Last Backup</p>
                  <p className="text-white font-bold">{databaseConfig.last_backup}</p>
                </div>
              </div>
              <div className="flex gap-3">
                <button className="px-4 py-2 bg-accent-cyan text-dark-sidebar rounded font-bold hover:opacity-90 text-sm">
                  Manual Backup
                </button>
                <button className="px-4 py-2 border border-dark-border rounded hover:bg-dark-hover transition text-sm">
                  Optimize Database
                </button>
                <button className="px-4 py-2 border border-dark-border rounded hover:bg-dark-hover transition text-sm">
                  Export Database
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Settings;
