import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import IsolatedDevices from './pages/IsolatedDevices';
import RulesTriggered from './pages/RulesTriggered';
import AnomaliesDetected from './pages/AnomaliesDetected';
import Incidents from './pages/Incidents';
import ThreatHunting from './pages/ThreatHunting';
import Settings from './pages/Settings';

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="isolated-devices" element={<IsolatedDevices />} />
        <Route path="rules-triggered" element={<RulesTriggered />} />
        <Route path="anomalies-detected" element={<AnomaliesDetected />} />
        <Route path="incidents" element={<Incidents />} />
        <Route path="threat-hunting" element={<ThreatHunting />} />
        <Route path="settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Route>
    </Routes>
  );
}
