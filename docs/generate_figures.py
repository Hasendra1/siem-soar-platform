"""Generate evidence screenshots for the interim report."""
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

OUT_DIR = r'C:\siem-soar-platform\docs\screenshots'
import os
os.makedirs(OUT_DIR, exist_ok=True)

# ── Figure 1: Device Ensemble Scores Bar Chart ──
with open(r'C:\siem-soar-platform\results\device_scores.json') as f:
    scores = json.load(f)

devices = [s['device_name'] for s in scores]
ensemble = [s['ensemble_score'] for s in scores]
iso_scores = [s['iso_score'] for s in scores]
db_scores = [s['db_score'] for s in scores]

fig, ax = plt.subplots(figsize=(12, 6))
x = np.arange(len(devices))
width = 0.25
bars1 = ax.bar(x - width, iso_scores, width, label='Isolation Forest', color='#2196F3', alpha=0.85)
bars2 = ax.bar(x, db_scores, width, label='DBSCAN', color='#FF9800', alpha=0.85)
bars3 = ax.bar(x + width, ensemble, width, label='Ensemble', color='#F44336', alpha=0.85)
ax.set_xlabel('Device', fontsize=12)
ax.set_ylabel('Anomaly Score', fontsize=12)
ax.set_title('Two-Tier ML Pipeline: Per-Device Anomaly Scores', fontsize=14, fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(devices, rotation=30, ha='right', fontsize=10)
ax.legend(fontsize=11)
ax.axhline(y=0.90, color='red', linestyle='--', alpha=0.7, label='Isolation Threshold (0.90)')
ax.axhline(y=0.70, color='orange', linestyle='--', alpha=0.5, label='Alert Threshold (0.70)')
ax.text(8.5, 0.91, 'Isolation Threshold', color='red', fontsize=9, ha='right')
ax.text(8.5, 0.71, 'Alert Threshold', color='orange', fontsize=9, ha='right')
ax.set_ylim(0, 1.15)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, 'fig_device_scores.png'), dpi=150)
print('Saved fig_device_scores.png')
plt.close()

# ── Figure 2: Attack Event Distribution ──
actions = {'PORT_SCAN': 600, 'UNAUTHORIZED_READ': 120, 'LATERAL_MOVEMENT': 96, 'MALICIOUS_WRITE': 72, 'DATA_EXFIL': 36}
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

colors = ['#F44336', '#FF9800', '#FFC107', '#9C27B0', '#2196F3']
wedges, texts, autotexts = ax1.pie(actions.values(), labels=actions.keys(), autopct='%1.1f%%',
                                     colors=colors, startangle=90, textprops={'fontsize': 10})
ax1.set_title('Attack Event Distribution by Type', fontsize=13, fontweight='bold')

bars = ax2.barh(list(actions.keys()), list(actions.values()), color=colors, alpha=0.85)
ax2.set_xlabel('Event Count', fontsize=11)
ax2.set_title('Attack Events (Total: 924)', fontsize=13, fontweight='bold')
for bar, val in zip(bars, actions.values()):
    ax2.text(bar.get_width() + 5, bar.get_y() + bar.get_height()/2, str(val), va='center', fontsize=11)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, 'fig_attack_distribution.png'), dpi=150)
print('Saved fig_attack_distribution.png')
plt.close()

# ── Figure 3: Feature Comparison ──
import pandas as pd
df = pd.read_csv(r'C:\siem-soar-platform\dataset\clustering_dataset.csv')
atk = df[df['device_name'] == 'Engineering-WS']
plc = df[df['device_name'] == 'PLC1']
hmi = df[df['device_name'] == 'HMI']
sensor = df[df['device_name'] == 'Sensor-Temp']

fig, axes = plt.subplots(2, 2, figsize=(14, 10))
# scan_rate over time
axes[0,0].plot(atk['window_id'], atk['scan_rate'], 'r-o', label='Engineering-WS (Attacker)', markersize=4)
axes[0,0].plot(plc['window_id'], plc['scan_rate'], 'b-s', label='PLC1 (Normal)', markersize=3, alpha=0.7)
axes[0,0].plot(hmi['window_id'], hmi['scan_rate'], 'g-^', label='HMI (Normal)', markersize=3, alpha=0.7)
axes[0,0].set_title('Scan Rate Over Time', fontweight='bold')
axes[0,0].set_ylabel('scan_rate')
axes[0,0].legend(fontsize=8)
axes[0,0].set_xlabel('Window ID')

# write_ratio over time
axes[0,1].plot(atk['window_id'], atk['write_ratio'], 'r-o', label='Engineering-WS (Attacker)', markersize=4)
axes[0,1].plot(plc['window_id'], plc['write_ratio'], 'b-s', label='PLC1 (Normal)', markersize=3, alpha=0.7)
axes[0,1].set_title('Write Ratio Over Time', fontweight='bold')
axes[0,1].set_ylabel('write_ratio')
axes[0,1].legend(fontsize=8)
axes[0,1].set_xlabel('Window ID')

# cross_zone_ratio over time
axes[1,0].plot(atk['window_id'], atk['cross_zone_ratio'], 'r-o', label='Engineering-WS (Attacker)', markersize=4)
axes[1,0].plot(sensor['window_id'], sensor['cross_zone_ratio'], 'c-d', label='Sensor-Temp (Normal)', markersize=3, alpha=0.7)
axes[1,0].set_title('Cross-Zone Ratio Over Time', fontweight='bold')
axes[1,0].set_ylabel('cross_zone_ratio')
axes[1,0].legend(fontsize=8)
axes[1,0].set_xlabel('Window ID')

# total_packets over time
axes[1,1].plot(atk['window_id'], atk['total_packets'], 'r-o', label='Engineering-WS (Attacker)', markersize=4)
axes[1,1].plot(plc['window_id'], plc['total_packets'], 'b-s', label='PLC1 (Normal)', markersize=3, alpha=0.7)
axes[1,1].plot(hmi['window_id'], hmi['total_packets'], 'g-^', label='HMI (Normal)', markersize=3, alpha=0.7)
axes[1,1].set_title('Total Packets Over Time', fontweight='bold')
axes[1,1].set_ylabel('total_packets')
axes[1,1].legend(fontsize=8)
axes[1,1].set_xlabel('Window ID')

fig.suptitle('Behavioural Feature Comparison: Attacker vs. Normal Devices', fontsize=14, fontweight='bold', y=1.01)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, 'fig_feature_comparison.png'), dpi=150, bbox_inches='tight')
print('Saved fig_feature_comparison.png')
plt.close()

# ── Figure 4: Network Topology Diagram ──
fig, ax = plt.subplots(figsize=(14, 8))
ax.set_xlim(0, 14)
ax.set_ylim(0, 9)
ax.set_aspect('equal')
ax.axis('off')

# Zone boxes
from matplotlib.patches import FancyBboxPatch
ot_box = FancyBboxPatch((0.5, 4.5), 4.5, 4, boxstyle="round,pad=0.3", facecolor='#BBDEFB', edgecolor='#1565C0', linewidth=2, alpha=0.3)
iot_box = FancyBboxPatch((5.5, 4.5), 4.5, 4, boxstyle="round,pad=0.3", facecolor='#C8E6C9', edgecolor='#2E7D32', linewidth=2, alpha=0.3)
dmz_box = FancyBboxPatch((10.5, 4.5), 3, 4, boxstyle="round,pad=0.3", facecolor='#FFE0B2', edgecolor='#E65100', linewidth=2, alpha=0.3)
ax.add_patch(ot_box); ax.add_patch(iot_box); ax.add_patch(dmz_box)
ax.text(2.75, 8.2, 'OT Zone\n192.168.10.0/24', ha='center', fontsize=11, fontweight='bold', color='#1565C0')
ax.text(7.75, 8.2, 'IoT Zone\n192.168.20.0/24', ha='center', fontsize=11, fontweight='bold', color='#2E7D32')
ax.text(12, 8.2, 'DMZ Zone\n192.168.30.0/24', ha='center', fontsize=11, fontweight='bold', color='#E65100')

# Devices
devices_pos = {
    'PLC1\n.10.10': (1.5, 7), 'PLC2\n.10.11': (3.5, 7), 'HMI\n.10.20': (2.5, 5.5),
    'Eng-WS\n.10.50\n(ATTACKER)': (1.5, 5.5),
    'Sensor-T\n.20.10': (6.5, 7), 'Sensor-P\n.20.11': (8.5, 7), 'MQTT\n.20.100': (7.5, 5.5),
    'CCTV\n.30.10': (11.5, 7), 'Gateway\n.30.100': (12, 5.5),
}
colors_dev = ['#2196F3','#2196F3','#4CAF50','#F44336','#8BC34A','#8BC34A','#009688','#FF9800','#FF5722']
for (label, (x, y)), color in zip(devices_pos.items(), colors_dev):
    circle = plt.Circle((x, y), 0.4, color=color, alpha=0.8)
    ax.add_patch(circle)
    ax.text(x, y-0.6, label, ha='center', va='top', fontsize=7, fontweight='bold')

# SIEM layer
siem_box = FancyBboxPatch((1, 0.5), 12, 3, boxstyle="round,pad=0.3", facecolor='#E8EAF6', edgecolor='#283593', linewidth=2, alpha=0.4)
ax.add_patch(siem_box)
ax.text(7, 3.2, 'SIEM + SOAR Analysis Layer', ha='center', fontsize=12, fontweight='bold', color='#283593')
components = ['Scapy\nCapture', 'Feature\nExtraction', 'Isolation\nForest', 'DBSCAN', 'Smart\nIsolator', 'Flask\nAPI', 'React\nDashboard']
for i, comp in enumerate(components):
    x = 2 + i * 1.6
    box = FancyBboxPatch((x-0.5, 1), 1.2, 1.5, boxstyle="round,pad=0.1", facecolor='white', edgecolor='#5C6BC0', linewidth=1)
    ax.add_patch(box)
    ax.text(x+0.1, 1.75, comp, ha='center', va='center', fontsize=7, fontweight='bold')

ax.set_title('System Architecture: IoT/OT SIEM+SOAR Platform', fontsize=15, fontweight='bold', pad=20)
plt.savefig(os.path.join(OUT_DIR, 'fig_architecture.png'), dpi=150, bbox_inches='tight')
print('Saved fig_architecture.png')
plt.close()

print('\nAll figures generated successfully!')
