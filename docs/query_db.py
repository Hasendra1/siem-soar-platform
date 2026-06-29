import sqlite3
conn = sqlite3.connect(r'C:\siem-soar-platform\dataset\siem_database.db')
conn.row_factory = sqlite3.Row

tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
print('TABLES:', tables)

ev = conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
print(f'\nTotal Events: {ev}')

rows = conn.execute('SELECT action, COUNT(*) as cnt FROM events GROUP BY action ORDER BY cnt DESC').fetchall()
print('\nEvents by Action:')
for r in rows:
    print(f'  {r["action"]:25s} {r["cnt"]}')

iso = conn.execute('SELECT container_name, ip_address, isolation_reason, isolation_timestamp FROM isolations WHERE success=1 ORDER BY isolation_timestamp').fetchall()
print(f'\nIsolations ({len(iso)}):')
for r in iso:
    print(f'  {r["container_name"]:18s} {r["ip_address"]:18s} {r["isolation_reason"]}')

anom = conn.execute('SELECT COUNT(*) FROM anomalies').fetchone()[0]
print(f'\nAnomalies: {anom}')

inc = conn.execute('SELECT incident_name, severity, status, description FROM incidents').fetchall()
print(f'\nIncidents ({len(inc)}):')
for r in inc:
    print(f'  [{r["severity"]}] {r["incident_name"]} - {r["status"]}')
    desc = r["description"]
    print(f'    {desc[:150]}')

conn.close()
