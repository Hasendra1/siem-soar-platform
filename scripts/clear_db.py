import sqlite3
from pathlib import Path

DB_PATH = Path("c:/siem-soar-platform/dataset/siem_database.db")

def clear_db():
    if not DB_PATH.exists():
        print(f"Database not found at {DB_PATH}")
        return
    conn = sqlite3.connect(str(DB_PATH))
    tables = ['events', 'anomalies', 'incidents', 'isolations', 'investigations']
    for table in tables:
        conn.execute(f"DELETE FROM {table}")
        print(f"Cleared table: {table}")
    
    # Reset autoincrements
    conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('events', 'anomalies', 'incidents', 'isolations', 'investigations')")
    print("Reset auto-increments.")
    conn.commit()
    conn.close()
    print("Database cleared successfully!")

if __name__ == "__main__":
    clear_db()
