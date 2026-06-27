import sqlite3

DB_PATH = "soc_assistant.db"  # adjust if your db is inside backend/ etc.

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

cur.execute("""
SELECT event_type, user_id, created_at
FROM system_logs
ORDER BY created_at DESC
LIMIT 20;
""")

rows = cur.fetchall()
for r in rows:
    print(r)

conn.close()