import json, sqlite3
from datetime import datetime, timezone
from ..config import DATABASE_PATH

def now(): return datetime.now(timezone.utc).isoformat()

def connect():
    c = sqlite3.connect(DATABASE_PATH)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    c = connect()
    c.executescript('''
    CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, alert_id TEXT, payload TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT, action TEXT, component TEXT, status TEXT, duration_ms INTEGER, message TEXT, created_at TEXT);
    CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT, channel TEXT, recipient TEXT, subject TEXT, body TEXT, status TEXT, created_at TEXT);
    CREATE TABLE IF NOT EXISTS system_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, scenario TEXT, status TEXT, duration_ms INTEGER, created_at TEXT);
    CREATE TABLE IF NOT EXISTS assets (id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS allowlist_entries (id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS responses (id TEXT PRIMARY KEY, incident_id TEXT, payload TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS rule_definitions (id TEXT PRIMARY KEY, version TEXT NOT NULL, enabled INTEGER NOT NULL, payload TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_incident ON audit_logs(incident_id);
    CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
    ''')
    c.commit(); c.close()

def save_alert(alert):
    c=connect(); c.execute('INSERT OR REPLACE INTO alerts VALUES (?,?,?)',(alert['alert_id'],json.dumps(alert),now())); c.commit(); c.close()

def save_incident(incident):
    c=connect(); c.execute('INSERT OR REPLACE INTO incidents VALUES (?,?,?,?)',(incident['incident_id'],incident['alert']['alert_id'],json.dumps(incident),now())); c.commit(); c.close()

def log(incident_id, action, component, status, duration_ms, message):
    c=connect(); c.execute('INSERT INTO audit_logs(incident_id,action,component,status,duration_ms,message,created_at) VALUES (?,?,?,?,?,?,?)',(incident_id,action,component,status,duration_ms,message,now())); c.commit(); c.close()

def list_incidents():
    c=connect(); rows=c.execute('SELECT payload FROM incidents ORDER BY created_at DESC').fetchall(); c.close(); return [json.loads(r['payload']) for r in rows]

def get_incident(i):
    c=connect(); r=c.execute('SELECT payload FROM incidents WHERE id=?',(i,)).fetchone(); c.close(); return json.loads(r['payload']) if r else None

def list_audit():
    c=connect(); rows=c.execute('SELECT * FROM audit_logs ORDER BY id DESC').fetchall(); c.close(); return [dict(r) for r in rows]

def _list_table(table):
    c = connect(); rows = c.execute(f'SELECT payload FROM {table} ORDER BY updated_at DESC').fetchall(); c.close()
    return [json.loads(r['payload']) for r in rows]

def save_entity(table, entity):
    entity_id = entity.get('id') or entity.get('asset_id') or entity.get('account_id') or entity.get('allowlist_id')
    timestamp = now(); entity = dict(entity); entity['id'] = entity_id
    c = connect(); c.execute(f'INSERT OR REPLACE INTO {table}(id,payload,created_at,updated_at) VALUES (?,?,COALESCE((SELECT created_at FROM {table} WHERE id=?),?),?)', (entity_id, json.dumps(entity), entity_id, timestamp, timestamp)); c.commit(); c.close(); return entity

def list_entities(table): return _list_table(table)

def delete_entity(table, entity_id):
    c = connect(); c.execute(f'DELETE FROM {table} WHERE id=?', (entity_id,)); changed = c.total_changes; c.commit(); c.close(); return changed > 0

def save_response(response):
    return save_entity('responses', response)

def get_response(response_id):
    c = connect(); row = c.execute('SELECT payload FROM responses WHERE id=?', (response_id,)).fetchone(); c.close(); return json.loads(row['payload']) if row else None
