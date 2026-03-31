import initSqlJs from 'sql.js';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DB_PATH = path.join(__dirname, '..', '..', 'data', 'sandbox.db');

let db = null;
let SQL = null;

export async function getDatabase() {
  if (db) return db;

  const dataDir = path.dirname(DB_PATH);
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  SQL = await initSqlJs();

  // Load existing database or create new
  if (fs.existsSync(DB_PATH)) {
    const buffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }

  initializeSchema(db);
  saveDatabase(); // persist initial schema
  return db;
}

function initializeSchema(database) {
  database.run(`
    CREATE TABLE IF NOT EXISTS executions (
      id TEXT PRIMARY KEY,
      language TEXT NOT NULL,
      code TEXT NOT NULL,
      input_method TEXT NOT NULL DEFAULT 'paste',
      input_source TEXT,
      filename TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      verdict TEXT DEFAULT 'pending',
      threat_score INTEGER DEFAULT 0,
      exit_code INTEGER,
      signal TEXT,
      termination_reason TEXT,
      stdout TEXT DEFAULT '',
      stderr TEXT DEFAULT '',
      execution_time_ms INTEGER DEFAULT 0,
      max_memory_mb REAL DEFAULT 0,
      max_cpu_percent REAL DEFAULT 0,
      timeout_limit_ms INTEGER DEFAULT 10000,
      memory_limit_mb INTEGER DEFAULT 128,
      static_analysis_result TEXT,
      threat_breakdown TEXT,
      behaviors_detected TEXT,
      policy_violations TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      started_at TEXT,
      completed_at TEXT
    );
  `);

  database.run(`
    CREATE TABLE IF NOT EXISTS violations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      execution_id TEXT NOT NULL,
      timestamp TEXT NOT NULL DEFAULT (datetime('now')),
      severity TEXT NOT NULL,
      category TEXT NOT NULL,
      operation TEXT NOT NULL,
      description TEXT NOT NULL,
      action_taken TEXT NOT NULL,
      FOREIGN KEY (execution_id) REFERENCES executions(id) ON DELETE CASCADE
    );
  `);

  database.run(`
    CREATE TABLE IF NOT EXISTS resource_samples (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      execution_id TEXT NOT NULL,
      timestamp_ms INTEGER NOT NULL,
      cpu_percent REAL DEFAULT 0,
      memory_mb REAL DEFAULT 0,
      memory_rss_mb REAL DEFAULT 0,
      FOREIGN KEY (execution_id) REFERENCES executions(id) ON DELETE CASCADE
    );
  `);

  database.run(`
    CREATE TABLE IF NOT EXISTS execution_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      execution_id TEXT NOT NULL,
      timestamp TEXT NOT NULL DEFAULT (datetime('now')),
      event_type TEXT NOT NULL,
      data TEXT,
      FOREIGN KEY (execution_id) REFERENCES executions(id) ON DELETE CASCADE
    );
  `);

  // Create indexes (ignore if exist)
  const indexes = [
    'CREATE INDEX IF NOT EXISTS idx_executions_created_at ON executions(created_at DESC)',
    'CREATE INDEX IF NOT EXISTS idx_executions_status ON executions(status)',
    'CREATE INDEX IF NOT EXISTS idx_executions_verdict ON executions(verdict)',
    'CREATE INDEX IF NOT EXISTS idx_violations_execution_id ON violations(execution_id)',
    'CREATE INDEX IF NOT EXISTS idx_resource_samples_execution_id ON resource_samples(execution_id)',
    'CREATE INDEX IF NOT EXISTS idx_execution_events_execution_id ON execution_events(execution_id)',
  ];
  for (const idx of indexes) {
    database.run(idx);
  }
}

export function saveDatabase() {
  if (db) {
    const data = db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(DB_PATH, buffer);
  }
}

export function closeDatabase() {
  if (db) {
    saveDatabase();
    db.close();
    db = null;
  }
}

// Helper functions for common DB operations
export function dbRun(sql, params = []) {
  if (!db) throw new Error('Database not initialized');
  db.run(sql, params);
  saveDatabase();
}

export function dbGet(sql, params = []) {
  if (!db) throw new Error('Database not initialized');
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return null;
}

export function dbAll(sql, params = []) {
  if (!db) throw new Error('Database not initialized');
  const stmt = db.prepare(sql);
  if (params.length) stmt.bind(params);
  const results = [];
  while (stmt.step()) {
    results.push(stmt.getAsObject());
  }
  stmt.free();
  return results;
}
