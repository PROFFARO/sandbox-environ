/**
 * Execution Logger Module
 * 
 * Comprehensive logging of execution timeline and events.
 * Stores all execution data to SQLite database.
 */

import { dbRun, dbGet, dbAll, saveDatabase } from '../database/schema.js';

/**
 * Create a new execution record
 */
export function createExecution(data) {
  const {
    id,
    language,
    code,
    inputMethod = 'paste',
    inputSource = null,
    filename = null,
    timeoutLimitMs = 10000,
    memoryLimitMb = 128,
  } = data;

  dbRun(
    `INSERT INTO executions (id, language, code, input_method, input_source, filename, status, timeout_limit_ms, memory_limit_mb)
     VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
    [id, language, code, inputMethod, inputSource, filename, timeoutLimitMs, memoryLimitMb]
  );

  logEvent(id, 'created', JSON.stringify({ language, inputMethod, codeLength: code.length }));
}

/**
 * Update execution with static analysis results
 */
export function updateStaticAnalysis(executionId, analysisResult) {
  dbRun(
    `UPDATE executions SET static_analysis_result = ?, status = 'analyzing' WHERE id = ?`,
    [JSON.stringify(analysisResult), executionId]
  );
  logEvent(executionId, 'static_analysis_complete', JSON.stringify({
    threatScore: analysisResult.threatScore,
    severity: analysisResult.overallSeverity,
    findingsCount: analysisResult.findings.length,
    blocked: analysisResult.blocked
  }));
}

/**
 * Mark execution as started
 */
export function markExecutionStarted(executionId) {
  dbRun(
    `UPDATE executions SET status = 'running', started_at = datetime('now') WHERE id = ?`,
    [executionId]
  );
  logEvent(executionId, 'execution_started', null);
}

/**
 * Mark execution as blocked (by static analysis or policy)
 */
export function markExecutionBlocked(executionId, reason, violations) {
  dbRun(
    `UPDATE executions SET status = 'blocked', verdict = 'blocked', termination_reason = ?,
     policy_violations = ?, completed_at = datetime('now') WHERE id = ?`,
    [reason, JSON.stringify(violations), executionId]
  );
  logEvent(executionId, 'execution_blocked', JSON.stringify({ reason }));
}

/**
 * Complete an execution with full results
 */
export function completeExecution(executionId, result) {
  const {
    stdout = '',
    stderr = '',
    exitCode,
    signal,
    executionTimeMs,
    maxMemoryMb,
    maxCpuPercent,
    killed,
    killReason,
    threatScore,
    verdict,
    threatBreakdown,
    behaviors,
    violations
  } = result;

  let status = 'completed';
  let terminationReason = 'normal';

  if (killed) {
    status = 'killed';
    terminationReason = killReason || 'unknown';
  } else if (exitCode !== 0) {
    status = 'error';
    terminationReason = 'non_zero_exit';
  }

  dbRun(
    `UPDATE executions SET
      status = ?, verdict = ?, threat_score = ?,
      exit_code = ?, signal = ?, termination_reason = ?,
      stdout = ?, stderr = ?,
      execution_time_ms = ?, max_memory_mb = ?, max_cpu_percent = ?,
      threat_breakdown = ?, behaviors_detected = ?,
      policy_violations = ?, completed_at = datetime('now')
    WHERE id = ?`,
    [
      status, verdict, threatScore,
      exitCode, signal, terminationReason,
      stdout.substring(0, 100000), // cap stored output
      stderr.substring(0, 50000),
      executionTimeMs, maxMemoryMb, maxCpuPercent,
      JSON.stringify(threatBreakdown),
      JSON.stringify(behaviors),
      JSON.stringify(violations),
      executionId
    ]
  );

  logEvent(executionId, 'execution_completed', JSON.stringify({
    status, verdict, threatScore, executionTimeMs, exitCode
  }));
}

/**
 * Store resource samples for an execution
 */
export function storeResourceSamples(executionId, samples) {
  for (const sample of samples) {
    dbRun(
      `INSERT INTO resource_samples (execution_id, timestamp_ms, cpu_percent, memory_mb, memory_rss_mb)
       VALUES (?, ?, ?, ?, ?)`,
      [executionId, sample.timestamp_ms, sample.cpu_percent, sample.memory_mb, sample.memory_rss_mb || sample.memory_mb]
    );
  }
}

/**
 * Store a violation record
 */
export function storeViolation(executionId, violation) {
  dbRun(
    `INSERT INTO violations (execution_id, severity, category, operation, description, action_taken)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [
      executionId,
      violation.severity,
      violation.category,
      violation.operation,
      violation.description,
      violation.action_taken || 'logged'
    ]
  );
}

/**
 * Log an execution event
 */
export function logEvent(executionId, eventType, data = null) {
  dbRun(
    `INSERT INTO execution_events (execution_id, event_type, data)
     VALUES (?, ?, ?)`,
    [executionId, eventType, data]
  );
}

/**
 * Get full execution details
 */
export function getExecution(executionId) {
  const execution = dbGet('SELECT * FROM executions WHERE id = ?', [executionId]);
  if (!execution) return null;

  // Parse JSON fields
  const jsonFields = ['static_analysis_result', 'threat_breakdown', 'behaviors_detected', 'policy_violations'];
  for (const field of jsonFields) {
    if (execution[field]) {
      try {
        execution[field] = JSON.parse(execution[field]);
      } catch (e) { /* keep as string */ }
    }
  }

  // Get violations
  execution.violations = dbAll(
    'SELECT * FROM violations WHERE execution_id = ? ORDER BY id',
    [executionId]
  );

  // Get resource samples
  execution.resource_samples = dbAll(
    'SELECT * FROM resource_samples WHERE execution_id = ? ORDER BY timestamp_ms',
    [executionId]
  );

  // Get events
  execution.events = dbAll(
    'SELECT * FROM execution_events WHERE execution_id = ? ORDER BY id',
    [executionId]
  );

  return execution;
}

/**
 * List executions with pagination and filtering
 */
export function listExecutions(options = {}) {
  const {
    limit = 50,
    offset = 0,
    language,
    verdict,
    status,
    search,
    sortBy = 'created_at',
    sortOrder = 'DESC'
  } = options;

  let where = [];
  let params = [];

  if (language) {
    where.push('language = ?');
    params.push(language);
  }
  if (verdict) {
    where.push('verdict = ?');
    params.push(verdict);
  }
  if (status) {
    where.push('status = ?');
    params.push(status);
  }
  if (search) {
    where.push('(code LIKE ? OR stdout LIKE ? OR stderr LIKE ?)');
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }

  const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';
  const validSortColumns = ['created_at', 'threat_score', 'execution_time_ms', 'language'];
  const col = validSortColumns.includes(sortBy) ? sortBy : 'created_at';
  const order = sortOrder.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

  const countResult = dbGet(`SELECT COUNT(*) as total FROM executions ${whereClause}`, params);
  const total = countResult ? countResult.total : 0;

  const executions = dbAll(
    `SELECT id, language, input_method, filename, status, verdict, threat_score,
            exit_code, termination_reason, execution_time_ms, max_memory_mb,
            created_at, completed_at,
            SUBSTR(code, 1, 200) as code_preview
     FROM executions ${whereClause}
     ORDER BY ${col} ${order}
     LIMIT ? OFFSET ?`,
    [...params, limit, offset]
  );

  return { executions, total, limit, offset };
}

/**
 * Delete an execution and its related data
 */
export function deleteExecution(executionId) {
  dbRun('DELETE FROM execution_events WHERE execution_id = ?', [executionId]);
  dbRun('DELETE FROM resource_samples WHERE execution_id = ?', [executionId]);
  dbRun('DELETE FROM violations WHERE execution_id = ?', [executionId]);
  dbRun('DELETE FROM executions WHERE id = ?', [executionId]);
}

/**
 * Get dashboard statistics
 */
export function getStats() {
  const total = dbGet('SELECT COUNT(*) as count FROM executions');
  const safe = dbGet("SELECT COUNT(*) as count FROM executions WHERE verdict = 'safe'");
  const blocked = dbGet("SELECT COUNT(*) as count FROM executions WHERE verdict = 'blocked' OR status = 'blocked'");
  const killed = dbGet("SELECT COUNT(*) as count FROM executions WHERE status = 'killed'");
  const avgScore = dbGet('SELECT AVG(threat_score) as avg FROM executions WHERE status != \'pending\'');
  const avgTime = dbGet('SELECT AVG(execution_time_ms) as avg FROM executions WHERE execution_time_ms > 0');

  const byLanguage = dbAll(
    'SELECT language, COUNT(*) as count FROM executions GROUP BY language'
  );

  const byVerdict = dbAll(
    'SELECT verdict, COUNT(*) as count FROM executions GROUP BY verdict'
  );

  const recentThreatScores = dbAll(
    'SELECT threat_score, created_at FROM executions WHERE status != \'pending\' ORDER BY created_at DESC LIMIT 20'
  );

  return {
    total: total?.count || 0,
    safe: safe?.count || 0,
    blocked: blocked?.count || 0,
    killed: killed?.count || 0,
    avgThreatScore: Math.round(avgScore?.avg || 0),
    avgExecutionTimeMs: Math.round(avgTime?.avg || 0),
    byLanguage,
    byVerdict,
    recentThreatScores,
  };
}
