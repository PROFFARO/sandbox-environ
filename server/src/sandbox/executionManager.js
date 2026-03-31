/**
 * Execution Manager (Orchestrator)
 * 
 * Orchestrates the full execution pipeline:
 * 1. Input validation
 * 2. Static analysis
 * 3. Policy enforcement
 * 4. Process isolation & execution
 * 5. Threat detection & scoring
 * 6. Result logging
 */

import { v4 as uuidv4 } from 'uuid';
import { analyzeCode } from './staticAnalyzer.js';
import { enforcePolicy, getExecutionConfig } from './policyEnforcer.js';
import { ProcessIsolator } from './processIsolator.js';
import { analyzeExecution } from './threatDetector.js';
import {
  createExecution,
  updateStaticAnalysis,
  markExecutionStarted,
  markExecutionBlocked,
  completeExecution,
  storeResourceSamples,
  storeViolation,
  logEvent,
  getExecution
} from './executionLogger.js';

// Active executions map for WebSocket streaming
const activeExecutions = new Map();

/**
 * Execute code through the full sandbox pipeline
 * @param {Object} params - Execution parameters
 * @param {Function} onEvent - Callback for real-time events
 * @returns {Object} Execution result
 */
export async function executeCode(params, onEvent = null) {
  const {
    code,
    language,
    inputMethod = 'paste',
    inputSource = null,
    filename = null,
    timeoutMs,
    memoryLimitMb,
  } = params;

  const executionId = uuidv4();
  const emit = (event, data) => {
    if (onEvent) onEvent(event, { executionId, ...data });
  };

  try {
    // ============================================
    // PHASE 1: Create execution record
    // ============================================
    const config = getExecutionConfig(language) || {};
    const timeout = timeoutMs || config.timeoutMs || 10000;
    const memLimit = memoryLimitMb || config.maxMemoryMb || 128;

    createExecution({
      id: executionId,
      language,
      code,
      inputMethod,
      inputSource,
      filename,
      timeoutLimitMs: timeout,
      memoryLimitMb: memLimit,
    });

    emit('execution:created', { language, codeLength: code.length });

    // ============================================
    // PHASE 2: Static Analysis
    // ============================================
    emit('execution:phase', { phase: 'static_analysis', message: 'Running static code analysis...' });
    const staticResult = analyzeCode(code, language);
    updateStaticAnalysis(executionId, staticResult);

    emit('execution:static_analysis', {
      threatScore: staticResult.threatScore,
      severity: staticResult.overallSeverity,
      findings: staticResult.findings,
      summary: staticResult.summary,
      blocked: staticResult.blocked
    });

    // If static analysis blocks, stop here
    if (staticResult.blocked) {
      markExecutionBlocked(executionId, 'static_analysis', staticResult.findings);

      const threatResult = analyzeExecution({
        staticAnalysis: staticResult,
        stdout: '',
        stderr: '',
        exitCode: null,
        wasKilled: true,
        killReason: 'policy_violation',
        violations: staticResult.findings,
      });

      // Update execution with threat data even though blocked
      completeExecution(executionId, {
        stdout: '',
        stderr: `Execution blocked by static analysis:\n${staticResult.summary}`,
        exitCode: null,
        signal: null,
        executionTimeMs: 0,
        maxMemoryMb: 0,
        maxCpuPercent: 0,
        killed: true,
        killReason: 'static_analysis_blocked',
        threatScore: threatResult.threatScore,
        verdict: 'blocked',
        threatBreakdown: threatResult.categoryScores,
        behaviors: threatResult.behaviors,
        violations: staticResult.findings,
      });

      emit('execution:blocked', {
        reason: 'static_analysis',
        summary: staticResult.summary,
        threatScore: threatResult.threatScore,
      });

      return getExecution(executionId);
    }

    // ============================================
    // PHASE 3: Policy Enforcement
    // ============================================
    emit('execution:phase', { phase: 'policy_check', message: 'Checking execution policies...' });
    const policyResult = enforcePolicy(code, language);

    if (!policyResult.allowed) {
      markExecutionBlocked(executionId, 'policy_violation', policyResult.violations);

      for (const violation of policyResult.violations) {
        storeViolation(executionId, {
          severity: violation.severity,
          category: 'Policy',
          operation: violation.rule,
          description: violation.message,
          action_taken: 'blocked'
        });
      }

      const threatResult = analyzeExecution({
        staticAnalysis: staticResult,
        wasKilled: true,
        killReason: 'policy_violation',
        violations: policyResult.violations,
      });

      completeExecution(executionId, {
        stdout: '',
        stderr: `Execution blocked by policy:\n${policyResult.violations.map(v => v.message).join('\n')}`,
        exitCode: null,
        signal: null,
        executionTimeMs: 0,
        maxMemoryMb: 0,
        maxCpuPercent: 0,
        killed: true,
        killReason: 'policy_violation',
        threatScore: threatResult.threatScore,
        verdict: 'blocked',
        threatBreakdown: threatResult.categoryScores,
        behaviors: threatResult.behaviors,
        violations: policyResult.violations,
      });

      emit('execution:blocked', {
        reason: 'policy_violation',
        violations: policyResult.violations,
        threatScore: threatResult.threatScore,
      });

      return getExecution(executionId);
    }

    // ============================================
    // PHASE 4: Sandboxed Execution
    // ============================================
    emit('execution:phase', { phase: 'execution', message: 'Starting sandboxed execution...' });
    markExecutionStarted(executionId);

    const isolator = new ProcessIsolator({
      executionId,
      language,
      timeoutMs: timeout,
      memoryLimitMb: memLimit,
      maxOutputBytes: config.maxOutputBytes || 512 * 1024,
    });

    // Store reference to active execution
    activeExecutions.set(executionId, isolator);

    // Wire up real-time events
    isolator.on('started', (data) => {
      emit('execution:started', data);
    });

    isolator.on('stdout', (data) => {
      emit('execution:output', { stream: 'stdout', data: data.data });
    });

    isolator.on('stderr', (data) => {
      emit('execution:output', { stream: 'stderr', data: data.data });
    });

    isolator.on('resource', (sample) => {
      emit('execution:resource', sample);
    });

    isolator.on('warning', (warning) => {
      emit('execution:warning', warning);
      storeViolation(executionId, {
        severity: 'warning',
        category: warning.type,
        operation: warning.type,
        description: warning.message,
        action_taken: 'warning_logged'
      });
    });

    isolator.on('violation', (violation) => {
      emit('execution:violation', violation);
      storeViolation(executionId, violation);
    });

    // Execute the code
    const execResult = await isolator.execute(code);

    // Remove from active executions
    activeExecutions.delete(executionId);

    // ============================================
    // PHASE 5: Threat Detection & Scoring
    // ============================================
    emit('execution:phase', { phase: 'threat_analysis', message: 'Analyzing execution behavior...' });

    const threatResult = analyzeExecution({
      staticAnalysis: staticResult,
      stdout: execResult.stdout,
      stderr: execResult.stderr,
      exitCode: execResult.exitCode,
      signal: execResult.signal,
      executionTimeMs: execResult.executionTimeMs,
      maxMemoryMb: execResult.maxMemoryMb,
      maxCpuPercent: execResult.maxCpuPercent,
      memoryLimitMb: memLimit,
      timeoutLimitMs: timeout,
      wasKilled: execResult.killed,
      killReason: execResult.killReason,
      resourceSamples: execResult.resourceSamples,
    });

    // ============================================
    // PHASE 6: Store Results
    // ============================================
    // Store resource samples
    storeResourceSamples(executionId, execResult.resourceSamples);

    // Complete execution record
    completeExecution(executionId, {
      stdout: execResult.stdout,
      stderr: execResult.stderr,
      exitCode: execResult.exitCode,
      signal: execResult.signal,
      executionTimeMs: execResult.executionTimeMs,
      maxMemoryMb: execResult.maxMemoryMb,
      maxCpuPercent: execResult.maxCpuPercent,
      killed: execResult.killed,
      killReason: execResult.killReason,
      threatScore: threatResult.threatScore,
      verdict: threatResult.verdict,
      threatBreakdown: threatResult.categoryScores,
      behaviors: threatResult.behaviors,
      violations: [],
    });

    emit('execution:completed', {
      threatScore: threatResult.threatScore,
      verdict: threatResult.verdict,
      summary: threatResult.summary,
      executionTimeMs: execResult.executionTimeMs,
      exitCode: execResult.exitCode,
    });

    return getExecution(executionId);

  } catch (err) {
    logEvent(executionId, 'error', JSON.stringify({ message: err.message }));
    emit('execution:error', { message: err.message });

    try {
      completeExecution(executionId, {
        stdout: '',
        stderr: `Internal error: ${err.message}`,
        exitCode: 1,
        signal: null,
        executionTimeMs: 0,
        maxMemoryMb: 0,
        maxCpuPercent: 0,
        killed: false,
        killReason: 'internal_error',
        threatScore: 0,
        verdict: 'error',
        threatBreakdown: {},
        behaviors: [],
        violations: [],
      });
    } catch (e) { /* ignore */ }

    return getExecution(executionId);
  }
}

/**
 * Get active execution isolator (for WebSocket management)
 */
export function getActiveExecution(executionId) {
  return activeExecutions.get(executionId);
}

export { activeExecutions };
