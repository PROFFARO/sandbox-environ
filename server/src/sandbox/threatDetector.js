/**
 * Threat Detector Module
 * 
 * Runtime behavior analysis and threat scoring inspired by VirusTotal.
 * Monitors execution output and behavior for suspicious patterns,
 * generates a threat score (0-100) and maps to threat categories.
 */

const THREAT_CATEGORIES = {
  EXECUTION: { name: 'Execution', icon: '⚡', description: 'Dynamic code execution or shell spawning' },
  PERSISTENCE: { name: 'Persistence', icon: '📌', description: 'Attempts to maintain access across restarts' },
  PRIVILEGE_ESCALATION: { name: 'Privilege Escalation', icon: '🔺', description: 'Attempting to gain higher privileges' },
  DEFENSE_EVASION: { name: 'Defense Evasion', icon: '🛡️', description: 'Techniques to avoid detection' },
  CREDENTIAL_ACCESS: { name: 'Credential Access', icon: '🔑', description: 'Attempts to steal credentials or keys' },
  DISCOVERY: { name: 'Discovery', icon: '🔍', description: 'System & environment enumeration' },
  LATERAL_MOVEMENT: { name: 'Lateral Movement', icon: '↔️', description: 'Moving across systems/networks' },
  COLLECTION: { name: 'Collection', icon: '📁', description: 'Gathering data of interest' },
  EXFILTRATION: { name: 'Exfiltration', icon: '📤', description: 'Stealing data from the system' },
  IMPACT: { name: 'Impact', icon: '💥', description: 'Destructive or disruptive operations' },
  RESOURCE_ABUSE: { name: 'Resource Abuse', icon: '📈', description: 'Excessive resource consumption' },
  COMMAND_AND_CONTROL: { name: 'Command & Control', icon: '📡', description: 'Remote communication setup' },
};

// Output patterns to check at runtime
const RUNTIME_PATTERNS = [
  // File access attempts
  { pattern: /permission denied/gi, category: 'DISCOVERY', severity: 'warning', description: 'File access denied — attempted restricted file read' },
  { pattern: /no such file or directory/gi, category: 'DISCOVERY', severity: 'info', description: 'Attempted to access non-existent path' },
  { pattern: /cannot open/gi, category: 'COLLECTION', severity: 'warning', description: 'Failed file open attempt' },
  { pattern: /access is denied/gi, category: 'DISCOVERY', severity: 'warning', description: 'Windows access denied' },

  // Network attempts
  { pattern: /connection refused/gi, category: 'COMMAND_AND_CONTROL', severity: 'danger', description: 'Network connection attempted but refused' },
  { pattern: /name or service not known/gi, category: 'COMMAND_AND_CONTROL', severity: 'danger', description: 'DNS resolution attempted' },
  { pattern: /network is unreachable/gi, category: 'COMMAND_AND_CONTROL', severity: 'danger', description: 'Network access attempted' },
  { pattern: /socket/gi, category: 'COMMAND_AND_CONTROL', severity: 'warning', description: 'Socket operation in output' },
  { pattern: /ECONNREFUSED/g, category: 'COMMAND_AND_CONTROL', severity: 'danger', description: 'Network connection refused (Node.js)' },
  { pattern: /ENETUNREACH/g, category: 'COMMAND_AND_CONTROL', severity: 'danger', description: 'Network unreachable (Node.js)' },

  // System enumeration
  { pattern: /linux|darwin|win32|windows/gi, category: 'DISCOVERY', severity: 'info', description: 'OS identification in output' },
  { pattern: /root:|admin:|user:/gi, category: 'CREDENTIAL_ACCESS', severity: 'warning', description: 'User credential info in output' },
  { pattern: /\/home\/|C:\\Users\\/gi, category: 'DISCOVERY', severity: 'warning', description: 'User home directory paths in output' },

  // Error patterns suggesting malicious intent
  { pattern: /ModuleNotFoundError.*(?:os|sys|subprocess|socket)/g, category: 'EXECUTION', severity: 'warning', description: 'Attempted to import restricted module' },
  { pattern: /ImportError.*(?:os|sys|subprocess|socket)/g, category: 'EXECUTION', severity: 'warning', description: 'Failed restricted module import' },
  { pattern: /NameError.*(?:exec|eval|compile|__import__)/g, category: 'EXECUTION', severity: 'danger', description: 'Attempted restricted builtin access' },
  { pattern: /ReferenceError.*(?:process|require|global)/g, category: 'EXECUTION', severity: 'danger', description: 'Attempted restricted global access' },

  // Resource abuse indicators
  { pattern: /MemoryError/g, category: 'RESOURCE_ABUSE', severity: 'critical', description: 'Memory exhaustion error' },
  { pattern: /RecursionError/g, category: 'RESOURCE_ABUSE', severity: 'danger', description: 'Recursion depth exceeded' },
  { pattern: /JavaScript heap out of memory/g, category: 'RESOURCE_ABUSE', severity: 'critical', description: 'V8 heap exhaustion' },
  { pattern: /FATAL ERROR.*allocation failed/g, category: 'RESOURCE_ABUSE', severity: 'critical', description: 'Fatal memory allocation failure' },
  { pattern: /Maximum call stack size exceeded/g, category: 'RESOURCE_ABUSE', severity: 'danger', description: 'Stack overflow (JS)' },

  // Privilege escalation
  { pattern: /operation not permitted/gi, category: 'PRIVILEGE_ESCALATION', severity: 'warning', description: 'Privilege restricted operation attempted' },
  { pattern: /EPERM/g, category: 'PRIVILEGE_ESCALATION', severity: 'warning', description: 'Permission error (Node.js)' },
  { pattern: /EACCES/g, category: 'PRIVILEGE_ESCALATION', severity: 'warning', description: 'Access error (Node.js)' },
];

/**
 * Analyze execution behavior and compute threat score
 */
export function analyzeExecution(executionData) {
  const {
    staticAnalysis,
    stdout = '',
    stderr = '',
    exitCode,
    signal,
    executionTimeMs,
    maxMemoryMb,
    maxCpuPercent,
    memoryLimitMb,
    timeoutLimitMs,
    wasKilled,
    killReason,
    violations = [],
    resourceSamples = []
  } = executionData;

  const behaviors = [];
  const categoryScores = {};

  // 1. Factor in static analysis results
  if (staticAnalysis) {
    const staticScore = staticAnalysis.threatScore || 0;
    for (const finding of (staticAnalysis.findings || [])) {
      addBehavior(behaviors, categoryScores, {
        source: 'static_analysis',
        category: mapCategory(finding.category),
        severity: finding.severity,
        description: finding.description,
        evidence: finding.matches ? finding.matches.join(', ') : ''
      });
    }
  }

  // 2. Analyze runtime output
  const combinedOutput = stdout + '\n' + stderr;
  for (const rule of RUNTIME_PATTERNS) {
    rule.pattern.lastIndex = 0;
    const matches = combinedOutput.match(rule.pattern);
    if (matches) {
      addBehavior(behaviors, categoryScores, {
        source: 'runtime_output',
        category: rule.category,
        severity: rule.severity,
        description: rule.description,
        evidence: matches.slice(0, 3).join(', ')
      });
    }
  }

  // 3. Analyze termination
  if (wasKilled) {
    if (killReason === 'timeout') {
      addBehavior(behaviors, categoryScores, {
        source: 'runtime_behavior',
        category: 'RESOURCE_ABUSE',
        severity: 'danger',
        description: `Execution timed out after ${timeoutLimitMs}ms — possible infinite loop or resource abuse`,
        evidence: `Execution time: ${executionTimeMs}ms`
      });
    } else if (killReason === 'memory_exceeded') {
      addBehavior(behaviors, categoryScores, {
        source: 'runtime_behavior',
        category: 'RESOURCE_ABUSE',
        severity: 'critical',
        description: `Memory limit exceeded (${maxMemoryMb?.toFixed(1)}MB / ${memoryLimitMb}MB)`,
        evidence: `Peak memory: ${maxMemoryMb?.toFixed(1)}MB`
      });
    } else if (killReason === 'policy_violation') {
      addBehavior(behaviors, categoryScores, {
        source: 'policy_enforcement',
        category: 'EXECUTION',
        severity: 'critical',
        description: 'Execution blocked by policy enforcer',
        evidence: violations.map(v => v.message).join('; ')
      });
    }
  }

  // 4. Analyze exit code
  if (exitCode !== 0 && exitCode !== null && !wasKilled) {
    addBehavior(behaviors, categoryScores, {
      source: 'runtime_behavior',
      category: 'EXECUTION',
      severity: 'info',
      description: `Process exited with non-zero code: ${exitCode}`,
      evidence: signal ? `Signal: ${signal}` : ''
    });
  }

  // 5. Analyze resource consumption pattern
  if (resourceSamples.length > 0) {
    const avgCpu = resourceSamples.reduce((s, r) => s + r.cpu_percent, 0) / resourceSamples.length;
    if (avgCpu > 80) {
      addBehavior(behaviors, categoryScores, {
        source: 'resource_monitoring',
        category: 'RESOURCE_ABUSE',
        severity: 'warning',
        description: `High average CPU usage: ${avgCpu.toFixed(1)}%`,
        evidence: `${resourceSamples.length} samples collected`
      });
    }
  }

  // 6. Compute final threat score
  const severityWeights = { info: 2, warning: 5, danger: 15, critical: 30 };
  let rawScore = 0;
  for (const behavior of behaviors) {
    rawScore += severityWeights[behavior.severity] || 0;
  }

  // Apply category multiplier for diverse threat coverage
  const uniqueCategories = Object.keys(categoryScores).length;
  if (uniqueCategories > 3) {
    rawScore = rawScore * 1.2; // Diverse threats are more dangerous
  }

  const threatScore = Math.min(100, Math.round(rawScore));

  // 7. Determine verdict
  let verdict;
  if (threatScore === 0) verdict = 'safe';
  else if (threatScore <= 20) verdict = 'low_risk';
  else if (threatScore <= 50) verdict = 'medium_risk';
  else if (threatScore <= 75) verdict = 'high_risk';
  else verdict = 'critical';

  return {
    threatScore,
    verdict,
    behaviors: behaviors.sort((a, b) => {
      const order = { critical: 0, danger: 1, warning: 2, info: 3 };
      return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
    }),
    categoryScores,
    categories: Object.entries(categoryScores).map(([cat, score]) => ({
      ...THREAT_CATEGORIES[cat],
      category: cat,
      score,
      detectionCount: behaviors.filter(b => b.category === cat).length
    })),
    summary: generateSummary(threatScore, verdict, behaviors, uniqueCategories)
  };
}

function addBehavior(behaviors, categoryScores, behavior) {
  behaviors.push(behavior);
  const cat = behavior.category;
  const severityPoints = { info: 1, warning: 3, danger: 8, critical: 15 };
  categoryScores[cat] = (categoryScores[cat] || 0) + (severityPoints[behavior.severity] || 0);
}

function mapCategory(staticCategory) {
  const mapping = {
    'Execution': 'EXECUTION',
    'File Access': 'COLLECTION',
    'Network Access': 'COMMAND_AND_CONTROL',
    'System Access': 'DISCOVERY',
    'Process Manipulation': 'EXECUTION',
    'Code Introspection': 'DEFENSE_EVASION',
    'Sandbox Evasion': 'DEFENSE_EVASION',
    'Resource Abuse': 'RESOURCE_ABUSE',
    'Data Exfiltration': 'EXFILTRATION',
    'Persistence': 'PERSISTENCE',
    'Privilege Escalation': 'PRIVILEGE_ESCALATION',
    'Destructive Operation': 'IMPACT',
  };
  return mapping[staticCategory] || 'EXECUTION';
}

function generateSummary(score, verdict, behaviors, uniqueCategories) {
  if (score === 0) {
    return 'No threats detected. The code executed safely within all policy constraints.';
  }

  const criticalCount = behaviors.filter(b => b.severity === 'critical').length;
  const dangerCount = behaviors.filter(b => b.severity === 'danger').length;

  let summary = `Threat score: ${score}/100 (${verdict.replace('_', ' ')}). `;
  summary += `Detected ${behaviors.length} behavior(s) across ${uniqueCategories} category(ies). `;

  if (criticalCount > 0) {
    summary += `${criticalCount} critical issue(s) found. `;
  }
  if (dangerCount > 0) {
    summary += `${dangerCount} dangerous behavior(s) identified. `;
  }

  return summary.trim();
}

export { THREAT_CATEGORIES };
