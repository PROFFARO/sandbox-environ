/**
 * Policy Enforcer Module
 * 
 * Defines and enforces execution policies using a whitelist approach.
 * Each language has specific allowed and blocked operations, resource limits,
 * and file system / network policies.
 */

const POLICIES = {
  python: {
    name: 'Python',
    extension: '.py',
    command: 'python',
    alternativeCommands: ['python3', 'py'],
    maxExecutionTimeMs: 300000,
    maxMemoryMb: 1024,
    maxOutputBytes: 1024 * 1024, // 1MB max output
    maxCodeLength: 100000, // 100KB max code

    allowedModules: [
      'math', 'random', 'string', 'datetime', 'time', 'json', 're',
      'collections', 'itertools', 'functools', 'operator', 'decimal',
      'fractions', 'statistics', 'copy', 'pprint', 'textwrap',
      'unicodedata', 'enum', 'dataclasses', 'typing', 'abc',
      'bisect', 'heapq', 'array', 'struct', 'hashlib',
      'hmac', 'base64', 'binascii', 'difflib', 'calendar',
      'csv', 'io', 'contextlib', 'warnings'
    ],

    blockedModules: [
      { module: 'os', reason: 'Operating system interface — allows file/process manipulation' },
      { module: 'sys', reason: 'System-specific parameters — allows interpreter manipulation' },
      { module: 'subprocess', reason: 'Subprocess management — allows shell command execution' },
      { module: 'socket', reason: 'Network interface — allows network connections' },
      { module: 'shutil', reason: 'File operations — allows file copying/deletion' },
      { module: 'signal', reason: 'Signal handling — allows process signal manipulation' },
      { module: 'ctypes', reason: 'C foreign function library — allows direct memory access' },
      { module: 'multiprocessing', reason: 'Process spawning — allows creating child processes' },
      { module: 'threading', reason: 'Thread management — allows concurrent execution' },
      { module: 'pickle', reason: 'Object serialization — allows arbitrary code execution via deserialization' },
      { module: 'shelve', reason: 'Object persistence — uses pickle internally' },
      { module: 'marshal', reason: 'Internal Python object serialization — allows code object manipulation' },
      { module: 'code', reason: 'Interactive interpreter — allows dynamic code execution' },
      { module: 'codeop', reason: 'Code compilation — allows dynamic code compilation' },
      { module: 'compileall', reason: 'Bytecode compilation — allows filesystem access' },
      { module: 'pty', reason: 'Pseudo-terminal — allows terminal control' },
      { module: 'pipes', reason: 'Shell pipeline — allows command chaining' },
      { module: 'importlib', reason: 'Import system — allows dynamic module loading' },
      { module: 'runpy', reason: 'Module runner — allows executing modules as scripts' },
      { module: 'http', reason: 'HTTP protocol — allows network communication' },
      { module: 'urllib', reason: 'URL handling — allows network requests' },
      { module: 'ftplib', reason: 'FTP protocol — allows network file transfer' },
      { module: 'smtplib', reason: 'SMTP protocol — allows sending emails' },
      { module: 'xmlrpc', reason: 'XML-RPC — allows remote procedure calls' },
      { module: 'webbrowser', reason: 'Browser control — allows opening browser' },
      { module: 'antigravity', reason: 'Opens web browser' },
      { module: 'turtle', reason: 'GUI interface — not available in sandbox' },
      { module: 'tkinter', reason: 'GUI interface — not available in sandbox' },
    ],

    blockedBuiltins: [
      { name: 'exec', reason: 'Dynamic code execution' },
      { name: 'eval', reason: 'Dynamic expression evaluation' },
      { name: 'compile', reason: 'Dynamic code compilation' },
      { name: '__import__', reason: 'Dynamic module import' },
      { name: 'open', reason: 'File system I/O' },
      { name: 'input', reason: 'Interactive input not supported in sandbox' },
      { name: 'breakpoint', reason: 'Debugger — not supported in sandbox' },
      { name: 'exit', reason: 'Process termination' },
      { name: 'quit', reason: 'Process termination' },
      { name: 'globals', reason: 'Global namespace access' },
      { name: 'locals', reason: 'Local namespace access' },
      { name: 'getattr', reason: 'Dynamic attribute access — sandbox escape vector' },
      { name: 'setattr', reason: 'Dynamic attribute mutation' },
      { name: 'delattr', reason: 'Dynamic attribute deletion' },
      { name: 'vars', reason: 'Namespace inspection' },
      { name: 'dir', reason: 'Object attribute enumeration' },
      { name: 'memoryview', reason: 'Direct memory access' },
    ],

    allowedBuiltins: [
      'print', 'len', 'range', 'int', 'float', 'str', 'bool', 'list', 'dict',
      'tuple', 'set', 'frozenset', 'type', 'isinstance', 'issubclass',
      'abs', 'all', 'any', 'bin', 'chr', 'complex', 'divmod', 'enumerate',
      'filter', 'format', 'hash', 'hex', 'id', 'iter', 'map', 'max', 'min',
      'next', 'oct', 'ord', 'pow', 'repr', 'reversed', 'round',
      'slice', 'sorted', 'sum', 'super', 'zip', 'bytearray', 'bytes',
      'callable', 'classmethod', 'staticmethod', 'property',
      'object', 'Exception', 'ValueError', 'TypeError', 'KeyError',
      'IndexError', 'AttributeError', 'RuntimeError', 'StopIteration',
      'NotImplementedError', 'ZeroDivisionError', 'OverflowError',
      'True', 'False', 'None'
    ],

    description: 'Python scripts are executed with restricted builtins and blocked system modules. Only mathematical, string processing, and data manipulation modules are allowed.'
  },

  javascript: {
    name: 'JavaScript',
    extension: '.js',
    command: 'node',
    alternativeCommands: [],
    maxExecutionTimeMs: 300000,
    maxMemoryMb: 1024,
    maxOutputBytes: 1024 * 1024,
    maxCodeLength: 100000,

    blockedModules: [
      { module: 'child_process', reason: 'Shell command execution' },
      { module: 'fs', reason: 'File system access' },
      { module: 'fs/promises', reason: 'File system access (async)' },
      { module: 'net', reason: 'Raw TCP/IPC network' },
      { module: 'http', reason: 'HTTP server/client' },
      { module: 'https', reason: 'HTTPS server/client' },
      { module: 'http2', reason: 'HTTP/2 protocol' },
      { module: 'dgram', reason: 'UDP networking' },
      { module: 'dns', reason: 'DNS resolution' },
      { module: 'tls', reason: 'TLS/SSL encryption' },
      { module: 'cluster', reason: 'Process forking/clustering' },
      { module: 'worker_threads', reason: 'Worker thread creation' },
      { module: 'vm', reason: 'V8 Virtual Machine contexts' },
      { module: 'os', reason: 'Operating system information' },
      { module: 'process', reason: 'Process information and control' },
      { module: 'v8', reason: 'V8 engine internals' },
      { module: 'perf_hooks', reason: 'Performance measurement' },
      { module: 'async_hooks', reason: 'Async resource tracking' },
      { module: 'inspector', reason: 'V8 inspector/debugger' },
      { module: 'repl', reason: 'Interactive REPL' },
      { module: 'readline', reason: 'Interactive input' },
    ],

    blockedGlobals: [
      { name: 'process', reason: 'Process object — allows system access and exit' },
      { name: 'global', reason: 'Global object — allows scope escape' },
      { name: 'globalThis', reason: 'Global object reference' },
      { name: 'require', reason: 'Module loading — allows importing restricted modules' },
      { name: 'eval', reason: 'Dynamic code execution' },
      { name: 'Function', reason: 'Dynamic function creation' },
      { name: 'fetch', reason: 'HTTP requests — network access' },
      { name: 'XMLHttpRequest', reason: 'HTTP requests — network access' },
      { name: 'WebSocket', reason: 'WebSocket connections — network access' },
    ],

    description: 'JavaScript code runs in an isolated Node.js process with require/import disabled, no file system or network access, and restricted globals.'
  },

  bash: {
    name: 'Bash',
    extension: '.sh',
    command: 'bash',
    alternativeCommands: ['sh'],
    maxExecutionTimeMs: 300000,
    maxMemoryMb: 1024,
    maxOutputBytes: 1024 * 1024 * 2, // 2MB
    maxCodeLength: 100000,

    allowedCommands: [
      'echo', 'printf', 'test', 'expr', 'let', 'seq', 'wc',
      'head', 'tail', 'sort', 'uniq', 'tr', 'cut', 'paste',
      'grep', 'awk', 'sed', 'date', 'cal', 'bc', 'factor',
      'basename', 'dirname', 'true', 'false', 'sleep',
      'rev', 'tac', 'fold', 'expand', 'unexpand',
      'comm', 'join', 'nl', 'od', 'fmt'
    ],

    blockedCommands: [
      { command: 'rm', reason: 'File deletion' },
      { command: 'rmdir', reason: 'Directory deletion' },
      { command: 'mv', reason: 'File moving/renaming' },
      { command: 'cp', reason: 'File copying' },
      { command: 'dd', reason: 'Low-level disk operations' },
      { command: 'mkfs', reason: 'Filesystem creation' },
      { command: 'fdisk', reason: 'Disk partitioning' },
      { command: 'mount', reason: 'Filesystem mounting' },
      { command: 'umount', reason: 'Filesystem unmounting' },
      { command: 'chmod', reason: 'Permission changes' },
      { command: 'chown', reason: 'Ownership changes' },
      { command: 'chroot', reason: 'Root directory change' },
      { command: 'sudo', reason: 'Privilege escalation' },
      { command: 'su', reason: 'User switching' },
      { command: 'curl', reason: 'HTTP requests' },
      { command: 'wget', reason: 'File downloads' },
      { command: 'nc', reason: 'Network connections' },
      { command: 'ncat', reason: 'Network utility' },
      { command: 'telnet', reason: 'Network connections' },
      { command: 'ssh', reason: 'Remote shell' },
      { command: 'scp', reason: 'Remote file copy' },
      { command: 'rsync', reason: 'Remote file sync' },
      { command: 'ftp', reason: 'File transfer' },
      { command: 'kill', reason: 'Process termination' },
      { command: 'killall', reason: 'Mass process kill' },
      { command: 'pkill', reason: 'Pattern process kill' },
      { command: 'crontab', reason: 'Scheduled tasks' },
      { command: 'systemctl', reason: 'Service management' },
      { command: 'service', reason: 'Service management' },
      { command: 'useradd', reason: 'User creation' },
      { command: 'userdel', reason: 'User deletion' },
      { command: 'passwd', reason: 'Password changes' },
      { command: 'cat', reason: 'File reading (restricted)' },
      { command: 'touch', reason: 'File creation' },
      { command: 'mkdir', reason: 'Directory creation' },
    ],

    description: 'Bash scripts run with a severely restricted command set. No file system manipulation or unauthorized network access.'
  },

  c: {
    name: 'C',
    extension: '.c',
    command: 'gcc',
    alternativeCommands: [],
    maxExecutionTimeMs: 300000,
    maxMemoryMb: 1024,
    maxOutputBytes: 1024 * 1024,
    maxCodeLength: 100000,
    description: 'C source is compiled with GCC and executed in a restricted environment.'
  },

  cpp: {
    name: 'C++',
    extension: '.cpp',
    command: 'g++',
    alternativeCommands: [],
    maxExecutionTimeMs: 300000,
    maxMemoryMb: 1024,
    maxOutputBytes: 1024 * 1024,
    maxCodeLength: 100000,
    description: 'C++ source is compiled with G++ and executed in a restricted environment.'
  },

  php: {
    name: 'PHP',
    extension: '.php',
    command: 'php',
    alternativeCommands: [],
    maxExecutionTimeMs: 300000,
    maxMemoryMb: 1024,
    maxOutputBytes: 1024 * 512,
    maxCodeLength: 100000,
    description: 'PHP scripts are executed using the PHP CLI with restricted configuration.'
  },

  powershell: {
    name: 'PowerShell',
    extension: '.ps1',
    command: 'powershell',
    alternativeCommands: ['pwsh'],
    maxExecutionTimeMs: 300000,
    maxMemoryMb: 1024,
    maxOutputBytes: 1024 * 512,
    maxCodeLength: 100000,
    description: 'PowerShell scripts are executed in restricted mode.'
  }
};

/**
 * Enforce policy on submitted code
 * @param {string} code - The source code
 * @param {string} language - The language
 * @returns {Object} Policy check result
 */
export function enforcePolicy(code, language) {
  const policy = POLICIES[language.toLowerCase()];
  if (!policy) {
    return {
      allowed: false,
      violations: [{ rule: 'language', message: `Unsupported language: ${language}` }],
      policy: null
    };
  }

  const violations = [];

  // Check code length
  if (code.length > policy.maxCodeLength) {
    violations.push({
      rule: 'code_length',
      severity: 'danger',
      message: `Code exceeds maximum length of ${policy.maxCodeLength} characters (got ${code.length})`,
      action: 'blocked'
    });
  }

  // Check empty code
  if (!code.trim()) {
    violations.push({
      rule: 'empty_code',
      severity: 'warning',
      message: 'Empty code submitted',
      action: 'blocked'
    });
  }

  // Language-specific policy checks
  if (language.toLowerCase() === 'bash') {
    // Check for blocked commands
    for (const blocked of policy.blockedCommands) {
      const cmdRegex = new RegExp(`(^|[;|&\\s])${blocked.command}(\\s|$|;|\\|)`, 'gm');
      if (cmdRegex.test(code)) {
        violations.push({
          rule: 'blocked_command',
          severity: 'critical',
          message: `Blocked command: '${blocked.command}' — ${blocked.reason}`,
          action: 'blocked'
        });
      }
    }
  }

  const allowed = !violations.some(v => v.severity === 'critical' || v.severity === 'danger');

  return {
    allowed,
    violations,
    policy: {
      language: policy.name,
      maxExecutionTimeMs: policy.maxExecutionTimeMs,
      maxMemoryMb: policy.maxMemoryMb,
      maxOutputBytes: policy.maxOutputBytes,
      maxCodeLength: policy.maxCodeLength,
      description: policy.description,
      ...(policy.allowedModules && { allowedModules: policy.allowedModules }),
      ...(policy.blockedModules && { blockedModules: policy.blockedModules }),
      ...(policy.allowedCommands && { allowedCommands: policy.allowedCommands }),
      ...(policy.blockedCommands && { blockedCommands: policy.blockedCommands }),
      ...(policy.blockedGlobals && { blockedGlobals: policy.blockedGlobals }),
    }
  };
}

/**
 * Get policy for a given language
 */
export function getPolicy(language) {
  const policy = POLICIES[language.toLowerCase()];
  if (!policy) return null;
  return {
    language: policy.name,
    extension: policy.extension,
    maxExecutionTimeMs: policy.maxExecutionTimeMs,
    maxMemoryMb: policy.maxMemoryMb,
    maxOutputBytes: policy.maxOutputBytes,
    maxCodeLength: policy.maxCodeLength,
    description: policy.description,
    ...(policy.allowedModules && { allowedModules: policy.allowedModules }),
    ...(policy.blockedModules && { blockedModules: policy.blockedModules }),
    ...(policy.allowedCommands && { allowedCommands: policy.allowedCommands }),
    ...(policy.blockedCommands && { blockedCommands: policy.blockedCommands }),
    ...(policy.blockedGlobals && { blockedGlobals: policy.blockedGlobals }),
    ...(policy.blockedBuiltins && { blockedBuiltins: policy.blockedBuiltins }),
    ...(policy.allowedBuiltins && { allowedBuiltins: policy.allowedBuiltins }),
  };
}

/**
 * Get all policies summary
 */
export function getAllPolicies() {
  return Object.keys(POLICIES).map(lang => getPolicy(lang));
}

/**
 * Get execution config from policy
 */
export function getExecutionConfig(language) {
  const policy = POLICIES[language.toLowerCase()];
  if (!policy) return null;
  return {
    command: policy.command,
    alternativeCommands: policy.alternativeCommands,
    extension: policy.extension,
    timeoutMs: policy.maxExecutionTimeMs,
    maxMemoryMb: policy.maxMemoryMb,
    maxOutputBytes: policy.maxOutputBytes,
  };
}

export { POLICIES };
