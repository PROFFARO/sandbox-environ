import crypto from 'crypto';

/**
 * Static Analyzer Module
 * 
 * Performs pre-execution static analysis on submitted code using pattern matching
 * and structural inspection. Returns a threat report with severity classifications.
 */

const SEVERITY = {
  SAFE: 'safe',
  INFO: 'info',
  WARNING: 'warning',
  DANGER: 'danger',
  CRITICAL: 'critical'
};

const CATEGORY = {
  EXECUTION: 'Execution',
  FILE_ACCESS: 'File Access',
  NETWORK: 'Network Access',
  SYSTEM: 'System Access',
  PROCESS: 'Process Manipulation',
  INTROSPECTION: 'Code Introspection',
  EVASION: 'Sandbox Evasion',
  RESOURCE: 'Resource Abuse',
  DATA_EXFIL: 'Data Exfiltration',
  PERSISTENCE: 'Persistence',
  PRIVILEGE_ESC: 'Privilege Escalation',
  DESTRUCTIVE: 'Destructive Operation'
};

// ============================================================
// PYTHON PATTERNS
// ============================================================
const PYTHON_PATTERNS = [
  // --- CRITICAL: OS/System Command Execution ---
  { pattern: /\bos\s*\.\s*system\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'os.system() - Direct shell command execution' },
  { pattern: /\bos\s*\.\s*popen\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'os.popen() - Shell command with pipe' },
  { pattern: /\bos\s*\.\s*exec[vl]p?\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'os.exec*() - Process replacement execution' },
  { pattern: /\bos\s*\.\s*spawn[vl]p?e?\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'os.spawn*() - Process spawning' },
  { pattern: /\bsubprocess\s*\.\s*(call|run|Popen|check_output|check_call|getoutput|getstatusoutput)\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'subprocess module - Shell command execution' },
  { pattern: /\bcommands\s*\.\s*(getoutput|getstatusoutput)\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'commands module - Shell execution (legacy)' },

  // --- CRITICAL: Dynamic Code Execution ---
  { pattern: /\bexec\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'exec() - Dynamic code execution' },
  { pattern: /\beval\s*\(/g, severity: SEVERITY.DANGER, category: CATEGORY.EXECUTION, description: 'eval() - Dynamic expression evaluation' },
  { pattern: /\bcompile\s*\(/g, severity: SEVERITY.DANGER, category: CATEGORY.EXECUTION, description: 'compile() - Dynamic code compilation' },
  { pattern: /\b__import__\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: '__import__() - Dynamic module import' },
  { pattern: /\bimportlib/g, severity: SEVERITY.DANGER, category: CATEGORY.EXECUTION, description: 'importlib - Dynamic module loading' },

  // --- CRITICAL: File System Access ---
  { pattern: /\bopen\s*\(\s*['"\/]/g, severity: SEVERITY.DANGER, category: CATEGORY.FILE_ACCESS, description: 'open() with path - File system read/write' },
  { pattern: /\bos\s*\.\s*(remove|unlink|rmdir|removedirs|rename|renames|makedirs|mkdir|chmod|chown|chroot)\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.FILE_ACCESS, description: 'os file operations - File system modification' },
  { pattern: /\bshutil\s*\.\s*(rmtree|copy|copy2|copytree|move|disk_usage)\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.FILE_ACCESS, description: 'shutil operations - File system manipulation' },
  { pattern: /\bos\s*\.\s*path\s*\./g, severity: SEVERITY.WARNING, category: CATEGORY.FILE_ACCESS, description: 'os.path - File system path operations' },
  { pattern: /\bpathlib/g, severity: SEVERITY.WARNING, category: CATEGORY.FILE_ACCESS, description: 'pathlib - File system access' },
  { pattern: /\bglob\s*\.\s*glob\s*\(/g, severity: SEVERITY.WARNING, category: CATEGORY.FILE_ACCESS, description: 'glob - File system enumeration' },
  { pattern: /\btempfile/g, severity: SEVERITY.WARNING, category: CATEGORY.FILE_ACCESS, description: 'tempfile - Temporary file creation' },

  // --- CRITICAL: Network Access ---
  { pattern: /\bsocket\s*\.\s*socket\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'Raw socket creation - Network access' },
  { pattern: /\bsocket\s*\.\s*connect\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'Socket connection - Outbound network' },
  { pattern: /\burllib/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'urllib - HTTP requests' },
  { pattern: /\brequests\s*\.\s*(get|post|put|delete|head|patch|options)\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'requests library - HTTP requests' },
  { pattern: /\bhttp\s*\.\s*(client|server)/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'http module - HTTP client/server' },
  { pattern: /\bftplib/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'ftplib - FTP access' },
  { pattern: /\bsmtplib/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'smtplib - Email sending' },
  { pattern: /\bxmlrpc/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'xmlrpc - Remote procedure calls' },

  // --- CRITICAL: System/Process Access ---
  { pattern: /\bos\s*\.\s*environ/g, severity: SEVERITY.DANGER, category: CATEGORY.SYSTEM, description: 'os.environ - Environment variable access' },
  { pattern: /\bos\s*\.\s*(getuid|getgid|getpid|getppid|kill|killpg|getlogin)\s*\(/g, severity: SEVERITY.DANGER, category: CATEGORY.SYSTEM, description: 'os process info - System enumeration' },
  { pattern: /\bos\s*\.\s*(fork|wait|waitpid)\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.PROCESS, description: 'os.fork/wait - Process forking' },
  { pattern: /\bsys\s*\.\s*(exit|executable|platform|version|path|modules|argv)\b/g, severity: SEVERITY.WARNING, category: CATEGORY.SYSTEM, description: 'sys module - System information access' },
  { pattern: /\bplatform\s*\.\s*(system|node|release|machine|processor)\s*\(/g, severity: SEVERITY.WARNING, category: CATEGORY.SYSTEM, description: 'platform module - System enumeration' },
  { pattern: /\bctypes/g, severity: SEVERITY.CRITICAL, category: CATEGORY.SYSTEM, description: 'ctypes - C foreign function interface' },
  { pattern: /\bsignal\s*\.\s*(signal|alarm|SIGKILL|SIGTERM)\b/g, severity: SEVERITY.CRITICAL, category: CATEGORY.PROCESS, description: 'signal module - Signal handling manipulation' },
  { pattern: /\bmultiprocessing/g, severity: SEVERITY.DANGER, category: CATEGORY.PROCESS, description: 'multiprocessing - Process spawning' },
  { pattern: /\bthreading/g, severity: SEVERITY.WARNING, category: CATEGORY.PROCESS, description: 'threading - Thread spawning' },

  // --- CRITICAL: Introspection/Sandbox Escape ---
  { pattern: /__subclasses__/g, severity: SEVERITY.CRITICAL, category: CATEGORY.INTROSPECTION, description: '__subclasses__() - Class hierarchy introspection (sandbox escape)' },
  { pattern: /__bases__/g, severity: SEVERITY.CRITICAL, category: CATEGORY.INTROSPECTION, description: '__bases__ - Base class access (sandbox escape)' },
  { pattern: /__mro__/g, severity: SEVERITY.CRITICAL, category: CATEGORY.INTROSPECTION, description: '__mro__ - Method resolution order (sandbox escape)' },
  { pattern: /__globals__/g, severity: SEVERITY.CRITICAL, category: CATEGORY.INTROSPECTION, description: '__globals__ - Global namespace access' },
  { pattern: /__builtins__/g, severity: SEVERITY.CRITICAL, category: CATEGORY.INTROSPECTION, description: '__builtins__ - Builtins manipulation' },
  { pattern: /__class__/g, severity: SEVERITY.DANGER, category: CATEGORY.INTROSPECTION, description: '__class__ - Class reference access' },
  { pattern: /\bgetattr\s*\(/g, severity: SEVERITY.WARNING, category: CATEGORY.INTROSPECTION, description: 'getattr() - Dynamic attribute access' },
  { pattern: /\bsetattr\s*\(/g, severity: SEVERITY.DANGER, category: CATEGORY.INTROSPECTION, description: 'setattr() - Dynamic attribute mutation' },
  { pattern: /\bdelattr\s*\(/g, severity: SEVERITY.DANGER, category: CATEGORY.INTROSPECTION, description: 'delattr() - Dynamic attribute deletion' },
  { pattern: /\bvars\s*\(\s*\)/g, severity: SEVERITY.WARNING, category: CATEGORY.INTROSPECTION, description: 'vars() - Namespace inspection' },
  { pattern: /\bdir\s*\(\s*\)/g, severity: SEVERITY.INFO, category: CATEGORY.INTROSPECTION, description: 'dir() - Object inspection' },
  { pattern: /\bglobals\s*\(\s*\)/g, severity: SEVERITY.DANGER, category: CATEGORY.INTROSPECTION, description: 'globals() - Global namespace access' },
  { pattern: /\blocals\s*\(\s*\)/g, severity: SEVERITY.WARNING, category: CATEGORY.INTROSPECTION, description: 'locals() - Local namespace access' },

  // --- DANGER: Import of dangerous modules ---
  { pattern: /^\s*import\s+(os|sys|subprocess|socket|shutil|signal|ctypes|multiprocessing|pickle|shelve|marshal|code|codeop|compileall|pty|pipes)\b/gm, severity: SEVERITY.CRITICAL, category: CATEGORY.SYSTEM, description: 'Import of restricted system module' },
  { pattern: /^\s*from\s+(os|sys|subprocess|socket|shutil|signal|ctypes|multiprocessing|pickle|shelve|marshal|code|codeop|compileall|pty|pipes)\s+import/gm, severity: SEVERITY.CRITICAL, category: CATEGORY.SYSTEM, description: 'From-import of restricted system module' },

  // --- DANGER: Resource abuse ---
  { pattern: /while\s+True\s*:/g, severity: SEVERITY.WARNING, category: CATEGORY.RESOURCE, description: 'while True - Potential infinite loop' },
  { pattern: /\b10\s*\*\*\s*[89]\d*/g, severity: SEVERITY.WARNING, category: CATEGORY.RESOURCE, description: 'Large exponentiation - Potential memory exhaustion' },
  { pattern: /\*\s*10\s*\*\*\s*[6-9]/g, severity: SEVERITY.WARNING, category: CATEGORY.RESOURCE, description: 'Large sequence multiplication - Memory exhaustion' },
  { pattern: /\brecursion/gi, severity: SEVERITY.INFO, category: CATEGORY.RESOURCE, description: 'Recursion mention - Monitor for stack overflow' },

  // --- DANGER: Serialization (code execution via pickle, etc.) ---
  { pattern: /\bpickle\s*\.\s*(loads?|dump)\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'pickle - Arbitrary code execution via deserialization' },
  { pattern: /\bmarshal\s*\.\s*(loads?|dump)\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'marshal - Code object deserialization' },
  { pattern: /\byaml\s*\.\s*(load|unsafe_load)\s*\(/g, severity: SEVERITY.DANGER, category: CATEGORY.EXECUTION, description: 'YAML unsafe load - Code execution via deserialization' },
];

// ============================================================
// JAVASCRIPT PATTERNS
// ============================================================
const JAVASCRIPT_PATTERNS = [
  // --- CRITICAL: Module imports ---
  { pattern: /require\s*\(\s*['"]child_process['"]\s*\)/g, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'child_process - Shell command execution' },
  { pattern: /require\s*\(\s*['"]fs['"]\s*\)/g, severity: SEVERITY.CRITICAL, category: CATEGORY.FILE_ACCESS, description: 'fs module - File system access' },
  { pattern: /require\s*\(\s*['"]net['"]\s*\)/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'net module - Raw network access' },
  { pattern: /require\s*\(\s*['"]http['"]\s*\)/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'http module - HTTP server/client' },
  { pattern: /require\s*\(\s*['"]https['"]\s*\)/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'https module - HTTPS access' },
  { pattern: /require\s*\(\s*['"]dgram['"]\s*\)/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'dgram module - UDP network access' },
  { pattern: /require\s*\(\s*['"]dns['"]\s*\)/g, severity: SEVERITY.DANGER, category: CATEGORY.NETWORK, description: 'dns module - DNS resolution' },
  { pattern: /require\s*\(\s*['"]os['"]\s*\)/g, severity: SEVERITY.DANGER, category: CATEGORY.SYSTEM, description: 'os module - System information' },
  { pattern: /require\s*\(\s*['"]cluster['"]\s*\)/g, severity: SEVERITY.CRITICAL, category: CATEGORY.PROCESS, description: 'cluster module - Process forking' },
  { pattern: /require\s*\(\s*['"]worker_threads['"]\s*\)/g, severity: SEVERITY.DANGER, category: CATEGORY.PROCESS, description: 'worker_threads - Thread creation' },
  { pattern: /require\s*\(\s*['"]vm['"]\s*\)/g, severity: SEVERITY.DANGER, category: CATEGORY.EXECUTION, description: 'vm module - Code execution context' },
  { pattern: /require\s*\(\s*['"]path['"]\s*\)/g, severity: SEVERITY.WARNING, category: CATEGORY.FILE_ACCESS, description: 'path module - File path manipulation' },
  { pattern: /require\s*\(\s*['"]crypto['"]\s*\)/g, severity: SEVERITY.WARNING, category: CATEGORY.SYSTEM, description: 'crypto module - Cryptographic operations' },

  // --- ES Module imports ---
  { pattern: /import\s+.*\s+from\s+['"]child_process['"]/g, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'ES import child_process' },
  { pattern: /import\s+.*\s+from\s+['"](fs|fs\/promises)['"]/g, severity: SEVERITY.CRITICAL, category: CATEGORY.FILE_ACCESS, description: 'ES import fs' },
  { pattern: /import\s+.*\s+from\s+['"](net|http|https|dgram)['"]/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'ES import network module' },

  // --- CRITICAL: Dynamic code execution ---
  { pattern: /\beval\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'eval() - Dynamic code execution' },
  { pattern: /\bFunction\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'Function() constructor - Dynamic function creation' },
  { pattern: /\bnew\s+Function\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'new Function() - Dynamic code generation' },
  { pattern: /setTimeout\s*\(\s*['"`]/g, severity: SEVERITY.DANGER, category: CATEGORY.EXECUTION, description: 'setTimeout with string - Implicit eval' },
  { pattern: /setInterval\s*\(\s*['"`]/g, severity: SEVERITY.DANGER, category: CATEGORY.EXECUTION, description: 'setInterval with string - Implicit eval' },

  // --- CRITICAL: Process and system access ---
  { pattern: /\bprocess\s*\.\s*exit\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.PROCESS, description: 'process.exit() - Force process termination' },
  { pattern: /\bprocess\s*\.\s*kill\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.PROCESS, description: 'process.kill() - Signal sending' },
  { pattern: /\bprocess\s*\.\s*env\b/g, severity: SEVERITY.DANGER, category: CATEGORY.SYSTEM, description: 'process.env - Environment variable access' },
  { pattern: /\bprocess\s*\.\s*argv\b/g, severity: SEVERITY.WARNING, category: CATEGORY.SYSTEM, description: 'process.argv - Command line arguments' },
  { pattern: /\bprocess\s*\.\s*cwd\s*\(/g, severity: SEVERITY.WARNING, category: CATEGORY.SYSTEM, description: 'process.cwd() - Working directory' },
  { pattern: /\bprocess\s*\.\s*(execPath|mainModule)\b/g, severity: SEVERITY.DANGER, category: CATEGORY.SYSTEM, description: 'process execution paths - System enumeration' },
  { pattern: /\bglobal\b(?!\s*\.)/g, severity: SEVERITY.DANGER, category: CATEGORY.INTROSPECTION, description: 'global object - Global scope access' },
  { pattern: /\bglobalThis\b/g, severity: SEVERITY.DANGER, category: CATEGORY.INTROSPECTION, description: 'globalThis - Global scope access' },

  // --- Prototype pollution ---
  { pattern: /__proto__/g, severity: SEVERITY.CRITICAL, category: CATEGORY.INTROSPECTION, description: '__proto__ - Prototype pollution vector' },
  { pattern: /\bconstructor\s*\.\s*constructor/g, severity: SEVERITY.CRITICAL, category: CATEGORY.INTROSPECTION, description: 'constructor.constructor - Sandbox escape' },
  { pattern: /Object\s*\.\s*setPrototypeOf/g, severity: SEVERITY.CRITICAL, category: CATEGORY.INTROSPECTION, description: 'setPrototypeOf - Prototype manipulation' },
  { pattern: /Object\s*\.\s*defineProperty/g, severity: SEVERITY.DANGER, category: CATEGORY.INTROSPECTION, description: 'defineProperty - Object manipulation' },
  { pattern: /Reflect\s*\.\s*/g, severity: SEVERITY.WARNING, category: CATEGORY.INTROSPECTION, description: 'Reflect API - Meta-programming' },
  { pattern: /Proxy\s*\(/g, severity: SEVERITY.WARNING, category: CATEGORY.INTROSPECTION, description: 'Proxy - Object interception' },

  // --- Fetch/network ---
  { pattern: /\bfetch\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'fetch() - HTTP request' },
  { pattern: /\bXMLHttpRequest/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'XMLHttpRequest - HTTP request' },
  { pattern: /\bWebSocket\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'WebSocket - Persistent network connection' },

  // --- Resource abuse ---
  { pattern: /while\s*\(\s*true\s*\)/g, severity: SEVERITY.WARNING, category: CATEGORY.RESOURCE, description: 'while(true) - Potential infinite loop' },
  { pattern: /for\s*\(\s*;\s*;\s*\)/g, severity: SEVERITY.WARNING, category: CATEGORY.RESOURCE, description: 'for(;;) - Infinite loop' },
  { pattern: /Array\s*\(\s*\d{7,}\s*\)/g, severity: SEVERITY.DANGER, category: CATEGORY.RESOURCE, description: 'Large array allocation - Memory exhaustion' },
  { pattern: /Buffer\s*\.\s*alloc(Unsafe)?\s*\(\s*\d{7,}\s*\)/g, severity: SEVERITY.DANGER, category: CATEGORY.RESOURCE, description: 'Large Buffer allocation - Memory exhaustion' },
];

// ============================================================
// C / C++ PATTERNS
// ============================================================
const CPP_PATTERNS = [
  { pattern: /\bsystem\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'system() - Direct command execution' },
  { pattern: /\bpopen\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'popen() - Process execution with pipe' },
  { pattern: /\bexecl|execv|execle|execve|execlp|execvp\b/g, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'exec*() - Process replacement' },
  { pattern: /\bfork\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.PROCESS, description: 'fork() - Process forking' },
  { pattern: /\bsocket\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'socket() - Raw network access' },
  { pattern: /\bconnect\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'connect() - Outbound connection' },
  { pattern: /#include\s+<(windows\.h|winsock2?\.h|unistd\.h|sys\/socket\.h|dlfcn\.h)>/g, severity: SEVERITY.WARNING, category: CATEGORY.SYSTEM, description: 'Inclusion of system/network headers' },
  { pattern: /\bmount\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.SYSTEM, description: 'mount() - Filesystem mounting' },
  { pattern: /\bchroot\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.SYSTEM, description: 'chroot() - Root directory change (sandbox escape)' },
  { pattern: /\bmmap\s*\(/g, severity: SEVERITY.DANGER, category: CATEGORY.RESOURCE, description: 'mmap() - Manual memory mapping' },
  { pattern: /\basm\b/g, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'Inline assembly - Low-level manipulation' },
];

// ============================================================
// POWERSHELL PATTERNS
// ============================================================
const POWERSHELL_PATTERNS = [
  { pattern: /Invoke-Expression|IEX/gi, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'IEX - Dynamic command execution' },
  { pattern: /Start-Process|saps/gi, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'Start-Process - Process spawning' },
  { pattern: /New-Object\s+System\.Net\.WebClient/gi, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'WebClient - Network download' },
  { pattern: /Invoke-WebRequest|iwr|curl|wget/gi, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'Invoke-WebRequest - HTTP request' },
  { pattern: /Get-WmiObject|gwmi|Get-CimInstance/gi, severity: SEVERITY.DANGER, category: CATEGORY.SYSTEM, description: 'WMI query - System enumeration' },
  { pattern: /\[System\.Convert\]::FromBase64String/gi, severity: SEVERITY.DANGER, category: CATEGORY.EVASION, description: 'Base64 decoding - Potential obfuscation' },
  { pattern: /-ExecutionPolicy\s+Bypass/gi, severity: SEVERITY.CRITICAL, category: CATEGORY.EVASION, description: 'Execution policy bypass' },
  { pattern: /Add-Type\s+-TypeDefinition/gi, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'Add-Type - Compilation of C# code' },
];

// ============================================================
// PHP PATTERNS
// ============================================================
const PHP_PATTERNS = [
  { pattern: /\b(exec|shell_exec|system|passthru|popen|proc_open)\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'Dangerous system call' },
  { pattern: /\beval\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'eval() - Dynamic code execution' },
  { pattern: /\b(assert|create_function)\s*\(/g, severity: SEVERITY.DANGER, category: CATEGORY.EXECUTION, description: 'Risky dynamic evaluation' },
  { pattern: /\b(include|require)(_once)?\s*\(/g, severity: SEVERITY.DANGER, category: CATEGORY.FILE_ACCESS, description: 'Dynamic file inclusion' },
  { pattern: /\bbase64_decode\s*\(/g, severity: SEVERITY.DANGER, category: CATEGORY.EVASION, description: 'base64_decode - Potential obfuscation' },
  { pattern: /\b(file_get_contents|fopen|readfile)\s*\(/g, severity: SEVERITY.WARNING, category: CATEGORY.FILE_ACCESS, description: 'File system access' },
  { pattern: /\b(curl_init|fsockopen|pfsockopen)\s*\(/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'Network connection' },
];

/**
 * Calculate Shannon Entropy of a string/buffer
 */
function calculateEntropy(data) {
  if (!data || data.length === 0) return 0;
  const len = data.length;
  const frequencies = {};
  for (let i = 0; i < len; i++) {
    const char = data[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Detect file type from magic bytes
 */
function detectFileType(buffer) {
  if (buffer.length < 4) return 'unknown';
  
  const magic = buffer.toString('hex', 0, 4).toUpperCase();
  
  if (magic.startsWith('4D5A')) return 'PE Executable (.exe, .dll)';
  if (magic === '7F454C46') return 'ELF Executable (Linux)';
  if (magic === '89504E47') return 'PNG Image';
  if (magic.startsWith('FFD8FF')) return 'JPEG Image';
  if (magic === '25504446') return 'PDF Document';
  if (magic === '504B0304') return 'ZIP Archive / Office Doc';
  if (magic === '7B5C7274') return 'RTF Document';
  if (magic === '23212F62') return 'Bash/Shell Script';
  if (magic === '3C3F7068') return 'PHP Script';
  
  return 'Text/Source Code';
}

/**
 * MITRE ATT&CK Mapping Simulation
 */
const MITRE_MAPPING = {
  [CATEGORY.EXECUTION]: { id: 'T1059', name: 'Command and Scripting Interpreter' },
  [CATEGORY.PERSISTENCE]: { id: 'T1547', name: 'Boot or Logon Autostart Execution' },
  [CATEGORY.PRIVILEGE_ESC]: { id: 'T1068', name: 'Exploitation for Privilege Escalation' },
  [CATEGORY.EVASION]: { id: 'T1027', name: 'Obfuscated Files or Information' },
  [CATEGORY.NETWORK]: { id: 'T1071', name: 'Application Layer Protocol' },
  [CATEGORY.DATA_EXFIL]: { id: 'T1041', name: 'Exfiltration Over C2 Channel' },
  [CATEGORY.FILE_ACCESS]: { id: 'T1083', name: 'File and Directory Discovery' },
  [CATEGORY.SYSTEM]: { id: 'T1082', name: 'System Information Discovery' },
};

/**
 * Analyze code for security threats
 */
export function analyzeCode(code, language) {
  const startTime = Date.now();
  const buffer = Buffer.from(code);
  
  // Forensic Metadata
  const hashes = {
    md5: crypto.createHash('md5').update(buffer).digest('hex'),
    sha1: crypto.createHash('sha1').update(buffer).digest('hex'),
    sha256: crypto.createHash('sha256').update(buffer).digest('hex'),
  };
  
  const entropy = calculateEntropy(code);
  const fileType = detectFileType(buffer);
  
  let patterns;

  switch (language.toLowerCase()) {
    case 'python': patterns = PYTHON_PATTERNS; break;
    case 'javascript': patterns = JAVASCRIPT_PATTERNS; break;
    case 'bash': patterns = BASH_PATTERNS; break;
    case 'cpp': case 'c': patterns = CPP_PATTERNS; break;
    case 'powershell': patterns = POWERSHELL_PATTERNS; break;
    case 'php': patterns = PHP_PATTERNS; break;
    default:
      return {
        language,
        forensics: { hashes, entropy, fileType },
        findings: [],
        overallSeverity: SEVERITY.WARNING,
        threatScore: 0,
        summary: `Generic analysis for ${language}. High-fidelity heuristics only available for primary targets.`,
        analysisTimeMs: Date.now() - startTime,
        blocked: false
      };
  }

  const findings = [];
  const categoryCounts = {};

  for (const rule of patterns) {
    // Reset regex lastIndex for global patterns
    rule.pattern.lastIndex = 0;
    const matches = code.match(rule.pattern);
    if (matches) {
      const mitre = MITRE_MAPPING[rule.category] || null;
      
      findings.push({
        severity: rule.severity,
        category: rule.category,
        description: rule.description,
        matchCount: matches.length,
        matches: matches.slice(0, 5).map(m => m.trim()),
        mitre
      });

      categoryCounts[rule.category] = (categoryCounts[rule.category] || 0) + matches.length;
    }
  }

  // Calculate threat score
  let threatScore = 0;
  const severityWeights = {
    [SEVERITY.INFO]: 2,
    [SEVERITY.WARNING]: 8,
    [SEVERITY.DANGER]: 20,
    [SEVERITY.CRITICAL]: 35,
  };

  for (const finding of findings) {
    threatScore += (severityWeights[finding.severity] || 0) * finding.matchCount;
  }

  // Cap at 100
  threatScore = Math.min(100, threatScore);

  // Determine overall severity
  let overallSeverity = SEVERITY.SAFE;
  if (findings.some(f => f.severity === SEVERITY.CRITICAL)) overallSeverity = SEVERITY.CRITICAL;
  else if (findings.some(f => f.severity === SEVERITY.DANGER)) overallSeverity = SEVERITY.DANGER;
  else if (findings.some(f => f.severity === SEVERITY.WARNING)) overallSeverity = SEVERITY.WARNING;
  else if (findings.some(f => f.severity === SEVERITY.INFO)) overallSeverity = SEVERITY.INFO;

  // Determine if should be blocked
  // ONLY block if user tries specific catastrophic things, but allow analysis usually
  const blocked = threatScore >= 95;

  // Generate summary
  const criticalCount = findings.filter(f => f.severity === SEVERITY.CRITICAL).length;
  const dangerCount = findings.filter(f => f.severity === SEVERITY.DANGER).length;
  const warningCount = findings.filter(f => f.severity === SEVERITY.WARNING).length;

  let summary;
  if (findings.length === 0) {
    summary = 'No security threats detected. Code appears safe for execution.';
  } else if (blocked) {
    summary = `CRITICAL THREAT: ${criticalCount} critical violation(s) detected. Integrity risk high.`;
  } else {
    summary = `${findings.length} findings: ${criticalCount} critical, ${dangerCount} dangerous. MITRE mapping complete.`;
  }

  return {
    language,
    forensics: { hashes, entropy: entropy.toFixed(4), fileType },
    findings: findings.sort((a, b) => {
      const order = { critical: 0, danger: 1, warning: 2, info: 3, safe: 4 };
      return (order[a.severity] || 5) - (order[b.severity] || 5);
    }),
    categoryCounts,
    overallSeverity,
    threatScore,
    summary,
    analysisTimeMs: Date.now() - startTime,
    blocked
  };
}

export { SEVERITY, CATEGORY };
