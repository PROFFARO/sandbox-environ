/**
 * Static Analyzer Module
 * 
 * Performs pre-execution static analysis on submitted code using pattern matching
 * and structural inspection. Returns a threat report with severity classifications.
 * 
 * Approach: WHITELIST-based analysis. We define what's dangerous rather than what's safe,
 * but we check for known dangerous patterns comprehensively.
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
// BASH PATTERNS
// ============================================================
const BASH_PATTERNS = [
  // --- CRITICAL: Destructive commands ---
  { pattern: /\brm\s+(-[rRfiv]*\s+)*\//g, severity: SEVERITY.CRITICAL, category: CATEGORY.DESTRUCTIVE, description: 'rm on root path - Destructive file deletion' },
  { pattern: /\brm\s+.*-[rR]f/g, severity: SEVERITY.CRITICAL, category: CATEGORY.DESTRUCTIVE, description: 'rm -rf - Recursive force deletion' },
  { pattern: /\bdd\s+/g, severity: SEVERITY.CRITICAL, category: CATEGORY.DESTRUCTIVE, description: 'dd - Low-level disk write (destructive)' },
  { pattern: /\bmkfs\b/g, severity: SEVERITY.CRITICAL, category: CATEGORY.DESTRUCTIVE, description: 'mkfs - Filesystem creation (destructive)' },
  { pattern: /\bfdisk\b/g, severity: SEVERITY.CRITICAL, category: CATEGORY.DESTRUCTIVE, description: 'fdisk - Disk partitioning (destructive)' },
  { pattern: /\bformat\b/g, severity: SEVERITY.DANGER, category: CATEGORY.DESTRUCTIVE, description: 'format - Disk formatting' },
  { pattern: />\s*\/dev\/(sda|hda|nvme|disk)/g, severity: SEVERITY.CRITICAL, category: CATEGORY.DESTRUCTIVE, description: 'Write to disk device - Destructive' },

  // --- CRITICAL: Fork bomb / resource abuse ---
  { pattern: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:/g, severity: SEVERITY.CRITICAL, category: CATEGORY.RESOURCE, description: 'Fork bomb detected :(){ :|:& };:' },
  { pattern: /\bfork\s*\(\s*\)/g, severity: SEVERITY.CRITICAL, category: CATEGORY.RESOURCE, description: 'fork() - Process forking' },
  { pattern: /\b(bash|sh|zsh)\s+-c\s+.*&\s*$/gm, severity: SEVERITY.DANGER, category: CATEGORY.PROCESS, description: 'Background shell execution' },
  { pattern: /while\s+true\s*;?\s*do/g, severity: SEVERITY.WARNING, category: CATEGORY.RESOURCE, description: 'while true - Potential infinite loop' },
  { pattern: /\byes\s*\|/g, severity: SEVERITY.WARNING, category: CATEGORY.RESOURCE, description: 'yes pipe - Infinite output stream' },

  // --- CRITICAL: Network access ---
  { pattern: /\bcurl\s+/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'curl - HTTP request / download' },
  { pattern: /\bwget\s+/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'wget - File download' },
  { pattern: /\bnc\s+/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'netcat - Raw network connection' },
  { pattern: /\bncat\s+/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'ncat - Network utility' },
  { pattern: /\btelnet\s+/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'telnet - Network connection' },
  { pattern: /\bssh\s+/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'ssh - Remote shell access' },
  { pattern: /\bscp\s+/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'scp - Secure file copy' },
  { pattern: /\brsync\s+/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'rsync - Remote file sync' },
  { pattern: /\bftp\s+/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: 'ftp - File transfer protocol' },
  { pattern: /\/dev\/tcp/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: '/dev/tcp - Bash network redirect' },
  { pattern: /\/dev\/udp/g, severity: SEVERITY.CRITICAL, category: CATEGORY.NETWORK, description: '/dev/udp - Bash UDP redirect' },

  // --- CRITICAL: File system access ---
  { pattern: /\bcat\s+\/etc\/(passwd|shadow|sudoers|hosts)/g, severity: SEVERITY.CRITICAL, category: CATEGORY.FILE_ACCESS, description: 'Reading sensitive system files' },
  { pattern: /\bcat\s+~?\/?\.?(ssh|gnupg|bash_history|bashrc|profile|aws|config)/g, severity: SEVERITY.CRITICAL, category: CATEGORY.DATA_EXFIL, description: 'Reading sensitive user files' },
  { pattern: /\bchmod\s+(777|666|u\+s|g\+s|\+s)/g, severity: SEVERITY.CRITICAL, category: CATEGORY.PRIVILEGE_ESC, description: 'chmod dangerous permissions' },
  { pattern: /\bchown\s+/g, severity: SEVERITY.DANGER, category: CATEGORY.PRIVILEGE_ESC, description: 'chown - Ownership change' },
  { pattern: /\bmount\s+/g, severity: SEVERITY.CRITICAL, category: CATEGORY.SYSTEM, description: 'mount - Filesystem mounting' },
  { pattern: /\bumount\s+/g, severity: SEVERITY.CRITICAL, category: CATEGORY.SYSTEM, description: 'umount - Filesystem unmounting' },

  // --- CRITICAL: Privilege escalation ---
  { pattern: /\bsudo\s+/g, severity: SEVERITY.CRITICAL, category: CATEGORY.PRIVILEGE_ESC, description: 'sudo - Privilege escalation' },
  { pattern: /\bsu\s+/g, severity: SEVERITY.CRITICAL, category: CATEGORY.PRIVILEGE_ESC, description: 'su - User switching' },
  { pattern: /\buseradd\b/g, severity: SEVERITY.CRITICAL, category: CATEGORY.PRIVILEGE_ESC, description: 'useradd - User creation' },
  { pattern: /\buserdel\b/g, severity: SEVERITY.CRITICAL, category: CATEGORY.PRIVILEGE_ESC, description: 'userdel - User deletion' },
  { pattern: /\bpasswd\b/g, severity: SEVERITY.CRITICAL, category: CATEGORY.PRIVILEGE_ESC, description: 'passwd - Password modification' },

  // --- CRITICAL: Pipe to shell (download & execute) ---
  { pattern: /\|\s*(bash|sh|zsh|ksh|csh)\b/g, severity: SEVERITY.CRITICAL, category: CATEGORY.EXECUTION, description: 'Pipe to shell - Download & execute attack' },
  { pattern: /\bsource\s+/g, severity: SEVERITY.DANGER, category: CATEGORY.EXECUTION, description: 'source - Script execution in current shell' },
  { pattern: /\b\.\s+\//g, severity: SEVERITY.DANGER, category: CATEGORY.EXECUTION, description: 'Dot-source execution' },

  // --- System information ---
  { pattern: /\buname\s+/g, severity: SEVERITY.WARNING, category: CATEGORY.SYSTEM, description: 'uname - System information gathering' },
  { pattern: /\bwhoami\b/g, severity: SEVERITY.WARNING, category: CATEGORY.SYSTEM, description: 'whoami - Current user identification' },
  { pattern: /\bid\b/g, severity: SEVERITY.INFO, category: CATEGORY.SYSTEM, description: 'id - User/group identification' },
  { pattern: /\bhostname\b/g, severity: SEVERITY.WARNING, category: CATEGORY.SYSTEM, description: 'hostname - System identification' },
  { pattern: /\bifconfig\b/g, severity: SEVERITY.WARNING, category: CATEGORY.SYSTEM, description: 'ifconfig - Network interface info' },
  { pattern: /\bip\s+(addr|link|route)\b/g, severity: SEVERITY.WARNING, category: CATEGORY.SYSTEM, description: 'ip - Network configuration' },
  { pattern: /\bps\s+/g, severity: SEVERITY.WARNING, category: CATEGORY.SYSTEM, description: 'ps - Process listing' },
  { pattern: /\bnetstat\s+/g, severity: SEVERITY.WARNING, category: CATEGORY.SYSTEM, description: 'netstat - Network statistics' },

  // --- Persistence ---
  { pattern: /\bcrontab\s+/g, severity: SEVERITY.CRITICAL, category: CATEGORY.PERSISTENCE, description: 'crontab - Scheduled task creation' },
  { pattern: /\/etc\/cron/g, severity: SEVERITY.CRITICAL, category: CATEGORY.PERSISTENCE, description: 'cron directory - Scheduled task persistence' },
  { pattern: /\bsystemctl\s+(enable|start)/g, severity: SEVERITY.CRITICAL, category: CATEGORY.PERSISTENCE, description: 'systemctl - Service persistence' },
  { pattern: /\.bashrc|\.profile|\.bash_profile/g, severity: SEVERITY.DANGER, category: CATEGORY.PERSISTENCE, description: 'Shell profile modification - Login persistence' },

  // --- Kill / process manipulation ---
  { pattern: /\bkill\s+/g, severity: SEVERITY.DANGER, category: CATEGORY.PROCESS, description: 'kill - Process termination' },
  { pattern: /\bkillall\s+/g, severity: SEVERITY.CRITICAL, category: CATEGORY.PROCESS, description: 'killall - Mass process termination' },
  { pattern: /\bpkill\s+/g, severity: SEVERITY.CRITICAL, category: CATEGORY.PROCESS, description: 'pkill - Pattern-based process kill' },

  // --- Evasion ---
  { pattern: /\bhistory\s*-c/g, severity: SEVERITY.DANGER, category: CATEGORY.EVASION, description: 'history -c - Command history clearing' },
  { pattern: /\bunset\s+HISTFILE/g, severity: SEVERITY.DANGER, category: CATEGORY.EVASION, description: 'Disabling command history' },
  { pattern: /\/dev\/null\s*2>&1/g, severity: SEVERITY.WARNING, category: CATEGORY.EVASION, description: 'Output redirection to null - Hiding output' },
];

/**
 * Analyze code for security threats
 * @param {string} code - The source code to analyze
 * @param {string} language - The programming language (python, javascript, bash)
 * @returns {Object} Analysis result with findings, overall severity, and threat score
 */
export function analyzeCode(code, language) {
  const startTime = Date.now();
  let patterns;

  switch (language.toLowerCase()) {
    case 'python':
      patterns = PYTHON_PATTERNS;
      break;
    case 'javascript':
      patterns = JAVASCRIPT_PATTERNS;
      break;
    case 'bash':
      patterns = BASH_PATTERNS;
      break;
    default:
      return {
        language,
        findings: [],
        overallSeverity: SEVERITY.WARNING,
        threatScore: 10,
        summary: `Unknown language: ${language}. Cannot perform static analysis.`,
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
      findings.push({
        severity: rule.severity,
        category: rule.category,
        description: rule.description,
        matchCount: matches.length,
        matches: matches.slice(0, 5).map(m => m.trim()) // cap displayed matches
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
  const blocked = overallSeverity === SEVERITY.CRITICAL;

  // Generate summary
  const criticalCount = findings.filter(f => f.severity === SEVERITY.CRITICAL).length;
  const dangerCount = findings.filter(f => f.severity === SEVERITY.DANGER).length;
  const warningCount = findings.filter(f => f.severity === SEVERITY.WARNING).length;

  let summary;
  if (findings.length === 0) {
    summary = 'No security threats detected. Code appears safe for execution.';
  } else if (blocked) {
    summary = `BLOCKED: ${criticalCount} critical threat(s) detected. Execution denied.`;
  } else {
    summary = `${findings.length} potential issue(s) found: ${criticalCount} critical, ${dangerCount} dangerous, ${warningCount} warnings.`;
  }

  return {
    language,
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
