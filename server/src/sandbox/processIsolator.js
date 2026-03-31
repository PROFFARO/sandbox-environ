/**
 * Process Isolator Module
 * 
 * Executes code in isolated child processes with strict constraints.
 * Handles process spawning, timeout enforcement, output capture,
 * and clean termination.
 */

import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { v4 as uuidv4 } from 'uuid';
import { EventEmitter } from 'events';
import { ResourceMonitor } from './resourceMonitor.js';
import { getExecutionConfig } from './policyEnforcer.js';

const SANDBOX_DIR = path.join(os.tmpdir(), 'controlled-sandbox');

// Ensure sandbox directory exists
if (!fs.existsSync(SANDBOX_DIR)) {
  fs.mkdirSync(SANDBOX_DIR, { recursive: true });
}

/**
 * Generate a sandboxed Python wrapper that restricts builtins
 */
function generatePythonWrapper(codePath) {
  return `
import sys
import builtins

# Remove dangerous builtins
_BLOCKED = [
    'exec', 'eval', 'compile', '__import__', 'open',
    'input', 'breakpoint', 'exit', 'quit',
    'globals', 'locals', 'getattr', 'setattr', 'delattr',
    'vars', 'dir', 'memoryview', 'help'
]

_safe_builtins = {}
for name in dir(builtins):
    if name not in _BLOCKED and not name.startswith('_'):
        _safe_builtins[name] = getattr(builtins, name)

# Add safe versions
_safe_builtins['print'] = print
_safe_builtins['len'] = len
_safe_builtins['range'] = range
_safe_builtins['int'] = int
_safe_builtins['float'] = float
_safe_builtins['str'] = str
_safe_builtins['bool'] = bool
_safe_builtins['list'] = list
_safe_builtins['dict'] = dict
_safe_builtins['tuple'] = tuple
_safe_builtins['set'] = set
_safe_builtins['frozenset'] = frozenset
_safe_builtins['type'] = type
_safe_builtins['isinstance'] = isinstance
_safe_builtins['issubclass'] = issubclass
_safe_builtins['abs'] = abs
_safe_builtins['all'] = all
_safe_builtins['any'] = any
_safe_builtins['bin'] = bin
_safe_builtins['chr'] = chr
_safe_builtins['complex'] = complex
_safe_builtins['divmod'] = divmod
_safe_builtins['enumerate'] = enumerate
_safe_builtins['filter'] = filter
_safe_builtins['format'] = format
_safe_builtins['hash'] = hash
_safe_builtins['hex'] = hex
_safe_builtins['iter'] = iter
_safe_builtins['map'] = map
_safe_builtins['max'] = max
_safe_builtins['min'] = min
_safe_builtins['next'] = next
_safe_builtins['oct'] = oct
_safe_builtins['ord'] = ord
_safe_builtins['pow'] = pow
_safe_builtins['repr'] = repr
_safe_builtins['reversed'] = reversed
_safe_builtins['round'] = round
_safe_builtins['slice'] = slice
_safe_builtins['sorted'] = sorted
_safe_builtins['sum'] = sum
_safe_builtins['super'] = super
_safe_builtins['zip'] = zip
_safe_builtins['bytearray'] = bytearray
_safe_builtins['bytes'] = bytes
_safe_builtins['callable'] = callable
_safe_builtins['classmethod'] = classmethod
_safe_builtins['staticmethod'] = staticmethod
_safe_builtins['property'] = property
_safe_builtins['object'] = object
_safe_builtins['Exception'] = Exception
_safe_builtins['ValueError'] = ValueError
_safe_builtins['TypeError'] = TypeError
_safe_builtins['KeyError'] = KeyError
_safe_builtins['IndexError'] = IndexError
_safe_builtins['AttributeError'] = AttributeError
_safe_builtins['RuntimeError'] = RuntimeError
_safe_builtins['StopIteration'] = StopIteration
_safe_builtins['NotImplementedError'] = NotImplementedError
_safe_builtins['ZeroDivisionError'] = ZeroDivisionError
_safe_builtins['OverflowError'] = OverflowError
_safe_builtins['True'] = True
_safe_builtins['False'] = False
_safe_builtins['None'] = None
_safe_builtins['id'] = id

# Block dangerous module imports
_original_import = builtins.__import__
_BLOCKED_MODULES = {
    'os', 'sys', 'subprocess', 'socket', 'shutil', 'signal',
    'ctypes', 'multiprocessing', 'threading', 'pickle', 'shelve',
    'marshal', 'code', 'codeop', 'compileall', 'pty', 'pipes',
    'importlib', 'runpy', 'http', 'urllib', 'ftplib', 'smtplib',
    'xmlrpc', 'webbrowser', 'antigravity', 'turtle', 'tkinter',
    'io', 'tempfile', 'glob', 'pathlib', 'fcntl', 'resource',
    'select', 'mmap', 'asyncio', 'concurrent', 'ssl', 'telnetlib',
    'poplib', 'imaplib', 'nntplib', 'socketserver', 'xmlrpc',
    'ipaddress', 'logging', 'platform', 'getpass', 'curses',
}

def _restricted_import(name, *args, **kwargs):
    top_module = name.split('.')[0]
    if top_module in _BLOCKED_MODULES:
        raise ImportError(f"SANDBOX VIOLATION: Import of '{name}' is not allowed. Module '{top_module}' is restricted.")
    return _original_import(name, *args, **kwargs)

builtins.__import__ = _restricted_import

# Read and execute the user code with restricted builtins
try:
    with _original_import('builtins').__dict__['open']('${codePath.replace(/\\/g, '\\\\')}', 'r') as f:
        user_code = f.read()
    
    restricted_globals = {'__builtins__': _safe_builtins, '__name__': '__main__'}
    _original_import('builtins').__dict__['exec'](user_code, restricted_globals)
except ImportError as e:
    print(f"SECURITY VIOLATION: {e}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"Error: {type(e).__name__}: {e}", file=sys.stderr)
    sys.exit(1)
`;
}

/**
 * Generate a sandboxed JavaScript wrapper
 */
function generateJavaScriptWrapper(codePath) {
  return `
// Sandbox wrapper — restrict dangerous globals
'use strict';

// Store originals we need
const _originalConsole = console;
const _setTimeout = setTimeout;
const _clearTimeout = clearTimeout;

// Delete dangerous globals
delete globalThis.fetch;

// Restrict require
const _blockedModules = new Set([
  'child_process', 'fs', 'fs/promises', 'net', 'http', 'https',
  'http2', 'dgram', 'dns', 'tls', 'cluster', 'worker_threads',
  'vm', 'os', 'v8', 'perf_hooks', 'async_hooks', 'inspector',
  'repl', 'readline', 'path', 'crypto', 'zlib', 'stream',
  'events', 'url', 'querystring', 'assert', 'buffer',
  'string_decoder', 'punycode', 'domain', 'constants',
  'sys', 'util', 'module'
]);

// Override require
const Module = require('module');
const _origRequire = Module.prototype.require;
Module.prototype.require = function(id) {
  if (_blockedModules.has(id)) {
    throw new ReferenceError(\`SANDBOX VIOLATION: require('\${id}') is not allowed. Module '\${id}' is restricted.\`);
  }
  return _origRequire.call(this, id);
};

// Read and execute user code
const _fs = _origRequire.call(module, 'fs');
const userCode = _fs.readFileSync('${codePath.replace(/\\/g, '\\\\')}', 'utf8');

try {
  // Create restricted scope
  const _vm = _origRequire.call(module, 'vm');
  const sandbox = {
    console: _originalConsole,
    setTimeout: (fn, ms) => _setTimeout(fn, Math.min(ms, 5000)),
    clearTimeout: _clearTimeout,
    Math: Math,
    Date: Date,
    JSON: JSON,
    parseInt: parseInt,
    parseFloat: parseFloat,
    isNaN: isNaN,
    isFinite: isFinite,
    encodeURI: encodeURI,
    decodeURI: decodeURI,
    encodeURIComponent: encodeURIComponent,
    decodeURIComponent: decodeURIComponent,
    Array: Array,
    Object: Object,
    String: String,
    Number: Number,
    Boolean: Boolean,
    Symbol: Symbol,
    Map: Map,
    Set: Set,
    WeakMap: WeakMap,
    WeakSet: WeakSet,
    Promise: Promise,
    RegExp: RegExp,
    Error: Error,
    TypeError: TypeError,
    RangeError: RangeError,
    ReferenceError: ReferenceError,
    SyntaxError: SyntaxError,
    undefined: undefined,
    NaN: NaN,
    Infinity: Infinity,
  };

  const context = _vm.createContext(sandbox);
  const script = new _vm.Script(userCode, { filename: 'sandbox.js', timeout: 10000 });
  script.runInContext(context, { timeout: 10000 });
} catch (e) {
  if (e.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT') {
    console.error('SANDBOX TIMEOUT: Script execution exceeded time limit.');
  } else {
    console.error(\`Error: \${e.constructor.name}: \${e.message}\`);
  }
  process.exit(1);
}
`;
}

export class ProcessIsolator extends EventEmitter {
  constructor(options = {}) {
    super();
    this.executionId = options.executionId || uuidv4();
    this.language = options.language;
    this.timeoutMs = options.timeoutMs || 10000;
    this.memoryLimitMb = options.memoryLimitMb || 128;
    this.maxOutputBytes = options.maxOutputBytes || 512 * 1024;

    this.process = null;
    this.resourceMonitor = null;
    this.stdout = '';
    this.stderr = '';
    this.exitCode = null;
    this.signal = null;
    this.startTime = null;
    this.endTime = null;
    this.killed = false;
    this.killReason = null;
    this.tempDir = null;
    this.outputTruncated = false;
  }

  /**
   * Execute code in an isolated process
   * @param {string} code - The source code to execute
   * @returns {Promise<Object>} Execution result
   */
  async execute(code) {
    // Create temp directory for this execution
    this.tempDir = path.join(SANDBOX_DIR, this.executionId);
    if (!fs.existsSync(this.tempDir)) {
      fs.mkdirSync(this.tempDir, { recursive: true });
    }

    const config = getExecutionConfig(this.language);
    if (!config) {
      throw new Error(`Unsupported language: ${this.language}`);
    }

    // Write user code to temp file
    const codeFilePath = path.join(this.tempDir, `usercode${config.extension}`);
    fs.writeFileSync(codeFilePath, code, 'utf8');

    // Determine execution command
    let command, args;

    if (this.language === 'python') {
      // Write wrapper
      const wrapperCode = generatePythonWrapper(codeFilePath);
      const wrapperPath = path.join(this.tempDir, 'wrapper.py');
      fs.writeFileSync(wrapperPath, wrapperCode, 'utf8');
      command = await this._findCommand(config);
      args = ['-u', wrapperPath]; // -u for unbuffered output
    } else if (this.language === 'javascript') {
      // Write wrapper
      const wrapperCode = generateJavaScriptWrapper(codeFilePath);
      const wrapperPath = path.join(this.tempDir, 'wrapper.js');
      fs.writeFileSync(wrapperPath, wrapperCode, 'utf8');
      command = 'node';
      args = [`--max-old-space-size=${this.memoryLimitMb}`, wrapperPath];
    } else if (this.language === 'bash') {
      command = await this._findCommand(config);
      args = ['--restricted', codeFilePath]; // --restricted limits bash functionality
    }

    return new Promise((resolve) => {
      this.startTime = Date.now();
      this.emit('started', { executionId: this.executionId, command, language: this.language });

      // Spawn process
      try {
        this.process = spawn(command, args, {
          cwd: this.tempDir,
          timeout: this.timeoutMs,
          killSignal: 'SIGTERM',
          env: {
            // Minimal environment — don't leak host env
            PATH: process.env.PATH,
            HOME: this.tempDir,
            TEMP: this.tempDir,
            TMP: this.tempDir,
            LANG: 'en_US.UTF-8',
          },
          stdio: ['ignore', 'pipe', 'pipe'],
          windowsHide: true,
        });
      } catch (err) {
        this.endTime = Date.now();
        this._cleanup();
        resolve({
          executionId: this.executionId,
          stdout: '',
          stderr: `Failed to start process: ${err.message}`,
          exitCode: 1,
          signal: null,
          executionTimeMs: 0,
          killed: false,
          killReason: 'spawn_error',
          resourceSamples: [],
          maxMemoryMb: 0,
          maxCpuPercent: 0,
        });
        return;
      }

      // Start resource monitoring
      this.resourceMonitor = new ResourceMonitor({
        memoryLimitMb: this.memoryLimitMb,
        pollIntervalMs: 200,
      });

      this.resourceMonitor.on('resource', (sample) => {
        this.emit('resource', { executionId: this.executionId, ...sample });
      });

      this.resourceMonitor.on('warning', (warning) => {
        this.emit('warning', { executionId: this.executionId, ...warning });
      });

      this.resourceMonitor.on('kill', (reason) => {
        if (!this.killed) {
          this.killed = true;
          this.killReason = 'memory_exceeded';
          this.emit('violation', {
            executionId: this.executionId,
            severity: 'critical',
            category: 'Resource Abuse',
            operation: 'memory_exceeded',
            description: reason.message,
            action_taken: 'Process killed'
          });
          this._killProcess();
        }
      });

      if (this.process.pid) {
        this.resourceMonitor.start(this.process.pid);
      }

      // Capture stdout
      this.process.stdout.on('data', (data) => {
        const chunk = data.toString();
        if (this.stdout.length + chunk.length > this.maxOutputBytes) {
          this.outputTruncated = true;
          this.stdout += chunk.substring(0, this.maxOutputBytes - this.stdout.length);
          this.stdout += '\n\n[OUTPUT TRUNCATED — exceeded maximum output size]';
        } else {
          this.stdout += chunk;
        }
        this.emit('stdout', { executionId: this.executionId, data: chunk });
      });

      // Capture stderr
      this.process.stderr.on('data', (data) => {
        const chunk = data.toString();
        if (this.stderr.length + chunk.length > this.maxOutputBytes) {
          this.stderr += chunk.substring(0, this.maxOutputBytes - this.stderr.length);
        } else {
          this.stderr += chunk;
        }
        this.emit('stderr', { executionId: this.executionId, data: chunk });
      });

      // Handle process exit
      this.process.on('close', (code, signal) => {
        this.endTime = Date.now();
        this.exitCode = code;
        this.signal = signal;

        if (signal === 'SIGTERM' && !this.killReason) {
          this.killed = true;
          this.killReason = 'timeout';
          this.emit('violation', {
            executionId: this.executionId,
            severity: 'danger',
            category: 'Resource Abuse',
            operation: 'timeout',
            description: `Execution timed out after ${this.timeoutMs}ms`,
            action_taken: 'Process killed (SIGTERM)'
          });
        }

        // Stop resource monitor
        this.resourceMonitor.stop();
        const resourceSummary = this.resourceMonitor.getSummary();
        const resourceSamples = this.resourceMonitor.getSamples();

        const result = {
          executionId: this.executionId,
          stdout: this.stdout,
          stderr: this.stderr,
          exitCode: this.exitCode,
          signal: this.signal,
          executionTimeMs: this.endTime - this.startTime,
          killed: this.killed,
          killReason: this.killReason,
          resourceSamples,
          maxMemoryMb: resourceSummary.maxMemoryMb,
          maxCpuPercent: resourceSummary.maxCpuPercent,
          outputTruncated: this.outputTruncated,
        };

        this.emit('completed', result);
        this._cleanup();
        resolve(result);
      });

      // Handle errors
      this.process.on('error', (err) => {
        this.endTime = Date.now();
        this.resourceMonitor?.stop();
        this._cleanup();
        resolve({
          executionId: this.executionId,
          stdout: this.stdout,
          stderr: `Process error: ${err.message}`,
          exitCode: 1,
          signal: null,
          executionTimeMs: this.endTime - this.startTime,
          killed: false,
          killReason: 'error',
          resourceSamples: [],
          maxMemoryMb: 0,
          maxCpuPercent: 0,
        });
      });
    });
  }

  /**
   * Kill the running process
   */
  _killProcess() {
    if (this.process && !this.process.killed) {
      try {
        this.process.kill('SIGTERM');
        // Force kill after 2 seconds if still alive
        setTimeout(() => {
          if (this.process && !this.process.killed) {
            try { this.process.kill('SIGKILL'); } catch (e) { /* ignore */ }
          }
        }, 2000);
      } catch (e) { /* ignore */ }
    }
  }

  /**
   * Clean up temporary files
   */
  _cleanup() {
    if (this.tempDir && fs.existsSync(this.tempDir)) {
      try {
        fs.rmSync(this.tempDir, { recursive: true, force: true });
      } catch (e) {
        // Best effort cleanup
      }
    }
  }

  /**
   * Find available command for language
   */
  async _findCommand(config) {
    const commands = [config.command, ...(config.alternativeCommands || [])];
    
    for (const cmd of commands) {
      try {
        const { execSync } = await import('child_process');
        const isWindows = process.platform === 'win32';
        const checkCmd = isWindows ? `where ${cmd}` : `which ${cmd}`;
        execSync(checkCmd, { stdio: 'ignore' });
        return cmd;
      } catch (e) {
        continue;
      }
    }

    // Return default and let spawn error handle it
    return config.command;
  }
}
