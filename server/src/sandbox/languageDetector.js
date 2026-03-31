/**
 * Advanced Language Detector Utility
 * 
 * Heuristic-based detection of programming languages from source code artifacts.
 * Uses a weight-based scoring system to resolve ambiguous syntax.
 */

const LANG_PROFILES = [
  {
    lang: 'python',
    rules: [
      { pattern: /^#!\/.*python/m, weight: 10 }, // Strong shebang
      { pattern: /import\s+[\w.]+/, weight: 2 },
      { pattern: /from\s+[\w.]+\s+import/, weight: 2 },
      { pattern: /def\s+\w+\s*\([^)]*\)\s*:/, weight: 3 },
      { pattern: /if\s+__name__\s*==\s*['"]__main__['"]\s*:/, weight: 8 },
      { pattern: /print\s*\(.*\)/, weight: 1 },
      { pattern: /pip\s+install/, weight: 3 },
      { pattern: /elif\s+.*:/, weight: 3 },
      { pattern: /class\s+\w+(\(.*\))?\s*:/, weight: 3 },
      { pattern: /try:\s*[\n\r]\s*except\s*.*:/, weight: 3 },
      { pattern: /'''[\s\S]*'''|"""[\s\S]*"""/, weight: 2 }, // Docstrings
      { pattern: /os\.(system|popen|path)/, weight: 2 },
      { pattern: /sys\.(argv|exit|path)/, weight: 2 },
    ]
  },
  {
    lang: 'javascript',
    rules: [
      { pattern: /^#!\/.*node/m, weight: 10 },
      { pattern: /import\s+.*\s+from\s+['"].*['"]/, weight: 4 },
      { pattern: /require\s*\(['"].*['"]\)/, weight: 4 },
      { pattern: /const\s+.*\s*=\s*require\(/, weight: 4 },
      { pattern: /function\s+\w+\s*\(/, weight: 2 },
      { pattern: /console\.(log|error|warn|debug)\s*\(/, weight: 1 },
      { pattern: /module\.exports/, weight: 5 },
      { pattern: /export\s+(default|const|let|function)/, weight: 3 },
      { pattern: /await\s+/, weight: 2 },
      { pattern: /async\s+function/, weight: 3 },
      { pattern: /\(.*\)\s*=>\s*\{/, weight: 4 }, // Arrow functions
      { pattern: /process\.(argv|env|exit|stdout)/, weight: 4 },
      { pattern: /fs\.(readFileSync|writeFileSync|exists)/, weight: 3 },
      { pattern: /JSON\.(parse|stringify)/, weight: 1 },
    ]
  },
  {
    lang: 'bash',
    rules: [
      { pattern: /^#!\/bin\/(bash|sh|zsh|dash)/m, weight: 12 },
      { pattern: /echo\s+(-[neE]\s+)?['"].*['"]/, weight: 1 },
      { pattern: /if\s+\[\[\s+.*\s+\]\];?\s+then/, weight: 5 },
      { pattern: /elif\s+\[\[\s+.*\s+\]\];?\s+then/, weight: 5 },
      { pattern: /sudo\s+/, weight: 2 },
      { pattern: /apt-get\s+install|yum\s+install|brew\s+install/, weight: 4 },
      { pattern: /curl\s+(-sL|-X|-H)/, weight: 3 },
      { pattern: /export\s+\w+=/, weight: 2 },
      { pattern: /\$\(\s*.*\s*\)/, weight: 3 }, // Command substitution
      { pattern: /grep\s+|sed\s+|awk\s+/, weight: 2 },
      { pattern: /done\s+[\n\r]/, weight: 4 },
      { pattern: /case\s+.*\s+in/, weight: 4 },
      { pattern: /chmod\s+\+x/, weight: 3 },
    ]
  },
  {
    lang: 'php',
    rules: [
      { pattern: /<\?php/, weight: 15 }, // Extremely strong
      { pattern: /echo\s+.*;/, weight: 1 },
      { pattern: /\$\w+\s*=\s*.*/, weight: 1 },
      { pattern: /public\s+function\s+\w+/, weight: 2 },
      { pattern: /include(_once)?\s+['"].*['"];|require(_once)?\s+['"].*['"];/ , weight: 4 },
      { pattern: /foreach\s*\(.*\s+as\s+.*\)/, weight: 3 },
      { pattern: /namespace\s+[\w\\]+;/, weight: 4 },
      { pattern: /use\s+[\w\\]+;/, weight: 3 },
      { pattern: /var_dump\(.*\);/, weight: 4 },
    ]
  },
  {
    lang: 'cpp',
    rules: [
      { pattern: /#include\s+<iostream>/, weight: 8 },
      { pattern: /#include\s+<[\w.]+>/, weight: 2 },
      { pattern: /using\s+namespace\s+std;/, weight: 10 },
      { pattern: /std::cout|std::endl|std::cin/, weight: 8 },
      { pattern: /int\s+main\s*\(.*\)\s*\{/, weight: 3 },
      { pattern: /cout\s*<<\s*/, weight: 6 },
      { pattern: /cin\s*>>\s*/, weight: 6 },
      { pattern: /template\s*<.*>/, weight: 5 },
      { pattern: /class\s+\w+\s*\{[\s\S]*public:/, weight: 5 },
      { pattern: /vector\s*<.*>/, weight: 5 },
      { pattern: /::\w+/, weight: 2 },
    ]
  },
  {
    lang: 'c',
    rules: [
      { pattern: /#include\s+<stdio\.h>/, weight: 10 },
      { pattern: /#include\s+<stdlib\.h>/, weight: 5 },
      { pattern: /#include\s+<[\w./]+.h>/, weight: 3 },
      { pattern: /printf\s*\(.*\);/, weight: 4 },
      { pattern: /scanf\s*\(.*\);/, weight: 4 },
      { pattern: /char\s*\*.*\s*=\s*malloc\(/, weight: 6 },
      { pattern: /struct\s+\w+\s*\{/, weight: 3 },
      { pattern: /typedef\s+struct/, weight: 5 },
      { pattern: /int\s+main\s*\(int\s+argc,\s+char\s*\*argv\[\]\)/, weight: 8 },
      { pattern: /void\s+\w+\s*\(.*\);/, weight: 1 },
    ]
  },
  {
    lang: 'powershell',
    rules: [
      { pattern: /Write-Host|Write-Output|Write-Debug/, weight: 8 },
      { pattern: /Get-Process|Get-Service|Get-Content|Get-Item/, weight: 8 },
      { pattern: /Invoke-WebRequest|Invoke-RestMethod|Invoke-Expression/, weight: 8 },
      { pattern: /\$PSVersionTable/, weight: 10 },
      { pattern: /param\s*\(/, weight: 4 },
      { pattern: /\[CmdletBinding\(\)\]/, weight: 10 },
      { pattern: /New-Object/, weight: 6 },
      { pattern: /Set-ExecutionPolicy/, weight: 8 },
      { pattern: /\$true|\$false|\$null/, weight: 3 },
      { pattern: /try\s*\{.*\}\s*catch\s*\{/, weight: 3 },
    ]
  }
];

export function detectLanguage(code, filename = null) {
  if (!code || code.trim().length === 0) return 'python';

  // 1. Try by filename extension first (most reliable)
  if (filename) {
    const parts = filename.split('.');
    if (parts.length > 1) {
      const ext = parts.pop().toLowerCase();
      const extMap = {
        'py': 'python',
        'js': 'javascript',
        'mjs': 'javascript',
        'cjs': 'javascript',
        'sh': 'bash',
        'bash': 'bash',
        'zsh': 'bash',
        'c': 'c',
        'h': 'c',
        'cpp': 'cpp',
        'hpp': 'cpp',
        'cc': 'cpp',
        'php': 'php',
        'ps1': 'powershell',
        'psm1': 'powershell'
      };
      if (extMap[ext]) return extMap[ext];
    }
  }

  // 2. Advanced weight-based scoring
  let scores = {};
  for (const profile of LANG_PROFILES) {
    scores[profile.lang] = 0;
    for (const rule of profile.rules) {
      if (rule.pattern.test(code)) {
        scores[profile.lang] += rule.weight;
      }
    }
  }

  // 3. Resolve winner
  let bestMatch = 'python';
  let maxScore = 0;

  for (const [lang, score] of Object.entries(scores)) {
    if (score > maxScore) {
      maxScore = score;
      bestMatch = lang;
    }
  }

  // Handle lack of data
  if (maxScore === 0) return 'python';

  // 4. Custom disambiguation logic
  // If we found a generic match like 'c' but it has C++ headers, flip to 'cpp'
  if (bestMatch === 'c' && (code.includes('iostream') || code.includes('vector') || code.includes('namespace std'))) {
    return 'cpp';
  }

  return bestMatch;
}
