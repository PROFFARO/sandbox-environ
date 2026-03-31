import { Shield, Lock, Activity, Database, Terminal, FileCode, Zap, Info, ChevronRight, Binary, Layers } from 'lucide-react';

export default function Documentation() {
  const sections = [
    {
      id: 'architecture',
      title: '1. SYSTEM ARCHITECTURE & ISOLATION',
      icon: Layers,
      content: (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <p>The Controlled Execution Sandbox (CES) is a high-fidelity forensic platform designed to execute untrusted code in a strictly bounded environment. Our isolation strategy is based on three pillars:</p>
          <div className="grid-cols-2" style={{ gap: '20px', marginTop: '10px' }}>
            <div className="stat-widget" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <Lock size={20} color="var(--accent-blue)" />
                <div style={{ fontWeight: 700 }}>PROCESS_JAIL</div>
              </div>
              <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                Every submission spawns a dedicated child process with restricted permissions. OS-level primitives are used to deny file system access, network socket creation, and inter-process communication (IPC).
              </div>
            </div>
            <div className="stat-widget" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <Activity size={20} color="var(--accent-blue)" />
                <div style={{ fontWeight: 700 }}>TELEMETRY_ENGINE</div>
              </div>
              <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                A sub-50ms sampling process monitors CPU residency, thread count, and heap allocation. Any violation of the 300s/1GB boundary triggers an immediate SIGKILL forensic capture.
              </div>
            </div>
          </div>
        </div>
      )
    },
    {
      id: 'forensics',
      title: '2. FORENSIC INTELLIGENCE ENGINE',
      icon: Binary,
      content: (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <p>Our Static Analyzer performs deep-scan operations before the execution phase begins. This ensures known-malicious patterns are flagged before they can interact with the sandbox.</p>
          <div className="card" style={{ background: 'var(--bg-secondary)', border: 'none' }}>
            <ul style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '13px', padding: '0 0 0 20px', margin: 0 }}>
              <li><strong>Multi-Factor Hashing:</strong> Simultaneous MD5, SHA-1, and SHA-256 generation for artifact identification.</li>
              <li><strong>Shannon Entropy Analysis:</strong> Calculation of data density to detect packed/encrypted payloads used for evasion.</li>
              <li><strong>MITRE ATT&CK Mapping:</strong> Automated classification of heuristic findings against the standard MITRE framework (e.g., T1059, T1027).</li>
              <li><strong>Magic Byte Detection:</strong> Verification of true file types regardless of user-provided extension.</li>
            </ul>
          </div>
        </div>
      )
    },
    {
      id: 'languages',
      title: '3. SUPPORTED LANGUAGES & RUNTIMES',
      icon: FileCode,
      content: (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Runtime</th>
                <th>Compiler/Interpreter</th>
                <th>Isolation Strategy</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style={{ fontWeight: 700 }}>Python 3.x</td>
                <td>Python 3.12 (CLI)</td>
                <td>Restricted Builtins & Whitelisted Modules</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 700 }}>JavaScript</td>
                <td>Node.js 20.x</td>
                <td>V8 VM Context with Proxy-Blocked Globals</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 700 }}>C / C++</td>
                <td>GCC / G++ 11.x</td>
                <td>Native Binary Execution in Restricted Shell</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 700 }}>Bash / PS</td>
                <td>Restricted Shell</td>
                <td>Command Whitelisting & Path Sanitization</td>
              </tr>
            </tbody>
          </table>
        </div>
      )
    }
  ];

  return (
    <div className="page-content fade-in" style={{ padding: '40px' }}>
      <div style={{ maxWidth: '1000px', margin: '0 auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '40px' }}>
          <div style={{ width: '48px', height: '48px', backgroundColor: 'var(--accent-blue)', borderRadius: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Info size={28} color="#fff" />
          </div>
          <div>
            <h1 style={{ fontSize: '32px', fontWeight: 900, letterSpacing: '-0.02em', margin: 0 }}>SECURITY_MODEL.PDF</h1>
            <p style={{ color: 'var(--text-tertiary)', fontSize: '14px', margin: 0, fontFamily: 'var(--font-mono)' }}>Internal Research & System White-paper v2.4.0</p>
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
          {sections.map(section => (
            <div key={section.id} className="card" style={{ padding: '32px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '24px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '16px' }}>
                <section.icon size={22} color="var(--accent-blue)" />
                <h2 style={{ fontSize: '16px', fontWeight: 800, margin: 0 }}>{section.title}</h2>
              </div>
              <div style={{ fontSize: '14px', lineHeight: 1.8, color: 'var(--text-secondary)' }}>
                {section.content}
              </div>
            </div>
          ))}
        </div>

        <div className="card" style={{ marginTop: '40px', padding: '32px', backgroundColor: 'var(--accent-blue-soft)', border: '1px solid var(--accent-blue)' }}>
           <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
              <Shield size={20} color="var(--accent-blue)" />
              <div style={{ fontWeight: 800, fontSize: '14px', color: 'var(--accent-blue)' }}>COMPLIANCE_CERTIFICATION</div>
           </div>
           <p style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: 0 }}>
              The sandbox core complies with enterprise-grade security standards for malware execution laboratories. Our multi-agent architecture ensures zero host leakage even during high-entropy payload execution.
           </p>
        </div>
      </div>
    </div>
  );
}
