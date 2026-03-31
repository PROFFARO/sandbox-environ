import { useState, useEffect } from 'react';
import { getPolicies } from '../utils/api';
import { Shield, Lock, Cpu, Globe, FileCheck, AlertTriangle, Zap, Terminal } from 'lucide-react';

export default function Policies() {
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeLanguage, setActiveLanguage] = useState('python');

  useEffect(() => {
    loadPolicies();
  }, []);

  async function loadPolicies() {
    try {
      const data = await getPolicies();
      setPolicies(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error('Failed to load policies:', err);
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
        <div className="terminal-content">Synchronizing global security registry...</div>
      </div>
    );
  }

  const activePolicy = policies.find(p => p.language?.toLowerCase() === activeLanguage) || policies[0];
  const langIcons = { Python: Cpu, JavaScript: Zap, Bash: Terminal };

  return (
    <div className="page-content fade-in">
      <div className="header-title" style={{ marginBottom: '24px', display: 'flex', alignItems: 'center', gap: '12px' }}>
        <Shield size={24} color="var(--accent-blue)" />
        Active Security Policy Framework
      </div>

      <div style={{ marginBottom: '24px', maxWidth: '800px' }}>
        <p style={{ fontSize: '14px', color: 'var(--text-tertiary)', lineHeight: 1.6 }}>
          Operational constraints are systematically enforced across all isolated execution nodes. 
          Policies are derived from a combination of static heuristics and runtime guardrail parameters.
        </p>
      </div>

      {/* Language Toggle */}
      <div className="tabs" style={{ 
        display: 'flex', 
        gap: '4px', 
        marginBottom: '20px', 
        backgroundColor: 'var(--bg-secondary)', 
        padding: '4px', 
        borderRadius: '6px',
        width: 'fit-content'
      }}>
        {policies.map(p => {
          const Icon = langIcons[p.language] || Terminal;
          return (
            <button
              key={p.language}
              className={`tab ${activeLanguage === p.language?.toLowerCase() ? 'active' : ''}`}
              onClick={() => setActiveLanguage(p.language?.toLowerCase())}
              style={{
                padding: '8px 16px',
                border: 'none',
                borderRadius: '4px',
                backgroundColor: activeLanguage === p.language?.toLowerCase() ? 'var(--bg-card)' : 'transparent',
                color: activeLanguage === p.language?.toLowerCase() ? 'var(--text-primary)' : 'var(--text-muted)',
                fontSize: '12px',
                fontWeight: 700,
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                cursor: 'pointer',
                transition: 'all 0.2s',
                boxShadow: activeLanguage === p.language?.toLowerCase() ? '0 2px 8px rgba(0,0,0,0.2)' : 'none'
              }}
            >
              <Icon size={14} />
              {p.language.toUpperCase()}
            </button>
          );
        })}
      </div>

      {activePolicy && (
        <div className="fade-in">
          <div className="grid-cols-2" style={{ marginBottom: '24px' }}>
            <div className="card">
              <div className="card-header">
                <div className="card-title">
                  <Lock size={16} color="var(--accent-blue)" />
                  RESOURCE_QUOTAS
                </div>
              </div>
              <div className="grid-cols-2" style={{ gap: '16px' }}>
                <div>
                  <div className="stat-label">Execution Timeout</div>
                  <div style={{ fontSize: '18px', fontWeight: 700 }}>{activePolicy.maxExecutionTimeMs / 1000}s</div>
                </div>
                <div>
                  <div className="stat-label">Memory Hard-Limit</div>
                  <div style={{ fontSize: '18px', fontWeight: 700 }}>{activePolicy.maxMemoryMb}MB</div>
                </div>
                <div>
                  <div className="stat-label">Max Output Stdout</div>
                  <div style={{ fontSize: '18px', fontWeight: 700 }}>{activePolicy.maxOutputBytes / 1024}KB</div>
                </div>
                <div>
                  <div className="stat-label">Max Artifact Size</div>
                  <div style={{ fontSize: '18px', fontWeight: 700 }}>{activePolicy.maxCodeLength / 1024}KB</div>
                </div>
              </div>
            </div>

            <div className="card">
              <div className="card-header">
                <div className="card-title">
                  <Globe size={16} color="var(--danger)" />
                  ISOLATION_EVIDENCE
                </div>
              </div>
              <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                Processes are spawned with <code>UID: 1001</code> and <code>GID: 1001</code>. 
                Inbound/Outbound network traffic is truncated at the network interface layer.
              </p>
              <div style={{ marginTop: '16px', padding: '12px', backgroundColor: 'var(--danger-soft)', borderRadius: '4px', border: '1px solid var(--danger)', color: 'var(--danger)', fontSize: '11px', fontWeight: 700 }}>
                CRITICAL: NETWORK_Egress is strictly DISALLOWED.
              </div>
            </div>
          </div>

          <div className="card">
             <div className="card-header">
                <div className="card-title">
                  <AlertTriangle size={16} color="var(--warning)" />
                  RESTRICTED_ENTITIES
                </div>
              </div>
              
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Entity Category</th>
                      <th>Identification</th>
                      <th>Constraint Logic</th>
                    </tr>
                  </thead>
                  <tbody>
                    {activePolicy.blockedModules?.map((m, i) => (
                      <tr key={`m-${i}`}>
                        <td><span className="badge badge-danger">MODULE</span></td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{m.module}</td>
                        <td style={{ fontSize: '12px' }}>{m.reason}</td>
                      </tr>
                    ))}
                    {activePolicy.blockedCommands?.map((c, i) => (
                      <tr key={`c-${i}`}>
                        <td><span className="badge badge-danger">COMMAND</span></td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{c.command}</td>
                        <td style={{ fontSize: '12px' }}>{c.reason}</td>
                      </tr>
                    ))}
                    {activePolicy.blockedBuiltins?.map((b, i) => (
                      <tr key={`b-${i}`}>
                        <td><span className="badge badge-warning">BUILTIN</span></td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{b.name}</td>
                        <td style={{ fontSize: '12px' }}>{b.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
          </div>
        </div>
      )}
    </div>
  );
}
