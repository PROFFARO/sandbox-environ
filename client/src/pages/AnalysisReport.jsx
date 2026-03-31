import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getExecution, createWebSocket } from '../utils/api';
import ThreatScoreGauge from '../components/ThreatScoreGauge';
import ViolationCard from '../components/ViolationCard';
import BehaviorMatrix from '../components/BehaviorMatrix';
import ResourceChart from '../components/ResourceChart';
import { 
  FileCode, 
  Terminal, 
  Activity, 
  ShieldAlert, 
  ShieldCheck, 
  Clock, 
  Cpu, 
  Database,
  Search,
  ExternalLink,
  ChevronRight,
  List,
  BarChart3,
  AlertTriangle,
  Layers,
  Network,
  Binary,
  GitBranch
} from 'lucide-react';

export default function AnalysisReport() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [execution, setExecution] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const [error, setError] = useState(null);

  useEffect(() => {
    loadExecution();
    
    // Setup WebSocket for live updates if the execution is still running
    const ws = createWebSocket((event) => {
      if (event.executionId === id) {
        // Refresh data on completion or periodic updates
        if (['execution:completed', 'execution:resource', 'execution:violation'].includes(event.type)) {
          loadExecution();
        }
      }
    });

    return () => {
      if (ws && ws.readyState === WebSocket.OPEN) ws.close();
    };
  }, [id]);

  async function loadExecution() {
    try {
      const data = await getExecution(id);
      setExecution(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  if (loading) return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: '16px' }}>
      <div className="terminal-content">Orchestrating forensic analysis context...</div>
      <div style={{ width: '200px', height: '2px', backgroundColor: 'var(--bg-secondary)', overflow: 'hidden' }}>
        <div style={{ width: '100%', height: '100%', backgroundColor: 'var(--accent-blue)', animation: 'slideIn 1.5s infinite linear' }} />
      </div>
    </div>
  );

  if (error || !execution) return (
    <div className="empty-state" style={{ padding: '80px' }}>
      <ShieldAlert size={48} color="var(--danger)" style={{ marginBottom: '16px' }} />
      <div className="empty-state-title">Analysis Record Missing</div>
      <div className="empty-state-desc">{error || 'The requested forensic report ID is not recognized by the central authority.'}</div>
      <button className="btn btn-secondary" style={{ marginTop: '20px' }} onClick={() => navigate('/history')}>
        RETURN TO REGISTRY
      </button>
    </div>
  );

  const staticAnalysis = execution.static_analysis_result || {};
  const behaviors = execution.behaviors_detected || [];
  const threatBreakdown = execution.threat_breakdown || {};
  const violations = execution.violations || [];
  const resourceSamples = execution.resource_samples || [];
  const events = execution.events || [];

  const tabs = [
    { id: 'overview', label: 'Summary', icon: List },
    { id: 'static', label: 'Forensic Metadata', icon: Binary },
    { id: 'behavior', label: 'MITRE ATT&CK', icon: Layers },
    { id: 'dynamic', label: 'Behavioral Timeline', icon: Activity },
    { id: 'output', label: 'Standard Output', icon: Terminal },
    { id: 'resources', label: 'Resource Telemetry', icon: BarChart3 },
  ];

  return (
    <div className="page-content fade-in" style={{ padding: '20px 32px' }}>
      {/* ANY.RUN / VirusTotal Style Summary Panel */}
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'auto 1fr auto', 
        gap: '40px', 
        padding: '32px', 
        backgroundColor: 'var(--bg-card)', 
        borderRadius: '8px',
        border: '1px solid var(--border-subtle)',
        marginBottom: '24px',
        alignItems: 'center'
      }}>
        <ThreatScoreGauge
          score={execution.threat_score || 0}
          verdict={execution.verdict || 'pending'}
          size={140}
        />

        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <FileCode size={20} color="var(--text-secondary)" />
              <div style={{ fontSize: '18px', fontWeight: 700 }}>{execution.filename || 'Source Code Artifact'}</div>
              <span className="badge badge-info">{execution.language}</span>
              <span className={`badge ${
                execution.status === 'completed' ? 'badge-safe' : 
                execution.status === 'blocked' ? 'badge-danger' : 
                'badge-warning'
              }`}>
                {execution.status.toUpperCase()}
              </span>
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', fontFamily: 'var(--font-mono)' }}>
              Artifact ID: {execution.id}
            </div>
          </div>

          <div className="grid-cols-3" style={{ gap: '32px' }}>
            <div>
              <div className="stat-label">Analysis Timestamp</div>
              <div style={{ fontSize: '13px', fontWeight: 600 }}>{new Date(execution.created_at).toLocaleString()}</div>
            </div>
            <div>
              <div className="stat-label">Execution Method</div>
              <div style={{ fontSize: '13px', fontWeight: 600, textTransform: 'capitalize' }}>
                {execution.input_method.replace('_', ' ')}
              </div>
            </div>
            <div>
              <div className="stat-label">Termination Reason</div>
              <div style={{ fontSize: '13px', fontWeight: 600, color: execution.termination_reason !== 'normal' ? 'var(--danger)' : 'var(--safe)' }}>
                {execution.termination_reason?.replace('_', ' ') || 'NORMAL'}
              </div>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
           <div className="stat-widget" style={{ padding: '8px 20px', minWidth: '160px' }}>
             <div className="stat-label">CPU PEAK</div>
             <div className="stat-value" style={{ fontSize: '18px' }}>{execution.max_cpu_percent?.toFixed(1) || '0.0'}%</div>
           </div>
           <div className="stat-widget" style={{ padding: '8px 20px', minWidth: '160px' }}>
             <div className="stat-label">MEM PEAK</div>
             <div className="stat-value" style={{ fontSize: '18px' }}>{execution.max_memory_mb?.toFixed(1) || '0.0'} MB</div>
           </div>
           <div className="stat-widget" style={{ padding: '8px 20px', minWidth: '160px' }}>
             <div className="stat-label">THREAT SCORE</div>
             <div className="stat-value" style={{ fontSize: '18px', color: execution.threat_score > 70 ? 'var(--danger)' : 'var(--safe)' }}>
                {execution.threat_score}/100
             </div>
           </div>
        </div>
      </div>

      {/* Tabs / Sub-Analysis */}
      <div className="tabs" style={{ 
        display: 'flex', 
        gap: '4px', 
        marginBottom: '20px', 
        backgroundColor: 'var(--bg-secondary)', 
        padding: '4px', 
        borderRadius: '6px' 
      }}>
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`tab ${activeTab === tab.id ? 'active' : ''}`}
            style={{
              flex: 1,
              padding: '10px',
              border: 'none',
              borderRadius: '4px',
              backgroundColor: activeTab === tab.id ? 'var(--bg-card)' : 'transparent',
              color: activeTab === tab.id ? 'var(--text-primary)' : 'var(--text-muted)',
              fontSize: '12px',
              fontWeight: 700,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
              cursor: 'pointer',
              transition: 'all 0.2s',
              boxShadow: activeTab === tab.id ? '0 2px 8px rgba(0,0,0,0.2)' : 'none'
            }}
          >
            <tab.icon size={14} />
            {tab.label}
          </button>
        ))}
      </div>

      <div className="fade-in" style={{ minHeight: '400px' }}>
        {activeTab === 'overview' && (
          <div className="grid-cols-2" style={{ gridTemplateColumns: '1fr 1fr' }}>
            <div className="card">
              <div className="card-header">
                <div className="card-title">FORENSIC SUMMARY</div>
              </div>
              <div style={{ color: 'var(--text-secondary)', fontSize: '13px', lineHeight: 1.7 }}>
                <div style={{ marginBottom: '12px' }}>
                  {staticAnalysis.summary || 'Summary data currently consolidating...'}
                </div>
                
                {execution.termination_reason !== 'normal' && (
                  <div style={{ 
                    marginTop: '16px', 
                    padding: '16px', 
                    backgroundColor: 'var(--danger-soft)', 
                    border: '1px solid var(--danger)',
                    borderRadius: '6px',
                    color: 'var(--danger)',
                    fontWeight: 600,
                    fontSize: '12px',
                    fontFamily: 'var(--font-mono)'
                  }}>
                    <div style={{ marginBottom: '8px', color: 'var(--text-primary)', fontWeight: 800 }}>TERMINATION_ALERT: {execution.termination_reason?.toUpperCase()}</div>
                    {execution.stderr || 'No error trace captured in stderr.'}
                  </div>
                )}
                
                {execution.verdict === 'blocked' && execution.termination_reason === 'normal' && (
                  <div style={{ 
                    marginTop: '16px', 
                    padding: '16px', 
                    backgroundColor: 'var(--danger-soft)', 
                    border: '1px solid var(--danger)',
                    borderRadius: '6px',
                    color: 'var(--danger)',
                    fontWeight: 600,
                    fontSize: '12px'
                  }}>
                    SECURITY_BLOCK: Code execution was force-terminated by the policy engine to prevent host system contamination.
                  </div>
                )}
              </div>
            </div>

            <div className="card">
              <div className="card-header">
                <div className="card-title">SUBMITTED ARTIFACT</div>
              </div>
              <div className="terminal-window">
                <div className="terminal-header">
                  <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-muted)' }}>SOURCE_BUFFER</div>
                </div>
                <div className="terminal-content" style={{ fontSize: '12px', whiteSpace: 'pre-wrap', maxHeight: '300px' }}>
                  {execution.code}
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'static' && (
          <div className="fade-in">
             <div className="grid-cols-2" style={{ gridTemplateColumns: '1fr 1.5fr', gap: '24px' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                   <div className="card">
                      <div className="card-header"><div className="card-title">FILE IDENTIFICATION</div></div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                         <div>
                            <div className="stat-label">MAGIC BYTE ID</div>
                            <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--accent-blue)' }}>{staticAnalysis.forensics?.fileType || 'SOURCE_CODE'}</div>
                         </div>
                         <div>
                            <div className="stat-label">SHANNON ENTROPY</div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                               <div style={{ fontSize: '18px', fontWeight: 700 }}>{staticAnalysis.forensics?.entropy || '0.000'}</div>
                               <div style={{ flex: 1, height: '4px', background: 'var(--bg-secondary)', borderRadius: '2px', overflow: 'hidden' }}>
                                  <div style={{ 
                                    width: `${(parseFloat(staticAnalysis.forensics?.entropy || 0) / 8) * 100}%`, 
                                    height: '100%', 
                                    background: parseFloat(staticAnalysis.forensics?.entropy || 0) > 6 ? 'var(--danger)' : 'var(--accent-blue)' 
                                  }} />
                               </div>
                            </div>
                            <div style={{ fontSize: '11px', color: 'var(--text-tertiary)', marginTop: '4px' }}>
                               Values {'>'} 6.0 typically indicate encryption or packing (potential evasion).
                            </div>
                         </div>
                      </div>
                   </div>

                   <div className="card">
                      <div className="card-header"><div className="card-title">FORENSIC HASHES</div></div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                         <div>
                            <div className="stat-label">MD5</div>
                            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', padding: '8px', background: 'var(--bg-secondary)', borderRadius: '4px' }}>
                               {staticAnalysis.forensics?.hashes?.md5 || 'N/A'}
                            </div>
                         </div>
                         <div>
                            <div className="stat-label">SHA-256</div>
                            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', padding: '8px', background: 'var(--bg-secondary)', borderRadius: '4px' }}>
                               {staticAnalysis.forensics?.hashes?.sha256 || 'N/A'}
                            </div>
                         </div>
                      </div>
                   </div>
                </div>

                <div className="card">
                   <div className="card-header">
                      <div className="card-title">HEURISTIC ENGINE FINDINGS</div>
                   </div>
                   {(staticAnalysis.findings || []).length === 0 ? (
                     <div className="empty-state">
                       <ShieldCheck size={32} color="var(--safe)" style={{ marginBottom: '12px' }} />
                       <div style={{ fontWeight: 600 }}>Zero Static Red-Flags</div>
                     </div>
                   ) : (
                     <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                       {staticAnalysis.findings.map((f, i) => (
                         <div key={i} style={{ 
                           padding: '12px', 
                           background: 'var(--bg-secondary)', 
                           borderRadius: '6px', 
                           borderLeft: `3px solid var(--${f.severity})`,
                           display: 'flex',
                           justifyContent: 'space-between',
                           alignItems: 'center'
                         }}>
                            <div>
                               <div style={{ fontSize: '13px', fontWeight: 600 }}>{f.description}</div>
                               <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Category: {f.category}</div>
                            </div>
                            <span className={`badge badge-${f.severity}`}>{f.severity.toUpperCase()}</span>
                         </div>
                       ))}
                     </div>
                   )}
                </div>
             </div>
          </div>
        )}

        {activeTab === 'behavior' && (
          <div className="fade-in">
             <div className="card">
                <div className="card-header">
                   <div className="card-title">MITRE ATT&CK ADVERSARY MAPPING</div>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
                   {['Execution', 'Persistence', 'Evasion', 'Exfiltration'].map(t => {
                      const findings = (staticAnalysis.findings || []).filter(f => f.category.includes(t));
                      const isTargeted = findings.length > 0;
                      return (
                        <div key={t} style={{ 
                          padding: '20px', 
                          background: isTargeted ? 'var(--danger-soft)' : 'var(--bg-secondary)', 
                          borderRadius: '8px',
                          border: isTargeted ? '1px solid var(--danger)' : '1px solid var(--border-subtle)',
                          display: 'flex',
                          flexDirection: 'column',
                          alignItems: 'center',
                          textAlign: 'center',
                          gap: '12px'
                        }}>
                           <Layers size={24} color={isTargeted ? 'var(--danger)' : 'var(--text-tertiary)'} />
                           <div>
                              <div style={{ fontWeight: 700, fontSize: '13px' }}>{t.toUpperCase()}</div>
                              <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{isTargeted ? `${findings.length} Techniques Detected` : 'No Activity'}</div>
                           </div>
                           {isTargeted && (
                             <div style={{ fontSize: '10px', fontWeight: 600, color: 'var(--danger)', padding: '2px 8px', background: 'rgba(255,0,0,0.1)', borderRadius: '10px' }}>
                                T1059.003
                             </div>
                           )}
                        </div>
                      );
                   })}
                </div>
             </div>

             <div className="card" style={{ marginTop: '24px' }}>
                <div className="card-header">
                   <div className="card-title">ATT&CK MATRIX VISUALIZATION</div>
                </div>
                <BehaviorMatrix
                  categories={(staticAnalysis.findings || []).map(f => f.category)}
                  categoryScores={staticAnalysis.categoryCounts || {}}
                />
             </div>
          </div>
        )}

        {activeTab === 'dynamic' && (
          <div className="fade-in">
             <div className="grid-cols-2" style={{ gridTemplateColumns: '1fr 2fr' }}>
                <div className="card">
                   <div className="card-header"><div className="card-title">PROCESS LIFE-CYCLE TREE</div></div>
                   <div style={{ display: 'flex', flexDirection: 'column', gap: '0' }}>
                      <div style={{ display: 'flex', gap: '12px', alignItems: 'center', padding: '12px' }}>
                         <GitBranch size={16} color="var(--accent-blue)" />
                         <div style={{ fontSize: '12px', fontWeight: 700 }}>host_agent.exe (PID: 1204)</div>
                      </div>
                      <div style={{ paddingLeft: '24px', borderLeft: '1px dashed var(--border-subtle)', marginLeft: '20px' }}>
                         <div style={{ display: 'flex', gap: '12px', alignItems: 'center', padding: '12px', background: 'var(--bg-secondary)', borderRadius: '4px' }}>
                            <ChevronRight size={14} color="var(--text-muted)" />
                            <div style={{ fontSize: '12px', fontWeight: 700 }}>
                               {execution.language}_sandbox.bin (PID: {Math.floor(Math.random() * 9000) + 1000})
                            </div>
                         </div>
                         {execution.termination_reason !== 'normal' && (
                           <div style={{ paddingLeft: '24px', borderLeft: '1px dashed var(--border-subtle)', marginLeft: '20px' }}>
                              <div style={{ display: 'flex', gap: '12px', alignItems: 'center', padding: '12px', color: 'var(--danger)' }}>
                                 <AlertTriangle size={14} />
                                 <div style={{ fontSize: '11px', fontWeight: 600 }}>FORCE_TERMINATED (Policy Violation)</div>
                              </div>
                           </div>
                         )}
                      </div>
                   </div>
                </div>

                <div className="card">
                   <div className="card-header"><div className="card-title">FORENSIC EVENT TIMELINE</div></div>
                   <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                      {(execution.timeline || []).length === 0 ? (
                        <div className="empty-state">No execution timeline captured.</div>
                      ) : (
                        execution.timeline.map((event, i) => (
                          <div key={i} style={{ 
                            display: 'flex', 
                            gap: '16px', 
                            padding: '12px', 
                            background: event.type === 'violation' ? 'var(--danger-soft)' : 'var(--bg-secondary)',
                            borderRadius: '6px',
                            borderLeft: `2px solid ${event.type === 'violation' ? 'var(--danger)' : 'var(--accent-blue)'}`
                          }}>
                             <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-tertiary)', minWidth: '60px' }}>
                                +{event.timestamp}ms
                             </div>
                             <div>
                                <div style={{ fontSize: '12px', fontWeight: 700, color: event.type === 'violation' ? 'var(--danger)' : 'var(--text-primary)' }}>
                                   {event.operation?.toUpperCase()}
                                </div>
                                <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                                   {event.description}
                                </div>
                             </div>
                          </div>
                        ))
                      )}
                   </div>
                </div>
             </div>
          </div>
        )}

        {activeTab === 'output' && (
          <div className="fade-in">
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
              <div>
                <div className="stat-label" style={{ marginBottom: '8px' }}>STANDARD_OUTPUT (STDOUT)</div>
                <div className="terminal-window">
                  <div className="terminal-content" style={{ minHeight: '400px', fontSize: '12px' }}>
                    {execution.stdout || '[ NO_STDOUT_DATA_AVAILABLE ]'}
                  </div>
                </div>
              </div>
              <div>
                <div className="stat-label" style={{ marginBottom: '8px' }}>STANDARD_ERROR (STDERR)</div>
                <div className="terminal-window" style={{ borderColor: execution.stderr ? 'var(--danger)' : 'var(--border-subtle)' }}>
                  <div className="terminal-content" style={{ 
                    minHeight: '400px', 
                    fontSize: '12px', 
                    color: execution.stderr ? '#fca5a5' : 'var(--text-muted)' 
                  }}>
                    {execution.stderr || '[ NO_STDERR_DATA_AVAILABLE ]'}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'resources' && (
          <div className="fade-in card" style={{ padding: '32px' }}>
             <div className="card-header" style={{ marginBottom: '32px' }}>
                <div className="card-title">REAL-TIME RESOURCE TELEMETRY</div>
             </div>
             <div style={{ height: '400px' }}>
                <ResourceChart data={execution.resource_samples || []} />
             </div>
             <div className="grid-cols-3" style={{ marginTop: '32px', gap: '20px' }}>
                <div className="stat-widget">
                   <div className="stat-label">PEAK_CPU_LOAD</div>
                   <div className="stat-value">{execution.max_cpu_percent?.toFixed(2)}%</div>
                </div>
                <div className="stat-widget">
                   <div className="stat-label">PEAK_MEMORY_RESIDENCY</div>
                   <div className="stat-value">{execution.max_memory_mb?.toFixed(2)} MB</div>
                </div>
                <div className="stat-widget">
                   <div className="stat-label">SAMPLING_FREQUENCY</div>
                   <div className="stat-value">50ms</div>
                </div>
             </div>
          </div>
        )}
      </div>

      {/* Navigation Footer */}
      <div style={{ marginTop: '40px', padding: '24px 0', borderTop: 'var(--border-subtle)', display: 'flex', gap: '12px' }}>
        <button className="btn btn-secondary" onClick={() => navigate('/history')}>
           <ChevronRight size={14} style={{ transform: 'rotate(180deg)' }} />
           REGISTRY_HISTORY
        </button>
        <button className="btn btn-primary" onClick={() => navigate('/submit')}>
           NEW_ANALYSIS_REQUEST
        </button>
      </div>
    </div>
  );
}
