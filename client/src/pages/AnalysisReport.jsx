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
  AlertTriangle
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
    { id: 'static', label: 'Static Analysis', icon: Search },
    { id: 'behavior', label: 'Behavioral', icon: Activity },
    { id: 'output', label: 'Terminal Output', icon: Terminal },
    { id: 'resources', label: 'Telemetry', icon: BarChart3 },
    { id: 'violations', label: `Flags (${violations.length})`, icon: ShieldAlert },
    { id: 'timeline', label: 'Timeline', icon: Clock },
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

        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
           <div className="stat-widget" style={{ padding: '12px 20px', minWidth: '160px' }}>
             <div className="stat-label">CPU Peak</div>
             <div className="stat-value" style={{ fontSize: '20px' }}>{execution.max_cpu_percent?.toFixed(1) || '0.0'}%</div>
           </div>
           <div className="stat-widget" style={{ padding: '12px 20px', minWidth: '160px' }}>
             <div className="stat-label">Mem Peak</div>
             <div className="stat-value" style={{ fontSize: '20px' }}>{execution.max_memory_mb?.toFixed(1) || '0.0'} MB</div>
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
                {staticAnalysis.summary || 'Summary data currently consolidating...'}
                {execution.verdict === 'blocked' && (
                  <div style={{ 
                    marginTop: '20px', 
                    padding: '16px', 
                    backgroundColor: 'var(--danger-soft)', 
                    border: '1px solid var(--danger)',
                    borderRadius: '6px',
                    color: 'var(--danger)',
                    fontWeight: 600,
                    fontSize: '12px'
                  }}>
                    SANDBOX ESCAPE ATTEMPT DETECTED: Code execution was force-terminated by the policy engine to prevent host system contamination.
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
             <div className="card-header" style={{ marginBottom: '16px', borderBottom: 'none' }}>
                <div className="card-title">Static Intelligence Flags</div>
             </div>
             {(staticAnalysis.findings || []).length === 0 ? (
               <div className="empty-state">
                 <ShieldCheck size={32} color="var(--safe)" style={{ marginBottom: '12px' }} />
                 <div style={{ fontWeight: 600 }}>Zero Static Red-Flags</div>
                 <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Code passes all heuristic and pattern-matching intelligence checks.</div>
               </div>
             ) : (
               staticAnalysis.findings.map((f, i) => (
                 <ViolationCard key={i} violation={f} />
               ))
             )}
          </div>
        )}

        {activeTab === 'behavior' && (
          <div className="fade-in">
             <div className="card-header" style={{ marginBottom: '16px', borderBottom: 'none' }}>
                <div className="card-title">ATT&CK Matrix Behavioral Mapping</div>
             </div>
             <BehaviorMatrix
               categories={behaviors}
               categoryScores={threatBreakdown}
             />
             
             {behaviors.length > 0 && (
               <div style={{ marginTop: '32px' }}>
                 <div className="card-title" style={{ marginBottom: '16px', fontSize: '12px' }}>DETECTION HISTORY ({behaviors.length})</div>
                 {behaviors.map((b, i) => (
                   <ViolationCard key={i} violation={{
                     severity: b.severity,
                     category: b.category,
                     description: b.description,
                     operation: b.source,
                     action_taken: b.evidence
                   }} />
                 ))}
               </div>
             )}
          </div>
        )}

        {activeTab === 'output' && (
          <div className="fade-in">
            <div className="grid-cols-2" style={{ gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)' }}>
              <div>
                <div className="stat-label" style={{ marginBottom: '8px' }}>Standard Output (STDOUT)</div>
                <div className="terminal-window">
                  <div className="terminal-content" style={{ minHeight: '400px' }}>
                    {execution.stdout || '[ NO_STDOUT_DATA_AVAILABLE ]'}
                  </div>
                </div>
              </div>
              <div>
                <div className="stat-label" style={{ marginBottom: '8px' }}>Standard Error (STDERR)</div>
                <div className="terminal-window" style={{ borderColor: 'var(--danger-soft)' }}>
                  <div className="terminal-content" style={{ minHeight: '400px', color: '#ffb3b3' }}>
                    {execution.stderr || '[ NO_STDERR_DATA_AVAILABLE ]'}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'resources' && (
          <div className="fade-in">
            <div className="card-header" style={{ marginBottom: '16px', borderBottom: 'none' }}>
               <div className="card-title">Real-time Telemetry Artifacts</div>
            </div>
            <div className="card">
              <ResourceChart samples={resourceSamples} />
            </div>
          </div>
        )}

        {activeTab === 'violations' && (
          <div className="fade-in">
             <div className="card-header" style={{ marginBottom: '16px', borderBottom: 'none' }}>
                <div className="card-title">Policy & Guardrail Compliance Records</div>
             </div>
             {violations.length === 0 ? (
               <div className="empty-state">
                 <ShieldCheck size={32} color="var(--safe)" style={{ marginBottom: '12px' }} />
                 <div style={{ fontWeight: 600 }}>Zero Compliance Violations</div>
                 <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>All guardrail policies remained intact during entire lifecycle.</div>
               </div>
             ) : (
               violations.map((v, i) => (
                 <ViolationCard key={i} violation={v} />
               ))
             )}
          </div>
        )}

        {activeTab === 'timeline' && (
          <div className="fade-in">
            <div className="card-header" style={{ marginBottom: '16px', borderBottom: 'none' }}>
               <div className="card-title">Serialized Event Lifecycle</div>
            </div>
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Timestamp Offset</th>
                    <th>Intelligence Event Type</th>
                    <th>Metadata Payload</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((e, idx) => {
                    let data = {};
                    try { data = JSON.parse(e.data); } catch (err) {}
                    const isError = e.event_type.includes('error') || e.event_type.includes('block') || e.event_type.includes('violation');
                    
                    return (
                      <tr key={idx}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-tertiary)' }}>
                          {new Date(e.timestamp).toLocaleTimeString()}
                        </td>
                        <td>
                          <span className={`badge ${isError ? 'badge-danger' : 'badge-info'}`}>
                            {e.event_type.toUpperCase()}
                          </span>
                        </td>
                        <td style={{ maxWidth: '400px' }}>
                          <div style={{ 
                            fontFamily: 'var(--font-mono)', 
                            fontSize: '11px', 
                            color: isError ? 'var(--danger)' : 'var(--text-secondary)',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap'
                          }}>
                            {JSON.stringify(data)}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
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
