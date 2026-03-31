import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getExecutions, deleteExecution } from '../utils/api';
import { 
  History as HistoryIcon, 
  Search, 
  Filter, 
  Trash2, 
  ExternalLink, 
  Calendar, 
  ChevronLeft, 
  ChevronRight,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle
} from 'lucide-react';

export default function History() {
  const navigate = useNavigate();
  const [executions, setExecutions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [limit] = useState(25);
  const [search, setSearch] = useState('');
  const [language, setLanguage] = useState('');
  const [verdict, setVerdict] = useState('');
  const [deleteId, setDeleteId] = useState(null);

  useEffect(() => {
    loadExecutions();
  }, [page, language, verdict]);

  async function loadExecutions() {
    setLoading(true);
    try {
      const data = await getExecutions({
        limit,
        offset: page * limit,
        language: language || undefined,
        verdict: verdict || undefined,
        search: search || undefined,
      });
      setExecutions(data.executions || []);
      setTotal(data.total || 0);
    } catch (err) {
      console.error('Failed to load history:', err);
    } finally {
      setLoading(false);
    }
  }

  const requestDelete = (id, e) => {
    e.stopPropagation();
    setDeleteId(id);
  };

  const confirmDelete = async () => {
    try {
      await deleteExecution(deleteId);
      loadExecutions();
      setDeleteId(null);
    } catch (err) {
      alert('Action Failed: ' + err.message);
    }
  };

  const totalPages = Math.ceil(total / limit);

  return (
    <div className="page-content fade-in">
      <div className="header-title" style={{ marginBottom: '24px', display: 'flex', alignItems: 'center', gap: '12px' }}>
        <HistoryIcon size={24} color="var(--accent-blue)" />
        Historical Analysis Registry
      </div>

      <div className="card" style={{ marginBottom: '24px', padding: '16px' }}>
        <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: '300px', position: 'relative' }}>
            <Search size={16} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            <input 
              type="text" 
              className="input" 
              style={{ paddingLeft: '40px' }} 
              placeholder="SEARCH_REGISTRY: Filename, ID, or Source Snippet..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && loadExecutions()}
            />
          </div>

          <div style={{ display: 'flex', gap: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Filter size={14} color="var(--text-muted)" />
              <select className="input" style={{ width: '140px', padding: '8px' }} value={language} onChange={(e) => setLanguage(e.target.value)}>
                <option value="">ALL_LANGS</option>
                <option value="python">PYTHON</option>
                <option value="javascript">NODE.JS</option>
                <option value="bash">BASH</option>
                <option value="c">C (GCC)</option>
                <option value="cpp">C++ (G++)</option>
                <option value="php">PHP 8.X</option>
                <option value="powershell">POWERSHELL</option>
              </select>
            </div>

            <select className="input" style={{ width: '140px', padding: '8px' }} value={verdict} onChange={(e) => setVerdict(e.target.value)}>
              <option value="">ALL_VERDICTS</option>
              <option value="safe">CLEAN/SAFE</option>
              <option value="blocked">MALICIOUS</option>
              <option value="suspicious">SUSPICIOUS</option>
            </select>

            <button className="btn btn-primary" onClick={loadExecutions}>
              APPLY_FILTERS
            </button>
          </div>
        </div>
      </div>

      <div className="card" style={{ padding: 0 }}>
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Artifact Instance</th>
                <th>Environment</th>
                <th>Forensic Verdict</th>
                <th>Threat Score</th>
                <th>Execution Time</th>
                <th>Registry Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="6" style={{ textAlign: 'center', padding: '100px' }}>
                     <div className="loading-spinner loading-spinner-sm" style={{ margin: '0 auto 16px' }} />
                     <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>SYNCHRONIZING_WITH_REGISTRY...</div>
                  </td>
                </tr>
              ) : executions.map((exec) => (
                <tr key={exec.id} className="row-clickable" onClick={() => navigate(`/report/${exec.id}`)}>
                  <td>
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{exec.filename || 'Source_Artifact'}</div>
                    <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{exec.id.substring(0, 18)}...</div>
                  </td>
                  <td>
                    <span className="badge badge-info">{exec.language.toUpperCase()}</span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      {exec.verdict === 'safe' ? <ShieldCheck size={14} color="var(--safe)" /> : 
                       exec.verdict === 'blocked' ? <ShieldAlert size={14} color="var(--danger)" /> : 
                       <AlertTriangle size={14} color="var(--warning)" />}
                      <span className={`badge ${
                        exec.verdict === 'safe' ? 'badge-safe' : 
                        exec.verdict === 'blocked' ? 'badge-danger' : 
                        'badge-warning'
                      }`}>
                        {exec.verdict?.toUpperCase() || 'UNKNOWN'}
                      </span>
                    </div>
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <div style={{ 
                        width: '40px', 
                        height: '4px', 
                        backgroundColor: 'var(--bg-secondary)',
                        borderRadius: '2px',
                        overflow: 'hidden'
                      }}>
                        <div style={{ 
                          width: `${exec.threat_score}%`, 
                          height: '100%', 
                          backgroundColor: exec.threat_score >= 70 ? 'var(--danger)' : exec.threat_score >= 30 ? 'var(--warning)' : 'var(--safe)'
                        }} />
                      </div>
                      <span style={{ fontWeight: 700, color: exec.threat_score >= 70 ? 'var(--danger)' : 'var(--text-primary)' }}>
                        {exec.threat_score}
                      </span>
                    </div>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-tertiary)' }}>
                    {exec.execution_time_ms}ms
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <button className="btn btn-ghost" style={{ padding: '4px' }} title="View Intelligence Report">
                        <ExternalLink size={16} />
                      </button>
                      <button className="btn btn-ghost" style={{ padding: '4px', color: 'var(--danger)' }} onClick={(e) => requestDelete(exec.id, e)} title="Purge Record">
                        <Trash2 size={16} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {!loading && executions.length === 0 && (
                <tr>
                  <td colSpan="6" style={{ textAlign: 'center', padding: '60px', color: 'var(--text-muted)' }}>
                    Zero artifacts found matching current filter context.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {total > limit && (
          <div style={{ padding: '16px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: 'var(--border-subtle)' }}>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Showing {page * limit + 1} to {Math.min((page + 1) * limit, total)} of {total} records
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button 
                className="btn btn-secondary" 
                style={{ padding: '6px 12px' }}
                disabled={page === 0} 
                onClick={() => setPage(page - 1)}
              >
                <ChevronLeft size={16} />
                PREVIOUS_BATCH
              </button>
              <button 
                className="btn btn-secondary" 
                style={{ padding: '6px 12px' }}
                disabled={page >= totalPages - 1} 
                onClick={() => setPage(page + 1)}
              >
                NEXT_BATCH
                <ChevronRight size={16} />
              </button>
            </div>
          </div>
        )}
      </div>

      <div style={{ marginTop: '32px', display: 'flex', gap: '12px', alignItems: 'center', color: 'var(--text-muted)', fontSize: '11px' }}>
        <Calendar size={14} />
        <span>Registry data persists locally on this node unless purged manually.</span>
      </div>

      {/* Purge Confirmation Modal */}
      {deleteId && (
        <div className="modal-overlay" onClick={() => setDeleteId(null)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div 
                style={{ 
                  width: '32px', 
                  height: '32px', 
                  borderRadius: '50%', 
                  backgroundColor: 'var(--danger-soft)', 
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'center',
                  color: 'var(--danger)'
                }}
              >
                <ShieldAlert size={20} />
              </div>
              <div className="modal-title" style={{ color: 'var(--danger)' }}>CRITICAL_ACTION_REQUIRED</div>
            </div>
            <div className="modal-content">
               <div style={{ color: 'var(--text-primary)', fontWeight: 700, marginBottom: '8px' }}>Confirm Permanent Purge</div>
               <div style={{ color: 'var(--text-secondary)', fontSize: '13px', lineHeight: 1.6 }}>
                  You are about to permanently remove this forensic artifact and all associated telemetries from the historical registry.
                  <div style={{ marginTop: '12px', fontWeight: 600, color: 'var(--text-muted)' }}>
                    Artifact Sequence: <span style={{ color: 'var(--accent-blue)', fontFamily: 'var(--font-mono)' }}>{deleteId.substring(0, 12)}...</span>
                  </div>
               </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setDeleteId(null)}>
                ABORT_PURGE
              </button>
              <button className="btn btn-primary" style={{ backgroundColor: 'var(--danger)' }} onClick={confirmDelete}>
                CONFIRM_PURGE
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
