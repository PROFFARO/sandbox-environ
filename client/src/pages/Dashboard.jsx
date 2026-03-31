import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getStats, getExecutions } from '../utils/api';
import { 
  Activity, 
  FileCode, 
  ShieldCheck, 
  XCircle, 
  Clock, 
  TrendingUp,
  BarChart3,
  ExternalLink,
  Search,
  Cpu,
  Database
} from 'lucide-react';

export default function Dashboard() {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [recent, setRecent] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        const [statsData, recentData] = await Promise.all([
          getStats(),
          getExecutions({ limit: 10 })
        ]);
        setStats(statsData);
        setRecent(recentData.executions || []);
      } catch (err) {
        console.error('Failed to load dashboard data:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
      <div className="terminal-content">Initializing dashboard context...</div>
    </div>
  );

  const statCards = [
    { label: 'Total Scans', value: stats?.total, icon: Database, color: 'var(--accent-blue)' },
    { label: 'Clean', value: stats?.safe, icon: ShieldCheck, color: 'var(--safe)' },
    { label: 'Threats Blocked', value: stats?.blocked, icon: XCircle, color: 'var(--danger)' },
    { label: 'Avg Threat Score', value: stats?.avgThreatScore, icon: BarChart3, color: 'var(--warning)' },
  ];

  return (
    <div className="page-content fade-in">
      <div className="header-title" style={{ marginBottom: '24px', display: 'flex', alignItems: 'center', gap: '12px' }}>
        <Activity size={24} color="var(--accent-blue)" />
        System Operational Dashboard
      </div>

      <div className="grid-cols-4" style={{ marginBottom: '32px' }}>
        {statCards.map((stat, idx) => (
          <div key={idx} className="stat-widget">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <stat.icon size={20} color={stat.color} />
              <TrendingUp size={14} color="var(--text-muted)" />
            </div>
            <div className="stat-label">{stat.label}</div>
            <div className="stat-value">{stat.value || 0}</div>
          </div>
        ))}
      </div>

      <div className="grid-cols-2" style={{ marginBottom: '32px' }}>
        {/* Quick Analysis Area */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Zap size={18} color="var(--warning)" />
              Immediate Action Required
            </div>
            <button className="btn btn-secondary" style={{ padding: '4px 8px', fontSize: '11px' }}>
              RE-SCAN ALL
            </button>
          </div>
          <div style={{ padding: '12px 0' }}>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
              The system is currently monitoring <strong>{stats?.total || 0}</strong> active sandbox instances. 
              No integrity violations detected in the past 24 hours.
            </p>
            <button className="btn btn-primary" onClick={() => navigate('/submit')}>
              <Plus size={16} />
              Submit New Sample
            </button>
          </div>
        </div>

        {/* Global Stats */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Cpu size={18} color="var(--accent-blue)" />
              Instance Architecture
            </div>
          </div>
          <div style={{ display: 'flex', gap: '24px', marginTop: '8px' }}>
            {stats?.byLanguage?.map((lang, idx) => (
              <div key={idx}>
                <div className="stat-label">{lang.language}</div>
                <div style={{ fontSize: '18px', fontWeight: 700 }}>{lang.count}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Executions */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Clock size={18} color="var(--text-muted)" />
            Recent Security Analysis Results
          </div>
          <button className="btn btn-outline" onClick={() => navigate('/history')}>
            VIEW FULL LOGS
          </button>
        </div>

        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Language</th>
                <th>Method</th>
                <th>Status</th>
                <th>Threat Score</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {recent.map((exec) => (
                <tr key={exec.id} className="row-clickable" onClick={() => navigate(`/report/${exec.id}`)}>
                  <td style={{ color: 'var(--text-tertiary)', fontSize: '12px' }}>
                    {new Date(exec.created_at).toLocaleString()}
                  </td>
                  <td>
                    <span className="badge badge-info">{exec.language}</span>
                  </td>
                  <td style={{ textTransform: 'capitalize' }}>
                    {exec.input_method.replace('_', ' ')}
                  </td>
                  <td>
                    <span className={`badge ${
                      exec.status === 'completed' ? 'badge-safe' : 
                      exec.status === 'blocked' ? 'badge-danger' : 
                      'badge-warning'
                    }`}>
                      {exec.status}
                    </span>
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
                        {exec.threat_score}/100
                      </span>
                    </div>
                  </td>
                  <td>
                    <button className="btn btn-ghost" style={{ padding: '4px' }}>
                      <ExternalLink size={14} />
                    </button>
                  </td>
                </tr>
              ))}
              {recent.length === 0 && (
                <tr>
                  <td colSpan="6" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                    No execution data available.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// Helper icons missing in imports
function Zap(props) { return <Activity {...props} />; }
function Plus(props) { return <span style={{ fontSize: '18px', fontWeight: 'bold' }}>+</span>; }
