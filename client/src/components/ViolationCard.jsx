import { AlertTriangle, ShieldCheck, ShieldAlert, Zap, Search, Activity, Flag } from 'lucide-react';

export default function ViolationCard({ violation }) {
  const severity = (violation.severity || 'info').toLowerCase();
  
  const config = {
    critical: { color: 'var(--critical)', bg: 'rgba(220, 38, 38, 0.1)', icon: ShieldAlert },
    danger: { color: 'var(--danger)', bg: 'var(--danger-soft)', icon: AlertTriangle },
    warning: { color: 'var(--warning)', bg: 'var(--warning-soft)', icon: Zap },
    info: { color: 'var(--accent-blue)', bg: 'var(--accent-blue-soft)', icon: Flag },
    safe: { color: 'var(--safe)', bg: 'var(--safe-soft)', icon: ShieldCheck },
  };

  const { color, bg, icon: Icon } = config[severity] || config.info;

  return (
    <div className="card" style={{ 
      display: 'flex', 
      gap: '16px', 
      marginBottom: '12px', 
      backgroundColor: bg,
      borderLeft: `4px solid ${color}`,
      padding: '16px'
    }}>
      <div style={{ color }}>
        <Icon size={20} />
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div style={{ 
            fontSize: '11px', 
            fontWeight: 700, 
            textTransform: 'uppercase', 
            letterSpacing: '0.05em',
            color: color,
            marginBottom: '4px'
          }}>
            {violation.category || 'Security Flag'}
          </div>
          <span className="badge" style={{ backgroundColor: 'rgba(255,255,255,0.05)', color: 'var(--text-muted)' }}>
            {violation.operation || 'GENERAL'}
          </span>
        </div>
        <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
          {violation.description}
        </div>
        {violation.action_taken && (
          <div style={{ fontSize: '11px', color: 'var(--text-tertiary)', fontFamily: 'var(--font-mono)' }}>
            <span style={{ fontWeight: 700 }}>RESPONSE_ACTION:</span> {violation.action_taken}
          </div>
        )}
      </div>
    </div>
  );
}
