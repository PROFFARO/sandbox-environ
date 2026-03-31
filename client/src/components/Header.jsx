import { ShieldCheck, Cpu, Terminal, Activity } from 'lucide-react';

export default function Header() {
  return (
    <header className="header">
      <div className="header-title">
        Controlled Execution Environment
      </div>
      
      <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--safe)', fontSize: '12px', fontWeight: 600 }}>
          <Activity size={16} />
          <span>SYSTEM ONLINE</span>
          <div style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--safe)', boxShadow: '0 0 8px var(--safe)' }} />
        </div>
        
        <div style={{ width: '1px', height: '24px', backgroundColor: 'var(--border-subtle)' }} />
        
        <div style={{ display: 'flex', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-secondary)', fontSize: '12px' }}>
            <Cpu size={14} className="lucide-icon" />
            <span>Worker: Node_P1</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-secondary)', fontSize: '12px' }}>
            <Terminal size={14} className="lucide-icon" />
            <span>Sandbox: v2.4</span>
          </div>
        </div>
      </div>
    </header>
  );
}
