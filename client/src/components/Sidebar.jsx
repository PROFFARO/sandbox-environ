import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  ShieldAlert, 
  History, 
  ShieldCheck, 
  FileText, 
  Terminal,
  Zap
} from 'lucide-react';

export default function Sidebar() {
  const navGroups = [
    {
      label: 'Main',
      items: [
        { path: '/', label: 'Dashboard', icon: LayoutDashboard },
        { path: '/submit', label: 'Submit Code', icon: Zap },
        { path: '/history', label: 'Execution History', icon: History },
      ]
    },
    {
      label: 'Security',
      items: [
        { path: '/policies', label: 'Security Policies', icon: ShieldCheck },
      ]
    }
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <ShieldAlert className="sidebar-logo-icon" />
        <span>SandboxGuard</span>
      </div>

      <nav className="sidebar-nav">
        {navGroups.map((group, idx) => (
          <div key={idx} className="nav-group">
            <div className="nav-label">{group.label}</div>
            {group.items.map((item) => (
              <NavLink 
                key={item.path} 
                to={item.path} 
                className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
              >
                <item.icon className="nav-icon" />
                <span>{item.label}</span>
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      <div style={{ padding: '20px', borderTop: 'var(--border-subtle)' }}>
        <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 500 }}>
          v1.2.0-enterprise
        </div>
      </div>
    </aside>
  );
}
