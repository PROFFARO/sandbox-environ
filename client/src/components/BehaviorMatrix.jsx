import { Activity, LayoutGrid } from 'lucide-react';

const CATEGORY_INFO = {
  EXECUTION: { name: 'Execution', description: 'Dynamic code execution or shell spawning' },
  PERSISTENCE: { name: 'Persistence', description: 'Attempts to maintain access' },
  PRIVILEGE_ESCALATION: { name: 'Privilege Escalation', description: 'Gaining higher privileges' },
  DEFENSE_EVASION: { name: 'Defense Evasion', description: 'Techniques to avoid detection' },
  CREDENTIAL_ACCESS: { name: 'Credential Access', description: 'Stealing credentials or keys' },
  DISCOVERY: { name: 'Discovery', description: 'System enumeration' },
  LATERAL_MOVEMENT: { name: 'Lateral Movement', description: 'Moving across systems' },
  COLLECTION: { name: 'Collection', description: 'Gathering data' },
  EXFILTRATION: { name: 'Exfiltration', description: 'Data theft' },
  IMPACT: { name: 'Impact', description: 'Destructive operations' },
  RESOURCE_ABUSE: { name: 'Resource Abuse', description: 'Excessive consumption' },
  COMMAND_AND_CONTROL: { name: 'Command & Control', description: 'Remote communication' },
};

export default function BehaviorMatrix({ categories = [], categoryScores = {} }) {
  const allCategories = Object.keys(CATEGORY_INFO);

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
      gap: '12px'
    }}>
      {allCategories.map(cat => {
        const info = CATEGORY_INFO[cat];
        const score = categoryScores[cat] || 0;
        const detected = Array.isArray(categories) ? categories.find(c => c.category === cat) : null;
        const isActive = score > 0;

        return (
          <div key={cat} style={{
            padding: '12px',
            borderRadius: '6px',
            backgroundColor: isActive ? 'rgba(59, 130, 246, 0.05)' : 'var(--bg-secondary)',
            border: isActive ? '1px solid var(--accent-blue)' : '1px solid var(--border-subtle)',
            opacity: isActive ? 1 : 0.6,
            transition: 'all 0.2s'
          }}>
            <div style={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: '8px', 
              marginBottom: '6px'
            }}>
              <Activity size={14} color={isActive ? 'var(--accent-blue)' : 'var(--text-muted)'} />
              <div style={{ fontSize: '12px', fontWeight: 700, color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
                {info.name}
              </div>
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)', lineHeight: 1.4 }}>
              {isActive ? (
                <div style={{ color: score > 50 ? 'var(--danger)' : score > 20 ? 'var(--warning)' : 'var(--accent-blue)', fontWeight: 600 }}>
                  DETECTED (Score: {score})
                </div>
              ) : (
                'No activity'
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
