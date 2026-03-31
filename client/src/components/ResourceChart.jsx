import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Activity, Cpu } from 'lucide-react';

export default function ResourceChart({ samples = [] }) {
  if (!samples || samples.length === 0) {
    return (
      <div style={{ 
        display: 'flex', 
        flexDirection: 'column', 
        alignItems: 'center', 
        justifyContent: 'center', 
        padding: '40px', 
        color: 'var(--text-muted)',
        backgroundColor: 'var(--bg-secondary)',
        borderRadius: '8px',
        border: '1px dashed var(--border-subtle)'
      }}>
        <Activity size={32} style={{ marginBottom: '12px', opacity: 0.5 }} />
        <div style={{ fontSize: '14px', fontWeight: 600 }}>No telemetry data captured</div>
        <div style={{ fontSize: '12px' }}>Real-time resource tracking will appear during execution.</div>
      </div>
    );
  }

  const data = samples.map(s => ({
    time: (s.timestamp_ms / 1000).toFixed(1) + 's',
    cpu: Number(s.cpu_percent || 0),
    memory: Number(s.memory_mb || 0),
  }));

  const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload) return null;
    return (
      <div style={{
        backgroundColor: 'var(--bg-card)',
        border: '1px solid var(--border-active)',
        borderRadius: '4px',
        padding: '8px 12px',
        boxShadow: '0 4px 12px rgba(0,0,0,0.5)',
        fontSize: '11px',
      }}>
        <div style={{ color: 'var(--text-muted)', marginBottom: '4px' }}>Time: {label}</div>
        {payload.map((p, i) => (
          <div key={i} style={{ color: p.color, fontWeight: 700 }}>
            {p.name}: {p.value.toFixed(2)}{p.name === 'CPU' ? '%' : ' MB'}
          </div>
        ))}
      </div>
    );
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="grid-cols-2">
        {/* CPU Chart */}
        <div className="card" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <Cpu size={14} color="var(--accent-cyan)" />
            <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>CPU Load / Threading</div>
          </div>
          <ResponsiveContainer width="100%" height={150}>
            <AreaChart data={data}>
              <defs>
                <linearGradient id="cpuGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="var(--accent-cyan)" stopOpacity={0.2}/>
                  <stop offset="95%" stopColor="var(--accent-cyan)" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
              <XAxis dataKey="time" hide />
              <YAxis tick={{ fontSize: 10, fill: '#64748b' }} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="cpu" name="CPU" stroke="var(--accent-cyan)" fill="url(#cpuGrad)" strokeWidth={1.5} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Memory Chart */}
        <div className="card" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <div style={{ width: '14px', height: '14px', borderRadius: '2px', backgroundColor: 'var(--warning)' }} />
            <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Memory Allocation (RSS)</div>
          </div>
          <ResponsiveContainer width="100%" height={150}>
            <AreaChart data={data}>
              <defs>
                <linearGradient id="memGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="var(--warning)" stopOpacity={0.2}/>
                  <stop offset="95%" stopColor="var(--warning)" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
              <XAxis dataKey="time" hide />
              <YAxis tick={{ fontSize: 10, fill: '#64748b' }} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="memory" name="Memory" stroke="var(--warning)" fill="url(#memGrad)" strokeWidth={1.5} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
