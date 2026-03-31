import { ShieldCheck, AlertTriangle, XCircle, ShieldAlert } from 'lucide-react';

export default function ThreatScoreGauge({ score, verdict, size = 150 }) {
  const isSafe = verdict === 'safe' || score < 10;
  const isMalicious = verdict === 'blocked' || score >= 70;
  const isSuspicious = !isSafe && !isMalicious;

  const color = isSafe ? 'var(--safe)' : isMalicious ? 'var(--danger)' : 'var(--warning)';
  const bgColor = isSafe ? 'var(--safe-soft)' : isMalicious ? 'var(--danger-soft)' : 'var(--warning-soft)';
  const Icon = isSafe ? ShieldCheck : isMalicious ? XCircle : AlertTriangle;

  const strokeWidth = 10;
  const radius = (size / 2) - strokeWidth;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div style={{ 
      display: 'flex', 
      flexDirection: 'column', 
      alignItems: 'center', 
      gap: '12px',
      position: 'relative'
    }}>
      <div style={{ position: 'relative', width: size, height: size }}>
        {/* Background Circle */}
        <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="var(--bg-secondary)"
            strokeWidth={strokeWidth}
          />
          {/* Progress Circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 0.8s ease-out' }}
          />
        </svg>

        {/* Center Content */}
        <div style={{
          position: 'absolute',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center'
        }}>
          <div style={{ 
            fontSize: size * 0.22, 
            fontWeight: 800, 
            lineHeight: 1,
            color: color
          }}>
            {score}
          </div>
          <div style={{ 
            fontSize: '10px', 
            fontWeight: 700, 
            color: 'var(--text-muted)',
            textTransform: 'uppercase',
            letterSpacing: '1px',
            marginTop: '2px'
          }}>
            Score
          </div>
        </div>
      </div>

      {/* Verdict Label */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '6px',
        padding: '6px 12px',
        borderRadius: '4px',
        backgroundColor: bgColor,
        border: `1px solid ${color}`,
        color: color,
        fontSize: '11px',
        fontWeight: 700,
        textTransform: 'uppercase',
        letterSpacing: '0.05em'
      }}>
        <Icon size={14} />
        <span>{verdict || 'PENDING ANALYSIS'}</span>
      </div>
    </div>
  );
}
