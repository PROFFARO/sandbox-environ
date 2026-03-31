import { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { executeCode, executeFile, executeFromUrl, executeFromGist } from '../utils/api';
import { 
  Code, 
  Upload, 
  Link as LinkIcon, 
  Github, 
  Settings, 
  Play, 
  AlertCircle,
  FileCode,
  Terminal,
  Shield
} from 'lucide-react';

export default function Submit() {
  const navigate = useNavigate();
  const [method, setMethod] = useState('paste');
  const [code, setCode] = useState('');
  const [language, setLanguage] = useState('python');
  const [url, setUrl] = useState('');
  const [gistUrl, setGistUrl] = useState('');
  const [file, setFile] = useState(null);
  const [timeout, setTimeoutVal] = useState(10000);
  const [memoryLimit, setMemoryLimit] = useState(128);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const fileInputRef = useRef(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      let result;
      if (method === 'paste') {
        result = await executeCode(code, language, { timeout, memoryLimit });
      } else if (method === 'upload') {
        if (!file) throw new Error('Please select a file');
        const formData = new FormData();
        formData.append('file', file);
        formData.append('language', language);
        formData.append('timeout', timeout);
        formData.append('memoryLimit', memoryLimit);
        result = await executeFile(formData);
      } else if (method === 'url') {
        result = await executeFromUrl(url, language, { timeout, memoryLimit });
      } else if (method === 'gist') {
        result = await executeFromGist(gistUrl, language, { timeout, memoryLimit });
      }

      if (result && result.id) {
        navigate(`/report/${result.id}`);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const inputMethods = [
    { id: 'paste', label: 'Paste Code', icon: Code },
    { id: 'upload', label: 'File Upload', icon: Upload },
    { id: 'url', label: 'Remote URL', icon: LinkIcon },
    { id: 'gist', label: 'GitHub Gist', icon: Github },
  ];

  return (
    <div className="page-content fade-in">
      <div className="header-title" style={{ marginBottom: '24px', display: 'flex', alignItems: 'center', gap: '12px' }}>
        <Terminal size={24} color="var(--accent-blue)" />
        Sample Submission Protocol
      </div>

      <div className="grid-cols-3" style={{ gridTemplateColumns: '2fr 1fr' }}>
        {/* Main Input Area */}
        <div className="card" style={{ padding: '0' }}>
          <div className="tabs" style={{ display: 'flex', borderBottom: 'var(--border-subtle)' }}>
            {inputMethods.map((m) => (
              <button
                key={m.id}
                onClick={() => setMethod(m.id)}
                className={`tab ${method === m.id ? 'active' : ''}`}
                style={{ 
                  flex: 1, 
                  padding: '12px', 
                  border: 'none', 
                  backgroundColor: 'transparent',
                  color: method === m.id ? 'var(--accent-blue)' : 'var(--text-muted)',
                  fontSize: '13px',
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px',
                  cursor: 'pointer',
                  borderBottom: method === m.id ? '2px solid var(--accent-blue)' : 'none'
                }}
              >
                <m.icon size={16} />
                {m.label}
              </button>
            ))}
          </div>

          <div style={{ padding: '24px' }}>
            {error && (
              <div style={{ 
                backgroundColor: 'var(--danger-soft)', 
                color: 'var(--danger)', 
                padding: '12px', 
                borderRadius: '6px',
                marginBottom: '20px',
                fontSize: '13px',
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                border: '1px solid var(--danger)'
              }}>
                <AlertCircle size={18} />
                {error}
              </div>
            )}

            {method === 'paste' && (
              <textarea
                className="input"
                style={{ 
                  fontFamily: 'var(--font-mono)', 
                  height: '400px', 
                  fontSize: '13px',
                  resize: 'none',
                  backgroundColor: '#0d1117'
                }}
                placeholder="PROMPT: Input raw source code artifacts for sandboxed analysis..."
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
            )}

            {method === 'upload' && (
              <div 
                onClick={() => fileInputRef.current.click()}
                style={{
                  border: '2px dashed var(--border-subtle)',
                  borderRadius: '8px',
                  height: '300px',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '16px',
                  cursor: 'pointer',
                  transition: 'all 0.2s'
                }}
                onMouseOver={(e) => e.currentTarget.style.borderColor = 'var(--accent-blue)'}
                onMouseOut={(e) => e.currentTarget.style.borderColor = 'var(--border-subtle)'}
              >
                <Upload size={48} color="var(--text-muted)" />
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontWeight: 600 }}>{file ? file.name : 'Select malware artifact or script file'}</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                    Supported formats: .py, .js, .sh, .bash, .txt (max 100KB)
                  </div>
                </div>
                <input 
                  type="file" 
                  hidden 
                  ref={fileInputRef} 
                  onChange={(e) => setFile(e.target.files[0])}
                />
                {file && <button className="btn btn-secondary" style={{ marginTop: '16px' }}>Change File</button>}
              </div>
            )}

            {method === 'url' && (
              <div>
                <label className="nav-label" style={{ padding: 0 }}>Remote Resource URL</label>
                <input 
                  className="input" 
                  placeholder="https://raw.githubusercontent.com/.../main.py"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                />
                <p style={{ marginTop: '12px', fontSize: '12px', color: 'var(--text-muted)' }}>
                  The environment will automatically attempt to fetch the raw source content from the URL.
                </p>
              </div>
            )}

            {method === 'gist' && (
              <div>
                <label className="nav-label" style={{ padding: 0 }}>GitHub Gist Reference URL</label>
                <input 
                  className="input" 
                  placeholder="https://gist.github.com/username/gist_id"
                  value={gistUrl}
                  onChange={(e) => setGistUrl(e.target.value)}
                />
                <p style={{ marginTop: '12px', fontSize: '12px', color: 'var(--text-muted)' }}>
                  Gist parsing is enabled. If multiple files are present, the primary entry point will be analyzed.
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Configuration Sidebar */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          <div className="card">
            <div className="card-header">
              <div className="card-title">
                <Settings size={16} />
                Analysis Parameters
              </div>
            </div>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div>
                <label className="nav-label" style={{ padding: 0 }}>Language Environment</label>
                <select 
                  className="input" 
                  value={language}
                  onChange={(e) => setLanguage(e.target.value)}
                  style={{ marginTop: '4px' }}
                >
                  <option value="python">Python 3.x</option>
                  <option value="javascript">Node.js (LTS)</option>
                  <option value="bash">Restricted Bash</option>
                  <option value="c">C (GCC Compiler)</option>
                  <option value="cpp">C++ (G++ Compiler)</option>
                  <option value="php">PHP 8.x</option>
                  <option value="powershell">PowerShell 7.x</option>
                </select>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <label className="nav-label" style={{ padding: 0 }}>Execution Timeout</label>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <input 
                      type="number" 
                      min="1" 
                      max="300" 
                      className="input" 
                      style={{ width: '60px', padding: '4px 8px', fontSize: '12px', textAlign: 'center' }}
                      value={timeout / 1000}
                      onChange={(e) => setTimeoutVal(parseInt(e.target.value || 0) * 1000)}
                    />
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 600 }}>SEC</span>
                  </div>
                </div>
                <input 
                  type="range" 
                  min="1000" 
                  max="300000" 
                  step="1000"
                  className="input"
                  style={{ padding: 0, height: '4px', appearance: 'none', background: 'var(--bg-secondary)', cursor: 'pointer' }}
                  value={timeout}
                  onChange={(e) => setTimeoutVal(parseInt(e.target.value))}
                />
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <label className="nav-label" style={{ padding: 0 }}>Memory Limit</label>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <input 
                      type="number" 
                      min="32" 
                      max="1024" 
                      className="input" 
                      style={{ width: '60px', padding: '4px 8px', fontSize: '12px', textAlign: 'center' }}
                      value={memoryLimit}
                      onChange={(e) => setMemoryLimit(parseInt(e.target.value || 0))}
                    />
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 600 }}>MB</span>
                  </div>
                </div>
                <input 
                  type="range" 
                  min="32" 
                  max="1024" 
                  step="16"
                  className="input"
                  style={{ padding: 0, height: '4px', appearance: 'none', background: 'var(--bg-secondary)', cursor: 'pointer' }}
                  value={memoryLimit}
                  onChange={(e) => setMemoryLimit(parseInt(e.target.value))}
                />
              </div>

              <div style={{ 
                padding: '12px', 
                backgroundColor: 'var(--safe-soft)', 
                borderRadius: '6px',
                border: '1px solid var(--safe)',
                fontSize: '11px',
                color: 'var(--safe)',
                display: 'flex',
                gap: '8px'
              }}>
                <Shield size={14} style={{ flexShrink: 0 }} />
                <span>Sandbox isolation is active for this configuration. Outbound network access restricted.</span>
              </div>
            </div>
          </div>

          <button 
            className="btn btn-primary" 
            style={{ width: '100%', padding: '16px', fontSize: '15px' }}
            disabled={loading || (method === 'paste' && !code) || (method === 'url' && !url) || (method === 'gist' && !gistUrl)}
            onClick={handleSubmit}
          >
            {loading ? (
              <>
                <div className="loading-spinner loading-spinner-sm" />
                <span>ORCHESTRATING...</span>
              </>
            ) : (
              <>
                <Play size={18} fill="currentColor" />
                <span>INITIATE ANALYSIS</span>
              </>
            )
          }
          </button>
        </div>
      </div>
    </div>
  );
}
