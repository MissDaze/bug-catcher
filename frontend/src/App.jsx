import React, { useState, useEffect, useRef, useCallback } from 'react';
import { io } from 'socket.io-client';
import axios from 'axios';

const API = process.env.REACT_APP_API_URL || '';
const SOCKET_URL = process.env.REACT_APP_SOCKET_URL || window.location.origin;

const TOP_PLATFORMS = [
  { name: 'HackerOne', url: 'https://hackerone.com/bug-bounty-programs', icon: '🔒' },
  { name: 'Bugcrowd', url: 'https://bugcrowd.com/programs', icon: '👑' },
  { name: 'Intigriti', url: 'https://app.intigriti.com/programs', icon: '🎯' },
  { name: 'Synack', url: 'https://www.synack.com/red-team/', icon: '⚡' },
  { name: 'YesWeHack', url: 'https://yeswehack.com/programs', icon: '🌐' },
  { name: 'Cobalt', url: 'https://cobalt.io/programs', icon: '💎' },
  { name: 'Open Bug Bounty', url: 'https://www.openbugbounty.org', icon: '🌍' },
  { name: 'Immunefi', url: 'https://immunefi.com/bug-bounty', icon: '🛡️' },
  { name: 'Federacy', url: 'https://www.federacy.com', icon: '🔭' },
  { name: 'Integrity', url: 'https://www.integrity.pt/bugbounty', icon: '🏆' },
];

const SEV_COLORS = { critical: 'sev-critical', high: 'sev-high', medium: 'sev-medium', low: 'sev-low', informational: 'sev-informational' };

function Header({ scanActive }) {
  return (
    <header className="header">
      <div>
        <div className="header-logo glitch">🐛 BUG<span> CATCHER</span></div>
        <div className="header-subtitle">AI-POWERED BUG BOUNTY HUNTING TOOL v2.0</div>
      </div>
      <div className="header-status">
        <div className="status-dot" style={{ background: scanActive ? '#ff8800' : '#00ff41' }}></div>
        <span>{scanActive ? 'SCAN ACTIVE' : 'SYSTEM READY'}</span>
      </div>
    </header>
  );
}

function PlatformsPanel() {
  return (
    <div className="panel mb-16">
      <div className="panel-header">
        <span className="panel-icon">🌐</span>
        <span className="panel-title">Top Bug Bounty Platforms</span>
      </div>
      <div className="platform-grid">
        {TOP_PLATFORMS.map(p => (
          <a key={p.name} href={p.url} target="_blank" rel="noopener noreferrer" className="platform-card">
            <span className="platform-icon">{p.icon}</span>
            <span className="platform-name">{p.name}</span>
            <span className="platform-url">{p.url.replace('https://', '').split('/')[0]}</span>
          </a>
        ))}
      </div>
    </div>
  );
}

function ConsolePanel({ logs, title = 'SCAN CONSOLE' }) {
  const ref = useRef(null);
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, [logs]);
  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-icon">💻</span>
        <span className="panel-title">{title}</span>
        <span style={{ marginLeft: 'auto', fontSize: '11px', color: 'var(--gray)' }}>{logs.length} lines</span>
      </div>
      <div className="console" ref={ref}>
        {logs.length === 0 ? (
          <div className="text-gray">{'>'} Awaiting commands...</div>
        ) : logs.map((log, i) => (
          <div key={i} className={`console-line log-${log.type || 'info'}`}>
            <span className="log-time">[{new Date(log.timestamp || Date.now()).toLocaleTimeString()}]</span>
            {log.msg}
          </div>
        ))}
      </div>
    </div>
  );
}

function ProgressPanel({ percent, step, findingCount, screenshotCount }) {
  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-icon">📡</span>
        <span className="panel-title">Scan Progress</span>
      </div>
      <div className="progress-bar-wrapper"><div className="progress-bar" style={{ width: `${percent}%` }}></div></div>
      <div className="progress-label">{percent}% — {step || 'Initializing...'}</div>
      <div className="stats-bar mt-16">
        <div className="stat-chip"><span className="stat-value text-green">{percent}%</span><span className="stat-label">Progress</span></div>
        <div className="stat-chip"><span className="stat-value text-red">{findingCount}</span><span className="stat-label">Findings</span></div>
        <div className="stat-chip"><span className="stat-value" style={{color:'var(--cyan)'}}>{screenshotCount}</span><span className="stat-label">Screenshots</span></div>
      </div>
    </div>
  );
}

function FindingCard({ finding, onViewScreenshot }) {
  const [expanded, setExpanded] = useState(false);
  const sev = (finding.severity || 'low').toLowerCase();
  return (
    <div className={`finding-card ${sev}`}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', cursor: 'pointer' }} onClick={() => setExpanded(!expanded)}>
        <div className="finding-title">{finding.type || finding.vulnerability_name || 'Unknown Vulnerability'}</div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <span className={`sev-badge ${SEV_COLORS[sev] || 'sev-low'}`}>{sev}</span>
          {finding.cvss_score && <span className="sev-badge" style={{background:'rgba(0,255,65,0.1)',color:'var(--green)',border:'var(--border)'}}>{finding.cvss_score}</span>}
          <span style={{ color: 'var(--gray)', fontSize: 12 }}>{expanded ? '▲' : '▼'}</span>
        </div>
      </div>
      <div className="finding-url">{finding.url || finding.targetUrl}</div>
      {expanded && (
        <div className="mt-8">
          {finding.description && <div className="finding-desc mb-8">{finding.description}</div>}
          {finding.details && <div className="finding-desc mb-8" style={{color:'var(--gray)'}}><strong style={{color:'var(--green)'}}>Details:</strong> {finding.details}</div>}
          {finding.impact && <div className="finding-desc mb-8"><strong style={{color:'var(--orange)'}}>Impact:</strong> {finding.impact}</div>}
          {finding.exploitation_steps?.length > 0 && (
            <div className="mb-8">
              <strong style={{color:'var(--green)'}}>Steps to Reproduce:</strong>
              <ol style={{ paddingLeft: 20, marginTop: 4 }}>
                {finding.exploitation_steps.map((s, i) => <li key={i} className="finding-desc">{s}</li>)}
              </ol>
            </div>
          )}
          {finding.proof_of_concept && (
            <div className="mb-8">
              <strong style={{color:'var(--cyan)'}}>PoC:</strong>
              <div style={{ background: '#050505', padding: 8, borderRadius: 4, marginTop: 4, color: '#00cc33', fontSize: 11 }}>{finding.proof_of_concept}</div>
            </div>
          )}
          {finding.remediation && <div className="finding-desc"><strong style={{color:'var(--yellow)'}}>Remediation:</strong> {finding.remediation}</div>}
        </div>
      )}
    </div>
  );
}

function ScreenshotGallery({ screenshots, onView }) {
  if (!screenshots.length) return <div className="empty-state"><span className="empty-icon">📸</span>No screenshots yet</div>;
  return (
    <div className="screenshot-grid">
      {screenshots.map((s, i) => (
        <div key={i} className="screenshot-thumb" onClick={() => onView(s)}>
          <img src={`${SOCKET_URL}${s.webPath}`} alt={s.label} onError={e => { e.target.style.display='none'; }} />
          <div className="screenshot-label">{s.label || 'Screenshot'}</div>
        </div>
      ))}
    </div>
  );
}

function ScopeSelector({ scope, selected, onToggle, credentials, onCredsChange }) {
  if (!scope?.in_scope?.length) return <div className="empty-state"><span className="empty-icon">🔍</span>No scope URLs extracted yet</div>;
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
        <span style={{ color: 'var(--green)', fontSize: 12 }}>{selected.size} of {scope.in_scope.length} selected</span>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-sm" onClick={() => scope.in_scope.forEach((_, i) => !selected.has(i) && onToggle(i))}>Select All</button>
          <button className="btn btn-sm btn-danger" onClick={() => scope.in_scope.forEach((_, i) => selected.has(i) && onToggle(i))}>Clear</button>
        </div>
      </div>
      {scope.in_scope.map((item, i) => (
        <div key={i} className={`scope-item ${selected.has(i) ? 'selected' : ''}`}>
          <input type="checkbox" checked={selected.has(i)} onChange={() => onToggle(i)} />
          <div style={{ flex: 1 }}>
            <div className="scope-url">{item.url}</div>
            {item.requires_credentials && (
              <div style={{ marginTop: 6, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <input className="input" style={{ width: 160, padding: '4px 8px', fontSize: 11 }}
                  placeholder="Username" value={credentials[i]?.user || ''}
                  onChange={e => onCredsChange(i, 'user', e.target.value)} />
                <input className="input" type="password" style={{ width: 160, padding: '4px 8px', fontSize: 11 }}
                  placeholder="Password" value={credentials[i]?.pass || ''}
                  onChange={e => onCredsChange(i, 'pass', e.target.value)} />
              </div>
            )}
            {item.notes && <div style={{ fontSize: 11, color: 'var(--gray)', marginTop: 3 }}>{item.notes}</div>}
          </div>
          <div style={{ display: 'flex', gap: 4, flexDirection: 'column', alignItems: 'flex-end' }}>
            {item.requires_credentials && <span className="scope-badge badge-creds">🔑 CREDS REQ.</span>}
            <span className={`scope-badge ${item.type === 'web' ? 'badge-web' : 'badge-type'}`}>{item.type?.toUpperCase() || 'WEB'}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function BountyAnalyzer({ onStartScan, logs, setLogs, scanActive }) {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [scope, setScope] = useState(null);
  const [selected, setSelected] = useState(new Set());
  const [credentials, setCredentials] = useState({});
  const [tab, setTab] = useState('scope');

  const analyze = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    setScope(null);
    setSelected(new Set());
    setLogs(prev => [...prev, { msg: `🔍 Analyzing bounty page: ${url}`, type: 'info', timestamp: Date.now() }]);
    try {
      const res = await axios.post(`${API}/api/bounty/analyze`, { url });
      setScope(res.data.data);
      setLogs(prev => [...prev,
        { msg: `✅ Scope extracted: ${res.data.data.program_name || 'Unknown Program'}`, type: 'success', timestamp: Date.now() },
        { msg: `📋 In-scope URLs: ${res.data.data.in_scope?.length || 0}`, type: 'info', timestamp: Date.now() },
        { msg: `📜 Rules: ${res.data.data.rules?.length || 0}`, type: 'info', timestamp: Date.now() },
      ]);
      setTab('scope');
    } catch (err) {
      setLogs(prev => [...prev, { msg: `❌ Error: ${err.response?.data?.message || err.message}`, type: 'error', timestamp: Date.now() }]);
    } finally { setLoading(false); }
  };

  const toggleSelect = useCallback((i) => {
    setSelected(prev => { const n = new Set(prev); n.has(i) ? n.delete(i) : n.add(i); return n; });
  }, []);

  const handleCredsChange = (i, field, val) => {
    setCredentials(prev => ({ ...prev, [i]: { ...prev[i], [field === 'user' ? 'user' : 'pass']: val } }));
  };

  const handleStartScan = () => {
    const urls = [...selected].map(i => ({
      url: scope.in_scope[i].url,
      requiresCredentials: scope.in_scope[i].requires_credentials,
      credentials: credentials[i] || null,
      type: scope.in_scope[i].type
    }));
    onStartScan(urls, scope);
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-icon">🎯</span>
        <span className="panel-title">Bug Bounty Program Analyzer</span>
        <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--gray)' }}>Box 1</span>
      </div>
      <form onSubmit={analyze}>
        <div className="input-group">
          <label className="input-label">Bug Bounty Program URL</label>
          <div style={{ display: 'flex', gap: 8 }}>
            <input className="input" type="url" placeholder="https://hackerone.com/programs/example"
              value={url} onChange={e => setUrl(e.target.value)} required />
            <button className="btn btn-primary" type="submit" disabled={loading} style={{ whiteSpace: 'nowrap' }}>
              {loading ? <><span className="spinner"></span> Analyzing...</> : '🤖 AI Analyze'}
            </button>
          </div>
        </div>
      </form>

      {scope && (
        <div className="mt-16">
          <div style={{ background: 'var(--bg3)', border: 'var(--border)', borderRadius: 4, padding: 12, marginBottom: 14 }}>
            <div style={{ color: 'var(--green)', fontFamily: 'var(--font-title)', fontSize: 13 }}>{scope.program_name || 'Bug Bounty Program'}</div>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 6, fontSize: 11, color: 'var(--gray)' }}>
              {scope.platform && <span>Platform: <span style={{color:'var(--white)'}}>{scope.platform}</span></span>}
              {scope.bounty_range && <span>Bounty: <span style={{color:'var(--green)'}}>{scope.bounty_range}</span></span>}
              {scope.in_scope?.length > 0 && <span>In-Scope: <span style={{color:'var(--cyan)'}}>{scope.in_scope.length} targets</span></span>}
            </div>
          </div>

          <div className="tabs">
            <button className={`tab-btn ${tab === 'scope' ? 'active' : ''}`} onClick={() => setTab('scope')}>📍 In-Scope URLs</button>
            <button className={`tab-btn ${tab === 'rules' ? 'active' : ''}`} onClick={() => setTab('rules')}>📜 Rules</button>
            <button className={`tab-btn ${tab === 'oos' ? 'active' : ''}`} onClick={() => setTab('oos')}>🚫 Out of Scope</button>
          </div>

          {tab === 'scope' && (
            <ScopeSelector scope={scope} selected={selected} onToggle={toggleSelect}
              credentials={credentials} onCredsChange={handleCredsChange} />
          )}
          {tab === 'rules' && (
            <div style={{ color: 'var(--gray)', fontSize: 12 }}>
              {scope.report_format && <div style={{ marginBottom: 12 }}><strong style={{color:'var(--green)'}}>Report Format:</strong> {scope.report_format}</div>}
              {scope.rules?.length > 0 ? scope.rules.map((r, i) => (
                <div key={i} style={{ padding: '6px 0', borderBottom: 'var(--border)' }}>• {r}</div>
              )) : <div className="empty-state">No rules extracted</div>}
            </div>
          )}
          {tab === 'oos' && (
            <div style={{ color: 'var(--gray)', fontSize: 12 }}>
              {scope.out_of_scope?.length > 0 ? scope.out_of_scope.map((o, i) => (
                <div key={i} style={{ padding: '6px 0', borderBottom: 'var(--border)', color: 'var(--red)' }}>🚫 {typeof o === 'string' ? o : o.url || JSON.stringify(o)}</div>
              )) : <div className="empty-state">No out-of-scope items extracted</div>}
            </div>
          )}

          {selected.size > 0 && (
            <button className="btn btn-primary btn-full mt-16" onClick={handleStartScan} disabled={scanActive}>
              {scanActive ? <><span className="spinner"></span> Scan Running...</> : `🚀 Start Scan (${selected.size} targets)`}
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function DirectScanner({ onStartScan, scanActive }) {
  const [url, setUrl] = useState('');
  const handleSubmit = (e) => {
    e.preventDefault();
    if (!url.trim()) return;
    onStartScan([{ url: url.trim(), type: 'web' }], null);
  };
  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-icon">🔬</span>
        <span className="panel-title">Direct URL Scanner</span>
        <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--gray)' }}>Box 2</span>
      </div>
      <p style={{ color: 'var(--gray)', fontSize: 12, marginBottom: 14 }}>Scan any URL directly for vulnerabilities without a bug bounty program.</p>
      <form onSubmit={handleSubmit}>
        <div className="input-group">
          <label className="input-label">Target URL</label>
          <input className="input" type="url" placeholder="https://example.com"
            value={url} onChange={e => setUrl(e.target.value)} required />
        </div>
        <button className="btn btn-primary btn-full" type="submit" disabled={scanActive}>
          {scanActive ? <><span className="spinner"></span> Scan Running...</> : '⚡ Scan Target'}
        </button>
      </form>
      <div style={{ marginTop: 16, padding: 12, background: 'var(--bg3)', borderRadius: 4, border: 'var(--border)' }}>
        <div style={{ color: 'var(--green)', fontSize: 11, marginBottom: 8 }}>Checks performed:</div>
        {['XSS / Injection', 'Security Headers', 'SSL/TLS Config', 'Open Redirect', 'Sensitive Files', 'Cookie Security', 'CORS Misconfiguration'].map(c => (
          <div key={c} style={{ color: 'var(--gray)', fontSize: 11, padding: '3px 0' }}>✓ {c}</div>
        ))}
      </div>
    </div>
  );
}

function ImageModal({ shot, onClose }) {
  if (!shot) return null;
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 1000 }}>
        <div className="modal-header">
          <span style={{ color: 'var(--green)' }}>{shot.label}</span>
          <button className="btn btn-sm btn-danger" onClick={onClose}>✕ Close</button>
        </div>
        <div className="modal-body">
          <img src={`${SOCKET_URL}${shot.webPath}`} alt={shot.label} className="modal-img" />
          <div style={{ color: 'var(--gray)', fontSize: 11, marginTop: 8 }}>{shot.url} — {shot.timestamp}</div>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [logs, setLogs] = useState([]);
  const [scanActive, setScanActive] = useState(false);
  const [scanId, setScanId] = useState(null);
  const [findings, setFindings] = useState([]);
  const [screenshots, setScreenshots] = useState([]);
  const [progress, setProgress] = useState({ percent: 0, step: '' });
  const [programInfo, setProgramInfo] = useState(null);
  const [mainTab, setMainTab] = useState('analyzer');
  const [resultsTab, setResultsTab] = useState('findings');
  const [viewShot, setViewShot] = useState(null);
  const [reportLoading, setReportLoading] = useState(false);
  const socketRef = useRef(null);

  const addLog = useCallback((msg, type = 'info') => {
    setLogs(prev => [...prev.slice(-200), { msg, type, timestamp: Date.now() }]);
  }, []);

  const startScan = useCallback(async (urls, program) => {
    if (scanActive) return;
    setFindings([]);
    setScreenshots([]);
    setProgress({ percent: 0, step: 'Starting...' });
    setScanActive(true);
    setProgramInfo(program);
    setMainTab('scan');
    addLog(`🚀 Initiating scan of ${urls.length} target(s)...`, 'info');
    try {
      const res = await axios.post(`${API}/api/scan/start`, { urls, programInfo: program });
      const id = res.data.scanId;
      setScanId(id);
      addLog(`✅ Scan ID: ${id}`, 'success');
      if (socketRef.current) {
        socketRef.current.emit('join_scan', id);
        addLog('📡 Connected to scan socket', 'info');
      }
    } catch (err) {
      addLog(`❌ Failed to start scan: ${err.response?.data?.message || err.message}`, 'error');
      setScanActive(false);
    }
  }, [scanActive, addLog]);

  const cancelScan = useCallback(async () => {
    if (!scanId) return;
    try {
      await axios.post(`${API}/api/scan/${scanId}/cancel`);
      addLog('🛑 Scan cancellation requested', 'warn');
    } catch (err) { addLog(`Cancel error: ${err.message}`, 'error'); }
  }, [scanId, addLog]);

  const downloadReport = useCallback(async () => {
    if (!scanId || findings.length === 0) return;
    setReportLoading(true);
    addLog('📄 Generating PDF report...', 'ai');
    try {
      const res = await axios.post(`${API}/api/report/generate`, { scanId, programInfo });
      const reportUrl = `${SOCKET_URL}${res.data.data.webPath}`;
      window.open(reportUrl, '_blank');
      addLog(`✅ Report ready: ${res.data.data.filename}`, 'success');
    } catch (err) {
      addLog(`❌ Report error: ${err.response?.data?.message || err.message}`, 'error');
    } finally { setReportLoading(false); }
  }, [scanId, findings, programInfo, addLog]);

  // Socket.io setup
  useEffect(() => {
    const socket = io(SOCKET_URL, { transports: ['websocket', 'polling'] });
    socketRef.current = socket;
    socket.on('connect', () => addLog('🔌 Socket connected', 'success'));
    socket.on('disconnect', () => addLog('🔌 Socket disconnected', 'warn'));
    socket.on('log', (data) => addLog(data.msg, data.type));
    socket.on('progress', (data) => {
      if (data.percent !== undefined) setProgress({ percent: data.percent, step: data.step });
    });
    socket.on('finding', (finding) => {
      setFindings(prev => [...prev, finding]);
      addLog(`🚨 NEW FINDING: ${finding.type} [${finding.severity?.toUpperCase() || 'UNKNOWN'}] at ${finding.url || finding.targetUrl}`, 'alert');
    });
    socket.on('screenshot', (shot) => {
      setScreenshots(prev => [...prev, shot]);
      addLog(`📸 Screenshot captured: ${shot.label}`, 'info');
    });
    socket.on('scan_started', (data) => addLog(`🎯 Scan started — ${data.urlCount} targets queued`, 'success'));
    socket.on('scan_complete', (data) => {
      setScanActive(false);
      setProgress({ percent: 100, step: 'Complete' });
      addLog(`🏁 SCAN COMPLETE — ${data.findingCount} findings, ${data.screenshotCount} screenshots, ${Math.round(data.duration/1000)}s`, 'success');
      setResultsTab('findings');
      setMainTab('results');
    });
    socket.on('scan_error', (data) => {
      setScanActive(false);
      addLog(`❌ Scan error: ${data.message}`, 'error');
    });
    return () => socket.disconnect();
  }, []); // eslint-disable-line

  const sevCount = (sev) => findings.filter(f => (f.severity || 'low').toLowerCase() === sev).length;

  return (
    <div>
      <Header scanActive={scanActive} />
      <div className="app-container">
        <PlatformsPanel />

        {/* Main Tabs */}
        <div className="tabs">
          <button className={`tab-btn ${mainTab === 'analyzer' ? 'active' : ''}`} onClick={() => setMainTab('analyzer')}>🎯 Bounty Analyzer</button>
          <button className={`tab-btn ${mainTab === 'scanner' ? 'active' : ''}`} onClick={() => setMainTab('scanner')}>🔬 Direct Scanner</button>
          <button className={`tab-btn ${mainTab === 'scan' ? 'active' : ''}`} onClick={() => setMainTab('scan')} style={{ display: scanActive ? 'block' : 'none' }}>📡 Live Scan</button>
          <button className={`tab-btn ${mainTab === 'results' ? 'active' : ''}`} onClick={() => setMainTab('results')}>
            📊 Results {findings.length > 0 && <span style={{background:'var(--red)',color:'white',borderRadius:10,padding:'1px 7px',marginLeft:4,fontSize:10}}>{findings.length}</span>}
          </button>
        </div>

        {/* ANALYZER TAB */}
        {mainTab === 'analyzer' && (
          <div className="grid-2">
            <BountyAnalyzer onStartScan={startScan} logs={logs} setLogs={setLogs} scanActive={scanActive} />
            <ConsolePanel logs={logs} title="ANALYSIS LOG" />
          </div>
        )}

        {/* DIRECT SCANNER TAB */}
        {mainTab === 'scanner' && (
          <div className="grid-2">
            <DirectScanner onStartScan={startScan} scanActive={scanActive} />
            <ConsolePanel logs={logs} title="SCAN LOG" />
          </div>
        )}

        {/* LIVE SCAN TAB */}
        {mainTab === 'scan' && (
          <div>
            <div className="grid-2 mb-16">
              <ProgressPanel percent={progress.percent} step={progress.step} findingCount={findings.length} screenshotCount={screenshots.length} />
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {scanActive && (
                  <button className="btn btn-danger btn-full" onClick={cancelScan}>🛑 Cancel Scan</button>
                )}
                <button className="btn btn-full" onClick={() => setMainTab('results')} disabled={findings.length === 0}>
                  📊 View Results ({findings.length})
                </button>
              </div>
            </div>
            <ConsolePanel logs={logs} title="LIVE SCAN CONSOLE" />
          </div>
        )}

        {/* RESULTS TAB */}
        {mainTab === 'results' && (
          <div>
            {findings.length > 0 && (
              <div className="stats-bar mb-16">
                <div className="stat-chip"><span className="stat-value" style={{color:'#cc0000'}}>{sevCount('critical')}</span><span className="stat-label">Critical</span></div>
                <div className="stat-chip"><span className="stat-value text-red">{sevCount('high')}</span><span className="stat-label">High</span></div>
                <div className="stat-chip"><span className="stat-value" style={{color:'var(--orange)'}}>{sevCount('medium')}</span><span className="stat-label">Medium</span></div>
                <div className="stat-chip"><span className="stat-value text-yellow">{sevCount('low')}</span><span className="stat-label">Low</span></div>
                <div className="stat-chip"><span className="stat-value text-gray">{sevCount('informational')}</span><span className="stat-label">Info</span></div>
                <div style={{ marginLeft: 'auto' }}>
                  <button className="btn btn-primary" onClick={downloadReport} disabled={reportLoading || findings.length === 0}>
                    {reportLoading ? <><span className="spinner"></span> Generating...</> : '📄 Download PDF Report'}
                  </button>
                </div>
              </div>
            )}
            <div className="tabs">
              <button className={`tab-btn ${resultsTab === 'findings' ? 'active' : ''}`} onClick={() => setResultsTab('findings')}>🚨 Findings ({findings.length})</button>
              <button className={`tab-btn ${resultsTab === 'screenshots' ? 'active' : ''}`} onClick={() => setResultsTab('screenshots')}>📸 Screenshots ({screenshots.length})</button>
              <button className={`tab-btn ${resultsTab === 'console' ? 'active' : ''}`} onClick={() => setResultsTab('console')}>💻 Console</button>
            </div>
            {resultsTab === 'findings' && (
              findings.length === 0
                ? <div className="empty-state"><span className="empty-icon">🛡️</span>No findings yet — run a scan first</div>
                : findings.sort((a,b) => {
                    const order = { critical:0, high:1, medium:2, low:3, informational:4 };
                    return (order[a.severity?.toLowerCase()] ?? 3) - (order[b.severity?.toLowerCase()] ?? 3);
                  }).map(f => <FindingCard key={f.id} finding={f} onViewScreenshot={setViewShot} />)
            )}
            {resultsTab === 'screenshots' && <ScreenshotGallery screenshots={screenshots} onView={setViewShot} />}
            {resultsTab === 'console' && <ConsolePanel logs={logs} />}
          </div>
        )}
      </div>
      <ImageModal shot={viewShot} onClose={() => setViewShot(null)} />
      <footer style={{ textAlign: 'center', padding: '20px', color: 'var(--gray)', fontSize: 11, borderTop: 'var(--border)', marginTop: 40 }}>
        🐛 Bug Catcher v2.0 — AI-Powered Bug Bounty Tool — Built with ❤️ by MissDaze
      </footer>
    </div>
  );
}
