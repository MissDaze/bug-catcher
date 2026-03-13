const axios = require('axios');
const { fetchPageContent, extractLinks, checkUrl } = require('./scraper.service');
const { takeScreenshot } = require('./screenshot.service');
const { analyzeVulnerability } = require('./ai.service');
const { v4: uuidv4 } = require('uuid');

// Active scans store
const activeScans = new Map();

function emit(io, scanId, event, data) {
  io.to(scanId).emit(event, { ...data, timestamp: new Date().toISOString() });
}

// Vulnerability check modules
const CHECKS = {
  async xss(url, io, scanId) {
    const payloads = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "'\'><svg/onload=alert(1)>"];
    const findings = [];
    emit(io, scanId, 'progress', { step: 'XSS Testing', url, status: 'running' });
    try {
      const { html } = await fetchPageContent(url);
      for (const payload of payloads) {
        if (html.includes(payload.replace(/</g, '&lt;').replace(/>/g, '&gt;')) || html.includes(payload)) {
          findings.push({ type: 'XSS', payload, url, details: 'Reflected XSS payload found in response' });
        }
      }
      // Check for forms without CSRF
      if (html.includes('<form') && !html.includes('csrf') && !html.includes('_token')) {
        findings.push({ type: 'Missing CSRF', url, details: 'Form found without CSRF protection' });
      }
    } catch (e) { emit(io, scanId, 'log', { msg: `XSS check error: ${e.message}`, type: 'warn' }); }
    return findings;
  },

  async headers(url, io, scanId) {
    const findings = [];
    emit(io, scanId, 'progress', { step: 'Security Headers Check', url, status: 'running' });
    try {
      const res = await axios.get(url, { timeout: 15000, validateStatus: () => true,
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; BugCatcher/2.0)' } });
      const h = res.headers;
      const missing = [];
      if (!h['strict-transport-security']) missing.push('Strict-Transport-Security');
      if (!h['x-content-type-options']) missing.push('X-Content-Type-Options');
      if (!h['x-frame-options'] && !h['content-security-policy']) missing.push('X-Frame-Options / CSP');
      if (!h['content-security-policy']) missing.push('Content-Security-Policy');
      if (!h['referrer-policy']) missing.push('Referrer-Policy');
      if (!h['permissions-policy']) missing.push('Permissions-Policy');
      if (missing.length > 0) {
        findings.push({ type: 'Missing Security Headers', url, details: `Missing: ${missing.join(', ')}`, headers: h, missing });
      }
      // Check for sensitive headers
      if (h['server']) findings.push({ type: 'Server Version Disclosure', url, details: `Server: ${h['server']}`, severity: 'low' });
      if (h['x-powered-by']) findings.push({ type: 'Technology Disclosure', url, details: `X-Powered-By: ${h['x-powered-by']}`, severity: 'low' });
    } catch (e) { emit(io, scanId, 'log', { msg: `Headers check error: ${e.message}`, type: 'warn' }); }
    return findings;
  },

  async ssl(url, io, scanId) {
    const findings = [];
    emit(io, scanId, 'progress', { step: 'SSL/TLS Check', url, status: 'running' });
    try {
      if (url.startsWith('http://')) {
        findings.push({ type: 'HTTP Not HTTPS', url, details: 'Site not using HTTPS - data transmitted in plaintext', severity: 'high' });
      }
      const httpsUrl = url.replace('http://', 'https://');
      try {
        await axios.get(httpsUrl, { timeout: 10000, validateStatus: () => true });
      } catch (e) {
        if (e.code === 'CERT_HAS_EXPIRED') findings.push({ type: 'Expired SSL Certificate', url, details: 'SSL certificate has expired', severity: 'high' });
        if (e.code === 'DEPTH_ZERO_SELF_SIGNED_CERT') findings.push({ type: 'Self-Signed Certificate', url, details: 'Self-signed SSL certificate detected', severity: 'medium' });
      }
    } catch (e) { emit(io, scanId, 'log', { msg: `SSL check error: ${e.message}`, type: 'warn' }); }
    return findings;
  },

  async openRedirect(url, io, scanId) {
    const findings = [];
    emit(io, scanId, 'progress', { step: 'Open Redirect Check', url, status: 'running' });
    try {
      const parsed = new URL(url);
      const redirectParams = ['redirect', 'url', 'next', 'return', 'returnUrl', 'redirect_uri', 'goto', 'dest'];
      for (const param of redirectParams) {
        if (parsed.searchParams.has(param)) {
          const testUrl = new URL(url);
          testUrl.searchParams.set(param, 'https://evil.com');
          try {
            const res = await axios.get(testUrl.toString(), { maxRedirects: 0, validateStatus: () => true, timeout: 10000 });
            if (res.status >= 300 && res.status < 400) {
              const loc = res.headers['location'] || '';
              if (loc.includes('evil.com')) {
                findings.push({ type: 'Open Redirect', url: testUrl.toString(), details: `Parameter '${param}' allows open redirect to arbitrary URL`, severity: 'medium' });
              }
            }
          } catch {}
        }
      }
    } catch (e) { emit(io, scanId, 'log', { msg: `Open redirect check error: ${e.message}`, type: 'warn' }); }
    return findings;
  },

  async sensitiveFiles(url, io, scanId) {
    const findings = [];
    emit(io, scanId, 'progress', { step: 'Sensitive Files Check', url, status: 'running' });
    const paths = ['.git/config','.env','config.php','wp-config.php','phpinfo.php',
      'robots.txt','sitemap.xml','.htaccess','backup.zip','db.sql',
      'admin','administrator','.DS_Store','package.json','composer.json'];
    const base = new URL(url).origin;
    for (const p of paths) {
      try {
        const res = await axios.get(`${base}/${p}`, { timeout: 8000, validateStatus: () => true,
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; BugCatcher/2.0)' } });
        if (res.status === 200) {
          const severity = ['.env','.git/config','db.sql','backup.zip'].includes(p) ? 'critical' : 'medium';
          findings.push({ type: 'Sensitive File Exposed', url: `${base}/${p}`, details: `Accessible sensitive path: /${p} (HTTP ${res.status})`, severity, path: p });
        }
      } catch {}
    }
    return findings;
  },

  async cookies(url, io, scanId) {
    const findings = [];
    emit(io, scanId, 'progress', { step: 'Cookie Security Check', url, status: 'running' });
    try {
      const res = await axios.get(url, { timeout: 15000, validateStatus: () => true,
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; BugCatcher/2.0)' } });
      const cookies = res.headers['set-cookie'] || [];
      for (const cookie of cookies) {
        const issues = [];
        if (!cookie.toLowerCase().includes('httponly')) issues.push('Missing HttpOnly flag');
        if (!cookie.toLowerCase().includes('secure')) issues.push('Missing Secure flag');
        if (!cookie.toLowerCase().includes('samesite')) issues.push('Missing SameSite attribute');
        if (issues.length > 0) {
          findings.push({ type: 'Insecure Cookie', url, details: issues.join(', '), cookie: cookie.split(';')[0], severity: 'medium' });
        }
      }
    } catch (e) { emit(io, scanId, 'log', { msg: `Cookie check error: ${e.message}`, type: 'warn' }); }
    return findings;
  },

  async cors(url, io, scanId) {
    const findings = [];
    emit(io, scanId, 'progress', { step: 'CORS Misconfiguration Check', url, status: 'running' });
    try {
      const res = await axios.get(url, { timeout: 15000, validateStatus: () => true,
        headers: { 'Origin': 'https://evil.com', 'User-Agent': 'Mozilla/5.0 (compatible; BugCatcher/2.0)' } });
      const acao = res.headers['access-control-allow-origin'];
      const acac = res.headers['access-control-allow-credentials'];
      if (acao === '*') {
        findings.push({ type: 'CORS Wildcard', url, details: 'Access-Control-Allow-Origin: * allows any origin', severity: 'medium' });
      } else if (acao === 'https://evil.com') {
        findings.push({ type: 'CORS Misconfiguration', url, details: 'Server reflects arbitrary Origin in ACAO header', severity: acac === 'true' ? 'high' : 'medium' });
      }
    } catch (e) { emit(io, scanId, 'log', { msg: `CORS check error: ${e.message}`, type: 'warn' }); }
    return findings;
  }
};

async function runScan(io, scanId, urls, options = {}) {
  const scan = { id: scanId, status: 'running', startTime: new Date(), findings: [], screenshots: [], urls };
  activeScans.set(scanId, scan);

  emit(io, scanId, 'scan_started', { scanId, urlCount: urls.length });

  for (let i = 0; i < urls.length; i++) {
    const target = urls[i];
    if (scan.status === 'cancelled') break;

    emit(io, scanId, 'progress', { step: `Scanning target ${i+1}/${urls.length}`, url: target.url, status: 'starting', percent: Math.round((i/urls.length)*100) });
    emit(io, scanId, 'log', { msg: `🎯 Starting scan of: ${target.url}`, type: 'info' });

    // Check URL alive
    const alive = await checkUrl(target.url);
    if (!alive.alive) {
      emit(io, scanId, 'log', { msg: `⚠️ ${target.url} is unreachable (${alive.status})`, type: 'warn' });
      continue;
    }

    emit(io, scanId, 'log', { msg: `✅ Target alive: ${target.url} (${alive.responseTime}ms)`, type: 'success' });

    // Initial screenshot
    emit(io, scanId, 'log', { msg: `📸 Taking initial screenshot...`, type: 'info' });
    const initShot = await takeScreenshot(target.url, 'Initial State');
    if (initShot) { scan.screenshots.push(initShot); emit(io, scanId, 'screenshot', initShot); }

    // Run all checks
    const allFindings = [];
    for (const [checkName, checkFn] of Object.entries(CHECKS)) {
      if (scan.status === 'cancelled') break;
      try {
        emit(io, scanId, 'log', { msg: `🔍 Running ${checkName.toUpperCase()} check...`, type: 'info' });
        const results = await checkFn(target.url, io, scanId);
        allFindings.push(...results);
        if (results.length > 0) {
          emit(io, scanId, 'log', { msg: `🚨 Found ${results.length} issue(s) in ${checkName} check`, type: 'alert' });
        } else {
          emit(io, scanId, 'log', { msg: `✓ ${checkName} check passed`, type: 'success' });
        }
      } catch (e) {
        emit(io, scanId, 'log', { msg: `Error in ${checkName}: ${e.message}`, type: 'error' });
      }
    }

    // AI Analysis of findings
    for (const finding of allFindings) {
      if (scan.status === 'cancelled') break;
      emit(io, scanId, 'log', { msg: `🤖 AI analyzing: ${finding.type}...`, type: 'ai' });
      try {
        const analysis = await analyzeVulnerability(finding, target.url, {});
        const enriched = { ...finding, ...analysis, targetUrl: target.url, id: uuidv4() };
        scan.findings.push(enriched);
        // Take evidence screenshot for confirmed vulns
        if (analysis.confirmed || finding.type.includes('Exposed') || finding.type.includes('Missing')) {
          const evidenceShot = await takeScreenshot(finding.url || target.url, `Evidence: ${finding.type}`);
          if (evidenceShot) {
            evidenceShot.findingId = enriched.id;
            scan.screenshots.push(evidenceShot);
            emit(io, scanId, 'screenshot', evidenceShot);
          }
        }
        emit(io, scanId, 'finding', enriched);
      } catch (e) {
        const basic = { ...finding, targetUrl: target.url, id: uuidv4(), confirmed: true };
        scan.findings.push(basic);
        emit(io, scanId, 'finding', basic);
      }
    }

    emit(io, scanId, 'progress', { step: `Completed ${target.url}`, status: 'done', percent: Math.round(((i+1)/urls.length)*100) });
  }

  scan.status = 'completed';
  scan.endTime = new Date();
  emit(io, scanId, 'scan_complete', { scanId, findingCount: scan.findings.length, screenshotCount: scan.screenshots.length, duration: scan.endTime - scan.startTime });
  emit(io, scanId, 'log', { msg: `✅ Scan complete! Found ${scan.findings.length} potential vulnerabilities`, type: 'success' });
  return scan;
}

function setupScanSocket(io) {
  io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);
    socket.on('join_scan', (scanId) => { socket.join(scanId); });
    socket.on('cancel_scan', (scanId) => {
      const scan = activeScans.get(scanId);
      if (scan) { scan.status = 'cancelled'; emit(io, scanId, 'log', { msg: '🛑 Scan cancelled by user', type: 'warn' }); }
    });
    socket.on('disconnect', () => console.log('Client disconnected:', socket.id));
  });
}

function getScan(scanId) { return activeScans.get(scanId); }

module.exports = { runScan, setupScanSocket, getScan, activeScans };
