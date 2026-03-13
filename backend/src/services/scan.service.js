"use strict";
const axios = require("axios");
const cheerio = require("cheerio");
const dns = require("dns").promises;
const { v4: uuidv4 } = require("uuid");
const { fetchPageContent } = require("./scraper.service");
const { takeScreenshot, takePageScreenshot, getBrowser, closeBrowserPool } = require("./screenshot.service");
const { analyzeVulnerability } = require("./ai.service");

process.on("exit", () => closeBrowserPool());
process.on("SIGINT", async () => { await closeBrowserPool(); process.exit(); });
process.on("SIGTERM", async () => { await closeBrowserPool(); process.exit(); });

const activeScans = new Map();

function emit(io, scanId, event, data) {
  if (io && scanId) io.to(scanId).emit(event, { ...data, timestamp: new Date().toISOString() });
}

function addLog(io, scanId, message, level = "info") {
  const scan = activeScans.get(scanId);
  if (scan) scan.logs.push({ message, level, timestamp: new Date().toISOString() });
  emit(io, scanId, "log", { message, level });
}

const PRIVATE_RANGES = [/^127\./, /^10\./, /^172\.(1[6-9]|2[0-9]|3[01])\./, /^192\.168\./, /^169\.254\./, /^0\.0\.0\.0/, /^::1$/];
const BLOCKED_HOSTS = ["localhost","metadata.google.internal","169.254.169.254","0.0.0.0"];

function isSafeUrl(url) {
  try {
    const u = new URL(url);
    if (!["http:","https:"].includes(u.protocol)) return false;
    const h = u.hostname.toLowerCase();
    if (BLOCKED_HOSTS.includes(h)) return false;
    if (PRIVATE_RANGES.some(r => r.test(h))) return false;
    return true;
  } catch { return false; }
}

function isScopeUrl(url, inScopeList) {
  if (!inScopeList || inScopeList.length === 0) return true;
  try {
    const target = new URL(url);
    for (const item of inScopeList) {
      try {
        const scopeRaw = (item.url || item || "").toString().trim();
        if (!scopeRaw) continue;
        if (scopeRaw.startsWith("*.")) {
          const domain = scopeRaw.slice(2).toLowerCase();
          if (target.hostname === domain || target.hostname.endsWith("." + domain)) return true;
        } else {
          const scope = new URL(scopeRaw.startsWith("http") ? scopeRaw : "https://" + scopeRaw);
          if (target.hostname === scope.hostname || target.hostname.endsWith("." + scope.hostname)) return true;
        }
      } catch {}
    }
  } catch {}
  return false;
}

const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36";

async function safeGet(url, opts = {}) {
  if (!isSafeUrl(url)) return null;
  try { return await axios.get(url, { timeout: 12000, maxRedirects: 3, validateStatus: () => true, headers: { "User-Agent": UA, ...(opts.headers||{}) }, ...opts }); } catch { return null; }
}

async function safeHead(url, opts = {}) {
  if (!isSafeUrl(url)) return null;
  try { return await axios.head(url, { timeout: 10000, maxRedirects: 3, validateStatus: () => true, headers: { "User-Agent": UA, ...(opts.headers||{}) }, ...opts }); } catch { return null; }
}

async function safePost(url, data, opts = {}) {
  if (!isSafeUrl(url)) return null;
  try { return await axios.post(url, data, { timeout: 15000, maxRedirects: 0, validateStatus: () => true, headers: { "User-Agent": UA, "Content-Type": "application/json", ...(opts.headers||{}) }, ...opts }); } catch { return null; }
}

function getUrlParams(url) {
  try { return [...new URL(url).searchParams.keys()]; } catch { return []; }
}

function injectParam(url, param, value) {
  try { const u = new URL(url); u.searchParams.set(param, value); return u.href; } catch { return null; }
}

async function crawlUrl(startUrl, inScopeList, maxDepth = 2, maxUrls = 50) {
  const visited = new Set([startUrl]);
  const queue = [{ url: startUrl, depth: 0 }];
  const discovered = [];
  while (queue.length > 0 && discovered.length < maxUrls) {
    const { url, depth } = queue.shift();
    if (depth > maxDepth) continue;
    try {
      const { html } = await fetchPageContent(url);
      const $ = cheerio.load(html);
      const base = new URL(url);
      $("a[href]").each((_, el) => {
        try {
          const href = $(el).attr("href");
          if (!href || href.startsWith("#") || href.startsWith("mailto:") || href.startsWith("javascript:")) return;
          const abs = new URL(href, base).href.split("#")[0];
          if (!visited.has(abs) && abs.startsWith("http") && isSafeUrl(abs) && isScopeUrl(abs, inScopeList)) {
            visited.add(abs);
            discovered.push(abs);
            if (depth + 1 <= maxDepth) queue.push({ url: abs, depth: depth + 1 });
          }
        } catch {}
      });
    } catch {}
  }
  return discovered.slice(0, maxUrls);
}

async function reportFinding(io, scanId, finding, page = null) {
  const scan = activeScans.get(scanId);
  let screenshot = null;
  try {
    if (page) screenshot = await takePageScreenshot(page, finding.type);
    else if (finding.url && isSafeUrl(finding.url)) screenshot = await takeScreenshot(finding.url, finding.type);
  } catch {}
  const f = { ...finding, id: uuidv4(), screenshot, timestamp: new Date().toISOString() };
  if (scan) scan.findings.push(f);
  emit(io, scanId, "finding", f);
  return f;
}

// ═══════════════════════════════════════════════════════════════════════════════
// VULNERABILITY CHECKS
// ═══════════════════════════════════════════════════════════════════════════════
const CHECKS = {

  // 1. Security Headers
  async headers(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "Security Headers", url, status: "running" });
    const res = await safeGet(url);
    if (!res) return findings;
    const h = res.headers;
    const missing = [];
    if (!h["strict-transport-security"]) missing.push("Strict-Transport-Security (HSTS)");
    if (!h["x-content-type-options"]) missing.push("X-Content-Type-Options");
    if (!h["x-frame-options"] && !(h["content-security-policy"]||[]).includes("frame-ancestors")) missing.push("X-Frame-Options");
    if (!h["content-security-policy"]) missing.push("Content-Security-Policy");
    if (!h["referrer-policy"]) missing.push("Referrer-Policy");
    if (!h["permissions-policy"]) missing.push("Permissions-Policy");
    if (missing.length > 0) findings.push({ type: "Missing Security Headers", severity: "medium", url, details: `Missing headers: ${missing.join(", ")}`, confirmed: true });
    if (h["server"]) findings.push({ type: "Server Version Disclosure", severity: "low", url, details: `Server: ${h["server"]}`, confirmed: true });
    if (h["x-powered-by"]) findings.push({ type: "Technology Disclosure", severity: "low", url, details: `X-Powered-By: ${h["x-powered-by"]}`, confirmed: true });
    return findings;
  },

  // 2. SSL/TLS
  async ssl(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "SSL/TLS Check", url, status: "running" });
    if (url.startsWith("http://")) findings.push({ type: "Plaintext HTTP", severity: "high", url, details: "Site uses HTTP — data transmitted in plaintext", confirmed: true });
    try {
      const httpsUrl = url.replace("http://", "https://");
      await axios.get(httpsUrl, { timeout: 8000, validateStatus: () => true });
    } catch (e) {
      if (e.code === "CERT_HAS_EXPIRED") findings.push({ type: "Expired SSL Certificate", severity: "high", url, details: "SSL certificate expired", confirmed: true });
      if (e.code === "DEPTH_ZERO_SELF_SIGNED_CERT" || e.code === "SELF_SIGNED_CERT_IN_CHAIN") findings.push({ type: "Self-Signed Certificate", severity: "medium", url, details: "Self-signed SSL certificate in use", confirmed: true });
    }
    return findings;
  },

  // 3. Cookies
  async cookies(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "Cookie Security", url, status: "running" });
    const res = await safeGet(url);
    if (!res) return findings;
    const cookies = [].concat(res.headers["set-cookie"] || []);
    for (const cookie of cookies) {
      const cl = cookie.toLowerCase();
      const issues = [];
      if (!cl.includes("httponly")) issues.push("Missing HttpOnly (XSS can steal cookie)");
      if (!cl.includes("secure")) issues.push("Missing Secure flag (sent over HTTP)");
      if (!cl.includes("samesite")) issues.push("Missing SameSite (CSRF risk)");
      if (issues.length > 0) findings.push({ type: "Insecure Cookie Configuration", severity: "medium", url, details: issues.join("; ") + " — Cookie: " + cookie.split(";")[0], confirmed: true });
    }
    return findings;
  },

  // 4. CORS
  async cors(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "CORS Misconfiguration", url, status: "running" });
    const res = await safeGet(url, { headers: { "Origin": "https://evil-attacker.com" } });
    if (!res) return findings;
    const acao = res.headers["access-control-allow-origin"] || "";
    const acac = res.headers["access-control-allow-credentials"] || "";
    if (acao === "*") findings.push({ type: "CORS Wildcard", severity: "medium", url, details: "ACAO: * — any origin can read responses", confirmed: true });
    else if (acao.includes("evil-attacker.com")) findings.push({ type: "CORS Origin Reflection", severity: acac === "true" ? "critical" : "high", url, details: `Server reflects arbitrary Origin header. Credentials allowed: ${acac}. Full account takeover possible if credentials=true.`, confirmed: true });
    return findings;
  },

  // 5. Sensitive Files
  async sensitiveFiles(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "Sensitive Files", url, status: "running" });
    const PATHS = [
      ".git/config",".git/HEAD",".git/COMMIT_EDITMSG",
      ".env",".env.local",".env.production",".env.backup",
      "config.php","wp-config.php","phpinfo.php","info.php","test.php",
      "robots.txt","sitemap.xml",".htaccess",".htpasswd",
      "backup.zip","backup.tar.gz","backup.sql","db.sql","database.sql","dump.sql",
      "admin","administrator","wp-admin","wp-login.php",
      ".DS_Store","package.json","composer.json","composer.lock",
      "Dockerfile","docker-compose.yml",".travis.yml",".github/workflows",
      "server-status","server-info","_profiler","debug","actuator","actuator/env",
      "api/swagger","api/swagger.json","api/swagger.yaml","swagger.json","swagger.yaml",
      "openapi.json","openapi.yaml",".well-known/security.txt",
      "crossdomain.xml","clientaccesspolicy.xml","elmah.axd","trace.axd",
      "web.config","appsettings.json",".bash_history",".ssh/id_rsa",
      ".npmrc",".pypirc","credentials.json","secrets.json","config.yml","config.yaml"
    ];
    const CRITICAL = [".env",".env.local",".env.production",".env.backup",".git/config",".git/HEAD","db.sql","database.sql","dump.sql","backup.sql","backup.zip","backup.tar.gz",".ssh/id_rsa",".bash_history","wp-config.php","credentials.json","secrets.json"];
    const base = new URL(url).origin;
    const results = await Promise.allSettled(PATHS.map(async p => {
      const target = `${base}/${p}`;
      if (!isSafeUrl(target)) return;
      const res = await safeGet(target);
      if (res && res.status === 200 && res.headers["content-type"] && !res.headers["content-type"].includes("text/html")) {
        findings.push({ type: "Sensitive File Exposed", severity: CRITICAL.includes(p) ? "critical" : "medium", url: target, details: `Publicly accessible: /${p} (HTTP ${res.status})`, confirmed: true });
      } else if (res && res.status === 200) {
        const body = typeof res.data === "string" ? res.data : "";
        if (body.length > 10 && !body.toLowerCase().includes("<!doctype html") && !body.toLowerCase().startsWith("<html")) {
          findings.push({ type: "Sensitive File Exposed", severity: CRITICAL.includes(p) ? "critical" : "medium", url: target, details: `Publicly accessible: /${p} (HTTP ${res.status})`, confirmed: true });
        }
      }
    }));
    return findings;
  },

  // 6. HTTP Methods
  async httpMethods(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "HTTP Methods", url, status: "running" });
    try {
      const res = await axios.options(url, { timeout: 10000, validateStatus: () => true, headers: { "User-Agent": UA } });
      const allow = (res.headers["allow"] || res.headers["access-control-allow-methods"] || "").toUpperCase();
      if (allow.includes("TRACE")) findings.push({ type: "HTTP TRACE Enabled (XST)", severity: "medium", url, details: "TRACE method enabled — Cross-Site Tracing attack possible", confirmed: true });
      if (allow.includes("PUT")) findings.push({ type: "HTTP PUT Enabled", severity: "high", url, details: "PUT method enabled — may allow arbitrary file upload to server", confirmed: true });
      if (allow.includes("DELETE")) findings.push({ type: "HTTP DELETE Enabled", severity: "medium", url, details: "DELETE method enabled on server", confirmed: true });
    } catch {}
    return findings;
  },

  // 7. Open Redirect
  async openRedirect(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "Open Redirect", url, status: "running" });
    const REDIRECT_PARAMS = ["redirect","url","next","return","returnUrl","redirect_uri","goto","dest","destination","back","continue","rurl","target","to","out","view","go","returnTo","checkout_url","return_path","forward","location","link"];
    const params = getUrlParams(url);
    const toTest = params.filter(p => REDIRECT_PARAMS.some(r => p.toLowerCase().includes(r)));
    for (const param of toTest.slice(0, 5)) {
      const testUrl = injectParam(url, param, "https://evil-attacker.com");
      if (!testUrl) continue;
      try {
        const res = await axios.get(testUrl, { maxRedirects: 0, validateStatus: () => true, timeout: 8000, headers: { "User-Agent": UA } });
        if ([301,302,303,307,308].includes(res.status)) {
          const loc = res.headers["location"] || "";
          if (loc.includes("evil-attacker.com")) findings.push({ type: "Open Redirect", severity: "medium", url: testUrl, details: `Parameter '${param}' causes open redirect to arbitrary URLs — phishing risk`, confirmed: true });
        }
      } catch {}
    }
    return findings;
  },

  // 8. Information Disclosure
  async informationDisclosure(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "Information Disclosure", url, status: "running" });
    const ERROR_PATHS = ["/zzz-nonexistent-xyz-404", "/api/zzz-fake-endpoint", "/error-test-500"];
    const ERROR_PATTERNS = [
      { re: /at\s+\S+\s*\(\S+\.js:\d+:\d+\)/i, label: "Node.js Stack Trace" },
      { re: /at\s+\S+\.\S+\(\S+\.java:\d+\)/i, label: "Java Stack Trace" },
      { re: /Traceback \(most recent call last\)/i, label: "Python Stack Trace" },
      { re: /SQL syntax.*MySQL|mysql_fetch|ORA-\d+|pg_query|sqlite3?\w*|SQLSTATE/i, label: "Database Error" },
      { re: /Fatal error:|Warning:|Notice:/i, label: "PHP Error" },
      { re: /NullPointerException|StackTrace|System\.Exception/i, label: "Framework Exception" },
      { re: /\/(home|var|usr|etc|app|srv|opt)\//i, label: "Internal File Path" },
      { re: /192\.168\.|10\.\d+\.|172\.(1[6-9]|2\d|3[01])\./i, label: "Internal IP Address" },
      { re: /password|passwd|secret|api.?key/i, label: "Credential Disclosure" },
    ];
    const base = new URL(url).origin;
    for (const p of ERROR_PATHS) {
      const target = base + p;
      if (!isSafeUrl(target)) continue;
      const res = await safeGet(target);
      if (!res) continue;
      const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data || {});
      for (const { re, label } of ERROR_PATTERNS) {
        if (re.test(body)) {
          findings.push({ type: `Information Disclosure: ${label}`, severity: "medium", url: target, details: `${label} exposed in HTTP ${res.status} response body`, confirmed: true });
          break;
        }
      }
    }
    return findings;
  },

  // 9. Directory Listing
  async directoryListing(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "Directory Listing", url, status: "running" });
    const DIRS = ["/uploads/","/images/","/files/","/backup/","/admin/","/assets/","/static/","/media/","/data/","/logs/","/tmp/","/temp/","/old/","/archive/"];
    const base = new URL(url).origin;
    await Promise.allSettled(DIRS.map(async dir => {
      const target = base + dir;
      if (!isSafeUrl(target)) return;
      const res = await safeGet(target);
      if (!res || res.status !== 200) return;
      const body = typeof res.data === "string" ? res.data : "";
      if (body.includes("Index of /") || body.includes("Directory listing") || (body.includes("Parent Directory") && body.includes("<a href"))) {
        findings.push({ type: "Directory Listing Enabled", severity: "medium", url: target, details: `Directory listing exposed at ${dir}`, confirmed: true });
      }
    }));
    return findings;
  },

  // 10. Source Map Exposure
  async sourceMaps(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "Source Map Exposure", url, status: "running" });
    try {
      const { html } = await fetchPageContent(url);
      const $ = cheerio.load(html);
      const scripts = [];
      $("script[src]").each((_, el) => { const s = $(el).attr("src"); if (s) scripts.push(s); });
      const base = new URL(url);
      for (const src of scripts.slice(0, 10)) {
        try {
          const absJs = new URL(src, base).href;
          if (!isSafeUrl(absJs)) continue;
          const jsRes = await safeGet(absJs);
          if (!jsRes) continue;
          const jsBody = typeof jsRes.data === "string" ? jsRes.data : "";
          const mapMatch = jsBody.match(/\/\/# sourceMappingURL=(.+)$/);
          if (mapMatch) {
            const mapUrl = new URL(mapMatch[1].trim(), absJs).href;
            if (isSafeUrl(mapUrl)) {
              const mr = await safeGet(mapUrl);
              if (mr && mr.status === 200) findings.push({ type: "Source Map Exposed", severity: "medium", url: mapUrl, details: `Source map at ${mapUrl} reveals original source code`, confirmed: true });
            }
          }
          const mapUrl2 = absJs + ".map";
          if (isSafeUrl(mapUrl2)) {
            const mr2 = await safeGet(mapUrl2);
            if (mr2 && mr2.status === 200) findings.push({ type: "Source Map Exposed", severity: "medium", url: mapUrl2, details: `Source map at ${mapUrl2} reveals original source code`, confirmed: true });
          }
        } catch {}
      }
    } catch {}
    return findings;
  },

  // 11. API Key Exposure
  async apiKeyExposure(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "API Key Exposure in JS", url, status: "running" });
    const KEY_PATTERNS = [
      { name: "AWS Access Key", re: /AKIA[0-9A-Z]{16}/g, severity: "critical" },
      { name: "Google API Key", re: /AIza[0-9A-Za-z\-_]{35}/g, severity: "high" },
      { name: "Stripe Live Secret", re: /sk_live_[a-zA-Z0-9]{24,}/g, severity: "critical" },
      { name: "GitHub Token", re: /ghp_[a-zA-Z0-9]{36}/g, severity: "critical" },
      { name: "Slack Token", re: /xox[baprs]-[0-9a-zA-Z\-]{10,}/g, severity: "high" },
      { name: "Private RSA Key", re: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/g, severity: "critical" },
      { name: "Generic API Secret", re: /["'](?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key)["']\s*[:=]\s*["']([^"']{10,})["']/gi, severity: "high" },
      { name: "Sendgrid API Key", re: /SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}/g, severity: "critical" },
      { name: "Twilio API Key", re: /SK[a-z0-9]{32}/g, severity: "high" },
    ];
    try {
      const { html } = await fetchPageContent(url);
      const $ = cheerio.load(html);
      const scripts = [];
      $("script[src]").each((_, el) => { const s = $(el).attr("src"); if (s) scripts.push(s); });
      const inlineTexts = [];
      $("script:not([src])").each((_, el) => inlineTexts.push($(el).html() || ""));
      const base = new URL(url);
      const sources = [...inlineTexts];
      for (const src of scripts.slice(0, 15)) {
        try {
          const abs = new URL(src, base).href;
          if (!isSafeUrl(abs)) continue;
          const res = await safeGet(abs);
          if (res && res.status === 200) sources.push(typeof res.data === "string" ? res.data : "");
        } catch {}
      }
      for (const source of sources) {
        for (const { name, re, severity } of KEY_PATTERNS) {
          const matches = source.match(re);
          if (matches && matches.length > 0) {
            findings.push({ type: `Exposed Credential: ${name}`, severity, url, details: `${name} found in JavaScript. Hint: ${matches[0].substring(0, 20)}...`, confirmed: true });
          }
        }
      }
    } catch {}
    return findings;
  },

  // 12. GraphQL Introspection
  async graphql(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "GraphQL Introspection", url, status: "running" });
    const ENDPOINTS = ["/graphql","/api/graphql","/v1/graphql","/query","/gql","/api/gql","/graphiql"];
    const base = new URL(url).origin;
    for (const ep of ENDPOINTS) {
      const target = base + ep;
      if (!isSafeUrl(target)) continue;
      const res = await safePost(target, { query: "{ __schema { types { name } } }" }, { headers: { "Content-Type": "application/json" } });
      if (res && res.status === 200 && res.data && res.data.data && res.data.data.__schema) {
        findings.push({ type: "GraphQL Introspection Enabled", severity: "medium", url: target, details: `GraphQL schema fully exposed at ${ep} — attackers can enumerate all types, queries, mutations`, confirmed: true });
      }
    }
    return findings;
  },

  // 13. Subdomain Takeover
  async subdomainTakeover(url, io, scanId, options = {}) {
    const findings = [];
    emit(io, scanId, "progress", { step: "Subdomain Takeover", url, status: "running" });
    const SIGNATURES = [
      { service: "GitHub Pages", pattern: /\.github\.io$/, fingerprint: "There isn't a GitHub Pages site here" },
      { service: "Heroku", pattern: /\.herokuapp\.com$/, fingerprint: "No such app" },
      { service: "AWS S3", pattern: /\.s3\.amazonaws\.com$/, fingerprint: "NoSuchBucket" },
      { service: "Azure", pattern: /\.azurewebsites\.net$/, fingerprint: "404 Web Site not found" },
      { service: "Shopify", pattern: /\.myshopify\.com$/, fingerprint: "Sorry, this shop is currently unavailable" },
      { service: "Fastly", pattern: /\.fastly\.net$/, fingerprint: "Fastly error: unknown domain" },
      { service: "Ghost", pattern: /\.ghost\.io$/, fingerprint: "The thing you were looking for" },
      { service: "Surge", pattern: /\.surge\.sh$/, fingerprint: "project not found" },
      { service: "Tumblr", pattern: /\.tumblr\.com$/, fingerprint: "Whatever you were looking for" },
    ];
    const inScopeList = options.inScopeList || [];
    const subdomains = new Set();
    try { subdomains.add(new URL(url).hostname); } catch {}
    for (const item of inScopeList) {
      try {
        const raw = item.url || item || "";
        if (raw.startsWith("*.")) subdomains.add(raw.slice(2));
        else subdomains.add(new URL(raw.startsWith("http") ? raw : "https://" + raw).hostname);
      } catch {}
    }
    for (const subdomain of subdomains) {
      try {
        const cnameRecords = await dns.resolve(subdomain, "CNAME").catch(() => []);
        for (const cname of cnameRecords) {
          for (const { service, pattern, fingerprint } of SIGNATURES) {
            if (pattern.test(cname)) {
              const testUrl = `https://${subdomain}`;
              const res = await safeGet(testUrl);
              const body = res ? (typeof res.data === "string" ? res.data : "") : "";
              if (!res || body.includes(fingerprint)) {
                findings.push({ type: "Subdomain Takeover Possible", severity: "high", url: testUrl, details: `${subdomain} has dangling CNAME to ${cname} (${service}) — unclaimed service, takeover possible`, confirmed: true });
              }
            }
          }
        }
      } catch {}
    }
    return findings;
  },

  // 14. CRLF Injection
  async crlfInjection(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "CRLF Injection", url, status: "running" });
    const PAYLOADS = ["%0d%0aX-CRLFInjected:bugcatcher","%0aX-CRLFInjected:bugcatcher","%0d%0aSet-Cookie:crlf_injected=1"];
    const params = getUrlParams(url);
    const toTest = params.length > 0 ? params.slice(0, 3) : ["q", "search", "id", "page"];
    for (const param of toTest) {
      for (const payload of PAYLOADS) {
        const testUrl = injectParam(url, param, payload);
        if (!testUrl || !isSafeUrl(testUrl)) continue;
        const res = await safeGet(testUrl);
        if (!res) continue;
        if (res.headers["x-crlfinjected"] === "bugcatcher" || (res.headers["set-cookie"] || []).join("").includes("crlf_injected")) {
          findings.push({ type: "CRLF Injection", severity: "high", url: testUrl, details: `CRLF injection confirmed via parameter '${param}' — HTTP response header injection possible`, confirmed: true });
          break;
        }
      }
    }
    return findings;
  },

  // 15. Web Cache Poisoning
  async webCachePoisoning(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "Web Cache Poisoning", url, status: "running" });
    const TESTS = [
      { header: "X-Forwarded-Host", value: "evil-cache-poison.com" },
      { header: "X-Original-URL", value: "/admin-poison" },
      { header: "X-Forwarded-Scheme", value: "evil" },
      { header: "X-HTTP-Method-Override", value: "DELETE" },
    ];
    for (const { header, value } of TESTS) {
      const res = await safeGet(url, { headers: { [header]: value } });
      if (!res) continue;
      const body = typeof res.data === "string" ? res.data : "";
      if (body.includes(value)) {
        findings.push({ type: "Web Cache Poisoning", severity: "high", url, details: `${header}: ${value} reflected in response — cache poisoning possible, attackers could serve malicious content to all users`, confirmed: true });
      }
    }
    return findings;
  },

  // 16. Prototype Pollution
  async prototypePollution(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "Prototype Pollution", url, status: "running" });
    const PAYLOADS = [
      "__proto__[bugcatcher]=polluted123",
      "constructor.prototype.bugcatcher=polluted123",
      "__proto__.bugcatcher=polluted123"
    ];
    for (const payload of PAYLOADS) {
      const separator = url.includes("?") ? "&" : "?";
      const testUrl = url + separator + payload;
      if (!isSafeUrl(testUrl)) continue;
      const res = await safeGet(testUrl);
      if (!res) continue;
      const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data || {});
      if (body.includes("polluted123")) {
        findings.push({ type: "Prototype Pollution", severity: "high", url: testUrl, details: `Prototype pollution payload reflected: ${payload} — may allow privilege escalation or RCE`, confirmed: true });
        break;
      }
    }
    return findings;
  },

  // 17. Rate Limit Testing
  async rateLimitTest(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "Rate Limit Testing", url, status: "running" });
    const AUTH_PATTERNS = ["/login","/signin","/auth","/api/auth","/account/login","/user/login","/session","/token","/password"];
    if (!AUTH_PATTERNS.some(p => url.toLowerCase().includes(p))) return findings;
    const requests = await Promise.allSettled(Array(20).fill(null).map(() => safePost(url, { username: "test", password: "test" })));
    const successes = requests.filter(r => r.status === "fulfilled" && r.value && r.value.status < 429).length;
    if (successes >= 18) {
      findings.push({ type: "Missing Rate Limiting on Auth Endpoint", severity: "medium", url, details: `${successes}/20 rapid POST requests to auth endpoint succeeded without rate limiting — brute force attacks possible`, confirmed: true });
    }
    return findings;
  },

  // 18. Clickjacking
  async clickjacking(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "Clickjacking", url, status: "running" });
    const res = await safeGet(url);
    if (!res) return findings;
    const xfo = (res.headers["x-frame-options"] || "").toLowerCase();
    const csp = res.headers["content-security-policy"] || "";
    const protected_ = xfo.includes("deny") || xfo.includes("sameorigin") || csp.includes("frame-ancestors");
    if (!protected_) {
      findings.push({ type: "Clickjacking Vulnerability", severity: "medium", url, details: "No X-Frame-Options or CSP frame-ancestors header — page embeddable in iframe, enabling UI redressing/clickjacking attacks", confirmed: true });
    }
    return findings;
  },

  // 19. Broken External Links (Hijacking)
  async brokenLinks(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "Broken Link Hijacking", url, status: "running" });
    try {
      const { html } = await fetchPageContent(url);
      const $ = cheerio.load(html);
      const extLinks = new Set();
      $("a[href]").each((_, el) => {
        try {
          const href = new URL($(el).attr("href"), url).href;
          const base = new URL(url);
          const linkBase = new URL(href);
          if (linkBase.hostname !== base.hostname && href.startsWith("http")) extLinks.add(linkBase.origin);
        } catch {}
      });
      for (const extUrl of [...extLinks].slice(0, 20)) {
        if (!isSafeUrl(extUrl)) continue;
        try {
          const res = await axios.get(extUrl, { timeout: 8000, validateStatus: () => true, headers: { "User-Agent": UA } });
          if (res.status >= 400) {
            findings.push({ type: "Broken External Link / Possible Hijacking", severity: "low", url, details: `External link to ${extUrl} returns HTTP ${res.status} — domain may be unregistered and hijackable`, confirmed: true });
          }
        } catch (e) {
          if (e.code === "ENOTFOUND" || e.code === "ECONNREFUSED") {
            findings.push({ type: "Broken External Link / Possible Hijacking", severity: "medium", url, details: `External link to ${extUrl} — domain does not resolve (ENOTFOUND). Domain may be available for registration.`, confirmed: true });
          }
        }
      }
    } catch {}
    return findings;
  },
};

// ═══════════════════════════════════════════════════════════════════════════════
// PLAYWRIGHT-BASED ACTIVE EXPLOIT CHECKS
// ═══════════════════════════════════════════════════════════════════════════════
const PLAYWRIGHT_CHECKS = {

  // 20. XSS - Active injection via Playwright
  async xss(url, io, scanId, options = {}) {
    const findings = [];
    emit(io, scanId, "progress", { step: "XSS Testing", url, status: "running" });
    const browser = await getBrowser();
    if (!browser) return findings;
    const XSS_PAYLOADS = [
      "<script>window.__xss_triggered=1</script>",
      "<img src=x onerror='window.__xss_triggered=1'>",
      "javascript:window.__xss_triggered=1",
      '" autofocus onfocus=window.__xss_triggered=1 x="',
      `');window.__xss_triggered=1;//`,
    ];
    let context, page;
    try {
      context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 } });
      page = await context.newPage();
      // Set up dialog handler
      let alertFired = false;
      page.on("dialog", async dialog => { alertFired = true; await dialog.dismiss().catch(() => {}); });
      await page.goto(url, { timeout: 20000, waitUntil: "domcontentloaded" }).catch(() => {});
      await page.waitForTimeout(1000).catch(() => {});

      // Test URL parameters
      const urlObj = new URL(url);
      for (const [param, _] of urlObj.searchParams) {
        for (const payload of XSS_PAYLOADS.slice(0, 3)) {
          try {
            alertFired = false;
            const testUrl = injectParam(url, param, payload);
            if (!testUrl || !isSafeUrl(testUrl)) continue;
            await page.goto(testUrl, { timeout: 15000, waitUntil: "domcontentloaded" }).catch(() => {});
            await page.waitForTimeout(800).catch(() => {});
            const triggered = await page.evaluate(() => window.__xss_triggered === 1).catch(() => false);
            if (triggered || alertFired) {
              const screenshot = await takePageScreenshot(page, "XSS Confirmed");
              findings.push({ type: "Cross-Site Scripting (XSS)", severity: "high", url: testUrl, details: `Reflected XSS confirmed via URL parameter '${param}'. Payload: ${payload.substring(0,50)}`, confirmed: true, screenshot });
              alertFired = false;
              break;
            }
          } catch {}
        }
      }

      // Test form inputs
      await page.goto(url, { timeout: 15000, waitUntil: "domcontentloaded" }).catch(() => {});
      await page.waitForTimeout(800).catch(() => {});
      const forms = await page.$$eval("form", fs => fs.map((f, i) => ({ index: i, action: f.action, method: f.method })));
      for (const form of forms.slice(0, 3)) {
        for (const payload of XSS_PAYLOADS.slice(0, 2)) {
          try {
            alertFired = false;
            await page.goto(url, { timeout: 15000, waitUntil: "domcontentloaded" }).catch(() => {});
            await page.waitForTimeout(500).catch(() => {});
            const inputs = await page.$$("form input[type=text], form input[type=search], form input:not([type=hidden]):not([type=submit]):not([type=checkbox]):not([type=radio])");
            for (const input of inputs.slice(0, 3)) {
              await input.fill(payload).catch(() => {});
            }
            const textareas = await page.$$("form textarea");
            for (const ta of textareas.slice(0, 2)) {
              await ta.fill(payload).catch(() => {});
            }
            const submitBtn = await page.$("form input[type=submit], form button[type=submit], form button");
            if (submitBtn) await submitBtn.click().catch(() => {});
            await page.waitForTimeout(1500).catch(() => {});
            const triggered = await page.evaluate(() => window.__xss_triggered === 1).catch(() => false);
            if (triggered || alertFired) {
              const screenshot = await takePageScreenshot(page, "XSS via Form");
              findings.push({ type: "Cross-Site Scripting (XSS) via Form", severity: "high", url, details: `Stored/Reflected XSS via form input. Payload: ${payload.substring(0,50)}`, confirmed: true, screenshot });
              break;
            }
          } catch {}
        }
      }
    } catch (err) {
      addLog(io, scanId, `XSS check error: ${err.message}`, "warn");
    } finally {
      if (page) await page.close().catch(() => {});
      if (context) await context.close().catch(() => {});
    }
    return findings;
  },

  // 21. SQL Injection
  async sqli(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "SQL Injection Testing", url, status: "running" });
    const PAYLOADS = [
      "'",
      "'OR'1'='1",
      "'OR 1=1--",
      `" OR 1=1--`,
      "1; DROP TABLE users--",
      "1 UNION SELECT NULL--",
      `1' AND SLEEP(0)--`,
    ];
    const SQL_ERRORS = [
      /SQL syntax.*MySQL/i, /Warning.*mysql_/i, /MySqlException/i,
      /valid MySQL result/i, /check the manual that corresponds to your MySQL/i,
      /ORA-\d{5}/i, /Oracle.*Driver/i, /quoted string not properly terminated/i,
      /PostgreSQL.*ERROR/i, /pg_query/i, /PSQLException/i,
      /SQLite.*error/i, /sqlite3/i,
      /Microsoft.*ODBC.*SQL Server/i, /Incorrect syntax near/i, /SQLSTATE/i,
      /Unclosed quotation mark/i, /SqlException/i,
      /DB2.*SQL error/i, /Sybase message/i,
    ];
    const params = getUrlParams(url);
    if (params.length === 0) return findings;
    for (const param of params.slice(0, 5)) {
      for (const payload of PAYLOADS) {
        const testUrl = injectParam(url, param, payload);
        if (!testUrl || !isSafeUrl(testUrl)) continue;
        const res = await safeGet(testUrl);
        if (!res) continue;
        const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data || {});
        if (SQL_ERRORS.some(re => re.test(body))) {
          const screenshot = await takeScreenshot(testUrl, "SQL Injection Error");
          findings.push({ type: "SQL Injection", severity: "critical", url: testUrl, details: `SQL error triggered via param '${param}' with payload: ${payload} — database error exposed in response`, confirmed: true, screenshot });
          break;
        }
      }
    }
    return findings;
  },

  // 22. Blind SQL Injection (Time-based)
  async blindSqli(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "Blind SQLi (Time-based)", url, status: "running" });
    const TIME_PAYLOADS = [
      { payload: "1; WAITFOR DELAY '0:0:5'--", db: "MSSQL" },
      { payload: `1'; SELECT SLEEP(5)--`, db: "MySQL" },
      { payload: `1'; SELECT pg_sleep(5)--`, db: "PostgreSQL" },
      { payload: "1 AND SLEEP(5)--", db: "MySQL" },
      { payload: `' OR SLEEP(5)--`, db: "MySQL" },
    ];
    const params = getUrlParams(url);
    if (params.length === 0) return findings;
    // Get baseline response time
    const baseStart = Date.now();
    await safeGet(url);
    const baseline = Date.now() - baseStart;
    for (const param of params.slice(0, 3)) {
      for (const { payload, db } of TIME_PAYLOADS) {
        const testUrl = injectParam(url, param, payload);
        if (!testUrl || !isSafeUrl(testUrl)) continue;
        const start = Date.now();
        await safeGet(testUrl);
        const elapsed = Date.now() - start;
        if (elapsed > baseline + 4000) {
          const screenshot = await takeScreenshot(url, "Blind SQLi Evidence");
          findings.push({ type: "Blind SQL Injection (Time-based)", severity: "critical", url: testUrl, details: `Time-based blind SQLi via param '${param}' (${db}). Response delayed ${elapsed}ms vs baseline ${baseline}ms — database sleep triggered`, confirmed: true, screenshot });
          break;
        }
      }
    }
    return findings;
  },

  // 23. Server-Side Template Injection (SSTI)
  async ssti(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "SSTI Testing", url, status: "running" });
    const SSTI_PAYLOADS = [
      { payload: "{{7*7}}", expect: "49", engine: "Jinja2/Twig" },
      { payload: "${7*7}", expect: "49", engine: "Freemarker/EL" },
      { payload: "<%= 7*7 %>", expect: "49", engine: "ERB" },
      { payload: "#{7*7}", expect: "49", engine: "Ruby" },
      { payload: "{{7*7}}_jinja", expect: "49", engine: "Jinja2" },
      { payload: "*{7*7}", expect: "49", engine: "Thymeleaf" },
    ];
    const params = getUrlParams(url);
    if (params.length === 0) return findings;
    for (const param of params.slice(0, 5)) {
      for (const { payload, expect, engine } of SSTI_PAYLOADS) {
        const testUrl = injectParam(url, param, payload);
        if (!testUrl || !isSafeUrl(testUrl)) continue;
        const res = await safeGet(testUrl);
        if (!res) continue;
        const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data || {});
        if (body.includes(expect)) {
          const screenshot = await takeScreenshot(testUrl, "SSTI Confirmed");
          findings.push({ type: "Server-Side Template Injection (SSTI)", severity: "critical", url: testUrl, details: `SSTI confirmed via param '${param}' (${engine}). Payload '${payload}' evaluated to '${expect}' — RCE may be possible`, confirmed: true, screenshot });
          break;
        }
      }
    }
    return findings;
  },

  // 24. Command Injection (Time-based)
  async cmdInjection(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "Command Injection Testing", url, status: "running" });
    const CMD_PAYLOADS = [
      "; sleep 5",
      "| sleep 5",
      "&& sleep 5",
      "`sleep 5`",
      "; ping -c 5 127.0.0.1",
      "| ping -n 5 127.0.0.1",
      "$(sleep 5)",
    ];
    const params = getUrlParams(url);
    if (params.length === 0) return findings;
    const baseStart = Date.now();
    await safeGet(url);
    const baseline = Date.now() - baseStart;
    for (const param of params.slice(0, 3)) {
      for (const payload of CMD_PAYLOADS) {
        const testUrl = injectParam(url, param, payload);
        if (!testUrl || !isSafeUrl(testUrl)) continue;
        const start = Date.now();
        await safeGet(testUrl);
        const elapsed = Date.now() - start;
        if (elapsed > baseline + 4000) {
          const screenshot = await takeScreenshot(url, "Command Injection Evidence");
          findings.push({ type: "OS Command Injection", severity: "critical", url: testUrl, details: `Time-based command injection via param '${param}'. Payload: '${payload}'. Response delayed ${elapsed}ms vs baseline ${baseline}ms — OS command likely executed`, confirmed: true, screenshot });
          break;
        }
      }
    }
    return findings;
  },

  // 25. Path Traversal
  async pathTraversal(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "Path Traversal Testing", url, status: "running" });
    const PAYLOADS = [
      "../../../etc/passwd",
      "..%2F..%2F..%2Fetc%2Fpasswd",
      "....//....//....//etc/passwd",
      "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
      "..\..\..\windows\win.ini",
      "..%5c..%5c..%5cwindows%5cwin.ini",
    ];
    const LINUX_SIG = /root:x:0:0/;
    const WINDOWS_SIG = /\[extensions\]/i;
    const params = getUrlParams(url);
    const pathParams = params.filter(p => /file|path|page|dir|doc|folder|template|include|src|load/i.test(p));
    for (const param of pathParams.slice(0, 3)) {
      for (const payload of PAYLOADS) {
        const testUrl = injectParam(url, param, payload);
        if (!testUrl || !isSafeUrl(testUrl)) continue;
        const res = await safeGet(testUrl);
        if (!res) continue;
        const body = typeof res.data === "string" ? res.data : "";
        if (LINUX_SIG.test(body) || WINDOWS_SIG.test(body)) {
          const screenshot = await takeScreenshot(testUrl, "Path Traversal Evidence");
          findings.push({ type: "Path Traversal / LFI", severity: "critical", url: testUrl, details: `Path traversal confirmed via param '${param}'. System file contents exposed in response.`, confirmed: true, screenshot });
          break;
        }
      }
    }
    return findings;
  },

  // 26. IDOR
  async idor(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "IDOR Testing", url, status: "running" });
    const params = getUrlParams(url);
    const idParams = params.filter(p => /^id$|_id$|^user|^account|^order|^invoice|^record/i.test(p));
    // Also check path for numeric segments
    try {
      const urlObj = new URL(url);
      const pathParts = urlObj.pathname.split("/").filter(p => /^\d+$/.test(p));
      for (const part of pathParts.slice(0, 2)) {
        const baseRes = await safeGet(url);
        const baseSize = baseRes ? JSON.stringify(baseRes.data || "").length : 0;
        const altId = parseInt(part) + 1;
        const altUrl = url.replace(`/${part}`, `/${altId}`);
        if (!isSafeUrl(altUrl)) continue;
        const altRes = await safeGet(altUrl);
        if (!altRes || altRes.status === 404 || altRes.status === 403) continue;
        const altSize = JSON.stringify(altRes.data || "").length;
        if (altRes.status === 200 && Math.abs(altSize - baseSize) > 50) {
          const screenshot = await takeScreenshot(altUrl, "IDOR Evidence");
          findings.push({ type: "Insecure Direct Object Reference (IDOR)", severity: "high", url: altUrl, details: `Incrementing ID in path from ${part} to ${altId} returns different valid data (${altSize} bytes vs ${baseSize} bytes) — IDOR possible`, confirmed: false, screenshot });
        }
      }
    } catch {}
    return findings;
  },

  // 27. XXE
  async xxe(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "XXE Testing", url, status: "running" });
    const XXE_PAYLOAD = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>`;
    const XXE_SIG = /root:x:0:0/;
    const base = new URL(url).origin;
    const ENDPOINTS = ["/api", "/upload", "/import", "/xml", "/feed", "/rss", "/soap", "/ws"];
    for (const ep of ENDPOINTS) {
      const target = base + ep;
      if (!isSafeUrl(target)) continue;
      const res = await safePost(target, XXE_PAYLOAD, { headers: { "Content-Type": "application/xml" } });
      if (!res) continue;
      const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data || {});
      if (XXE_SIG.test(body)) {
        const screenshot = await takeScreenshot(target, "XXE Confirmed");
        findings.push({ type: "XML External Entity (XXE)", severity: "critical", url: target, details: `XXE confirmed at ${ep} — /etc/passwd contents returned in response`, confirmed: true, screenshot });
      }
    }
    return findings;
  },

  // 28. SSRF (from app perspective)
  async ssrfTest(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "SSRF Testing", url, status: "running" });
    const SSRF_PARAMS = ["url","uri","src","href","link","redirect","callback","webhook","fetch","load","proxy","request","image","img","file","feed","endpoint","api","path"];
    const SSRF_TARGETS = [
      { target: "http://169.254.169.254/latest/meta-data/", sig: /ami-id|instance-id|local-ipv4/ },
      { target: "http://169.254.169.254/computeMetadata/v1/", sig: /google|project-id/ },
    ];
    const params = getUrlParams(url);
    const urlParams = params.filter(p => SSRF_PARAMS.some(s => p.toLowerCase().includes(s)));
    for (const param of urlParams.slice(0, 5)) {
      for (const { target, sig } of SSRF_TARGETS) {
        const testUrl = injectParam(url, param, target);
        if (!testUrl || !isSafeUrl(testUrl)) continue;
        const res = await safeGet(testUrl);
        if (!res) continue;
        const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data || {});
        if (sig.test(body)) {
          const screenshot = await takeScreenshot(testUrl, "SSRF Confirmed");
          findings.push({ type: "Server-Side Request Forgery (SSRF)", severity: "critical", url: testUrl, details: `SSRF confirmed via param '${param}' — cloud metadata endpoint (${target}) accessible from server`, confirmed: true, screenshot });
          break;
        }
      }
    }
    return findings;
  },

  // 29. JWT Analysis
  async jwtAnalysis(url, io, scanId) {
    const findings = [];
    emit(io, scanId, "progress", { step: "JWT Analysis", url, status: "running" });
    const res = await safeGet(url);
    if (!res) return findings;
    const allHeaders = JSON.stringify(res.headers);
    const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data || {});
    const combined = allHeaders + " " + body;
    // Find JWT tokens
    const JWT_RE = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
    const tokens = combined.match(JWT_RE) || [];
    for (const token of tokens.slice(0, 5)) {
      try {
        const parts = token.split(".");
        const header = JSON.parse(Buffer.from(parts[0], "base64").toString());
        const payload = JSON.parse(Buffer.from(parts[1], "base64").toString());
        // Check alg:none
        if ((header.alg || "").toLowerCase() === "none") {
          findings.push({ type: "JWT Algorithm None Vulnerability", severity: "critical", url, details: `JWT uses alg:none — signature validation bypassed. Token exposes: ${JSON.stringify(Object.keys(payload)).substring(0,100)}`, confirmed: true });
        }
        // Check sensitive data in payload
        const sensitiveKeys = ["password","pass","secret","key","token","ssn","credit","card"];
        for (const key of Object.keys(payload)) {
          if (sensitiveKeys.some(s => key.toLowerCase().includes(s))) {
            findings.push({ type: "Sensitive Data in JWT Payload", severity: "high", url, details: `JWT payload contains sensitive field: '${key}' — JWT payloads are base64-encoded not encrypted`, confirmed: true });
          }
        }
        // Check expiry
        if (!payload.exp) findings.push({ type: "JWT Missing Expiry", severity: "medium", url, details: `JWT token has no expiration (exp claim missing) — tokens never expire`, confirmed: true });
      } catch {}
    }
    return findings;
  },
};

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN SCAN ORCHESTRATOR
// ═══════════════════════════════════════════════════════════════════════════════

async function runScan(io, scanId, urls, options = {}) {
  const scan = activeScans.get(scanId);
  if (!scan) return;

  const inScopeList = options.inScopeList || [];
  const credentials = options.credentials || null;
  const crawlEnabled = options.crawl === true;

  addLog(io, scanId, `[*] Bug Catcher scan started. Targets: ${urls.length}. Crawler: ${crawlEnabled ? "ON" : "OFF"}`, "info");
  emit(io, scanId, "scan_status", { status: "running", total: urls.length });

  // ── Phase 1: Crawl (if enabled) ──────────────────────────────────────────
  let allUrls = [...urls.map(u => u.url || u)];
  if (crawlEnabled && inScopeList.length > 0) {
    addLog(io, scanId, `[*] Crawler enabled — discovering in-scope URLs (depth 2, max 50 per target)...`, "info");
    for (const targetUrl of urls.slice(0, 5)) {
      const startUrl = targetUrl.url || targetUrl;
      if (!isSafeUrl(startUrl)) continue;
      try {
        const discovered = await crawlUrl(startUrl, inScopeList, 2, 50);
        addLog(io, scanId, `[+] Crawler found ${discovered.length} additional URLs from ${startUrl}`, "info");
        allUrls = [...new Set([...allUrls, ...discovered])];
      } catch (e) {
        addLog(io, scanId, `[!] Crawler error on ${startUrl}: ${e.message}`, "warn");
      }
      if (scan.status === "cancelled") break;
    }
    addLog(io, scanId, `[*] Total URLs to scan after crawl: ${allUrls.length}`, "info");
    emit(io, scanId, "scan_status", { status: "running", total: allUrls.length, crawledUrls: allUrls });
  }

  // ── Phase 2: Scan each URL ───────────────────────────────────────────────
  for (let i = 0; i < allUrls.length; i++) {
    if (scan.status === "cancelled") {
      addLog(io, scanId, "[!] Scan cancelled by user", "warn");
      break;
    }

    const url = allUrls[i];
    if (!url || !isSafeUrl(url)) {
      addLog(io, scanId, `[!] Skipping unsafe/invalid URL: ${url}`, "warn");
      continue;
    }

    // Scope enforcement
    if (inScopeList.length > 0 && !isScopeUrl(url, inScopeList)) {
      addLog(io, scanId, `[!] OUT OF SCOPE — skipping: ${url}`, "warn");
      continue;
    }

    addLog(io, scanId, `
[${i+1}/${allUrls.length}] Scanning: ${url}`, "info");
    emit(io, scanId, "scan_progress", { current: i + 1, total: allUrls.length, url });

    // Check target is alive
    const alive = await checkUrl(url);
    if (!alive.alive) {
      addLog(io, scanId, `[!] Target not reachable (HTTP ${alive.status}): ${url}`, "warn");
      continue;
    }
    addLog(io, scanId, `[+] Target alive (HTTP ${alive.status}, ${alive.responseTime}ms)`, "info");

    // Initial screenshot
    const initScreenshot = await takeScreenshot(url, `Initial - ${url}`);
    if (initScreenshot) emit(io, scanId, "screenshot", { ...initScreenshot, label: `Initial screenshot: ${url}` });

    // ── Parallel checks (no Playwright needed) ────────────────────────────
    addLog(io, scanId, "[*] Running parallel passive checks...", "info");
    const parallelResults = await Promise.allSettled([
      CHECKS.headers(url, io, scanId),
      CHECKS.ssl(url, io, scanId),
      CHECKS.cookies(url, io, scanId),
      CHECKS.cors(url, io, scanId),
      CHECKS.sensitiveFiles(url, io, scanId),
      CHECKS.httpMethods(url, io, scanId),
      CHECKS.openRedirect(url, io, scanId),
      CHECKS.informationDisclosure(url, io, scanId),
      CHECKS.directoryListing(url, io, scanId),
      CHECKS.sourceMaps(url, io, scanId),
      CHECKS.apiKeyExposure(url, io, scanId),
      CHECKS.graphql(url, io, scanId),
      CHECKS.crlfInjection(url, io, scanId),
      CHECKS.webCachePoisoning(url, io, scanId),
      CHECKS.prototypePollution(url, io, scanId),
      CHECKS.clickjacking(url, io, scanId),
      CHECKS.rateLimitTest(url, io, scanId),
      CHECKS.brokenLinks(url, io, scanId),
      CHECKS.subdomainTakeover(url, io, scanId, { inScopeList }),
    ]);

    for (const result of parallelResults) {
      if (result.status === "fulfilled" && Array.isArray(result.value)) {
        for (const finding of result.value) {
          if (finding && finding.type) {
            addLog(io, scanId, `[!] FOUND: ${finding.type} [${finding.severity?.toUpperCase()}] at ${finding.url}`, "warn");
            await reportFinding(io, scanId, finding);
          }
        }
      }
    }

    // ── Sequential Playwright-based exploit checks ────────────────────────
    addLog(io, scanId, "[*] Running active exploit checks (Playwright)...", "info");
    const playwrightCheckList = [
      ["xss", "XSS"],
      ["sqli", "SQL Injection"],
      ["blindSqli", "Blind SQLi"],
      ["ssti", "SSTI"],
      ["cmdInjection", "Command Injection"],
      ["pathTraversal", "Path Traversal"],
      ["idor", "IDOR"],
      ["xxe", "XXE"],
      ["ssrfTest", "SSRF"],
      ["jwtAnalysis", "JWT Analysis"],
    ];

    for (const [checkName, label] of playwrightCheckList) {
      if (scan.status === "cancelled") break;
      try {
        addLog(io, scanId, `[*] Running ${label} check...`, "info");
        const findings = await PLAYWRIGHT_CHECKS[checkName](url, io, scanId, { inScopeList, credentials });
        for (const finding of findings) {
          if (finding && finding.type) {
            addLog(io, scanId, `[!] FOUND: ${finding.type} [${finding.severity?.toUpperCase()}] at ${finding.url}`, "warn");
            await reportFinding(io, scanId, finding, null);
          }
        }
      } catch (e) {
        addLog(io, scanId, `[!] ${label} check error: ${e.message}`, "warn");
      }
    }

    addLog(io, scanId, `[+] Completed scanning: ${url}`, "info");
  }

  // ── Phase 3: Finalize ────────────────────────────────────────────────────
  scan.status = "complete";
  scan.completedAt = new Date().toISOString();
  const totalFindings = scan.findings.length;
  const criticalCount = scan.findings.filter(f => f.severity === "critical").length;
  const highCount = scan.findings.filter(f => f.severity === "high").length;

  addLog(io, scanId, `
[=] Scan complete! ${totalFindings} findings (${criticalCount} critical, ${highCount} high)`, "info");
  emit(io, scanId, "scan_complete", {
    scanId,
    totalFindings,
    criticalCount,
    highCount,
    findings: scan.findings,
    scannedUrls: allUrls.length,
    completedAt: scan.completedAt,
  });
}

async function checkUrl(url) {
  try {
    const start = Date.now();
    const res = await safeHead(url);
    if (!res) return { url, alive: false, status: 0 };
    return { url, alive: res.status < 500, status: res.status, responseTime: Date.now() - start };
  } catch { return { url, alive: false, status: 0 }; }
}

function startScan(io, scanId, urls, options = {}) {
  const scan = { scanId, status: "running", startedAt: new Date().toISOString(), findings: [], logs: [], urls: urls.map(u => u.url || u), options };
  activeScans.set(scanId, scan);
  runScan(io, scanId, urls, options).catch(err => {
    const s = activeScans.get(scanId);
    if (s) { s.status = "error"; s.error = err.message; }
    emit(io, scanId, "scan_error", { message: err.message });
    addLog(io, scanId, `[X] Fatal scan error: ${err.message}`, "error");
  });
  return scan;
}

function getScan(scanId) { return activeScans.get(scanId) || null; }

function cancelScan(scanId) {
  const scan = activeScans.get(scanId);
  if (scan && scan.status === "running") { scan.status = "cancelled"; return true; }
  return false;
}

module.exports = { startScan, getScan, cancelScan, isScopeUrl, isSafeUrl };
