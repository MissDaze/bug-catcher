const axios = require('axios');

const OPENROUTER_API = 'https://openrouter.ai/api/v1/chat/completions';
const MODEL = process.env.OPENROUTER_MODEL || 'meta-llama/llama-3.1-8b-instruct:free';

// Domains to exclude from scope extraction (platform own URLs, CDNs, analytics etc.)
const EXCLUDE_DOMAINS = [
  'hackerone.com', 'bugcrowd.com', 'intigriti.com', 'yeswehack.com',
  'synack.com', 'cobalt.io', 'immunefi.com', 'federacy.com', 'integrity.st',
  'openbugbounty.org', 'openrouter.ai', 'railway.app', 'github.com',
  'google.com', 'twitter.com', 'facebook.com', 'linkedin.com', 'youtube.com',
  'cloudflare.com', 'amazonaws.com', 'cdn.', 'analytics', 'gravatar.com',
  'w3.org', 'schema.org', 'jquery.com', 'bootstrapcdn.com', 'fontawesome.com',
  'mozilla.org', 'apple.com', 'microsoft.com', 'stackoverflow.com'
];

function isExcludedUrl(url) {
  return EXCLUDE_DOMAINS.some(d => url.toLowerCase().includes(d));
}

// Convert wildcard/bare domains to scannable https:// URLs
function normalizeScopeUrl(url) {
  if (!url) return null;
  // Handle wildcard domains like *.example.com -> https://example.com
  if (url.startsWith('*.')) {
    url = 'https://' + url.slice(2);
  }
  // Handle bare domains like example.com -> https://example.com
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }
  // Validate it's a real URL
  try {
    const u = new URL(url);
    // Must have a real TLD-like hostname
    if (!u.hostname.includes('.')) return null;
    return url;
  } catch {
    return null;
  }
}

function isValidApiKey(key) {
  return key && key.length > 20 && !key.includes('placeholder') && !key.includes('your_key') && key.startsWith('sk-');
}

async function callAI(systemPrompt, userPrompt) {
  const apiKey = process.env.OPENROUTER_API_KEY;
  if (!isValidApiKey(apiKey)) {
    throw new Error('NO_AI_KEY');
  }
  try {
    const response = await axios.post(OPENROUTER_API, {
      model: MODEL,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt }
      ],
      max_tokens: 4096,
      temperature: 0.3
    }, {
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'https://github.com/MissDaze/bug-catcher',
        'X-Title': 'Bug Catcher'
      },
      timeout: 60000
    });
    return response.data.choices[0].message.content;
  } catch (err) {
    console.error('AI Error:', err.response?.data || err.message);
    throw new Error(err.response?.data?.error?.message || 'AI service error');
  }
}

// Smart fallback parser for bug bounty pages - no AI needed
function smartParseBountyPage(text, html, pageUrl) {
  const cheerio = require('cheerio');
  const $ = cheerio.load(html || '');

  // Detect platform
  let platform = 'Unknown';
  if (pageUrl.includes('hackerone.com')) platform = 'HackerOne';
  else if (pageUrl.includes('bugcrowd.com')) platform = 'Bugcrowd';
  else if (pageUrl.includes('intigriti.com')) platform = 'Intigriti';
  else if (pageUrl.includes('yeswehack.com')) platform = 'YesWeHack';
  else if (pageUrl.includes('synack.com')) platform = 'Synack';
  else if (pageUrl.includes('cobalt.io')) platform = 'Cobalt';
  else if (pageUrl.includes('immunefi.com')) platform = 'Immunefi';
  else if (pageUrl.includes('openbugbounty.org')) platform = 'Open Bug Bounty';

  // Extract program name
  let program_name = $('h1').first().text().trim() ||
                     $('title').text().trim() ||
                     'Bug Bounty Program';
  if (program_name.length > 80) program_name = program_name.substring(0, 80);

  // --- IMPROVED URL EXTRACTION ---

  // 1. Extract URLs directly from HTML elements (most reliable)
  const htmlUrls = new Set();

  // Look for URLs in table cells, list items, code blocks, pre blocks, paragraphs
  $('td, li, code, pre, p, span, div').each((_, el) => {
    const elText = $(el).text().trim();
    // Match https:// URLs and wildcard/bare scope domains
    const urlMatches = elText.match(/https?:\/\/[^\s"'<>\)\]\,]+|\*\.[a-z0-9][a-z0-9\-]*\.[a-z]{2,}(?:\.[a-z]{2,})?(?:\/[^\s"'<>]*)?/gi);
    if (urlMatches) {
      urlMatches.forEach(u => {
        // Clean trailing punctuation
        u = u.replace(/[.,;:!?]+$/, '');
        if (!isExcludedUrl(u)) htmlUrls.add(u);
      });
    }
  });

  // Also check href attributes for scope URLs
  $('a[href]').each((_, el) => {
    const href = $(el).attr('href') || '';
    if (href.startsWith('http') && !isExcludedUrl(href)) {
      htmlUrls.add(href);
    }
  });

  // 2. Extract URLs from plain text (fallback)
  const urlPattern = /https?:\/\/[^\s"'<>\)\]\,]+|\*\.[a-z0-9][a-z0-9\-]*\.[a-z]{2,}(?:\.[a-z]{2,})?(?:\/[^\s"'<>]*)*/gi;
  const textUrls = new Set(
    (text.match(urlPattern) || [])
      .map(u => u.replace(/[.,;:!?]+$/, ''))
      .filter(u => !isExcludedUrl(u))
  );

  // Merge all found URLs
  const allFoundUrls = [...new Set([...htmlUrls, ...textUrls])];

  // 3. Try to isolate in-scope section from text
  // Use greedy match to capture everything between in-scope and out-of-scope markers
  const inScopePattern = /in[\-\s]?scope[\s\S]+?(?=out[\-\s]?of[\-\s]?scope|$)/i;
  const outScopePattern = /out[\-\s]?of[\-\s]?scope[\s\S]+?(?=in[\-\s]?scope|reward|bounty|rules|$)/i;

  const inScopeMatch = text.match(inScopePattern);
  const outScopeMatch = text.match(outScopePattern);

  // Extract URLs specifically from in-scope section text
  let inScopeUrls = [];
  if (inScopeMatch) {
    const inScopeText = inScopeMatch[0];
    inScopeUrls = (inScopeText.match(urlPattern) || [])
      .map(u => u.replace(/[.,;:!?]+$/, ''))
      .filter(u => !isExcludedUrl(u));
  }

  // Extract out-of-scope URLs
  let outScopeUrls = [];
  if (outScopeMatch) {
    outScopeUrls = (outScopeMatch[0].match(urlPattern) || [])
      .map(u => u.replace(/[.,;:!?]+$/, ''))
      .filter(u => !isExcludedUrl(u))
      .slice(0, 15);
  }

  // 4. Build final in_scope list with priority:
  //    a) URLs from in-scope section text
  //    b) URLs from HTML elements
  //    c) All found URLs as last resort
  let rawScopeUrls;
  if (inScopeUrls.length > 0) {
    rawScopeUrls = [...new Set([...inScopeUrls, ...allFoundUrls])].slice(0, 30);
  } else {
    rawScopeUrls = allFoundUrls.slice(0, 30);
  }

  // 5. Normalize and validate all scope URLs
  const in_scope = rawScopeUrls
    .map(url => {
      const normalized = normalizeScopeUrl(url);
      if (!normalized) return null;
      return {
        url: normalized,
        type: normalized.includes('/api/') || normalized.includes('api.') ? 'api'
             : (normalized.includes('mobile') || normalized.includes('app.')) ? 'mobile'
             : 'web',
        requires_credentials: /login|admin|dashboard|account|portal|internal/i.test(normalized),
        notes: url !== normalized ? `Original: ${url}` : ''
      };
    })
    .filter(Boolean)
    // Deduplicate by URL
    .filter((item, idx, arr) => arr.findIndex(x => x.url === item.url) === idx)
    .slice(0, 25);

  // Extract bounty amounts
  const bountyMatch = text.match(/\$[\d,]+(?:\s*[-\u2013]\s*\$[\d,]+)?|\d+(?:,\d+)?\s*(?:USD|EUR|USDT)/i);
  const bounty_range = bountyMatch ? bountyMatch[0] : 'See program page';

  // Extract rules
  const rules = [];
  const ruleKeywords = ['do not', 'must not', 'prohibited', 'allowed', 'responsible', 'disclose'];
  const sentences = text.split(/[.!?\n]/).map(s => s.trim()).filter(s => s.length > 20 && s.length < 200);
  sentences.forEach(s => {
    if (ruleKeywords.some(k => s.toLowerCase().includes(k))) {
      rules.push(s);
    }
  });

  return {
    program_name,
    platform,
    in_scope,
    out_of_scope: outScopeUrls,
    bounty_range,
    rules: rules.slice(0, 10),
    report_format: 'Standard vulnerability report with steps to reproduce, impact, and PoC',
    severity_levels: ['critical', 'high', 'medium', 'low'],
    platform_guidelines_url: pageUrl,
    note: isValidApiKey(process.env.OPENROUTER_API_KEY)
      ? 'Extracted via smart parser (page may require login for full scope)'
      : 'Extracted via smart parser. Add an OpenRouter API key at openrouter.ai for enhanced AI analysis.'
  };
}

async function extractBountyScope(pageContent, pageUrl, html) {
  // Try AI first
  try {
    const system = `You are a bug bounty analyst. Extract structured information from bug bounty program pages. Always respond with valid JSON only, no markdown, no explanation.`;
    const user = `Extract all bug bounty scope information from this page content.
Page URL: ${pageUrl}

Page Content:
${pageContent.substring(0, 8000)}

Respond with JSON in this exact format:
{
  "program_name": "string",
  "platform": "string",
  "in_scope": [
    {
      "url": "string",
      "type": "web|api|mobile|other",
      "requires_credentials": true|false,
      "notes": "string"
    }
  ],
  "out_of_scope": ["url or description"],
  "bounty_range": "string",
  "rules": ["rule1", "rule2"],
  "report_format": "string",
  "severity_levels": ["critical","high","medium","low"],
  "platform_guidelines_url": "string"
}`;
    const result = await callAI(system, user);
    const clean = result.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    const parsed = JSON.parse(clean);
    // Normalize AI-returned URLs too (handles wildcards etc.)
    if (parsed.in_scope && Array.isArray(parsed.in_scope)) {
      parsed.in_scope = parsed.in_scope
        .map(item => {
          const normalized = normalizeScopeUrl(item.url);
          if (!normalized) return null;
          return { ...item, url: normalized };
        })
        .filter(Boolean);
    }
    return parsed;
  } catch (err) {
    if (err.message === 'NO_AI_KEY') {
      console.log('No valid AI key - using smart parser fallback');
    } else {
      console.warn('AI failed, falling back to smart parser:', err.message);
    }
    // Fallback to smart parser
    return smartParseBountyPage(pageContent, html || '', pageUrl);
  }
}

async function analyzeVulnerability(finding, targetUrl, evidence) {
  try {
    const system = `You are a senior penetration tester and security researcher.`;
    const user = `Analyze this potential vulnerability:

Target URL: ${targetUrl}
Finding Type: ${finding.type}
Finding Details: ${finding.details}
Evidence: ${JSON.stringify(evidence).substring(0, 2000)}

Provide a JSON response with:
{
  "confirmed": true|false,
  "severity": "critical|high|medium|low|informational",
  "cvss_score": 0.0-10.0,
  "vulnerability_name": "string",
  "description": "string",
  "impact": "string",
  "exploitation_steps": ["step1", "step2"],
  "proof_of_concept": "string",
  "remediation": "string",
  "references": ["CVE or OWASP reference"]
}`;
    const result = await callAI(system, user);
    const clean = result.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    return JSON.parse(clean);
  } catch {
    return {
      confirmed: true,
      severity: finding.severity || 'medium',
      cvss_score: 5.0,
      vulnerability_name: finding.type,
      description: finding.details,
      impact: 'Potential security risk identified',
      exploitation_steps: ['See finding details'],
      proof_of_concept: finding.details,
      remediation: 'Review and remediate the identified issue',
      references: ['OWASP Top 10']
    };
  }
}

async function generateReport(vulnerability, programInfo, screenshots) {
  try {
    const system = `You are an expert bug bounty report writer.`;
    const user = `Write a complete bug bounty report for this vulnerability:

Program: ${JSON.stringify(programInfo)}
Vulnerability: ${JSON.stringify(vulnerability)}
Screenshots available: ${screenshots.length}

Write a comprehensive report with: Title, Severity, Summary, Steps to Reproduce, Impact, Remediation.`;
    return await callAI(system, user);
  } catch {
    return `# Bug Bounty Report\n\n## ${vulnerability.vulnerability_name || vulnerability.type}\n\n**Severity:** ${vulnerability.severity}\n\n## Summary\n${vulnerability.description}\n\n## Impact\n${vulnerability.impact}\n\n## Steps to Reproduce\n${(vulnerability.exploitation_steps || []).map((s,i) => `${i+1}. ${s}`).join('\n')}\n\n## Remediation\n${vulnerability.remediation}`;
  }
}

module.exports = { callAI, extractBountyScope, analyzeVulnerability, generateReport };
