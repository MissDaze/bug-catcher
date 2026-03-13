const axios = require('axios');

const OPENROUTER_API = 'https://openrouter.ai/api/v1/chat/completions';
const MODEL = process.env.OPENROUTER_MODEL || 'mistralai/mistral-7b-instruct:free';

async function callAI(systemPrompt, userPrompt) {
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
        'Authorization': `Bearer ${process.env.OPENROUTER_API_KEY}`,
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

async function extractBountyScope(pageContent, pageUrl) {
  const system = `You are a bug bounty analyst. Extract structured information from bug bounty program pages.
Always respond with valid JSON only, no markdown, no explanation.`;
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
  try {
    const clean = result.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    return JSON.parse(clean);
  } catch {
    return { program_name: 'Unknown', in_scope: [], out_of_scope: [], rules: [], report_format: 'Standard', raw: result };
  }
}

async function analyzeVulnerability(finding, targetUrl, evidence) {
  const system = `You are a senior penetration tester and security researcher. Analyze vulnerability findings and provide detailed exploitation analysis.`;
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
  try {
    const clean = result.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    return JSON.parse(clean);
  } catch {
    return { confirmed: false, severity: 'low', description: result, exploitation_steps: [] };
  }
}

async function generateReport(vulnerability, programInfo, screenshots) {
  const system = `You are an expert bug bounty report writer. Write professional, detailed vulnerability reports following platform guidelines.`;
  const user = `Write a complete bug bounty report for this vulnerability:

Program: ${JSON.stringify(programInfo)}
Vulnerability: ${JSON.stringify(vulnerability)}
Screenshots available: ${screenshots.length}

Write a comprehensive report following the program's report format guidelines.
Include: Title, Severity, Summary, Steps to Reproduce, Impact, Remediation.
Make it professional and convincing with clear evidence references.`;
  return await callAI(system, user);
}

module.exports = { callAI, extractBountyScope, analyzeVulnerability, generateReport };
