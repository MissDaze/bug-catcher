const axios = require('axios');
const cheerio = require('cheerio');

const JS_HEAVY_DOMAINS = [
  'hackerone.com', 'bugcrowd.com', 'intigriti.com',
  'yeswehack.com', 'synack.com', 'cobalt.io',
  'immunefi.com', 'federacy.com', 'integrity.st'
];

async function fetchWithPlaywright(url) {
  let browser = null;
  try {
    const { chromium } = require('playwright');
    browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu']
    });
    const page = await browser.newPage();
    await page.setExtraHTTPHeaders({
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    });
    await page.goto(url, { waitUntil: 'networkidle', timeout: 30000 });
    // Wait extra for SPA content to fully render
    await page.waitForTimeout(4000);
    const html = await page.content();
    const $ = cheerio.load(html);
    // Only remove scripts and styles for text extraction - keep nav/header/footer
    // as scope sections may appear in sidebars or navigation-like elements
    $('script, style').remove();
    const text = $('body').text().replace(/\s+/g, ' ').trim();
    return { text, html, status: 200, url };
  } catch (err) {
    throw new Error(`Playwright fetch failed: ${err.message}`);
  } finally {
    if (browser) await browser.close();
  }
}

async function fetchPageContent(url) {
  const isJsHeavy = JS_HEAVY_DOMAINS.some(d => url.includes(d));

  if (isJsHeavy) {
    try {
      console.log(`Using Playwright for JS-heavy page: ${url}`);
      return await fetchWithPlaywright(url);
    } catch (pwErr) {
      console.warn(`Playwright failed, falling back to axios: ${pwErr.message}`);
    }
  }

  try {
    const response = await axios.get(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9'
      },
      timeout: 30000,
      maxRedirects: 5
    });
    const html = response.data;
    const $ = cheerio.load(html);
    // Only remove scripts and styles - preserve nav/header/footer for scope extraction
    $('script, style').remove();
    const text = $('body').text().replace(/\s+/g, ' ').trim();
    return { text, html, status: response.status, headers: response.headers, url: response.config.url };
  } catch (err) {
    throw new Error(`Failed to fetch ${url}: ${err.message}`);
  }
}

async function extractLinks(url) {
  try {
    const { html } = await fetchPageContent(url);
    const $ = cheerio.load(html);
    const baseUrl = new URL(url);
    const links = new Set();
    $('a[href]').each((_, el) => {
      const href = $(el).attr('href');
      try {
        const abs = new URL(href, baseUrl).href;
        if (abs.startsWith('http')) links.add(abs);
      } catch {}
    });
    return [...links];
  } catch { return []; }
}

async function checkUrl(url) {
  try {
    const start = Date.now();
    const res = await axios.head(url, { timeout: 10000, maxRedirects: 3,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; BugCatcher/2.0)' }
    });
    return { url, alive: true, status: res.status, responseTime: Date.now() - start, headers: res.headers };
  } catch (err) {
    return { url, alive: false, status: err.response?.status || 0, error: err.message };
  }
}

module.exports = { fetchPageContent, extractLinks, checkUrl };
