const axios = require('axios');
const cheerio = require('cheerio');

async function fetchPageContent(url) {
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
    const $ = cheerio.load(response.data);
    // Remove scripts and styles for cleaner text
    $('script, style, nav, footer').remove();
    const text = $('body').text().replace(/\s+/g, ' ').trim();
    const html = response.data;
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
