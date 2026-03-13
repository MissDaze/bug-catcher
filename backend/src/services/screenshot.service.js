const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const SCREENSHOTS_DIR = path.resolve(
  process.env.SCREENSHOTS_DIR || path.join(__dirname, '../../screenshots')
);

if (!fs.existsSync(SCREENSHOTS_DIR)) {
  fs.mkdirSync(SCREENSHOTS_DIR, { recursive: true });
}

let playwrightAvailable = false;
let chromium = null;

try {
  chromium = require('playwright').chromium;
  playwrightAvailable = true;
  console.log('✅ Playwright available - screenshots enabled');
} catch (e) {
  console.warn('⚠️  Playwright not available - screenshots will be skipped:', e.message);
}

async function takeScreenshot(url, label = '', options = {}) {
  if (!playwrightAvailable || !chromium) {
    console.warn('Screenshot skipped (Playwright unavailable):', label);
    return null;
  }

  let browser;
  try {
    const launchOptions = {
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--single-process',
        '--no-zygote'
      ]
    };

    if (process.env.CHROMIUM_PATH) {
      launchOptions.executablePath = process.env.CHROMIUM_PATH;
    }

    browser = await chromium.launch(launchOptions);
    const context = await browser.newContext({
      viewport: { width: 1280, height: 900 },
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
      ignoreHTTPSErrors: true
    });

    const page = await context.newPage();
    await page.goto(url, { timeout: 20000, waitUntil: 'domcontentloaded' }).catch(() => {});
    await page.waitForTimeout(1500).catch(() => {});

    const filename = `${uuidv4()}.png`;
    const filepath = path.join(SCREENSHOTS_DIR, filename);
    await page.screenshot({ path: filepath, fullPage: false });

    return {
      filename,
      filepath,
      url,
      label,
      timestamp: new Date().toISOString(),
      webPath: `/screenshots/${filename}`
    };
  } catch (err) {
    console.error('Screenshot error:', err.message);
    return null;
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
}

module.exports = { takeScreenshot };
