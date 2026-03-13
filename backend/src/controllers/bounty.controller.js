const { fetchPageContent } = require('../services/scraper.service');
const { extractBountyScope } = require('../services/ai.service');

exports.analyzeBountyPage = async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ success: false, message: 'URL is required' });
    console.log(`Analyzing bounty page: ${url}`);
    const { text, html } = await fetchPageContent(url);
    const scope = await extractBountyScope(text, url, html);
    res.json({ success: true, data: scope });
  } catch (err) {
    console.error('Bounty analyze error:', err);
    res.status(500).json({ success: false, message: err.message });
  }
};
