'use strict';
const { v4: uuidv4 } = require('uuid');
const { startScan, getScan, cancelScan } = require('../services/scan.service');

exports.startScan = async (req, res) => {
  try {
    const { urls, programInfo, crawl, inScopeList, credentials } = req.body;
    if (!urls || !Array.isArray(urls) || urls.length === 0) {
      return res.status(400).json({ success: false, message: 'URLs array is required' });
    }
    const scanId = uuidv4();
    const io = req.app.get('io');
    const scan = startScan(io, scanId, urls, {
      programInfo,
      crawl: crawl === true,
      inScopeList: inScopeList || [],
      credentials: credentials || null,
    });
    res.json({ success: true, scanId, message: 'Scan started' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

exports.getScanStatus = async (req, res) => {
  try {
    const scan = getScan(req.params.scanId);
    if (!scan) return res.status(404).json({ success: false, message: 'Scan not found' });
    res.json({ success: true, data: { scanId: scan.scanId, status: scan.status, findingCount: scan.findings.length, findings: scan.findings } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

exports.cancelScan = async (req, res) => {
  try {
    const cancelled = cancelScan(req.params.scanId);
    if (!cancelled) return res.status(404).json({ success: false, message: 'Scan not found or not running' });
    res.json({ success: true, message: 'Scan cancelled' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};
