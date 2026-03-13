const { v4: uuidv4 } = require('uuid');
const { runScan, getScan } = require('../services/scan.service');
const { io: getIO } = require('../server');

let _io;
const setIO = (io) => { _io = io; };

exports.startScan = async (req, res) => {
  try {
    const { urls, programInfo } = req.body;
    if (!urls || !Array.isArray(urls) || urls.length === 0) {
      return res.status(400).json({ success: false, message: 'URLs array is required' });
    }
    const scanId = uuidv4();
    res.json({ success: true, scanId, message: 'Scan started' });
    // Run scan async - io is injected via middleware
    const io = req.app.get('io');
    runScan(io, scanId, urls, { programInfo }).catch(err => {
      console.error('Scan error:', err);
      io.to(scanId).emit('scan_error', { message: err.message });
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

exports.getScanStatus = async (req, res) => {
  try {
    const scan = getScan(req.params.scanId);
    if (!scan) return res.status(404).json({ success: false, message: 'Scan not found' });
    res.json({ success: true, data: { id: scan.id, status: scan.status, findingCount: scan.findings.length, screenshotCount: scan.screenshots.length } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

exports.cancelScan = async (req, res) => {
  try {
    const scan = getScan(req.params.scanId);
    if (!scan) return res.status(404).json({ success: false, message: 'Scan not found' });
    scan.status = 'cancelled';
    res.json({ success: true, message: 'Scan cancelled' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};
