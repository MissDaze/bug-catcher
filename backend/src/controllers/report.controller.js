const { getScan } = require('../services/scan.service');
const { generatePDFReport } = require('../services/report.service');

exports.downloadReport = async (req, res) => {
  try {
    const { scanId, programInfo } = req.body;
    const scan = getScan(scanId);
    if (!scan) return res.status(404).json({ success: false, message: 'Scan not found' });
    const report = await generatePDFReport(scan, programInfo);
    res.json({ success: true, data: report });
  } catch (err) {
    console.error('Report error:', err);
    res.status(500).json({ success: false, message: err.message });
  }
};
