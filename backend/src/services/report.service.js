const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { generateReport } = require('./ai.service');

const REPORTS_DIR = path.join(__dirname, '../../reports');

async function generatePDFReport(scan, programInfo) {
  const reportId = uuidv4();
  const filename = `bug-catcher-report-${reportId}.pdf`;
  const filepath = path.join(REPORTS_DIR, filename);

  return new Promise(async (resolve, reject) => {
    try {
      const doc = new PDFDocument({ size: 'A4', margin: 50, info: { Title: 'Bug Catcher Security Report', Author: 'Bug Catcher v2.0' } });
      const stream = fs.createWriteStream(filepath);
      doc.pipe(stream);

      // Colors
      const GREEN = '#00ff41';
      const BLACK = '#0a0a0a';
      const WHITE = '#ffffff';
      const RED = '#ff4444';
      const YELLOW = '#ffcc00';

      // ---- COVER PAGE ----
      doc.rect(0, 0, doc.page.width, doc.page.height).fill(BLACK);
      doc.fill(GREEN).fontSize(42).font('Helvetica-Bold').text('[ BUG CATCHER ]', 50, 150, { align: 'center' });
      doc.fill(WHITE).fontSize(18).text('Security Assessment Report', { align: 'center' });
      doc.moveDown(2);
      doc.fill(GREEN).fontSize(12).text(`Generated: ${new Date().toUTCString()}`, { align: 'center' });
      doc.fill(WHITE).fontSize(12).text(`Scan ID: ${scan.id}`, { align: 'center' });
      doc.moveDown(1);
      doc.fill(GREEN).text(`Targets Scanned: ${scan.urls?.length || 0}`, { align: 'center' });
      doc.fill(RED).text(`Vulnerabilities Found: ${scan.findings?.length || 0}`, { align: 'center' });

      doc.addPage();

      // ---- EXECUTIVE SUMMARY ----
      doc.fill(GREEN).fontSize(20).font('Helvetica-Bold').text('Executive Summary');
      doc.moveDown(0.5);
      doc.rect(50, doc.y, doc.page.width - 100, 2).fill(GREEN);
      doc.moveDown(0.5);

      const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
      scan.findings?.forEach(f => {
        const sev = (f.severity || 'low').toLowerCase();
        if (severityCounts[sev] !== undefined) severityCounts[sev]++;
        else severityCounts.informational++;
      });

      doc.fill(WHITE).fontSize(11).font('Helvetica');
      doc.text(`This report documents the findings from an automated security assessment conducted by Bug Catcher.`);
      doc.moveDown(0.5);
      doc.text(`Scan Duration: ${scan.startTime ? Math.round((new Date(scan.endTime) - new Date(scan.startTime)) / 1000) : 0} seconds`);
      doc.text(`Screenshots Captured: ${scan.screenshots?.length || 0}`);
      doc.moveDown(1);

      // Severity table
      doc.fill(GREEN).fontSize(13).font('Helvetica-Bold').text('Vulnerability Summary by Severity:');
      doc.moveDown(0.5);
      const sevColors = { critical: '#cc0000', high: '#ff4444', medium: '#ffaa00', low: '#44cc44', informational: '#888888' };
      Object.entries(severityCounts).forEach(([sev, count]) => {
        doc.fill(sevColors[sev] || WHITE).font('Helvetica-Bold').text(`  ${sev.toUpperCase()}: `, { continued: true });
        doc.fill(WHITE).font('Helvetica').text(String(count));
      });

      if (programInfo) {
        doc.moveDown(1);
        doc.fill(GREEN).fontSize(13).font('Helvetica-Bold').text('Program Information:');
        doc.fill(WHITE).fontSize(11).font('Helvetica');
        if (programInfo.program_name) doc.text(`Program: ${programInfo.program_name}`);
        if (programInfo.bounty_range) doc.text(`Bounty Range: ${programInfo.bounty_range}`);
        if (programInfo.platform) doc.text(`Platform: ${programInfo.platform}`);
      }

      // ---- FINDINGS ----
      for (let i = 0; i < (scan.findings || []).length; i++) {
        const finding = scan.findings[i];
        doc.addPage();
        doc.rect(0, 0, doc.page.width, doc.page.height).fill('#050505');

        const sevColor = sevColors[finding.severity?.toLowerCase()] || WHITE;
        doc.fill(sevColor).fontSize(16).font('Helvetica-Bold');
        doc.text(`[${finding.severity?.toUpperCase() || 'UNKNOWN'}] Finding #${i + 1}: ${finding.type || finding.vulnerability_name || 'Vulnerability'}`);
        doc.moveDown(0.3);
        doc.rect(50, doc.y, doc.page.width - 100, 1).fill(sevColor);
        doc.moveDown(0.5);

        doc.fill(WHITE).fontSize(10).font('Helvetica');
        if (finding.targetUrl) doc.text(`Target URL: ${finding.targetUrl}`);
        if (finding.url && finding.url !== finding.targetUrl) doc.text(`Finding URL: ${finding.url}`);
        if (finding.cvss_score) doc.text(`CVSS Score: ${finding.cvss_score}`);
        doc.moveDown(0.5);

        if (finding.description) {
          doc.fill(GREEN).fontSize(12).font('Helvetica-Bold').text('Description:');
          doc.fill(WHITE).fontSize(10).font('Helvetica').text(finding.description);
          doc.moveDown(0.5);
        }

        if (finding.details) {
          doc.fill(GREEN).fontSize(12).font('Helvetica-Bold').text('Technical Details:');
          doc.fill(WHITE).fontSize(10).font('Helvetica').text(finding.details);
          doc.moveDown(0.5);
        }

        if (finding.impact) {
          doc.fill(GREEN).fontSize(12).font('Helvetica-Bold').text('Impact:');
          doc.fill(WHITE).fontSize(10).font('Helvetica').text(finding.impact);
          doc.moveDown(0.5);
        }

        if (finding.exploitation_steps?.length > 0) {
          doc.fill(GREEN).fontSize(12).font('Helvetica-Bold').text('Steps to Reproduce:');
          finding.exploitation_steps.forEach((step, idx) => {
            doc.fill(WHITE).fontSize(10).font('Helvetica').text(`${idx + 1}. ${step}`);
          });
          doc.moveDown(0.5);
        }

        if (finding.proof_of_concept) {
          doc.fill(GREEN).fontSize(12).font('Helvetica-Bold').text('Proof of Concept:');
          doc.fill('#00cc33').fontSize(9).font('Helvetica').text(finding.proof_of_concept);
          doc.moveDown(0.5);
        }

        if (finding.remediation) {
          doc.fill(YELLOW).fontSize(12).font('Helvetica-Bold').text('Remediation:');
          doc.fill(WHITE).fontSize(10).font('Helvetica').text(finding.remediation);
          doc.moveDown(0.5);
        }

        // Add screenshots for this finding
        const findingScreenshots = (scan.screenshots || []).filter(s => s.findingId === finding.id || s.label?.includes(finding.type));
        for (const shot of findingScreenshots.slice(0, 2)) {
          if (shot.filepath && fs.existsSync(shot.filepath)) {
            doc.moveDown(0.5);
            doc.fill(GREEN).fontSize(11).font('Helvetica-Bold').text(`Evidence Screenshot: ${shot.label}`);
            try {
              doc.image(shot.filepath, { fit: [480, 280], align: 'center' });
            } catch (imgErr) {
              doc.fill('#888888').text('[Screenshot could not be embedded]');
            }
          }
        }
      }

      // ---- APPENDIX ----
      doc.addPage();
      doc.rect(0, 0, doc.page.width, doc.page.height).fill(BLACK);
      doc.fill(GREEN).fontSize(18).font('Helvetica-Bold').text('Appendix: All Evidence Screenshots');
      doc.moveDown(0.5);
      doc.rect(50, doc.y, doc.page.width - 100, 2).fill(GREEN);
      doc.moveDown(0.5);

      for (const shot of (scan.screenshots || []).slice(0, 20)) {
        if (shot.filepath && fs.existsSync(shot.filepath)) {
          try {
            doc.fill(WHITE).fontSize(9).font('Helvetica').text(`${shot.label} - ${shot.url} - ${shot.timestamp}`);
            doc.image(shot.filepath, { fit: [450, 250], align: 'center' });
            doc.moveDown(0.5);
          } catch {}
        }
      }

      doc.end();
      stream.on('finish', () => resolve({ filename, filepath, webPath: `/reports/${filename}`, reportId }));
      stream.on('error', reject);
    } catch (err) { reject(err); }
  });
}

module.exports = { generatePDFReport };
