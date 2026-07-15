// Gates the scan/bounty/report routes behind a shared access code. These
// routes run an active vulnerability scanner and AI calls against
// arbitrary URLs with no login required — without this, any anonymous
// visitor could point the scanner at third-party sites using this
// server's infrastructure, or burn the configured AI key. Fails closed:
// if DEMO_ACCESS_CODE isn't set, every request is rejected.
function demoGate(req, res, next) {
  const code = process.env.DEMO_ACCESS_CODE;
  if (code && req.headers['x-demo-code'] === code) return next();
  return res.status(401).json({ error: 'Demo access code required.', gated: true });
}

module.exports = { demoGate };
