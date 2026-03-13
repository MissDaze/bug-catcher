require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');

const scanRoutes = require('./routes/scan.routes');
const bountyRoutes = require('./routes/bounty.routes');
const reportRoutes = require('./routes/report.routes');
const { cancelScan } = require('./services/scan.service');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*', methods: ['GET', 'POST'] } });

app.set('io', io);

['screenshots', 'reports'].forEach(dir => {
  const p = path.join(__dirname, '..', dir);
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
});

// Rate limiters
const scanLimiter = rateLimit({ windowMs: 60 * 1000, max: 10, message: { success: false, message: 'Too many scan requests, slow down.' } });
const bountyLimiter = rateLimit({ windowMs: 60 * 1000, max: 20, message: { success: false, message: 'Too many requests, slow down.' } });

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(morgan('dev'));
app.use('/screenshots', express.static(path.join(__dirname, '../screenshots')));
app.use('/reports', express.static(path.join(__dirname, '../reports')));

const frontendBuild = path.join(__dirname, '../../frontend/build');
if (fs.existsSync(frontendBuild)) app.use(express.static(frontendBuild));

app.use('/api/scan', scanLimiter, scanRoutes);
app.use('/api/bounty', bountyLimiter, bountyRoutes);
app.use('/api/report', reportRoutes);
app.get('/api/health', (req, res) => res.json({ status: 'OK', time: new Date().toISOString() }));

app.get('*', (req, res) => {
  const indexPath = path.join(__dirname, '../../frontend/build/index.html');
  if (fs.existsSync(indexPath)) res.sendFile(indexPath);
  else res.json({ message: 'Bug Catcher API v2.0', status: 'running' });
});

// Socket.IO — scan room management
io.on('connection', (socket) => {
  socket.on('join_scan', (scanId) => {
    if (scanId && typeof scanId === 'string') socket.join(scanId);
  });
  socket.on('cancel_scan', (scanId) => {
    if (scanId) {
      cancelScan(scanId);
      io.to(scanId).emit('log', { message: 'Scan cancelled by user', level: 'warn', timestamp: new Date().toISOString() });
    }
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n[*] Bug Catcher v2.0 running on port ${PORT}`);
  console.log(`[*] Comprehensive scanning: 29 vulnerability checks`);
  console.log(`[*] Crawler: available (user-configurable toggle)`);
});

module.exports = { app, io };
