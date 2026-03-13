require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');

const scanRoutes = require('./routes/scan.routes');
const bountyRoutes = require('./routes/bounty.routes');
const reportRoutes = require('./routes/report.routes');
const { setupScanSocket } = require('./services/scan.service');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*', methods: ['GET', 'POST'] } });

app.set('io', io);

['screenshots', 'reports'].forEach(dir => {
  const p = path.join(__dirname, '..', dir);
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(morgan('dev'));
app.use('/screenshots', express.static(path.join(__dirname, '../screenshots')));
app.use('/reports', express.static(path.join(__dirname, '../reports')));

const frontendBuild = path.join(__dirname, '../../frontend/build');
if (fs.existsSync(frontendBuild)) app.use(express.static(frontendBuild));

app.use('/api/scan', scanRoutes);
app.use('/api/bounty', bountyRoutes);
app.use('/api/report', reportRoutes);
app.get('/api/health', (req, res) => res.json({ status: 'OK', time: new Date().toISOString() }));

app.get('*', (req, res) => {
  const indexPath = path.join(__dirname, '../../frontend/build/index.html');
  if (fs.existsSync(indexPath)) res.sendFile(indexPath);
  else res.json({ message: 'Bug Catcher API v2.0', status: 'running' });
});

setupScanSocket(io);

const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🐛 Bug Catcher v2.0 running on port ${PORT}`);
});

module.exports = { app, io };
