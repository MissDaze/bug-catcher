const express = require('express');
const router = express.Router();
const { startScan, getScanStatus, cancelScan } = require('../controllers/scan.controller');
router.post('/start', startScan);
router.get('/:scanId', getScanStatus);
router.post('/:scanId/cancel', cancelScan);
module.exports = router;
