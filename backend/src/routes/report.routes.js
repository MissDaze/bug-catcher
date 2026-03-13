const express = require('express');
const router = express.Router();
const { downloadReport } = require('../controllers/report.controller');
router.post('/generate', downloadReport);
module.exports = router;
