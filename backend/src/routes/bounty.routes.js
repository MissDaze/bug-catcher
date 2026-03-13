const express = require('express');
const router = express.Router();
const { analyzeBountyPage } = require('../controllers/bounty.controller');
router.post('/analyze', analyzeBountyPage);
module.exports = router;
