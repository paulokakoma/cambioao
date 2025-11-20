const express = require('express');
const router = express.Router();
const publicController = require('../controllers/publicController');

router.get('/config', publicController.getConfig);
router.get('/informal-rates', publicController.getInformalRates);
router.post('/log-activity', publicController.logActivity);
router.get('/visa-settings', publicController.getVisaSettings);
router.get('/affiliate-details/:id', publicController.getAffiliateDetails);
router.get('/status', publicController.getStatus);

module.exports = router;
