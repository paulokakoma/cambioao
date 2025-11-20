const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');
const isAdmin = require('../middleware/auth');
const upload = require('../middleware/upload');

// Apply admin middleware to all routes in this router
router.use(isAdmin);

router.get('/rate_providers', adminController.getRateProviders);
router.get('/affiliate_links', adminController.getAffiliateLinks);
router.get('/supporters', adminController.getSupporters);
router.get('/currencies', adminController.getCurrencies);
router.get('/settings', adminController.getSettings);
router.post('/visa-settings', upload.single('visa_image'), adminController.updateVisaSettings);
router.post('/supporter', upload.single('banner_image'), adminController.createSupporter);
router.get('/recent-activity', adminController.getRecentActivity);
router.post('/notify-update', adminController.notifyUpdate);
router.post('/add-province', adminController.addProvince);
router.post('/update-status', adminController.updateStatus);
router.post('/update-cell', adminController.updateCell);

// Dashboard & Stats
router.get('/dashboard-stats', adminController.getDashboardStats);
router.get('/weekly-activity', adminController.getWeeklyActivity);
router.get('/event-types-stats', adminController.getEventTypeStats);
router.post('/reset-stats', adminController.resetStats);

// Generic Resource Handlers
router.post('/bank', adminController.handleResourcePost('bank', 'rate_providers'));
router.post('/affiliate', adminController.handleResourcePost('affiliate', 'affiliate_links'));
router.post('/currency', adminController.handleResourcePost('currency', 'currencies'));
router.post('/province', adminController.handleResourcePost('province', 'rate_providers'));
router.post('/rate_providers', adminController.handleResourcePost('rate_providers', 'rate_providers'));

// Delete Generic
router.delete('/:resource/:id', async (req, res) => {
    const { resource, id } = req.params;
    const tableMap = { rate_providers: 'rate_providers', bank: 'rate_providers', province: 'rate_providers', affiliate: 'affiliate_links', currency: 'currencies', supporter: 'supporters' };
    const tableName = tableMap[resource];
    if (!tableName) return res.status(404).json({ message: "Recurso não encontrado." });

    const supabase = require('../config/supabase');
    const { handleSupabaseError } = require('../utils/errorHandler');

    const { error } = await supabase.from(tableName).delete().eq('id', id);
    if (error) return handleSupabaseError(error, res);
    res.status(200).json({ success: true, message: "Recurso apagado." });
});

module.exports = router;
