const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const isAdmin = require('../middleware/auth');

router.post('/login', authController.login);
router.post('/logout', authController.logout);
router.get('/me', isAdmin, authController.me);

module.exports = router;
