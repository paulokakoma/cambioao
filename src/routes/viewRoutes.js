const express = require('express');
const router = express.Router();
const viewController = require('../controllers/viewController');
const config = require('../config/env');

router.get("/", viewController.serveIndex);
router.get("/login", viewController.serveLogin);
router.get("/admin", viewController.serveAdmin);
router.get(config.admin.secretPath, viewController.serveAdminSecret);
router.get("/sobre", viewController.serveAbout);
router.get("/visa", viewController.serveVisa);
router.get("/termos", viewController.serveTerms);
router.get("/privacidade", viewController.servePrivacy);
router.get("/robots.txt", viewController.serveRobots);
router.get("/sitemap.xml", viewController.serveSitemap);
router.get("/BingSiteAuth.xml", viewController.serveBingAuth);
router.get("/yandex_*.html", viewController.serveYandexAuth);

module.exports = router;
