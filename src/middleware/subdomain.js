const config = require('../config/env');

const subdomainMiddleware = (req, res, next) => {
    const host = req.get('host') || '';

    // Remove porta do host para análise
    const hostWithoutPort = host.split(':')[0];
    const parts = hostWithoutPort.split('.');

    // Detecta subdomínio admin
    // Em dev: admin.localhost -> parts = ['admin', 'localhost']
    // Em prod: admin.dominio.com -> parts = ['admin', 'dominio', 'com']
    // localhost -> parts = ['localhost']
    const isAdminSubdomain = parts[0] === 'admin' && parts.length > 1;

    // Define flag no request para uso nas rotas
    req.isAdminSubdomain = isAdminSubdomain;
    req.isMainDomain = !isAdminSubdomain;

    // Debug em desenvolvimento
    if (config.isDevelopment) {
        console.log(`[${req.method}] ${req.path} - Host: ${host} - Admin: ${isAdminSubdomain}`);
    }

    next();
};

module.exports = subdomainMiddleware;
