const config = require('../config/env');

const isAdmin = (req, res, next) => {
    // Em produção, só permite acesso ao admin via subdomínio admin
    if (!config.isDevelopment && !req.isAdminSubdomain && req.path.startsWith('/admin')) {
        return res.status(403).send('Acesso ao admin apenas via subdomínio admin.');
    }

    if (req.session.isAdmin) return next();

    // Para chamadas de API, retornar JSON 401 em vez de redirecionar (evita sucesso falso no frontend)
    if (req.path.startsWith('/api')) {
        return res.status(401).json({ success: false, message: 'Sessão expirada ou não autenticada.' });
    }
    // Para páginas, redireciona para login
    return res.redirect('/login');
};

module.exports = isAdmin;
