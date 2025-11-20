const path = require("path");
const config = require("../config/env");
const supabase = require("../config/supabase");

const serveIndex = (req, res) => {
    if (req.isAdminSubdomain) {
        return res.redirect('/admin');
    }
    res.sendFile(path.join(__dirname, "../../public", "index.html"));
};

const serveLogin = (req, res) => {
    res.sendFile(path.join(__dirname, "../../public", "login.html"));
};

const serveAdmin = (req, res) => {
    if (!config.isDevelopment && !req.isAdminSubdomain) {
        const protocol = req.protocol;
        const host = req.get('host') || '';
        const hostWithoutPort = host.split(':')[0];
        const adminUrl = `${protocol}://admin.${hostWithoutPort}${req.originalUrl}`;
        return res.redirect(adminUrl);
    }

    if (!req.session.isAdmin) {
        return res.redirect('/login');
    }

    res.sendFile(path.join(__dirname, "../../private", "admin.html"));
};

const serveAdminSecret = (req, res) => {
    if (req.session.isAdmin) {
        if (req.isAdminSubdomain) {
            return res.redirect('/admin');
        }
        const protocol = req.protocol;
        const host = req.get('host') || 'localhost:3000';
        const hostWithoutPort = host.split(':')[0];
        const adminUrl = config.isDevelopment
            ? `${protocol}://admin.localhost:${config.port}/admin`
            : `${protocol}://admin.${hostWithoutPort}/admin`;
        return res.redirect(adminUrl);
    }
    const protocol = req.protocol;
    const host = req.get('host') || 'localhost:3000';
    const hostWithoutPort = host.split(':')[0];
    const loginUrl = config.isDevelopment
        ? `${protocol}://admin.localhost:${config.port}/login`
        : `${protocol}://admin.${hostWithoutPort}/login`;
    return res.redirect(loginUrl);
};

const serveAbout = (req, res) => {
    if (req.isAdminSubdomain) {
        return res.status(404).send('Página não encontrada');
    }
    res.sendFile(path.join(__dirname, "../../public", "about.html"));
};

const serveVisa = (req, res) => {
    if (req.isAdminSubdomain) {
        return res.status(404).send('Página não encontrada');
    }
    res.sendFile(path.join(__dirname, "../../public", "visa.html"));
};

const serveTerms = (req, res) => {
    if (req.isAdminSubdomain) {
        return res.status(404).send('Página não encontrada');
    }
    res.sendFile(path.join(__dirname, "../../public", "termos.html"));
};

const servePrivacy = (req, res) => {
    if (req.isAdminSubdomain) {
        return res.status(404).send('Página não encontrada');
    }
    res.sendFile(path.join(__dirname, "../../public", "privacidade.html"));
};

const serveRobots = (req, res) => {
    res.type('text/plain');
    res.sendFile(path.join(__dirname, "../../public", "robots.txt"));
};

const serveSitemap = async (req, res) => {
    res.type('application/xml');

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const today = new Date().toISOString().split('T')[0];

    const staticPages = [
        { loc: '/', priority: '1.0', changefreq: 'daily' },
        { loc: '/sobre', priority: '0.8', changefreq: 'monthly' },
        { loc: '/termos', priority: '0.5', changefreq: 'yearly' },
        { loc: '/privacidade', priority: '0.5', changefreq: 'yearly' }
    ];

    let sitemapXml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`;

    staticPages.forEach(page => {
        sitemapXml += `
  <url>
    <loc>${baseUrl}${page.loc}</loc>
    <lastmod>${today}</lastmod>
    <changefreq>${page.changefreq}</changefreq>
    <priority>${page.priority}</priority>
  </url>`;
    });

    try {
        const { data: products, error } = await supabase.from('affiliate_links').select('id, updated_at').eq('is_active', true);
        if (error) throw error;

        products.forEach(product => {
            const productLastMod = new Date(product.updated_at).toISOString().split('T')[0];
            sitemapXml += `
  <url>
    <loc>${baseUrl}/details.html?id=${product.id}</loc>
    <lastmod>${productLastMod}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.9</priority>
  </url>`;
        });

    } catch (error) {
        console.error("Erro ao gerar URLs dinâmicas para o sitemap:", error);
    }

    sitemapXml += `
</urlset>`;

    res.send(sitemapXml);
};

const serveBingAuth = (req, res) => {
    res.type('application/xml');
    res.sendFile(path.join(__dirname, "../../public", "BingSiteAuth.xml"));
};

const serveYandexAuth = (req, res) => {
    res.sendFile(path.join(__dirname, "../../public", req.path));
};

module.exports = {
    serveIndex,
    serveLogin,
    serveAdmin,
    serveAdminSecret,
    serveAbout,
    serveVisa,
    serveTerms,
    servePrivacy,
    serveRobots,
    serveSitemap,
    serveBingAuth,
    serveYandexAuth
};
