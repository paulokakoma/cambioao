const express = require("express");
const http = require("http");
const path = require("path");
const session = require("express-session");
const FileStore = require('session-file-store')(session);
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

// Config & Utils
const config = require("./src/config/env");
const websocket = require("./src/websocket");

// Middleware
const subdomainMiddleware = require("./src/middleware/subdomain");
const isAdmin = require("./src/middleware/auth");

// Routes
const authRoutes = require("./src/routes/authRoutes");
const publicRoutes = require("./src/routes/publicRoutes");
const adminRoutes = require("./src/routes/adminRoutes");
const viewRoutes = require("./src/routes/viewRoutes");

const app = express();
const server = http.createServer(app);

// Initialize WebSocket
websocket.init(server);

// Security Middleware
app.use(helmet({
    contentSecurityPolicy: false, // Disable CSP for now to avoid breaking inline scripts/styles if any
}));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limiter); // Apply rate limiting to API routes

// Basic Middleware
app.set('trust proxy', 1);
app.use(express.json());
app.use(subdomainMiddleware);

// Session Configuration
app.use(session({
    store: new FileStore({
        path: path.join(__dirname, 'sessions'),
        ttl: 30 * 24 * 60 * 60,
        logFn: function () { }
    }),
    secret: config.session.secret,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
        secure: !config.isDevelopment,
        httpOnly: true,
        maxAge: 30 * 24 * 60 * 60 * 1000,
        sameSite: config.nodeEnv === 'production' ? 'lax' : 'lax',
        domain: config.isDevelopment ? undefined : config.session.cookieDomain
    }
}));

// Static Files
app.use(express.static("public", { index: false }));
app.use('/admin/assets', isAdmin, express.static(path.join(__dirname, 'private')));

// Routes
app.use('/api', authRoutes);
app.use('/api', publicRoutes);
app.use('/api', adminRoutes);
app.use('/', viewRoutes);

// Start Server
server.listen(config.port, '0.0.0.0', () => {
    if (config.isDevelopment) {
        console.log(`Servidor a correr em desenvolvimento:`);
        console.log(`  📱 Página Principal: http://localhost:${config.port}`);
        console.log(`  🔐 Admin: http://admin.localhost:${config.port}`);
    } else {
        console.log(`Servidor a correr em produção na porta ${config.port}`);
    }
}).on('error', (e) => {
    if (e.code === 'EADDRINUSE') {
        console.error(`\n❌ ERRO: A porta ${config.port} já está em uso.`);
        console.error('   Verifique se outra instância do servidor já não está a correr e tente novamente.');
        process.exit(1);
    }
});

module.exports = app;
