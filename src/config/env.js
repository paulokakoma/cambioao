const path = require("path");
const dotenv = require("dotenv");

// Load environment variables
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const requiredVars = [
    'SUPABASE_URL',
    'SUPABASE_SERVICE_KEY',
    'SUPABASE_ANON_KEY',
    'ADMIN_PASSWORD_HASH',
    'SESSION_SECRET'
];

const missingVars = requiredVars.filter(key => !process.env[key]);

if (missingVars.length > 0) {
    console.error(`Erro: Variáveis de ambiente em falta: ${missingVars.join(', ')}`);
    process.exit(1);
}

module.exports = {
    port: process.env.PORT || 3000,
    nodeEnv: process.env.NODE_ENV || 'development',
    isDevelopment: process.env.NODE_ENV !== 'production',
    supabase: {
        url: process.env.SUPABASE_URL,
        serviceKey: process.env.SUPABASE_SERVICE_KEY,
        anonKey: process.env.SUPABASE_ANON_KEY
    },
    admin: {
        passwordHash: process.env.ADMIN_PASSWORD_HASH,
        secretPath: process.env.ADMIN_SECRET_PATH || '/admin'
    },
    session: {
        secret: process.env.SESSION_SECRET,
        cookieDomain: process.env.COOKIE_DOMAIN
    }
};
