const { createClient } = require("@supabase/supabase-js");
const config = require("./env");

// Inicializa o cliente Supabase com configurações adequadas para Node.js
const supabase = createClient(config.supabase.url, config.supabase.serviceKey, {
    auth: {
        autoRefreshToken: false,
        persistSession: false
    }
});

module.exports = supabase;
