// Carrega as variáveis de ambiente do ficheiro .env
require("dotenv").config();
const express = require("express");
const { createClient } = require("@supabase/supabase-js");
const path = require("path");
const http = require("http");
const { WebSocketServer } = require("ws");
const session = require("express-session");
const bcrypt = require("bcrypt");
const multer = require("multer");

const app = express();
const port = process.env.PORT || 3000;

// Cria um servidor HTTP a partir da aplicação Express
const server = http.createServer(app);

// Configuração do Supabase (usando a service_role key para ter permissões de escrita)
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY; // IMPORTANTE: Usar a chave de serviço
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH;
const sessionSecret = process.env.SESSION_SECRET;
const adminSecretPath = process.env.ADMIN_SECRET_PATH || '/admin'; // Fallback para /admin se não estiver definido

if (!supabaseUrl || !supabaseServiceKey || !supabaseAnonKey || !adminPasswordHash || !sessionSecret || !adminSecretPath) {
  console.error("Erro: Uma ou mais variáveis de ambiente essenciais (SUPABASE_*, ADMIN_PASSWORD_HASH, SESSION_SECRET, ADMIN_SECRET_PATH) estão em falta.");
  process.exit(1);
}

// Corrige o erro 'TypeError: fetch failed' ao garantir que cada pedido
// para o Supabase usa uma nova ligação, desativando o 'keep-alive'.
// Isto é especialmente importante em ambientes de servidor Node.js.
const supabase = createClient(supabaseUrl, supabaseServiceKey, { 
    global: { 
        fetch: (input, init) => fetch(input, { ...init, keepalive: false }) 
    } 
}); 

// --- Configuração do WebSocket ---
const wss = new WebSocketServer({ server });

const broadcast = (data, target = 'all') => {
  const jsonData = JSON.stringify(data);
  wss.clients.forEach((client) => {
    if (client.readyState === client.OPEN) {
      if (target === 'all' || (target === 'admin' && client.isAdmin)) {
        client.send(jsonData);
      }
    }
  });
};

const broadcastUserCount = () => {
  const userCount = Array.from(wss.clients).filter(c => !c.isAdmin).length;
  broadcast({ type: 'user_count_update', count: userCount }, 'admin');
};

wss.on("connection", (ws, req) => {
  const params = new URLSearchParams(req.url.slice(1));
  ws.isAdmin = params.get('client') === 'admin';
  console.log(`Cliente WebSocket conectado ${ws.isAdmin ? '(Admin)' : '(Usuário)'}.`);
  broadcastUserCount();

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      if (data.type === 'log_activity' && data.payload) {
        // 1. Guarda a atividade na tabela de logs
        supabase.from('user_activity').insert(data.payload).then(({ error }) => {
          if (error) {
            console.error('Erro ao inserir atividade do WebSocket na BD:', error);
          }
        });

        // 2. Se for um clique de afiliado, incrementa o contador na tabela principal
        if ((data.payload.event_type === 'affiliate_click' || data.payload.event_type === 'buy_now_click') && data.payload.details?.link_id) {
            supabase.rpc('increment_affiliate_click', { link_id_to_inc: data.payload.details.link_id })
              .then(({ error }) => {
                if (error) {
                  console.error('Erro ao incrementar contador de cliques:', error);
                }
              });
        }
        // 2. Notifica os administradores em tempo real
        broadcast({ type: 'new_user_activity', payload: data.payload }, 'admin');
      }
    } catch (error) { console.error('Erro ao processar mensagem WebSocket:', error); }
  });

  ws.on("close", () => {
    console.log(`Cliente WebSocket desconectado ${ws.isAdmin ? '(Admin)' : '(Usuário)'}.`);
    broadcastUserCount();
  });
  ws.on("error", (error) => console.error('Erro no WebSocket:', error));
});

// --- MIDDLEWARES ---
// Servir ficheiros estáticos da pasta 'public' (CSS, JS, imagens).
// Esta linha deve vir ANTES de outras rotas para garantir que os ficheiros são encontrados.
app.use(express.static("public"));
app.use(express.json());
app.use(session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production', // Usar cookies seguros em produção
        httpOnly: true, // Previne acesso via JS no cliente
        maxAge: 24 * 60 * 60 * 1000 // Expira em 24 horas
    }
}));

// Middleware de verificação de autenticação
const isAdmin = (req, res, next) => {
    req.session.isAdmin ? next() : res.redirect('/login.html');
};

// Middleware para servir ficheiros estáticos da pasta 'private' APENAS para administradores.
// Isto permite que a página /admin carregue os seus próprios CSS e JS de forma segura.
app.use('/admin/assets', isAdmin, express.static(path.join(__dirname, 'private')));

// Configuração do Multer para upload de imagens em memória
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });


// --- GESTÃO DE ERROS CENTRALIZADA ---
function handleSupabaseError(error, res) {
    // Verifica se é um erro de violação de unicidade (código 23505)
    if (error.code === '23505') {
        return res.status(409).json({ message: "Erro: Já existe um registo com um destes valores (ex: código ou URL)." });
    }
    // Para outros erros da base de dados
    console.error("Erro do Supabase:", error);
    return res.status(500).json({ message: error.message });
}

// --- ROTAS PÚBLICAS DA API ---

// Rota para criar/atualizar Apoiadores com upload de imagem
app.post("/api/supporter", isAdmin, upload.single('banner_image'), async (req, res) => {
    const { id, name, website_url, is_active } = req.body;
    let banner_url;

    try {
        // Se um ficheiro foi enviado, faz o upload para o Supabase Storage
        if (req.file) {
            const file = req.file;
            const fileName = `supporter-${Date.now()}-${file.originalname.replace(/\s/g, '_')}`;
            
            // O bucket 'site-assets' deve ser público no Supabase
            const { data: uploadData, error: uploadError } = await supabase.storage
                .from('site-assets')
                .upload(`public/${fileName}`, file.buffer, {
                    contentType: file.mimetype,
                    upsert: true,
                });

            if (uploadError) throw uploadError;

            // Obtém o URL público do ficheiro
            const { data: urlData } = supabase.storage.from('site-assets').getPublicUrl(uploadData.path);
            banner_url = urlData.publicUrl;
        }

        const supporterData = { name, website_url, is_active: is_active === 'true' };
        if (banner_url) {
            supporterData.banner_url = banner_url;
        }

        // Se existe um ID, atualiza o registo. Caso contrário, cria um novo.
        const query = id ? supabase.from('supporters').update(supporterData).eq('id', id) : supabase.from('supporters').insert(supporterData);
        const { error } = await query;

        if (error) return handleSupabaseError(error, res);
        res.status(200).json({ success: true, message: "Apoiador salvo com sucesso." });
    } catch (error) {
        handleSupabaseError(error, res);
    }
});

// --- ROTAS DE AUTENTICAÇÃO ---
app.post('/api/login', async (req, res) => {
    const { password } = req.body;
    if (!password || !adminPasswordHash) {
        return res.status(400).json({ success: false, message: 'Pedido inválido.' });
    }

    const match = await bcrypt.compare(password, adminPasswordHash);

    if (match) {
        req.session.isAdmin = true;
        return res.status(200).json({ success: true, message: 'Login bem-sucedido.' });
    }
    res.status(401).json({ success: false, message: 'Senha incorreta.' });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ message: 'Não foi possível fazer logout.' });
        res.status(200).json({ success: true, message: 'Logout bem-sucedido.' });
    });
});

// Endpoint para fornecer configuração ao frontend (pode ser público)
app.get("/api/config", (req, res) => {
  res.json({
    supabaseUrl: supabaseUrl,
    supabaseAnonKey: supabaseAnonKey
  });
});

// --- ROTAS PROTEGIDAS DA API (REQUEREM LOGIN) ---

// Endpoint para buscar atividade recente (para preencher o feed no carregamento da página)
app.get("/api/recent-activity", isAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('user_activity')
            .select('*')
            .order('created_at', { ascending: false })
            .limit(25); // Busca as últimas 25 atividades

        if (error) throw error;
        res.status(200).json(data);
    } catch (error) {
        handleSupabaseError(error, res);
    }
});

app.post("/api/notify-update", isAdmin, (req, res) => {
  broadcast({ type: "rates_updated" }, 'all');
  res.status(200).json({ success: true, message: "Notificação enviada." });
});

app.post("/api/add-province", isAdmin, async (req, res) => {
    const { name } = req.body;
    if (!name) return res.status(400).json({ message: "O nome da província é obrigatório." });

    const { data, error } = await supabase.from('rate_providers').insert({ code: name, name, type: 'INFORMAL' }).select().single();
    if (error) return handleSupabaseError(error, res);

    const { error: ratesError } = await supabase.from('exchange_rates').insert([
        { provider_id: data.id, currency_pair: 'USD/AOA', sell_rate: 0 },
        { provider_id: data.id, currency_pair: 'EUR/AOA', sell_rate: 0 },
        { provider_id: data.id, currency_pair: 'USDT/AOA', sell_rate: 0 }
    ]);
    if (ratesError) return handleSupabaseError(ratesError, res);
    res.status(201).json({ success: true });
});

app.post("/api/update-status", isAdmin, async (req, res) => {
    const { type, id, isActive } = req.body;
    const tableMap = { bank: 'rate_providers', affiliate: 'affiliate_links', currency: 'currencies', supporter: 'supporters' };
    const tableName = tableMap[type];
    if (!tableName) return res.status(404).json({ message: "Tipo de recurso inválido." });

    const { error } = await supabase.from(tableName).update({ is_active: isActive }).eq('id', id);
    if (error) return handleSupabaseError(error, res);
    res.status(200).json({ success: true });
});

app.post("/api/update-cell", isAdmin, async (req, res) => {
    const { field, value, providerId, pair } = req.body;
    let query;
    if (field === 'sell_rate') {
        query = supabase.from('exchange_rates').update({ sell_rate: value }).eq('provider_id', providerId).eq('currency_pair', pair);
    } else if (field === 'fee_margin') {
        query = supabase.from('rate_providers').update({ [field]: value }).eq('id', providerId);
    } else {
        return res.status(400).json({ message: "Campo inválido." });
    }
    const { error } = await query;
    if (error) return handleSupabaseError(error, res);
    res.status(200).json({ success: true });
});

app.post("/api/informal-rates", isAdmin, async (req, res) => {
    const { rates } = req.body;
    if (!rates) return res.status(400).json({ message: "Dados de taxas em falta." });
    const upserts = rates.filter(r => r.provider_id).map(r => ({
        id: r.id || undefined,
        provider_id: r.provider_id,
        currency_pair: r.currency_pair,
        sell_rate: r.sell_rate
    }));

    if (upserts.length === 0) {
        return res.status(400).json({ message: "Nenhuma taxa válida para atualizar." });
    }

    const { error } = await supabase.from('exchange_rates').upsert(upserts, { onConflict: 'provider_id, currency_pair' });
    if (error) return handleSupabaseError(error, res);
    res.status(200).json({ success: true });
});

// Endpoint para Configurações (Criar/Atualizar)
app.post("/api/settings", isAdmin, async (req, res) => {
    const { settings } = req.body; // Espera um array de {key, value}
    if (!Array.isArray(settings)) {
        return res.status(400).json({ message: "Formato de dados inválido." });
    }

    // O método upsert é perfeito aqui: ele insere se a 'key' não existir, ou atualiza se existir.
    const { error } = await supabase.from('site_settings').upsert(settings, { onConflict: 'key' });

    if (error) {
        return handleSupabaseError(error, res);
    }
    res.status(200).json({ success: true, message: "Configurações atualizadas." });
});

// Endpoint para detalhes de um produto afiliado (PÚBLICO)
app.get("/api/affiliate-details/:id", async (req, res) => {
    const { id } = req.params;

    try {
        // Busca o produto, as taxas informais e as configurações em paralelo
        const [productRes, informalRatesRes] = await Promise.all([
            supabase.from('affiliate_links').select('*').eq('id', id).single(),
            supabase.rpc('get_average_informal_rate', { p_pair: 'USD/AOA' })
        ]);

        // Verificação robusta dos resultados do Promise.all
        if (productRes?.error || !productRes?.data) {
            return res.status(404).json({ message: "Produto não encontrado." });
        }
        if (informalRatesRes?.error) {
            console.warn("Erro ao buscar taxa média informal:", informalRatesRes.error.message);
            // Não retornamos erro aqui, pois podemos usar o fallback.
        }

        const product = productRes.data;

        let exchangeRate;
        if (informalRatesRes?.data && informalRatesRes.data > 0) {
            exchangeRate = informalRatesRes.data;
        } else {
            // Fallback para a taxa do BNA se a taxa informal não estiver disponível
            console.warn("Taxa média informal não encontrada, usando fallback para BNA.");
            const { data: bnaData, error: bnaError } = await supabase.from('exchange_rates').select('sell_rate').eq('provider_id', 1).eq('currency_pair', 'USD/AOA').maybeSingle();
            exchangeRate = bnaData?.sell_rate;
        }

        // Se nenhuma taxa de câmbio foi encontrada (nem informal, nem BNA), retorna um erro claro.
        if (!exchangeRate || exchangeRate <= 0) {
            console.error("Nenhuma taxa de câmbio (nem informal, nem BNA) foi encontrada para calcular o preço.");
            return res.status(503).json({ message: "Serviço indisponível: Nenhuma taxa de câmbio foi encontrada para calcular o preço." });
        }

        const totalCostAOA = ((product.price || 0) + (product.shipping_cost_usd || 0)) * exchangeRate;

        res.json({ product, total_cost_aoa: totalCostAOA });
    } catch (error) {
        handleSupabaseError(error, res);
    }
});

// --- ROTAS PARA SERVIR PÁGINAS HTML ---
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Rota "secreta" para iniciar o processo de login de administrador.
// Em vez de aceder a /admin, use este URL. Ele irá redirecionar para o login se não estiver autenticado.
app.get(adminSecretPath, isAdmin, (req, res) => {
    res.redirect('/admin'); // A página de admin continua a ser /admin
});

// Rota para a página de login
app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

// Rota para o painel de admin (agora protegida)
app.get("/admin", isAdmin, (req, res) => {
    // Serve o ficheiro a partir da pasta 'private' para garantir que não é acessível publicamente
    res.sendFile(path.join(__dirname, "private", "admin.html"));
});

// Rota para a nova página "Sobre Nós"
app.get("/sobre", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "about.html"));
});

// --- ROTAS GENÉRICAS (DEVEM VIR NO FIM) ---
app.delete("/api/:resource/:id", isAdmin, async (req, res) => {
    const { resource, id } = req.params; 
    const tableMap = { rate_providers: 'rate_providers', bank: 'rate_providers', province: 'rate_providers', affiliate: 'affiliate_links', currency: 'currencies', supporter: 'supporters' };
    const tableName = tableMap[resource];
    if (!tableName) return res.status(404).json({ message: "Recurso não encontrado." });

    const { error } = await supabase.from(tableName).delete().eq('id', id);
    if (error) return handleSupabaseError(error, res);
    res.status(200).json({ success: true, message: "Recurso apagado." });
});

// Rota para zerar estatísticas (DANGER ZONE)
app.post("/api/reset-stats", isAdmin, async (req, res) => {
    try {
        // 1. Zerar contadores de cliques dos afiliados
        const { error: affiliateError } = await supabase
            .from('affiliate_links')
            .update({ click_count: 0 }) // Define o campo a ser atualizado
            .neq('click_count', -1); // Filtro seguro: atualiza todas as linhas onde click_count não é -1 (ou seja, todas)

        if (affiliateError) throw affiliateError;

        // 2. Apagar todos os registos de atividade de utilizador
        const { error: activityError } = await supabase.from('user_activity').delete().neq('event_type', 'non_existent_event'); // Filtro seguro para apagar todas as linhas

        if (activityError) throw activityError;

        res.status(200).json({ success: true, message: "Estatísticas zeradas com sucesso." });
    } catch (error) {
        handleSupabaseError(error, res);
    }
});

// Rota genérica para criar/atualizar recursos (deve ser uma das últimas)
app.post("/api/:resource", isAdmin, async (req, res) => {
    const { resource } = req.params;
    const { id, ...data } = req.body;
    const tableMap = { affiliate: 'affiliate_links', currency: 'currencies', province: 'rate_providers', rate_providers: 'rate_providers' };
    const tableName = tableMap[resource];
    if (!tableName) return res.status(404).json({ message: "Recurso não encontrado." });

    // Garante que a propriedade 'id' não é enviada na inserção ou atualização, pois é gerida pela BD.
    delete data.id;

    const query = id ? supabase.from(tableName).update(data).eq('id', id) : supabase.from(tableName).insert(data);
    const { error } = await query;

    if (error) return handleSupabaseError(error, res);
    res.status(200).json({ success: true });
});

// --- INICIAR O SERVIDOR ---
server.listen(port, () => {
  console.log(`Servidor a correr em http://localhost:${port}`);
});

module.exports = app;
