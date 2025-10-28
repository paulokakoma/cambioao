// Carrega as variáveis de ambiente do ficheiro .env
require("dotenv").config();
const express = require("express");
const { createClient } = require("@supabase/supabase-js");
const path = require("path");
const http = require("http");
const { WebSocketServer } = require("ws");
const session = require("express-session");
const bcrypt = require("bcrypt");
const sharp = require("sharp");
const multer = require("multer");

const app = express();
const port = process.env.PORT || 3000;
const isDevelopment = process.env.NODE_ENV !== 'production';

// Cria um servidor HTTP a partir da aplicação Express
const server = http.createServer(app);

// --- MIDDLEWARE DE SUBDOMÍNIO ---
// Detecta se o request é para o subdomínio admin ou domínio principal
// IMPORTANTE: Este middleware deve vir ANTES de servir ficheiros estáticos
app.use((req, res, next) => {
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
    if (isDevelopment) {
        console.log(`[${req.method}] ${req.path} - Host: ${host} - Admin: ${isAdminSubdomain}`);
    }
    
    next();
});

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

// Inicializa o cliente Supabase com configurações adequadas para Node.js
const supabase = createClient(supabaseUrl, supabaseServiceKey, {
  auth: {
    autoRefreshToken: false,
    persistSession: false
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
// IMPORTANTE: Não serve index.html automaticamente - isso é controlado pelas rotas
app.use(express.static("public", { index: false }));
app.use(express.json());
app.use(session({
    secret: sessionSecret,
    resave: true, // Renova o cookie em cada request
    saveUninitialized: false,
    rolling: true, // Faz roll da expiração em cada request
    cookie: { 
        secure: process.env.NODE_ENV === 'production', // Usar cookies seguros em produção
        httpOnly: true, // Previne acesso via JS no cliente
        maxAge: 30 * 24 * 60 * 60 * 1000, // Expira em 30 dias
        // Em produção, usa o domínio base para compartilhar cookies entre subdomínios
        // Em dev, não define domain para funcionar com localhost
        domain: isDevelopment ? undefined : (process.env.COOKIE_DOMAIN || undefined)
    }
}));

// Middleware de verificação de autenticação
const isAdmin = (req, res, next) => {
    // Em produção, só permite acesso ao admin via subdomínio admin
    if (!isDevelopment && !req.isAdminSubdomain && req.path.startsWith('/admin')) {
        return res.status(403).send('Acesso ao admin apenas via subdomínio admin.');
    }

    if (req.session.isAdmin) return next();

    // Para chamadas de API, retornar JSON 401 em vez de redirecionar (evita sucesso falso no frontend)
    if (req.path.startsWith('/api')) {
        return res.status(401).json({ success: false, message: 'Sessão expirada ou não autenticada.' });
    }
    // Para páginas, redireciona para login
    return res.redirect('/login.html');
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

// --- ROTAS PÚBLICAS DA API ---

// Singleton para garantir que a verificação do bucket ocorra apenas uma vez.
const bucketCheckPromises = {};
async function ensureStorageBucketExists(bucketName) {
    if (!bucketCheckPromises[bucketName]) {
        bucketCheckPromises[bucketName] = (async () => {
            try {
                const { data: buckets, error: listError } = await supabase.storage.listBuckets();
                if (listError) throw listError;

                const bucketExists = buckets.some(bucket => bucket.name === bucketName);

                if (!bucketExists) {
                    console.log(`Bucket '${bucketName}' não encontrado. Criando...`);
                    const { error: createError } = await supabase.storage.createBucket(bucketName, {
                        public: true,
                        fileSizeLimit: 5 * 1024 * 1024, // 5MB
                        allowedMimeTypes: ['image/png', 'image/jpeg', 'image/gif', 'image/webp'],
                    });
                    if (createError) throw createError;
                    console.log(`Bucket '${bucketName}' criado com sucesso.`);
                } else {
                    console.log(`Bucket '${bucketName}' já existe.`);
                }
            } catch (error) {
                console.error(`Falha crítica ao garantir a existência do bucket '${bucketName}':`, error.message);
                // Libera a promessa em caso de erro para permitir nova tentativa
                delete bucketCheckPromises[bucketName];
                throw error; // Propaga o erro para a chamada original
            }
        })();
    }
    // Aguarda a conclusão da verificação/criação
    return bucketCheckPromises[bucketName];
}

// Rota para criar/atualizar Apoiadores com upload de imagem
app.post("/api/supporter", isAdmin, upload.single('banner_image'), async (req, res) => {
    const { id, name, website_url, is_active } = req.body;
    let banner_url;

    try {
        // Validação básica dos campos
        if (!name || !website_url) {
            return res.status(400).json({ message: "Nome e URL do website são obrigatórios." });
        }

        // Se um ficheiro foi enviado, faz o upload para o Supabase Storage
        if (req.file) {
            const file = req.file;
            
            // Validação do tipo de arquivo
            if (!file.mimetype.startsWith('image/')) {
                return res.status(400).json({ message: "Apenas arquivos de imagem são permitidos." });
            }
            
            // Validação do tamanho do arquivo (5MB)
            if (file.size > 5 * 1024 * 1024) {
                return res.status(400).json({ message: "O arquivo é muito grande. O tamanho máximo é 5MB." });
            }

            try {
                // Garante que o bucket existe
                await ensureStorageBucketExists('site-assets');
                
                // Otimiza a imagem antes do upload
                const optimizedBuffer = await sharp(file.buffer)
                    .resize({ width: 1200, withoutEnlargement: true }) // Redimensiona para max 1200px de largura, sem ampliar
                    .webp({ quality: 80 }) // Converte para WebP com 80% de qualidade
                    .toBuffer();

                // Sanitiza o nome do ficheiro original e muda a extensão para .webp
                const originalNameWithoutExt = path.parse(file.originalname).name;
                const sanitizedOriginalName = originalNameWithoutExt
                    .normalize("NFD") // Separa acentos dos caracteres (ex: 'é' -> 'e' + '´')
                    .replace(/[\u0300-\u036f]/g, "") // Remove os acentos
                    .replace(/[^a-zA-Z0-9._-]/g, '_'); // Substitui caracteres inválidos por '_'
                
                const fileName = `supporter-${Date.now()}-${sanitizedOriginalName}.webp`;
                
                // O bucket 'site-assets' deve ser público no Supabase
                const { data: uploadData, error: uploadError } = await supabase.storage.from('site-assets')
                    .upload(fileName, optimizedBuffer, {
                        contentType: 'image/webp', // Define o content type para webp
                        upsert: true,
                    });

                if (uploadError) throw uploadError;
                if (!uploadData?.path) throw new Error('Caminho do arquivo não retornado pelo upload');

                // Obtém o URL público do ficheiro. O Supabase serve o ficheiro com o Content-Type correto
                // independentemente da extensão, mas usar a extensão correta é uma boa prática.
                const { data: urlData } = supabase.storage
                    .from('site-assets')
                    .getPublicUrl(fileName);

                if (!urlData?.publicUrl) throw new Error('Não foi possível obter o URL público do arquivo');

                banner_url = urlData.publicUrl;
            } catch (storageError) {
                console.error('Erro no storage:', storageError);
                return res.status(500).json({ 
                    message: `Erro ao fazer upload da imagem: ${storageError.message || 'Erro desconhecido'}.` 
                });
            }
        }

        // Prepara os dados do apoiador
        const supporterData = { 
            name: name.trim(), 
            website_url: website_url.trim(), 
            is_active: is_active === 'true',
            ...(banner_url && { logo_url: banner_url }) // Adiciona logo_url apenas se banner_url existir
        };

        let result;

        // Se existe um ID, atualiza o registo. Caso contrário, cria um novo.
        if (id) {
            const { data: updateData, error: updateError } = await supabase
                .from('supporters')
                .update(supporterData)
                .eq('id', id)
                .select()
                .single();
            
            if (updateError) return handleSupabaseError(updateError, res);
            result = updateData;
        } else {
            const { data: insertData, error: insertError } = await supabase
                .from('supporters')
                .insert(supporterData)
                .select()
                .single();
            
            if (insertError) return handleSupabaseError(insertError, res);
            result = insertData;
        }

        // Se temos uma URL de banner, salvamos na tabela site_settings
        if (banner_url && result?.id) {
            const settingKey = `supporter_${result.id}_banner_url`;
            const { error: settingError } = await supabase
                .from('site_settings')
                .upsert({ 
                    key: settingKey,
                    value: banner_url 
                }, { 
                    onConflict: 'key' 
                });

            if (settingError) {
                console.error('Erro ao salvar banner_url em site_settings:', settingError);
                // Não retornamos erro aqui pois o apoiador já foi salvo
            }
        }

        res.status(200).json({ 
            success: true, 
            message: `Apoiador ${id ? 'atualizado' : 'adicionado'} com sucesso.`,
            data: result
        });
    } catch (error) {
        console.error('Erro inesperado na rota /api/supporter:', error);
        handleSupabaseError(error, res);
    }
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
    let error;
    
    if (field === 'sell_rate') {
        // Usar upsert para criar ou atualizar o registro de taxa
        const { error: upsertError } = await supabase
            .from('exchange_rates')
            .upsert(
                { 
                    provider_id: providerId, 
                    currency_pair: pair, 
                    sell_rate: value 
                },
                { onConflict: 'provider_id,currency_pair' }
            );
        error = upsertError;
    } else if (field === 'fee_margin') {
        const { error: updateError } = await supabase
            .from('rate_providers')
            .update({ [field]: value })
            .eq('id', providerId);
        error = updateError;
    } else {
        return res.status(400).json({ message: "Campo inválido." });
    }
    
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

// Rota para o domínio principal - página inicial
app.get("/", (req, res) => {
    // Se estiver no subdomínio admin, redireciona para /admin (que depois verifica auth e mostra login se necessário)
    if (req.isAdminSubdomain) {
        return res.redirect('/admin');
    }
    // Serve a página principal apenas no domínio principal
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Rota para a página de login (disponível em ambos os domínios)
app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

// Rota para o painel de admin - APENAS no subdomínio admin
app.get("/admin", (req, res) => {
    // Em produção, só permite acesso via subdomínio admin
    if (!isDevelopment && !req.isAdminSubdomain) {
        const protocol = req.protocol;
        const host = req.get('host') || '';
        const hostWithoutPort = host.split(':')[0];
        const adminUrl = `${protocol}://admin.${hostWithoutPort}${req.originalUrl}`;
        return res.redirect(adminUrl);
    }
    
    // Verifica autenticação
    if (!req.session.isAdmin) {
        return res.redirect('/login');
    }
    
    // Serve o ficheiro a partir da pasta 'private' para garantir que não é acessível publicamente
    res.sendFile(path.join(__dirname, "private", "admin.html"));
});

// Rota "secreta" para iniciar o processo de login de administrador (redireciona para subdomínio admin)
app.get(adminSecretPath, (req, res) => {
    if (req.session.isAdmin) {
        // Se já estiver autenticado e no subdomínio admin, vai direto para /admin
        if (req.isAdminSubdomain) {
            return res.redirect('/admin');
        }
        // Se não estiver no subdomínio admin, redireciona
        const protocol = req.protocol;
        const host = req.get('host') || 'localhost:3000';
        const hostWithoutPort = host.split(':')[0];
        const adminUrl = isDevelopment 
            ? `${protocol}://admin.localhost:${port}/admin`
            : `${protocol}://admin.${hostWithoutPort}/admin`;
        return res.redirect(adminUrl);
    }
    // Se não estiver autenticado, redireciona para login no subdomínio admin
    const protocol = req.protocol;
    const host = req.get('host') || 'localhost:3000';
    const hostWithoutPort = host.split(':')[0];
    const loginUrl = isDevelopment 
        ? `${protocol}://admin.localhost:${port}/login`
        : `${protocol}://admin.${hostWithoutPort}/login`;
    return res.redirect(loginUrl);
});

// Rota para a nova página "Sobre Nós" (apenas no domínio principal)
app.get("/sobre", (req, res) => {
    if (req.isAdminSubdomain) {
        return res.status(404).send('Página não encontrada');
    }
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
    const tableMap = { bank: 'rate_providers', affiliate: 'affiliate_links', currency: 'currencies', province: 'rate_providers', rate_providers: 'rate_providers' };
    const tableName = tableMap[resource];
    if (!tableName) return res.status(404).json({ message: "Recurso não encontrado." });

    try {
        console.log(`Tentando ${id ? 'atualizar' : 'criar'} ${resource}:`, data);

        // Guardar valores extras que não devem ir para a tabela principal (apenas para bancos)
        let extraData = {};
        if (resource === 'bank') {
            extraData = { usd_rate: data.usd_rate, eur_rate: data.eur_rate };
            delete data.usd_rate;
            delete data.eur_rate;
        }

        // Garante que a propriedade 'id' não é enviada na inserção ou atualização, pois é gerida pela BD.
        delete data.id;

        let query;
        if (id) {
            query = supabase.from(tableName).update(data).eq('id', id);
        } else {
            // Para novos registros, garante que is_active está definido
            if (!data.hasOwnProperty('is_active')) {
                data.is_active = true;
            }
            // Se for um banco novo, garantir que tem type='FORMAL'
            if (resource === 'bank' && !data.type) {
                data.type = 'FORMAL';
            }
            query = supabase.from(tableName).insert(data);
        }

        const { data: result, error } = await query;
        
        if (error) {
            console.error(`Erro ao ${id ? 'atualizar' : 'criar'} ${resource}:`, error);
            return handleSupabaseError(error, res);
        }

        // Se foi criado um novo banco, criar registos de taxas de câmbio (usando valores iniciais se fornecidos)
        if (!id && resource === 'bank' && result?.[0]?.id) {
            const providerId = result[0].id;
            const providedUsd = parseFloat(String(extraData.usd_rate ?? ''));
            const providedEur = parseFloat(String(extraData.eur_rate ?? ''));
            const usdRate = isNaN(providedUsd) ? 0 : providedUsd;
            const eurRate = isNaN(providedEur) ? 0 : providedEur;
            const currencyPairs = [
                { pair: 'USD/AOA', rate: usdRate },
                { pair: 'EUR/AOA', rate: eurRate },
                { pair: 'USDT/AOA', rate: 0 }
            ];
            const ratesToInsert = currencyPairs.map(({ pair, rate }) => ({
                provider_id: providerId,
                currency_pair: pair,
                sell_rate: rate
            }));
            const { error: ratesError } = await supabase.from('exchange_rates').insert(ratesToInsert);
            if (ratesError) {
                console.error('Erro ao inserir taxas iniciais do banco novo:', ratesError);
                // Não falhamos a criação do banco; apenas reportamos a falha das taxas
            }
        }

        console.log(`${resource} ${id ? 'atualizado' : 'criado'} com sucesso:`, result);
        res.status(200).json({ success: true, data: result });
    } catch (error) {
        console.error(`Erro inesperado ao ${id ? 'atualizar' : 'criar'} ${resource}:`, error);
        res.status(500).json({ success: false, message: "Erro interno do servidor", error: error.message });
    }
});

// --- INICIAR O SERVIDOR ---
server.listen(port, '0.0.0.0', () => {
  if (isDevelopment) {
    console.log(`Servidor a correr em desenvolvimento:`);
    console.log(`  📱 Página Principal: http://localhost:${port}`);
    console.log(`  🔐 Admin: http://admin.localhost:${port}`);
    console.log(`\nNota: Se admin.localhost não funcionar no seu navegador,`);
    console.log(`adicione ao /etc/hosts: 127.0.0.1 admin.localhost`);
  } else {
    console.log(`Servidor a correr em produção na porta ${port}`);
    console.log(`Certifique-se de configurar DNS para o subdomínio admin`);
  }
});

module.exports = app;
