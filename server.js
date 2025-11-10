// Carrega as variáveis de ambiente do ficheiro .env
const path = require("path");

// Carrega o .env APENAS em ambiente de desenvolvimento.
// Em produção (Docker), as variáveis são injetadas pelo Docker Compose.
if (process.env.NODE_ENV !== 'production') {
  require("dotenv").config({ path: path.resolve(__dirname, '.env') });
}
const express = require("express");
const { createClient } = require("@supabase/supabase-js");
const http = require("http");
const { WebSocketServer } = require("ws");
const session = require("express-session");
const FileStore = require('session-file-store')(session); // Adiciona o armazenamento em ficheiro
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

// Adiciona um listener de erro para o WebSocketServer
wss.on('error', (error) => {
  console.error('Erro no WebSocketServer (handshake ou geral):', error);
});

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
        // --- CORREÇÃO DE FUSO HORÁRIO NA INSERÇÃO ---
        // Garante que o timestamp seja sempre em UTC, independentemente do fuso horário do servidor.
        // O Supabase espera UTC, então forçamos isso aqui para evitar discrepâncias.
        const activityPayload = {
            ...data.payload,
            created_at: new Date().toISOString() // Adiciona/sobrescreve com o timestamp UTC atual
        };
        // 1. Guarda a atividade na tabela de logs
        supabase.from('user_activity').insert(activityPayload).then(({ error }) => {
          if (error) {
            console.error('[WS] Erro ao inserir atividade na BD:', error);
          }
        });

        // Esta lógica de incremento direto na tabela 'affiliate_links' pode ser redundante se contarmos os eventos.
        // 2. Se for um clique de afiliado, incrementa o contador na tabela principal
        if ((data.payload.event_type === 'affiliate_click' || data.payload.event_type === 'buy_now_click') && data.payload.details?.link_id) {
            // Converte o ID para inteiro para resolver a ambiguidade da função RPC (integer vs bigint)
            const linkId = parseInt(data.payload.details.link_id, 10);
            console.log(`[SERVER] Recebido clique de afiliado para o link ID: ${linkId}. A chamar RPC 'increment_affiliate_click'...`);
            
            supabase.rpc('increment_affiliate_click', { link_id_to_inc: linkId })
              .then(({ data: rpcData, error }) => { // eslint-disable-line
                if (error) {
                  console.error(`[SERVER] ❌ ERRO ao incrementar contador de cliques para o link ID ${linkId}:`, error);
                } else {
                  console.log(`[SERVER] ✅ SUCESSO ao incrementar contador de cliques para o link ID ${linkId}.`);
                }
              });
        }
        // 2. Notifica os administradores em tempo real
        broadcast({ type: 'new_user_activity', payload: activityPayload }, 'admin');
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
// Confiar em proxies (necessário para Render e outros serviços de hosting)
// Isso permite que req.protocol detecte corretamente HTTPS mesmo atrás de um proxy
app.set('trust proxy', 1);

// Servir ficheiros estáticos da pasta 'public' (CSS, JS, imagens).
// IMPORTANTE: Não serve index.html automaticamente - isso é controlado pelas rotas
app.use(express.static("public", { index: false }));
app.use(express.json());

// Configuração da sessão para ser persistente em ficheiros
app.use(session({
    store: new FileStore({
        path: path.join(__dirname, 'sessions'), // Guarda as sessões numa pasta 'sessions'
        ttl: 30 * 24 * 60 * 60, // Tempo de vida da sessão em segundos (30 dias)
        logFn: function() {} // Desativa logs do session-file-store
    }),
    secret: sessionSecret,
    resave: false, // Não guarda a sessão se não for modificada
    saveUninitialized: false,
    rolling: true, // Faz roll da expiração em cada request
    cookie: { 
        // Em produção, o cookie só deve ser enviado por HTTPS.
        // Em desenvolvimento (mesmo com NODE_ENV=production localmente),
        // permitimos HTTP para que o localhost funcione.
        secure: !isDevelopment,
        httpOnly: true, // Previne acesso via JS no cliente
        maxAge: 30 * 24 * 60 * 60 * 1000, // Expira em 30 dias
        // sameSite: 'lax' funciona para subdomínios do mesmo domínio (admin.dominio.com e dominio.com)
        // 'none' só é necessário para domínios completamente diferentes
        sameSite: process.env.NODE_ENV === 'production' ? 'lax' : 'lax',
        // Em produção, defina COOKIE_DOMAIN=.seudominio.com para partilhar cookies entre subdomínios
        domain: isDevelopment ? undefined : process.env.COOKIE_DOMAIN
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
    return res.redirect('/login');
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
        // Garante que a sessão seja salva antes de enviar a resposta
        req.session.save((err) => {
            if (err) {
                console.error('Erro ao salvar sessão:', err);
                return res.status(500).json({ success: false, message: 'Erro ao criar sessão.' });
            }
            if (isDevelopment) {
                console.log('Login bem-sucedido. Sessão criada:', req.sessionID);
            }
            return res.status(200).json({ success: true, message: 'Login bem-sucedido.' });
        });
    } else {
        res.status(401).json({ success: false, message: 'Senha incorreta.' });
    }
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

// --- NOVA ROTA: Obter dados do utilizador logado ---
app.get("/api/me", isAdmin, (req, res) => {
    // A sessão é validada pelo middleware 'isAdmin'
    // Aqui, podemos apenas retornar dados mock ou do user, se os guardarmos na sessão
    // Por agora, um mock é suficiente para o frontend.
    res.status(200).json({
        email: 'admin@ecokambio.com',
        user_metadata: { full_name: 'Admin' }
    });
});

// Rota de fallback para registar atividade via HTTP POST
app.post('/api/log-activity', async (req, res) => {
    const activityPayload = {
        ...req.body,
        created_at: new Date().toISOString() // Garante timestamp UTC no servidor
    };

    const { error } = await supabase.from('user_activity').insert(activityPayload);

    if (error) {
        return handleSupabaseError(error, res);
    }
    res.status(200).json({ success: true, message: 'Atividade registada.' });
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
    const { id, name, website_url, is_active, display_order } = req.body;
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
                    .resize({ width: 1500, height: 530, fit: 'cover' }) // Garante 1500x530, cortando o excesso se necessário
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
            display_order: parseInt(display_order, 10) || 0,
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

// --- NOVAS ROTAS GET PARA LISTAR DADOS ---

// GET /api/rate_providers?type=FORMAL ou ?type=INFORMAL
app.get("/api/rate_providers", isAdmin, async (req, res) => {
    const { type } = req.query;
    if (!type || (type !== 'FORMAL' && type !== 'INFORMAL')) {
        return res.status(400).json({ message: "É necessário especificar o 'type' (FORMAL ou INFORMAL)." });
    }

    try {
        const { data, error } = await supabase
            .from('rate_providers')
            .select('*, exchange_rates(currency_pair, sell_rate)')
            .eq('type', type)
            .order('name', { ascending: true });
        
        if (error) throw error;
        
        // Re-formatar os dados para o frontend (juntar taxas)
        const formattedData = data.map(provider => {
            const rates = provider.exchange_rates;
            const usdRateData = rates.find(r => r.currency_pair === 'USD/AOA');
            const eurRateData = rates.find(r => r.currency_pair === 'EUR/AOA');
            const usdtRateData = rates.find(r => r.currency_pair === 'USDT/AOA'); // Para o informal

            // Remove o array 'exchange_rates' para limpar a resposta
            delete provider.exchange_rates; 

            return {
                ...provider,
                usd_rate: usdRateData ? usdRateData.sell_rate : null,
                eur_rate: eurRateData ? eurRateData.sell_rate : null,
                usdt_rate: usdtRateData ? usdtRateData.sell_rate : null
            };
        });
        
        res.status(200).json(formattedData);
    } catch (error) {
        handleSupabaseError(error, res);
    }
});

// GET /api/affiliate_links
app.get("/api/affiliate_links", isAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase.from('affiliate_links').select('*').order('created_at', { ascending: false });
        if (error) throw error;
        res.status(200).json(data);
    } catch (error) {
        handleSupabaseError(error, res);
    }
});

// --- NOVAS ROTAS GET PARA LISTAR DADOS ---

// GET /api/rate_providers?type=FORMAL ou ?type=INFORMAL
app.get("/api/rate_providers", isAdmin, async (req, res) => {
    const { type } = req.query;
    if (!type || (type !== 'FORMAL' && type !== 'INFORMAL')) {
        return res.status(400).json({ message: "É necessário especificar o 'type' (FORMAL ou INFORMAL)." });
    }

    try {
        const { data, error } = await supabase
            .from('rate_providers')
            .select('*, exchange_rates(currency_pair, sell_rate)')
            .eq('type', type)
            .order('name', { ascending: true });
        
        if (error) throw error;
        
        // Re-formatar os dados para o frontend (juntar taxas)
        const formattedData = data.map(provider => {
            const rates = provider.exchange_rates;
            const usdRateData = rates.find(r => r.currency_pair === 'USD/AOA');
            const eurRateData = rates.find(r => r.currency_pair === 'EUR/AOA');
            const usdtRateData = rates.find(r => r.currency_pair === 'USDT/AOA'); // Para o informal

            // Remove o array 'exchange_rates' para limpar a resposta
            delete provider.exchange_rates; 

            return {
                ...provider,
                usd_rate: usdRateData ? usdRateData.sell_rate : null,
                eur_rate: eurRateData ? eurRateData.sell_rate : null,
                usdt_rate: usdtRateData ? usdtRateData.sell_rate : null
            };
        });
        
        res.status(200).json(formattedData);
    } catch (error) {
        handleSupabaseError(error, res);
    }
});

// GET /api/affiliate_links
app.get("/api/affiliate_links", isAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase.from('affiliate_links').select('*').order('created_at', { ascending: false });
        if (error) throw error;
        res.status(200).json(data);
    } catch (error) {
        handleSupabaseError(error, res);
    }
});

// GET /api/supporters
app.get("/api/supporters", isAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase.from('supporters').select('*').order('display_order', { ascending: true });
        if (error) throw error;
        res.status(200).json(data);
    } catch (error) {
        handleSupabaseError(error, res);
    }
});

// GET /api/currencies
app.get("/api/currencies", isAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase.from('currencies').select('*').order('code');
        if (error) throw error;
        res.status(200).json(data);
    } catch (error) {
        handleSupabaseError(error, res);
    }
});

// GET /api/settings (para preencher os formulários)
app.get("/api/settings", isAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase.from('site_settings').select('key, value');
        if (error) throw error;
        
        // Converter o array num objeto {key: value} para o frontend
        const settingsObject = data.reduce((acc, { key, value }) => {
            acc[key] = value;
            return acc;
        }, {});
        
        res.status(200).json(settingsObject);
    } catch (error) {
        handleSupabaseError(error, res);
    }
});

// GET /api/visa-settings (para preencher o formulário do admin)
app.get("/api/visa-settings", isAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase.from('site_settings').select('key, value').like('key', 'visa_%');
        if (error) throw error;
        
        const settingsObject = data.reduce((acc, { key, value }) => {
            acc[key] = value;
            return acc;
        }, {});
        
        res.status(200).json(settingsObject);
    } catch (error) {
        handleSupabaseError(error, res);
    }
});

// POST /api/visa-settings (para guardar as configurações do admin)
app.post("/api/visa-settings", isAdmin, async (req, res) => {
    const { settings } = req.body; // Espera um objeto {visa_title: "...", visa_description: "..."}
    if (!settings || typeof settings !== 'object') {
        return res.status(400).json({ message: "Formato de dados inválido." });
    }

    // Converte o objeto para o formato de array {key, value} que o upsert espera
    const settingsArray = Object.entries(settings).map(([key, value]) => ({ key, value }));

    const { error } = await supabase.from('site_settings').upsert(settingsArray, { onConflict: 'key' });

    if (error) {
        return handleSupabaseError(error, res);
    }
    res.status(200).json({ success: true, message: "Configurações do Cartão Visa atualizadas." });
});

// Endpoint para buscar atividade recente (para preencher o feed no carregamento da página)
app.get("/api/recent-activity", isAdmin, async (req, res) => {
    const limit = parseInt(req.query.limit, 10) || 25; // Padrão 25, mas permite override

    try {
        const { data, error } = await supabase
            .from('user_activity')
            .select('*')
            .order('created_at', { ascending: false })
            .limit(limit); // Usa o limite definido

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
        if (upsertError) return handleSupabaseError(upsertError, res);
    } else if (['fee_margin', 'base_fee_percent'].includes(field)) {
        const { error: updateError } = await supabase
            .from('rate_providers')
            .update({ [field]: value })
            .eq('id', providerId);
        if (updateError) return handleSupabaseError(updateError, res);
    } else {
        return res.status(400).json({ message: "Campo inválido." });
    }
    
    // If we got here, it was successful.
    res.status(200).json({ success: true });
});

app.post("/api/informal-rates", isAdmin, async (req, res) => {
    const { rates } = req.body;
    if (!rates) return res.status(400).json({ message: "Dados de taxas em falta." });

    // Filtra e mapeia as taxas, removendo o ID se ele não existir.
    // Isso garante que, ao criar um novo registro, o ID seja gerado automaticamente pela BD.
    const upserts = rates.filter(r => r.provider_id).map(r => {
        const rateData = { provider_id: r.provider_id, currency_pair: r.currency_pair, sell_rate: r.sell_rate };
        // Adiciona o ID apenas se ele existir (para atualizações)
        if (r.id) rateData.id = r.id;
        return rateData;
    });

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
        const [productRes, informalRatesRes, settingsRes] = await Promise.all([
            supabase.from('affiliate_links').select('*').eq('id', id).single(),
            supabase.rpc('get_average_informal_rate', { p_pair: 'USD/AOA' }).single(),
            supabase.from('site_settings').select('value').eq('key', 'social_media_links').single(),
        ]);

        // Verificação robusta dos resultados do Promise.all
        if (productRes?.error || !productRes?.data) {
            return res.status(404).json({ message: "Produto não encontrado." });
        }
        if (informalRatesRes?.error) {
            console.warn("Erro ao buscar taxa média informal:", informalRatesRes.error.message);
            // Não retornamos erro aqui, pois podemos usar o fallback.
        }

        // Adiciona os links das redes sociais ao objeto do produto
        if (settingsRes?.data?.value) {
            productRes.data.social_media_links = settingsRes.data.value;
        }

        const product = productRes.data;

        let exchangeRate;
        if (informalRatesRes?.data && informalRatesRes.data > 0) {
            exchangeRate = informalRatesRes.data;
        } else {
            // Fallback para a taxa do BNA se a taxa informal não estiver disponível
            console.warn("Taxa média informal não encontrada, usando fallback para BNA.");
            // Otimização: Seleciona apenas 'sell_rate' e limita a 1 para ser mais rápido.
            const { data: bnaData, error: bnaError } = await supabase
                .from('exchange_rates')
                .select('sell_rate')
                .eq('provider_id', 1) // Assumindo que 1 é o ID do BNA
                .eq('currency_pair', 'USD/AOA')
                .limit(1)
                .single();
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

// Endpoint para buscar estatísticas do dashboard
app.get("/api/dashboard-stats", isAdmin, async (req, res) => {
    // Calcula o número de utilizadores online em tempo real a partir dos clientes WebSocket
    const onlineUsers = Array.from(wss.clients).filter(c => !c.isAdmin).length;

    // Tenta usar a função RPC otimizada primeiro
    const { data: rpcData, error: rpcError } = await supabase.rpc('get_dashboard_stats_fallback').single();
    
    if (!rpcError && rpcData) {
        // Sucesso! A função RPC existe e retornou dados.
        return res.status(200).json({
            active_banks: rpcData.active_banks || 0,
            today_access: rpcData.today_views || 0,
            newVisitorsToday: rpcData.new_visitors_today || 0,
            newVisitorsToday: rpcData.new_visitors_today || 0,
            monthlyAffiliateClicks: rpcData.monthly_affiliate_clicks || 0,
            monthlyVisaClicks: rpcData.monthly_visa_clicks || 0, // Alterado de monthly_buy_now_clicks
            weeklyViews: rpcData.weekly_views || 0,
            monthlyViews: rpcData.monthly_views || 0,
            onlineUsers: onlineUsers // Adiciona a contagem de utilizadores online
        });
    }

    // Se a função RPC falhou (provavelmente porque não existe), usa o método de fallback com queries individuais.
    console.warn("A função RPC 'get_dashboard_stats_fallback' não foi encontrada. Usando queries de fallback. Considere adicionar a função SQL para melhor performance.");

    try {
        const nowUTC = new Date();
        const todayStart = new Date(Date.UTC(nowUTC.getUTCFullYear(), nowUTC.getUTCMonth(), nowUTC.getUTCDate(), 0, 0, 0, 0)).toISOString();
        const todayEnd = new Date(Date.UTC(nowUTC.getUTCFullYear(), nowUTC.getUTCMonth(), nowUTC.getUTCDate(), 23, 59, 59, 999)).toISOString();
        const monthStart = new Date(Date.UTC(nowUTC.getUTCFullYear(), nowUTC.getUTCMonth(), 1, 0, 0, 0, 0)).toISOString();
        const weekStartDate = new Date(nowUTC);
        weekStartDate.setUTCDate(weekStartDate.getUTCDate() - 6);
        weekStartDate.setUTCHours(0, 0, 0, 0);
        const weekStart = weekStartDate.toISOString();
        
        // Executa todas as queries em paralelo para melhor performance
        const [activeBanksRes, todayViewsRes, weeklyViewsRes, monthlyViewsRes, newVisitorsRes, monthlyAffiliateClicksRes, monthlyVisaClicksRes] = await Promise.all([
            supabase.from('rate_providers').select('id', { count: 'exact', head: true }).eq('type', 'FORMAL').eq('is_active', true),
            supabase.rpc('count_distinct_sessions', { event: 'page_view', start_time: todayStart, end_time: todayEnd }),
            supabase.rpc('count_distinct_sessions', { event: 'page_view', start_time: weekStart, end_time: todayEnd }),
            supabase.rpc('count_distinct_sessions', { event: 'page_view', start_time: monthStart, end_time: todayEnd }),
            supabase.rpc('count_distinct_sessions', { event: 'first_visit', start_time: todayStart, end_time: todayEnd }),
            supabase.from('user_activity').select('id', { count: 'exact', head: true }).eq('event_type', 'affiliate_click').gte('created_at', monthStart), // Conta cliques de afiliados
            supabase.from('user_activity').select('id', { count: 'exact', head: true }).eq('event_type', 'visa_cta_click').gte('created_at', monthStart) // Alterado de buy_now_click
        ]);

        res.status(200).json({ 
            active_banks: activeBanksRes.count || 0, 
            today_access: todayViewsRes.data || 0, 
            weeklyViews: weeklyViewsRes.data || 0, 
            monthlyViews: monthlyViewsRes.data || 0,
            newVisitorsToday: newVisitorsRes.data || 0,
            monthlyAffiliateClicks: monthlyAffiliateClicksRes.count || 0,
            monthlyVisaClicks: monthlyVisaClicksRes.count || 0, // Alterado de monthlyVisaClicksRes
            onlineUsers: onlineUsers // Adiciona a contagem de utilizadores online
        });
    } catch (error) {
        handleSupabaseError(error, res);
    }

});

// Endpoint para buscar atividade semanal de um mês específico
app.get("/api/weekly-activity", isAdmin, async (req, res) => {
    const { month, months } = req.query; // Aceita 'month' (YYYY-MM) ou 'months' (número)

    try {
        let rpcName, rpcParams;

        if (month && /^\d{4}-\d{2}$/.test(month)) {
            // Se 'month' for fornecido, busca dados semanais para esse mês
            rpcName = 'get_weekly_activity_for_month';
            rpcParams = { p_month: month };
        } else if (months) {
            // Se 'months' for fornecido, busca dados mensais para o período
            rpcName = 'get_monthly_activity';
            rpcParams = { p_months: months === 'all' ? null : parseInt(months, 10) };
        } else {
            return res.status(400).json({ message: "Parâmetro 'month' (YYYY-MM) ou 'months' (número) é obrigatório." });
        }

        const { data, error } = await supabase.rpc(rpcName, rpcParams);

        if (error) {
            throw error;
        }
        res.status(200).json(data);
    } catch (error) {
        handleSupabaseError(error, res);
    }
});

// Endpoint para buscar estatísticas de tipos de eventos
app.get("/api/event-types-stats", isAdmin, async (req, res) => {
    try {
        // Tenta chamar a função RPC otimizada primeiro
        const { data: rpcData, error: rpcError } = await supabase.rpc('get_event_type_counts');

        if (!rpcError && rpcData) {
            // Sucesso! A função RPC existe e retornou dados.
            return res.status(200).json(rpcData);
        }

        // Se a função RPC falhou, usa o método de fallback.
        console.warn("A função RPC 'get_event_type_counts' não foi encontrada. Usando query de fallback. Considere adicionar a função SQL para melhor performance.");

        const { data, error } = await supabase
            .from('user_activity')
            .select('event_type')
            .throwOnError();

        // Agrupa e conta os eventos no lado do servidor
        const counts = data.reduce((acc, { event_type }) => {
            acc[event_type] = (acc[event_type] || 0) + 1;
            return acc;
        }, {});

        const result = Object.entries(counts).map(([event_type, count]) => ({ event_type, count }));

        res.status(200).json(result);
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

// Rota para a página do Cartão Visa
app.get("/visa", (req, res) => {
    if (req.isAdminSubdomain) {
        return res.status(404).send('Página não encontrada');
    }
    res.sendFile(path.join(__dirname, "public", "visa.html"));
});

// Rota para a página "Termos e Condições"
app.get("/termos", (req, res) => {
    if (req.isAdminSubdomain) {
        return res.status(404).send('Página não encontrada');
    }
    res.sendFile(path.join(__dirname, "public", "termos.html"));
});

// Rota para a página "Política de Privacidade"
app.get("/privacidade", (req, res) => {
    if (req.isAdminSubdomain) {
        return res.status(404).send('Página não encontrada');
    }
    res.sendFile(path.join(__dirname, "public", "privacidade.html"));
});

// Rotas para SEO
app.get("/robots.txt", (req, res) => {
    res.type('text/plain');
    res.sendFile(path.join(__dirname, "public", "robots.txt"));
});

// Rota para gerar o sitemap dinamicamente
app.get("/sitemap.xml", async (req, res) => {
    res.type('application/xml');
    
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const today = new Date().toISOString().split('T')[0];

    // 1. Páginas estáticas
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
        // 2. Buscar produtos dinâmicos (afiliados)
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
});

// Rota para verificação do Bing
app.get("/BingSiteAuth.xml", (req, res) => {
    res.type('application/xml');
    res.sendFile(path.join(__dirname, "public", "BingSiteAuth.xml"));
});

// Rota para verificação do Yandex (assumindo que o arquivo seja yandex_verification.html)
// Ajuste o nome do arquivo se for diferente.
app.get("/yandex_*.html", (req, res) => {
    res.sendFile(path.join(__dirname, "public", req.path));
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

// Rota genérica para criar/atualizar recursos
app.post("/api/bank", isAdmin, handleResourcePost('bank', 'rate_providers'));
app.post("/api/affiliate", isAdmin, handleResourcePost('affiliate', 'affiliate_links'));
app.post("/api/currency", isAdmin, handleResourcePost('currency', 'currencies'));
app.post("/api/province", isAdmin, handleResourcePost('province', 'rate_providers'));
app.post("/api/rate_providers", isAdmin, handleResourcePost('rate_providers', 'rate_providers'));

function handleResourcePost(resource, tableName) {
  return async (req, res) => {
    const { id, ...data } = req.body;

    try {
        console.log(`Tentando ${id ? 'atualizar' : 'criar'} ${resource}:`, data);
        let extraData = {}; // Para guardar valores que não vão para a tabela principal
        if (resource === 'bank') {
            extraData = { usd_rate: data.usd_rate, eur_rate: data.eur_rate };
            delete data.usd_rate;
            delete data.eur_rate;
        }

        // Garante que a propriedade 'id' não é enviada na inserção ou atualização, pois é gerida pela BD.
        delete data.id;

        if (resource === 'bank') {
            // Verificação de duplicados para bancos
            const { data: existingBank, error: existingError } = await supabase
                .from(tableName)
                .select('id')
                .or(`code.eq.${data.code},name.eq.${data.name}`)
                .limit(1);

            if (existingError) {
                console.error('Erro ao verificar duplicados:', existingError);
                return handleSupabaseError(existingError, res);
            }

            if (existingBank && existingBank.length > 0) {
                // Se estamos a atualizar e o ID existente é diferente do ID atual, é um conflito
                if (id && String(existingBank[0].id) !== String(id)) {
                    return res.status(409).json({ message: "Já existe um banco com este nome ou código." });
                } else if (!id) {
                    return res.status(409).json({ message: "Já existe um banco com este nome ou código." });
                }
            }
        }

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

        const { data: result, error } = await query.select();
        
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
  };
}

// --- INICIAR O SERVIDOR ---
server.listen(port, '0.0.0.0', () => {
  if (isDevelopment) {
    console.log(`Servidor a correr em desenvolvimento:`);
    console.log(`  📱 Página Principal: http://localhost:${port}`);
    console.log(`  🔐 Admin: http://admin.localhost:${port}`);
  } else {
    console.log(`Servidor a correr em produção na porta ${port}`);
  }
}).on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    console.error(`\n❌ ERRO: A porta ${port} já está em uso.`);
    console.error('   Verifique se outra instância do servidor já não está a correr e tente novamente.');
    process.exit(1); // Encerra o processo para que o nodemon não tente reiniciar indefinidamente
  }
});

module.exports = app;
