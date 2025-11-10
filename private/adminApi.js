const express = require("express");
const multer = require("multer");
const sharp = require("sharp");
const path = require("path");
const { supabase, handleSupabaseError } = require("../services/supabase");
const { broadcast } = require("../services/websocket");

const router = express.Router();

// Configuração do Multer para upload de imagens em memória
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

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
                delete bucketCheckPromises[bucketName];
                throw error;
            }
        })();
    }
    return bucketCheckPromises[bucketName];
}

// Rota para criar/atualizar Apoiadores com upload de imagem
router.post("/supporter", upload.single('banner_image'), async (req, res) => {
    const { id, name, website_url, is_active, display_order } = req.body;
    let banner_url;

    try {
        if (!name || !website_url) {
            return res.status(400).json({ message: "Nome e URL do website são obrigatórios." });
        }

        if (req.file) {
            const file = req.file;
            
            if (!file.mimetype.startsWith('image/')) {
                return res.status(400).json({ message: "Apenas arquivos de imagem são permitidos." });
            }
            
            if (file.size > 5 * 1024 * 1024) {
                return res.status(400).json({ message: "O arquivo é muito grande. O tamanho máximo é 5MB." });
            }

            try {
                await ensureStorageBucketExists('site-assets');
                
                const optimizedBuffer = await sharp(file.buffer)
                    .resize({ width: 1500, height: 530, fit: 'cover' })
                    .webp({ quality: 80 })
                    .toBuffer();

                const originalNameWithoutExt = path.parse(file.originalname).name;
                const sanitizedOriginalName = originalNameWithoutExt
                    .normalize("NFD").replace(/[\u0300-\u036f]/g, "")
                    .replace(/[^a-zA-Z0-9._-]/g, '_');
                
                const fileName = `supporter-${Date.now()}-${sanitizedOriginalName}.webp`;
                
                const { data: uploadData, error: uploadError } = await supabase.storage.from('site-assets')
                    .upload(fileName, optimizedBuffer, {
                        contentType: 'image/webp',
                        upsert: true,
                    });

                if (uploadError) throw uploadError;
                if (!uploadData?.path) throw new Error('Caminho do arquivo não retornado pelo upload');

                const { data: urlData } = supabase.storage.from('site-assets').getPublicUrl(fileName);

                if (!urlData?.publicUrl) throw new Error('Não foi possível obter o URL público do arquivo');

                banner_url = urlData.publicUrl;
            } catch (storageError) {
                console.error('Erro no storage:', storageError);
                return res.status(500).json({ 
                    message: `Erro ao fazer upload da imagem: ${storageError.message || 'Erro desconhecido'}.` 
                });
            }
        }

        const supporterData = { 
            name: name.trim(), 
            website_url: website_url.trim(), 
            is_active: is_active === 'true',
            display_order: parseInt(display_order, 10) || 0,
            ...(banner_url && { logo_url: banner_url })
        };

        let result;

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

        if (banner_url && result?.id) {
            const settingKey = `supporter_${result.id}_banner_url`;
            const { error: settingError } = await supabase
                .from('site_settings')
                .upsert({ key: settingKey, value: banner_url }, { onConflict: 'key' });

            if (settingError) {
                console.error('Erro ao salvar banner_url em site_settings:', settingError);
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

// Endpoint para buscar atividade recente
router.get("/recent-activity", async (req, res) => {
    const limit = parseInt(req.query.limit, 10) || 25;

    try {
        const { data, error } = await supabase
            .from('user_activity')
            .select('*')
            .order('created_at', { ascending: false })
            .limit(limit);

        if (error) throw error;
        res.status(200).json(data);
    } catch (error) {
        handleSupabaseError(error, res);
    }
});

// Endpoint para buscar estatísticas do dashboard
router.get("/dashboard-stats", async (req, res) => {
    // Tenta usar a função RPC otimizada primeiro
    const { data: rpcData, error: rpcError } = await supabase.rpc('get_dashboard_stats_fallback').single();

    if (!rpcError && rpcData) {
        // Sucesso! A função RPC existe e retornou dados.
        return res.status(200).json({
            activeBanks: rpcData.active_banks || 0,
            todayViews: rpcData.today_views || 0,
            weeklyViews: rpcData.weekly_views || 0,
            monthlyViews: rpcData.monthly_views || 0,
            bouncedSessions: rpcData.bounced_sessions || 0
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

        const [activeBanksRes, todayViewsRes, weeklyViewsRes, monthlyViewsRes, bouncedSessionsRes] = await Promise.all([
            supabase.from('rate_providers').select('id', { count: 'exact', head: true }).eq('type', 'FORMAL').eq('is_active', true),
            supabase.rpc('count_distinct_sessions', { event: 'page_view', start_time: todayStart, end_time: todayEnd }),
            supabase.rpc('count_distinct_sessions', { event: 'page_view', start_time: weekStart, end_time: todayEnd }),
            supabase.rpc('count_distinct_sessions', { event: 'page_view', start_time: monthStart, end_time: todayEnd }),
            supabase.rpc('count_bounced_sessions', { start_time: todayStart, end_time: todayEnd })
        ]);

        // Verifica erros em cada uma das respostas
        const errors = [activeBanksRes, todayViewsRes, weeklyViewsRes, monthlyViewsRes, bouncedSessionsRes].map(r => r.error).filter(Boolean);
        if (errors.length > 0) {
            console.error("Erros nas queries de fallback do dashboard:", errors);
            // Lança o primeiro erro encontrado para ser tratado pelo handleSupabaseError
            throw errors[0];
        }

        const activeBanks = activeBanksRes.count || 0;
        const todayViews = todayViewsRes.data || 0;
        const weeklyViews = weeklyViewsRes.data || 0;
        const monthlyViews = monthlyViewsRes.data || 0;
        const bouncedSessions = bouncedSessionsRes.data || 0;

        res.status(200).json({
            activeBanks,
            todayViews,
            weeklyViews,
            monthlyViews,
            bouncedSessions
        });

    } catch (error) {
        handleSupabaseError(error, res);
    }
});


// Endpoint para buscar estatísticas de cliques de afiliados
router.get("/affiliate-clicks-stats", async (req, res) => {
    try {
        const nowUTC = new Date();
        const todayStart = new Date(Date.UTC(nowUTC.getUTCFullYear(), nowUTC.getUTCMonth(), nowUTC.getUTCDate(), 0, 0, 0, 0)).toISOString();
        const todayEnd = new Date(Date.UTC(nowUTC.getUTCFullYear(), nowUTC.getUTCMonth(), nowUTC.getUTCDate(), 23, 59, 59, 999)).toISOString();
        const monthStart = new Date(Date.UTC(nowUTC.getUTCFullYear(), nowUTC.getUTCMonth(), 1, 0, 0, 0, 0)).toISOString();
        const weekStartDate = new Date(nowUTC);
        weekStartDate.setUTCDate(weekStartDate.getUTCDate() - 6);
        weekStartDate.setUTCHours(0, 0, 0, 0);
        const weekStart = weekStartDate.toISOString();

        const [todayClicksRes, weeklyClicksRes, monthlyClicksRes, allClicksRes] = await Promise.all([
            supabase.from('user_activity').select('session_id, details').in('event_type', ['affiliate_click', 'buy_now_click']).gte('created_at', todayStart).lte('created_at', todayEnd),
            supabase.from('user_activity').select('session_id, details').in('event_type', ['affiliate_click', 'buy_now_click']).gte('created_at', weekStart),
            supabase.from('user_activity').select('session_id, details').in('event_type', ['affiliate_click', 'buy_now_click']).gte('created_at', monthStart),
            supabase.from('user_activity').select('session_id, details').in('event_type', ['affiliate_click', 'buy_now_click'])
        ]);

        const processClicks = (clicksRes) => {
            if (!clicksRes || clicksRes.error || !clicksRes.data) return { totalClicks: 0, uniqueSessions: 0, byLink: {} };
            const byLink = {};
            const uniqueSessions = new Set();
            clicksRes.data.forEach(click => {
                const linkId = click.details?.link_id;
                if (!linkId) return;
                if (!byLink[linkId]) byLink[linkId] = { totalClicks: 0, uniqueSessions: new Set() };
                byLink[linkId].totalClicks++;
                byLink[linkId].uniqueSessions.add(click.session_id);
                if (click.session_id) uniqueSessions.add(click.session_id);
            });
            Object.keys(byLink).forEach(linkId => { byLink[linkId].uniqueSessions = byLink[linkId].uniqueSessions.size; });
            return { totalClicks: clicksRes.data.length, uniqueSessions: uniqueSessions.size, byLink };
        };

        res.status(200).json({
            today: processClicks(todayClicksRes),
            weekly: processClicks(weeklyClicksRes),
            monthly: processClicks(monthlyClicksRes),
            allTime: processClicks(allClicksRes)
        });

    } catch (error) {
        handleSupabaseError(error, res);
    }
});

router.post("/notify-update", (req, res) => {
  broadcast({ type: "rates_updated" }, 'all');
  res.status(200).json({ success: true, message: "Notificação enviada." });
});

router.post("/add-province", async (req, res) => {
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

router.post("/update-status", async (req, res) => {
    const { type, id, isActive } = req.body;
    const tableMap = { bank: 'rate_providers', affiliate: 'affiliate_links', currency: 'currencies', supporter: 'supporters' };
    const tableName = tableMap[type];
    if (!tableName) return res.status(404).json({ message: "Tipo de recurso inválido." });

    const { error } = await supabase.from(tableName).update({ is_active: isActive }).eq('id', id);
    if (error) return handleSupabaseError(error, res);
    res.status(200).json({ success: true });
});

router.post("/update-cell", async (req, res) => {
    const { field, value, providerId, pair } = req.body;
    if (field === 'sell_rate') {
        const { error } = await supabase.from('exchange_rates').upsert({ provider_id: providerId, currency_pair: pair, sell_rate: value }, { onConflict: 'provider_id,currency_pair' });
        if (error) return handleSupabaseError(error, res);
    } else if (['fee_margin', 'base_fee_percent'].includes(field)) {
        const { error } = await supabase.from('rate_providers').update({ [field]: value }).eq('id', providerId);
        if (error) return handleSupabaseError(error, res);
    } else {
        return res.status(400).json({ message: "Campo inválido." });
    }
    res.status(200).json({ success: true });
});

router.post("/informal-rates", async (req, res) => {
    const { rates } = req.body;
    if (!rates) return res.status(400).json({ message: "Dados de taxas em falta." });
    const upserts = rates.filter(r => r.provider_id).map(r => ({
        id: r.id || undefined,
        provider_id: r.provider_id,
        currency_pair: r.currency_pair,
        sell_rate: r.sell_rate
    }));

    if (upserts.length === 0) return res.status(400).json({ message: "Nenhuma taxa válida para atualizar." });

    const { error } = await supabase.from('exchange_rates').upsert(upserts, { onConflict: 'provider_id, currency_pair' });
    if (error) return handleSupabaseError(error, res);
    res.status(200).json({ success: true });
});

router.post("/settings", async (req, res) => {
    const { settings } = req.body;
    if (!Array.isArray(settings)) return res.status(400).json({ message: "Formato de dados inválido." });

    const { error } = await supabase.from('site_settings').upsert(settings, { onConflict: 'key' });
    if (error) return handleSupabaseError(error, res);
    res.status(200).json({ success: true, message: "Configurações atualizadas." });
});

router.delete("/:resource/:id", async (req, res) => {
    const { resource, id } = req.params; 
    const tableMap = { rate_providers: 'rate_providers', bank: 'rate_providers', province: 'rate_providers', affiliate: 'affiliate_links', currency: 'currencies', supporter: 'supporters' };
    const tableName = tableMap[resource];
    if (!tableName) return res.status(404).json({ message: "Recurso não encontrado." });

    const { error } = await supabase.from(tableName).delete().eq('id', id);
    if (error) return handleSupabaseError(error, res);
    res.status(200).json({ success: true, message: "Recurso apagado." });
});

router.post("/reset-stats", async (req, res) => {
    try {
        const { error: affiliateError } = await supabase.from('affiliate_links').update({ click_count: 0 }).neq('click_count', -1);
        if (affiliateError) throw affiliateError;

        const { error: activityError } = await supabase.from('user_activity').delete().neq('event_type', 'non_existent_event');
        if (activityError) throw activityError;

        res.status(200).json({ success: true, message: "Estatísticas zeradas com sucesso." });
    } catch (error) {
        handleSupabaseError(error, res);
    }
});

router.post("/:resource", async (req, res) => {
    const { resource } = req.params;
    const { id, ...data } = req.body;
    const tableMap = { bank: 'rate_providers', affiliate: 'affiliate_links', currency: 'currencies', province: 'rate_providers', rate_providers: 'rate_providers' };
    const tableName = tableMap[resource];
    if (!tableName) return res.status(404).json({ message: "Recurso não encontrado." });

    try {
        let extraData = {};
        if (resource !== 'bank') delete data.base_fee_percent;
        if (resource === 'bank') {
            extraData = { usd_rate: data.usd_rate, eur_rate: data.eur_rate };
            delete data.usd_rate;
            delete data.eur_rate;
        }
        delete data.id;

        let query;
        if (id) {
            query = supabase.from(tableName).update(data).eq('id', id);
        } else {
            if (!data.hasOwnProperty('is_active')) data.is_active = true;
            if (resource === 'bank' && !data.type) data.type = 'FORMAL';
            query = supabase.from(tableName).insert(data);
        }

        const { data: result, error } = await query.select();
        
        if (error) {
            console.error(`Erro ao ${id ? 'atualizar' : 'criar'} ${resource}:`, error);
            return handleSupabaseError(error, res);
        }

        if (!id && resource === 'bank' && result?.[0]?.id) {
            const providerId = result[0].id;
            const usdRate = parseFloat(String(extraData.usd_rate ?? '')) || 0;
            const eurRate = parseFloat(String(extraData.eur_rate ?? '')) || 0;
            const ratesToInsert = [
                { provider_id: providerId, currency_pair: 'USD/AOA', sell_rate: usdRate },
                { provider_id: providerId, currency_pair: 'EUR/AOA', sell_rate: eurRate },
                { provider_id: providerId, currency_pair: 'USDT/AOA', sell_rate: 0 }
            ];
            const { error: ratesError } = await supabase.from('exchange_rates').insert(ratesToInsert);
            if (ratesError) console.error('Erro ao inserir taxas iniciais do banco novo:', ratesError);
        }

        res.status(200).json({ success: true, data: result });
    } catch (error) {
        console.error(`Erro inesperado ao ${id ? 'atualizar' : 'criar'} ${resource}:`, error);
        res.status(500).json({ success: false, message: "Erro interno do servidor", error: error.message });
    }
});

module.exports = router;