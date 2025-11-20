const supabase = require("../config/supabase");
const { handleSupabaseError } = require("../utils/errorHandler");
const { ensureStorageBucketExists } = require("../utils/storage");
const { broadcast } = require("../websocket");
const sharp = require("sharp");
const path = require("path");

const getRateProviders = async (req, res) => {
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

        const formattedData = data.map(provider => {
            const rates = provider.exchange_rates;
            const usdRateData = rates.find(r => r.currency_pair === 'USD/AOA');
            const eurRateData = rates.find(r => r.currency_pair === 'EUR/AOA');
            const usdtRateData = rates.find(r => r.currency_pair === 'USDT/AOA');

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
};

const getAffiliateLinks = async (req, res) => {
    try {
        const { data, error } = await supabase.from('affiliate_links').select('*').order('created_at', { ascending: false });
        if (error) throw error;
        res.status(200).json(data);
    } catch (error) {
        handleSupabaseError(error, res);
    }
};

const getSupporters = async (req, res) => {
    try {
        const { data, error } = await supabase.from('supporters').select('*').order('display_order', { ascending: true });
        if (error) throw error;
        res.status(200).json(data);
    } catch (error) {
        handleSupabaseError(error, res);
    }
};

const getCurrencies = async (req, res) => {
    try {
        const { data, error } = await supabase.from('currencies').select('*').order('code');
        if (error) throw error;
        res.status(200).json(data);
    } catch (error) {
        handleSupabaseError(error, res);
    }
};

const getSettings = async (req, res) => {
    const isPublicRequest = !req.session.isAdmin;

    try {
        let query = supabase.from('site_settings').select('key, value');

        if (isPublicRequest) {
            query = query.in('key', ['social_media_links', 'visa_image_url']);
        }

        const { data, error } = await query;
        if (error) throw error;

        const settingsObject = data.reduce((acc, { key, value }) => {
            acc[key] = value; return acc;
        }, {});

        res.status(200).json(settingsObject);
    } catch (error) {
        handleSupabaseError(error, res);
    }
};

const updateVisaSettings = async (req, res) => {
    const { visa_title, visa_fee_percent, visa_min_load, visa_whatsapp_number } = req.body;
    let newImageUrl;

    try {
        if (req.file) {
            console.log("Ficheiro de imagem recebido para /api/visa-settings. A processar...");

            await ensureStorageBucketExists('site-assets');
            const optimizedBuffer = await sharp(req.file.buffer)
                .resize({ width: 800, height: 800, fit: 'inside' })
                .webp({ quality: 85 })
                .toBuffer();
            const fileName = `visa-card-image-${Date.now()}.webp`;
            const { data: uploadData, error: uploadError } = await supabase.storage
                .from('site-assets')
                .upload(fileName, optimizedBuffer, {
                    contentType: 'image/webp',
                    upsert: true,
                });

            if (uploadError) throw uploadError;
            const { data: urlData } = supabase.storage.from('site-assets').getPublicUrl(fileName);
            if (!urlData?.publicUrl) throw new Error('Não foi possível obter o URL público da imagem.');

            newImageUrl = urlData.publicUrl;
        }

        const settingsToUpsert = [
            { key: 'visa_title', value: String(visa_title || '') },
            { key: 'visa_fee_percent', value: String(visa_fee_percent || '0') },
            { key: 'visa_min_load', value: String(visa_min_load || '') },
            { key: 'visa_whatsapp_number', value: String(visa_whatsapp_number || '') },
        ];

        if (newImageUrl) {
            settingsToUpsert.push({ key: 'visa_image_url', value: newImageUrl });
        }

        const { error: upsertError } = await supabase
            .from('site_settings')
            .upsert(settingsToUpsert, { onConflict: 'key' });

        if (upsertError) throw upsertError;

        res.status(200).json({
            success: true,
            message: `Configurações do Cartão Visa atualizadas com sucesso.${newImageUrl ? ' Nova imagem guardada.' : ''}`,
            newImageUrl: newImageUrl
        });

    } catch (error) {
        console.error("Erro ao atualizar configurações do Cartão Visa:", error);
        if (error.code) return handleSupabaseError(error, res);
        return res.status(500).json({ message: error.message || "Erro interno ao atualizar as configurações do Cartão Visa." });
    }
};

const createSupporter = async (req, res) => {
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
                    .resize({ width: 1500, height: 530, fit: 'inside' })
                    .webp({ quality: 80 })
                    .toBuffer();

                const originalNameWithoutExt = path.parse(file.originalname).name;
                const sanitizedOriginalName = originalNameWithoutExt
                    .normalize("NFD")
                    .replace(/[\u0300-\u036f]/g, "")
                    .replace(/[^a-zA-Z0-9._-]/g, '_');

                const fileName = `supporter-${Date.now()}-${sanitizedOriginalName}.webp`;

                const { data: uploadData, error: uploadError } = await supabase.storage.from('site-assets')
                    .upload(fileName, optimizedBuffer, {
                        contentType: 'image/webp',
                        upsert: true,
                    });

                if (uploadError) throw uploadError;
                if (!uploadData?.path) throw new Error('Caminho do arquivo não retornado pelo upload');

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
                .upsert({
                    key: settingKey,
                    value: banner_url
                }, {
                    onConflict: 'key'
                });

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
};

const getRecentActivity = async (req, res) => {
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
};

const notifyUpdate = (req, res) => {
    broadcast({ type: "rates_updated" }, 'all');
    res.status(200).json({ success: true, message: "Notificação enviada." });
};

const addProvince = async (req, res) => {
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
};

const updateStatus = async (req, res) => {
    const { type, id, isActive } = req.body;
    const tableMap = { bank: 'rate_providers', affiliate: 'affiliate_links', currency: 'currencies', supporter: 'supporters' };
    const tableName = tableMap[type];
    if (!tableName) return res.status(404).json({ message: "Tipo de recurso inválido." });

    const { error } = await supabase.from(tableName).update({ is_active: isActive }).eq('id', id);
    if (error) return handleSupabaseError(error, res);
    res.status(200).json({ success: true });
};

const updateCell = async (req, res) => {
    const { field, value, providerId, pair } = req.body;
    if (field === 'sell_rate') {
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

    res.status(200).json({ success: true });
};



const getDashboardStats = async (req, res) => {
    const onlineUsers = 0; // TODO: Get from WebSocket if possible, or pass it in.
    // Note: Accessing wss from here is tricky without dependency injection. 
    // For now we will skip onlineUsers or implement a way to get it.
    // We can export a getter from websocket.js

    const { getOnlineUserCount } = require('../websocket');
    const currentOnlineUsers = getOnlineUserCount ? getOnlineUserCount() : 0;

    const { data: rpcData, error: rpcError } = await supabase.rpc('get_dashboard_stats_fallback').single();

    if (!rpcError && rpcData) {
        return res.status(200).json({
            active_banks: rpcData.active_banks || 0,
            today_access: rpcData.today_views || 0,
            newVisitorsToday: rpcData.new_visitors_today || 0,
            monthlyAffiliateClicks: rpcData.monthly_affiliate_clicks || 0,
            monthlyVisaClicks: rpcData.monthly_visa_clicks || 0,
            weeklyViews: rpcData.weekly_views || 0,
            monthlyViews: rpcData.monthly_views || 0,
            onlineUsers: currentOnlineUsers
        });
    }

    console.warn("A função RPC 'get_dashboard_stats_fallback' não foi encontrada. Usando queries de fallback.");

    try {
        const nowUTC = new Date();
        const todayStart = new Date(Date.UTC(nowUTC.getUTCFullYear(), nowUTC.getUTCMonth(), nowUTC.getUTCDate(), 0, 0, 0, 0)).toISOString();
        const todayEnd = new Date(Date.UTC(nowUTC.getUTCFullYear(), nowUTC.getUTCMonth(), nowUTC.getUTCDate(), 23, 59, 59, 999)).toISOString();
        const monthStart = new Date(Date.UTC(nowUTC.getUTCFullYear(), nowUTC.getUTCMonth(), 1, 0, 0, 0, 0)).toISOString();
        const weekStartDate = new Date(nowUTC);
        weekStartDate.setUTCDate(weekStartDate.getUTCDate() - 6);
        weekStartDate.setUTCHours(0, 0, 0, 0);
        const weekStart = weekStartDate.toISOString();

        const [activeBanksRes, todayViewsRes, weeklyViewsRes, monthlyViewsRes, newVisitorsRes, monthlyAffiliateClicksRes, monthlyVisaClicksRes] = await Promise.all([
            supabase.from('rate_providers').select('id', { count: 'exact', head: true }).eq('type', 'FORMAL').eq('is_active', true),
            supabase.rpc('count_distinct_sessions', { event: 'page_view', start_time: todayStart, end_time: todayEnd }),
            supabase.rpc('count_distinct_sessions', { event: 'page_view', start_time: weekStart, end_time: todayEnd }),
            supabase.rpc('count_distinct_sessions', { event: 'page_view', start_time: monthStart, end_time: todayEnd }),
            supabase.rpc('count_distinct_sessions', { event: 'first_visit', start_time: todayStart, end_time: todayEnd }),
            supabase.from('user_activity').select('id', { count: 'exact', head: true }).eq('event_type', 'affiliate_click').gte('created_at', monthStart),
            supabase.from('user_activity').select('id', { count: 'exact', head: true }).eq('event_type', 'visa_cta_click').gte('created_at', monthStart)
        ]);

        res.status(200).json({
            active_banks: activeBanksRes.count || 0,
            today_access: todayViewsRes.data || 0,
            weeklyViews: weeklyViewsRes.data || 0,
            monthlyViews: monthlyViewsRes.data || 0,
            newVisitorsToday: newVisitorsRes.data || 0,
            monthlyAffiliateClicks: monthlyAffiliateClicksRes.count || 0,
            monthlyVisaClicks: monthlyVisaClicksRes.count || 0,
            onlineUsers: currentOnlineUsers
        });
    } catch (error) {
        handleSupabaseError(error, res);
    }
};

const getWeeklyActivity = async (req, res) => {
    const { month, months } = req.query;

    try {
        let rpcName, rpcParams;

        if (month && /^\d{4}-\d{2}$/.test(month)) {
            rpcName = 'get_weekly_activity_for_month';
            rpcParams = { p_month: month };
        } else if (months) {
            rpcName = 'get_monthly_activity';
            rpcParams = { p_months: months === 'all' ? null : parseInt(months, 10) };
        } else {
            return res.status(400).json({ message: "Parâmetro 'month' (YYYY-MM) ou 'months' (número) é obrigatório." });
        }

        const { data, error } = await supabase.rpc(rpcName, rpcParams);

        if (error) throw error;
        res.status(200).json(data);
    } catch (error) {
        handleSupabaseError(error, res);
    }
};

const getEventTypeStats = async (req, res) => {
    try {
        const { data: rpcData, error: rpcError } = await supabase.rpc('get_event_type_counts');

        if (!rpcError && rpcData) {
            return res.status(200).json(rpcData);
        }

        console.warn("A função RPC 'get_event_type_counts' não foi encontrada. Usando query de fallback.");

        const { data, error } = await supabase
            .from('user_activity')
            .select('event_type')
            .throwOnError();

        const counts = data.reduce((acc, { event_type }) => {
            acc[event_type] = (acc[event_type] || 0) + 1;
            return acc;
        }, {});

        const result = Object.entries(counts).map(([event_type, count]) => ({ event_type, count }));

        res.status(200).json(result);
    } catch (error) {
        handleSupabaseError(error, res);
    }
};

const resetStats = async (req, res) => {
    try {
        const { error: affiliateError } = await supabase
            .from('affiliate_links')
            .update({ click_count: 0 })
            .neq('click_count', -1);

        if (affiliateError) throw affiliateError;

        const { error: activityError } = await supabase.from('user_activity').delete().neq('event_type', 'non_existent_event');

        if (activityError) throw activityError;

        res.status(200).json({ success: true, message: "Estatísticas zeradas com sucesso." });
    } catch (error) {
        handleSupabaseError(error, res);
    }
};

const handleResourcePost = (resource, tableName) => {
    return async (req, res) => {
        const { id, ...data } = req.body;

        try {
            console.log(`Tentando ${id ? 'atualizar' : 'criar'} ${resource}:`, data);
            let extraData = {};
            if (resource === 'bank') {
                extraData = { usd_rate: data.usd_rate, eur_rate: data.eur_rate };
                delete data.usd_rate;
                delete data.eur_rate;
            }

            delete data.id;

            if (resource === 'bank') {
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
                if (!data.hasOwnProperty('is_active')) {
                    data.is_active = true;
                }
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
                }
            }

            console.log(`${resource} ${id ? 'atualizado' : 'criado'} com sucesso:`, result);
            res.status(200).json({ success: true, data: result });
        } catch (error) {
            console.error(`Erro inesperado ao ${id ? 'atualizar' : 'criar'} ${resource}:`, error);
            res.status(500).json({ success: false, message: "Erro interno do servidor", error: error.message });
        }
    };
};

module.exports = {
    getRateProviders,
    getAffiliateLinks,
    getSupporters,
    getCurrencies,
    getSettings,
    updateVisaSettings,
    createSupporter,
    getRecentActivity,
    notifyUpdate,
    addProvince,
    updateStatus,
    updateCell,
    getDashboardStats,
    getWeeklyActivity,
    getEventTypeStats,
    resetStats,
    handleResourcePost
};
