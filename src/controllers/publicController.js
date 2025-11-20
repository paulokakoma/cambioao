const supabase = require("../config/supabase");
const config = require("../config/env");
const { handleSupabaseError } = require("../utils/errorHandler");

const getConfig = (req, res) => {
    res.json({
        supabaseUrl: config.supabase.url,
        supabaseAnonKey: config.supabase.anonKey
    });
};

const getInformalRates = async (req, res) => {
    try {
        const [usdRateRes, eurRateRes] = await Promise.all([
            supabase.rpc('get_average_informal_rate', { p_pair: 'USD/AOA' }).single(),
            supabase.rpc('get_average_informal_rate', { p_pair: 'EUR/AOA' }).single()
        ]);

        if (usdRateRes.error || eurRateRes.error) {
            console.error("Erro ao buscar taxas informais:", usdRateRes.error || eurRateRes.error);
        }

        res.status(200).json({
            usd_rate: usdRateRes.data || 0,
            eur_rate: eurRateRes.data || 0
        });

    } catch (error) {
        handleSupabaseError(error, res);
    }
};

const logActivity = async (req, res) => {
    const activityPayload = {
        ...req.body,
        created_at: new Date().toISOString()
    };

    const { error } = await supabase.from('user_activity').insert(activityPayload);

    if (error) {
        return handleSupabaseError(error, res);
    }
    res.status(200).json({ success: true, message: 'Atividade registada.' });
};

// Public Visa Settings (for the card page)
const getVisaSettings = async (req, res) => {
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
};

const getAffiliateDetails = async (req, res) => {
    const { id } = req.params;

    try {
        const [productRes, informalRatesRes, settingsRes] = await Promise.all([
            supabase.from('affiliate_links').select('*').eq('id', id).single(),
            supabase.rpc('get_average_informal_rate', { p_pair: 'USD/AOA' }).single(),
            supabase.from('site_settings').select('value').eq('key', 'social_media_links').single(),
        ]);

        if (productRes?.error || !productRes?.data) {
            return res.status(404).json({ message: "Produto não encontrado." });
        }
        if (informalRatesRes?.error) {
            console.warn("Erro ao buscar taxa média informal:", informalRatesRes.error.message);
        }

        if (settingsRes?.data?.value) {
            productRes.data.social_media_links = settingsRes.data.value;
        }

        const product = productRes.data;

        let exchangeRate;
        if (informalRatesRes?.data && informalRatesRes.data > 0) {
            exchangeRate = informalRatesRes.data;
        } else {
            console.warn("Taxa média informal não encontrada, usando fallback para BNA.");
            const { data: bnaData } = await supabase
                .from('exchange_rates')
                .select('sell_rate')
                .eq('provider_id', 1)
                .eq('currency_pair', 'USD/AOA')
                .limit(1)
                .single();
            exchangeRate = bnaData?.sell_rate;
        }

        if (!exchangeRate || exchangeRate <= 0) {
            console.error("Nenhuma taxa de câmbio (nem informal, nem BNA) foi encontrada para calcular o preço.");
            return res.status(503).json({ message: "Serviço indisponível: Nenhuma taxa de câmbio foi encontrada para calcular o preço." });
        }

        const totalCostAOA = ((product.price || 0) + (product.shipping_cost_usd || 0)) * exchangeRate;

        res.json({ product, total_cost_aoa: totalCostAOA });
    } catch (error) {
        handleSupabaseError(error, res);
    }
};

const getStatus = (req, res) => {
    const os = require('os');
    res.status(200).json({
        status: "ok",
        hostname: os.hostname(),
        uptime_seconds: process.uptime(),
        node_version: process.version,
        environment: process.env.NODE_ENV || 'development',
        server_time_utc: new Date().toISOString()
    });
};

module.exports = { getConfig, getInformalRates, logActivity, getVisaSettings, getAffiliateDetails, getStatus };
