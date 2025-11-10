const express = require("express");
const { supabase, handleSupabaseError } = require("../services/supabase");
const router = express.Router();

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseAnonKey) {
  console.error("Erro: Variáveis de ambiente SUPABASE_URL ou SUPABASE_ANON_KEY estão em falta.");
  process.exit(1);
}

// Endpoint para fornecer configuração ao frontend (pode ser público)
router.get("/config", (req, res) => {
  res.json({
    supabaseUrl: supabaseUrl,
    supabaseAnonKey: supabaseAnonKey
  });
});

// Endpoint para detalhes de um produto afiliado (PÚBLICO)
router.get("/affiliate-details/:id", async (req, res) => {
    const { id } = req.params;

    try {
        const [productRes, informalRatesRes, settingsRes] = await Promise.all([
            supabase.from('affiliate_links').select('*').eq('id', id).single(),
            supabase.rpc('get_average_informal_rate', { p_pair: 'USD/AOA' }),
            supabase.from('site_settings').select('value').eq('key', 'social_media_links').single()
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

        let exchangeRate = informalRatesRes?.data > 0 ? informalRatesRes.data : (await supabase.from('exchange_rates').select('sell_rate').eq('provider_id', 1).eq('currency_pair', 'USD/AOA').maybeSingle())?.data?.sell_rate;

        if (!exchangeRate || exchangeRate <= 0) {
            console.error("Nenhuma taxa de câmbio foi encontrada para calcular o preço.");
            return res.status(503).json({ message: "Serviço indisponível: Nenhuma taxa de câmbio foi encontrada para calcular o preço." });
        }

        const totalCostAOA = ((product.price || 0) + (product.shipping_cost_usd || 0)) * exchangeRate;

        res.json({ product, total_cost_aoa: totalCostAOA });
    } catch (error) {
        handleSupabaseError(error, res);
    }
});

module.exports = router;