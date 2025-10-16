const express = require("express");
const { createClient } = require("@supabase/supabase-js");

const router = express.Router();

// Inicializa o cliente Supabase dentro do router
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// --- Lógica de Cache em Memória ---
let cachedData = null;
let cacheTimestamp = 0;
const CACHE_DURATION_MS = 5 * 60 * 1000; // 5 minutos

// Endpoint da API para obter TODOS os dados do mercado de uma só vez
router.get("/all-rates", async (req, res) => {
  const now = Date.now();
  if (cachedData && now - cacheTimestamp < CACHE_DURATION_MS) {
    console.log("Servindo dados do cache.");
    return res.json(cachedData);
  }

  try {
    const results = await Promise.allSettled([
      supabase.from("bank_rates").select("*"),
      supabase.from("informal_market_offers").select("*"),
      supabase.from("luibor_rates").select("*"),
      supabase.from("inflation_data").select("*"),
    ]);

    const [
      formalRatesResult,
      informalOffersResult,
      luiborRatesResult,
      inflationDataResult,
    ] = results;

    // Verifica cada resultado individualmente para um melhor diagnóstico de erros
    if (
      formalRatesResult.status === "rejected" ||
      formalRatesResult.value.error
    ) {
      throw new Error(
        `Falha ao buscar bank_rates: ${
          formalRatesResult.reason?.message ||
          formalRatesResult.value.error?.message
        }`
      );
    }
    if (
      informalOffersResult.status === "rejected" ||
      informalOffersResult.value.error
    ) {
      throw new Error(
        `Falha ao buscar informal_market_offers: ${
          informalOffersResult.reason?.message ||
          informalOffersResult.value.error?.message
        }`
      );
    }
    if (
      luiborRatesResult.status === "rejected" ||
      luiborRatesResult.value.error
    ) {
      throw new Error(
        `Falha ao buscar luibor_rates: ${
          luiborRatesResult.reason?.message ||
          luiborRatesResult.value.error?.message
        }`
      );
    }
    if (
      inflationDataResult.status === "rejected" ||
      inflationDataResult.value.error
    ) {
      throw new Error(
        `Falha ao buscar inflation_data: ${
          inflationDataResult.reason?.message ||
          inflationDataResult.value.error?.message
        }`
      );
    }

    const marketData = {
      formalRates: formalRatesResult.value.data,
      informalOffers: informalOffersResult.value.data,
      luiborRates: luiborRatesResult.value.data,
      inflationData: inflationDataResult.value.data,
    };

    // Armazena os novos dados e o timestamp no cache
    cachedData = marketData;
    cacheTimestamp = now;
    console.log("Cache atualizado com novos dados do Supabase.");

    res.json(marketData);
  } catch (error) {
    console.error("Erro detalhado ao buscar dados do Supabase:", error.message);
    res
      .status(500)
      .json({ error: "Não foi possível obter os dados do mercado." });
  }
});

module.exports = router;
