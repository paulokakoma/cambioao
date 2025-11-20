function handleSupabaseError(error, res) {
    // Verifica se é um erro de violação de unicidade (código 23505)
    if (error.code === '23505') {
        return res.status(409).json({ message: "Erro: Já existe um registo com um destes valores (ex: código ou URL)." });
    }
    // Para outros erros da base de dados
    console.error("Erro do Supabase:", error);
    return res.status(500).json({ message: error.message });
}

module.exports = { handleSupabaseError };
