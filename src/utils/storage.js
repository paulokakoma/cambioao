const supabase = require("../config/supabase");

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

module.exports = { ensureStorageBucketExists };
