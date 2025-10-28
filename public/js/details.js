// --- CONFIGURAÇÃO ---
const WEBSOCKET_URL = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}`;

let dbClient;
let ws;

async function init() {
    try {
        // Inicializa o cliente Supabase
        dbClient = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
        
        // Conecta ao WebSocket
        connectWebSocket();
        
        // Carrega os detalhes do produto
        await loadProductDetails();
        
    } catch (error) {
        console.error('Erro na inicialização:', error);
    }
}

function connectWebSocket() {
    ws = new WebSocket(WEBSOCKET_URL);
    
    ws.onopen = () => {
        console.log('WebSocket conectado.');
    };
    
    ws.onclose = () => {
        console.log('WebSocket desconectado. Tentando reconectar...');
        setTimeout(connectWebSocket, 1000);
    };
    
    ws.onerror = (error) => {
        console.error('Erro no WebSocket:', error);
    };
}

async function loadProductDetails() {
    const urlParams = new URLSearchParams(window.location.search);
    const productId = urlParams.get('id');
    
    if (!productId) {
        showError('ID do produto não fornecido');
        return;
    }
    
    try {
        // Busca os detalhes do produto
        const { data: product, error } = await dbClient
            .from('affiliate_links')
            .select('*')
            .eq('id', productId)
            .single();
            
        if (error) throw error;
        if (!product) {
            showError('Produto não encontrado');
            return;
        }
        
        // Registra a visualização
        logActivity('affiliate_view', {
            link_id: product.id,
            product_title: product.title
        });
        
        // Renderiza os detalhes do produto
        renderProductDetails(product);
        
    } catch (error) {
        console.error('Erro ao carregar detalhes:', error);
        showError('Erro ao carregar detalhes do produto');
    }
}

function renderProductDetails(product) {
    // Atualiza o título da página
    document.title = `${product.title} - Mercado Cambial`;
    
    // Atualiza a imagem e título
    document.getElementById('product-image').src = product.image_url || '/assets/error-state.svg';
    document.getElementById('product-title').textContent = product.title;
    
    // Atualiza o preço em USD
    const priceElement = document.getElementById('product-price');
    if (priceElement) {
        const totalUSD = (product.price || 0) + (product.shipping_cost_usd || 0);
        priceElement.textContent = new Intl.NumberFormat('en-US', {
            style: 'currency',
            currency: 'USD'
        }).format(totalUSD);
    }
    
    // Atualiza o link de compra
    const buyButton = document.getElementById('buy-button');
    if (buyButton && product.url) {
        buyButton.href = product.url;
        buyButton.addEventListener('click', () => {
            logActivity('affiliate_click', {
                link_id: product.id,
                product_title: product.title
            });
        });
    }
    
    // Atualiza o vídeo de prova, se existir
    const proofVideoContainer = document.getElementById('proof-video-container');
    if (proofVideoContainer && product.proof_video_url) {
        proofVideoContainer.innerHTML = `
            <div class="aspect-w-16 aspect-h-9">
                <iframe src="${product.proof_video_url}"
                        class="w-full h-full rounded-xl"
                        frameborder="0"
                        allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                        allowfullscreen></iframe>
            </div>`;
    } else if (proofVideoContainer) {
        proofVideoContainer.classList.add('hidden');
    }
}

function showError(message) {
    const container = document.querySelector('main');
    if (container) {
        container.innerHTML = `
            <div class="max-w-2xl mx-auto px-4 py-16 text-center">
                <img src="/assets/error-state.svg" alt="Erro" class="w-32 h-32 mx-auto mb-6">
                <h1 class="text-2xl font-bold text-slate-900 mb-2">Ops! Algo deu errado</h1>
                <p class="text-slate-600">${message}</p>
                <a href="/" class="inline-block mt-6 px-6 py-3 bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 transition-colors">
                    Voltar para a página inicial
                </a>
            </div>`;
    }
}

async function logActivity(type, metadata = {}) {
    try {
        const { error } = await dbClient
            .from('user_activity')
            .insert([{ type, metadata }]);
            
        if (error) throw error;
    } catch (error) {
        console.error('Erro ao registrar atividade:', error);
    }
}

// Inicializa quando o DOM estiver pronto
document.addEventListener('DOMContentLoaded', init);
