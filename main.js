
/**
 * EcoKambio - Lógica Principal de Rastreamento de Atividade
 * 
 * Este script é responsável por:
 * 1. Gerar um ID de sessão único para cada visitante.
 * 2. Conectar-se ao servidor via WebSocket para comunicação em tempo real.
 * 3. Se o WebSocket falhar, usar uma API HTTP como fallback.
 * 4. Registrar a visita inicial à página ('page_view').
 * 5. Expor uma função global `logActivity` para registrar outras interações.
 */

document.addEventListener('DOMContentLoaded', () => {
    const WEBSOCKET_URL = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}`;
    let ws;
    let sessionId;

    // --- 1. GESTÃO DA IDENTIDADE E SESSÃO ---

    /**
     * Gera ou recupera identificadores para o visitante.
     * - `sessionId`: Dura apenas enquanto a aba do navegador está aberta.
     * - `visitorId`: Persiste entre visitas, usado para identificar visitantes recorrentes.
     * @returns {{sessionId: string, visitorId: string, isNewVisitor: boolean}}
     */
    function getVisitorIdentity() {
        // ID de Sessão (dura enquanto a aba está aberta)
        if (!sessionStorage.getItem('ek_session_id')) {
            const randomPart = Math.random().toString(36).substring(2, 15);
            const timePart = Date.now().toString(36);
            sessionStorage.setItem('ek_session_id', `s_${timePart}_${randomPart}`);
        }
        const sessionId = sessionStorage.getItem('ek_session_id');

        // ID de Visitante (persiste entre visitas)
        let visitorId = localStorage.getItem('ek_visitor_id');
        let isNewVisitor = false;

        if (!visitorId) {
            isNewVisitor = true;
            visitorId = `v_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
            localStorage.setItem('ek_visitor_id', visitorId);
        }

        return { sessionId, visitorId, isNewVisitor };
    }

    /**
     * Tenta conectar-se ao servidor via WebSocket.
     */
    function connectWebSocket() {
        console.log('🔌 A tentar conectar ao WebSocket...');
        ws = new WebSocket(`${WEBSOCKET_URL}?client=user`);

        ws.onopen = () => {
            console.log('✅ WebSocket conectado.');
            // Assim que conecta, regista a visita à página
            logActivity('page_view', { path: window.location.pathname });
        };

        ws.onclose = () => {
            console.log('🔌 WebSocket desconectado.');
            ws = null; // Garante que o fallback seja usado
        };

        ws.onerror = (error) => {
            console.error('❌ Erro no WebSocket:', error);
            ws = null; // Garante que o fallback seja usado
        };
    }

    /**
     * Envia um evento de atividade para o servidor.
     * Tenta usar o WebSocket primeiro, e se falhar, usa a API HTTP.
     * @param {string} eventType - O tipo de evento (ex: 'page_view', 'tab_switch').
     * @param {object} details - Um objeto com detalhes adicionais sobre o evento.
     */
    async function logActivity(eventType, details = {}) {
        const identity = getVisitorIdentity();

        const payload = {
            event_type: eventType,
            session_id: identity.sessionId,
            details: {
                ...details,
                visitor_id: identity.visitorId, // Adiciona o ID persistente do visitante
                url: window.location.href,
                userAgent: navigator.userAgent,
            },
        };

        // Tenta enviar via WebSocket se a conexão estiver ativa
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'log_activity', payload }));
            console.log(`[WS] Atividade '${eventType}' enviada.`);
        } else {
            // Fallback para API HTTP
            try {
                console.log(`[HTTP] WebSocket não disponível. A enviar atividade '${eventType}' via API.`);
                await fetch('/api/log-activity', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                });
            } catch (error) {
                console.error(`[HTTP] Falha ao enviar atividade '${eventType}':`, error);
            }
        }
    }

    // --- 3. INICIALIZAÇÃO ---
    window.logActivity = logActivity; // Expõe a função globalmente

    // Verifica se é um novo visitante e registra o evento
    const { isNewVisitor } = getVisitorIdentity();
    if (isNewVisitor) {
        logActivity('first_visit');
    }

    // Adiciona o listener para o botão "Cartão Visa" no cabeçalho
    const visaHeaderButton = document.getElementById('header-visa-btn');
    if (visaHeaderButton) {
        visaHeaderButton.addEventListener('click', (e) => {
            // Previne a navegação imediata para dar tempo de registrar o evento
            e.preventDefault(); 
            
            // Registra o clique com o tipo de evento correto
            logActivity('visa_cta_click', { cta_position: 'header' });

            // Redireciona para a página do Visa após um pequeno atraso
            setTimeout(() => { window.location.href = visaHeaderButton.href; }, 300);
        });
    }

    connectWebSocket(); // Inicia a conexão ao carregar a página
});