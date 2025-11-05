const { WebSocketServer } = require("ws");
const { supabase } = require("./supabase");

let wss;

function initWebSocket(server) {
    wss = new WebSocketServer({ server });

    // Adiciona um listener de erro para o WebSocketServer
    wss.on('error', (error) => {
      console.error('Erro no WebSocketServer (handshake ou geral):', error);
    });

    wss.on("connection", (ws, req) => {
        const params = new URLSearchParams(req.url.slice(1));
        ws.isAdmin = params.get('client') === 'admin';
        console.log(`Cliente WebSocket conectado ${ws.isAdmin ? '(Admin)' : '(Usuário)'}.`);
        broadcastUserCount();

        ws.on('message', (message) => {
            try {
                const data = JSON.parse(message);
                if (data.type === 'log_activity' && data.payload) {
                    const activityPayload = {
                        ...data.payload,
                        created_at: new Date().toISOString()
                    };
                    
                    supabase.from('user_activity').insert(activityPayload).then(({ error }) => {
                        if (error) {
                            console.error('Erro ao inserir atividade do WebSocket na BD:', error);
                        }
                    });

                    if ((data.payload.event_type === 'affiliate_click' || data.payload.event_type === 'buy_now_click') && data.payload.details?.link_id) {
                        const linkId = data.payload.details.link_id;
                        console.log(`[SERVER] Recebido clique de afiliado para o link ID: ${linkId}. A chamar RPC 'increment_affiliate_click'...`);
                        
                        supabase.rpc('increment_affiliate_click', { link_id_to_inc: linkId }, { cast: 'bigint' })
                          .then(({ error }) => {
                            if (error) {
                              console.error(`[SERVER] ❌ ERRO ao incrementar contador de cliques para o link ID ${linkId}:`, error);
                            } else {
                              console.log(`[SERVER] ✅ SUCESSO ao incrementar contador de cliques para o link ID ${linkId}.`);
                            }
                          });
                    }
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
}

const broadcast = (data, target = 'all') => {
    if (!wss) return;
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
    if (!wss) return;
    const userCount = Array.from(wss.clients).filter(c => !c.isAdmin).length;
    broadcast({ type: 'user_count_update', count: userCount }, 'admin');
};

module.exports = { initWebSocket, broadcast };