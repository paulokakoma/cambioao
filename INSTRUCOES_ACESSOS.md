# Instruções: Garantir Cadastro e Exibição de Acessos

## ✅ O que foi implementado:

### 1. Melhorias no Frontend (`public/index.html`)
- ✅ Função `logActivity()` melhorada com múltiplos fallbacks
- ✅ Tentativa via WebSocket primeiro
- ✅ Fallback automático para API HTTP se WebSocket falhar
- ✅ Retry automático em caso de erros
- ✅ Garantia de que os acessos sejam sempre registrados

### 2. Melhorias no Servidor (`server.js`)
- ✅ Melhor tratamento de erros na inserção via WebSocket
- ✅ Logs detalhados em desenvolvimento
- ✅ Garantia de que `created_at` seja sempre preenchido
- ✅ Retorno de dados inseridos para confirmação

### 3. Melhorias no Admin (`private/admin.html`)
- ✅ Função `loadDashboardData()` melhorada
- ✅ Tratamento de erros robusto
- ✅ Exibição sempre mostra valores (mesmo que 0 em caso de erro)
- ✅ Logs detalhados no console para debug
- ✅ Atualização automática quando novas atividades chegam via WebSocket

## 📋 Passos para Configurar:

### Passo 1: Criar a Tabela no Supabase

1. Acesse o **Supabase Dashboard** do seu projeto
2. Vá em **SQL Editor**
3. Abra o arquivo `create_user_activity_table.sql`
4. Cole e execute todo o conteúdo
5. Verifique se aparece a mensagem de sucesso e estatísticas

### Passo 2: Verificar Configuração

O script SQL criará:
- ✅ Tabela `user_activity` com todas as colunas necessárias
- ✅ Índices para performance
- ✅ Row Level Security (RLS) configurado
- ✅ Funções RPC necessárias:
  - `increment_affiliate_click`
  - `get_weekly_activity`
  - `get_tab_visit_counts`

### Passo 3: Testar

1. **Teste o registro de acessos:**
   - Acesse a página principal do site
   - Abra o console do navegador (F12)
   - Deve ver logs de atividade sendo registrada

2. **Teste no Admin:**
   - Faça login no admin
   - Vá para o Dashboard
   - Verifique se os contadores aparecem:
     - Acessos Hoje
     - Acessos Semanais
     - Acessos Mensais
   - Abra o console (F12) e verifique logs:
     - `✅ Dashboard atualizado: {hoje: X, semana: Y, mes: Z}`

3. **Teste após recarregar:**
   - Recarregue a página do admin (F5)
   - Os contadores devem manter os mesmos valores

## 🔍 Como Verificar se está Funcionando:

### No Console do Navegador (Frontend):
- Ao acessar a página principal, deve aparecer: `WebSocket conectado.`
- Se houver erro, aparecerá: `WebSocket não disponível, usando API HTTP`

### No Console do Servidor:
- Em desenvolvimento, deve aparecer: `Atividade registrada com sucesso via WebSocket` ou `via API`

### No Supabase:
Execute esta query no SQL Editor:
```sql
SELECT 
    event_type,
    COUNT(*) as total,
    COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE) as hoje,
    MAX(created_at) as ultimo_acesso
FROM user_activity
WHERE event_type = 'page_view'
GROUP BY event_type;
```

## 🐛 Troubleshooting:

### Problema: Contadores mostram 0 ou "Erro"
**Solução:**
1. Verifique se a tabela `user_activity` foi criada corretamente
2. Verifique as políticas RLS no Supabase
3. Verifique os logs do servidor para erros de inserção

### Problema: Acessos não aparecem após recarregar
**Solução:**
1. Verifique no Supabase se os dados estão sendo inseridos
2. Verifique o console do navegador no admin para erros
3. Verifique se `loadDashboardData()` está sendo chamado

### Problema: WebSocket não conecta
**Solução:**
- O sistema tem fallback automático para API HTTP
- Verifique se a porta do WebSocket está correta
- Verifique se há firewall bloqueando conexões WebSocket

## 📊 Estrutura de Dados:

A tabela `user_activity` armazena:
```javascript
{
    id: número_auto_incremento,
    event_type: 'page_view' | 'affiliate_click' | 'tab_switch' | etc,
    session_id: 'ID_da_sessão',
    details: { /* dados adicionais em JSON */ },
    created_at: '2024-01-01T00:00:00Z'
}
```

## 🎯 Resultado Esperado:

Após seguir estes passos:
1. ✅ Cada acesso à página principal é registrado no banco
2. ✅ Os contadores no admin são atualizados em tempo real
3. ✅ Após recarregar o admin, os contadores mantêm os valores corretos
4. ✅ Os dados persistem no banco de dados

## 📝 Notas Importantes:

- Os acessos são registrados automaticamente quando um usuário visita a página principal
- O admin mostra os dados em tempo real via WebSocket
- Se o WebSocket falhar, o sistema usa API HTTP como fallback
- Todos os erros são logados no console para facilitar debug

