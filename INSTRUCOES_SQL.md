# Instruções para Garantir Persistência de Acessos

## Problema
Os contadores de acesso não estão sendo mantidos após recarregar a página do admin.

## Solução
Execute os scripts SQL no Supabase para garantir que a tabela `user_activity` existe e está configurada corretamente.

## Como Executar

### Opção 1: Script Completo (Recomendado)
1. Acesse o **Supabase Dashboard** do seu projeto
2. Vá em **SQL Editor**
3. Abra o arquivo `ensure_user_activity_table.sql`
4. Cole todo o conteúdo no editor SQL
5. Clique em **Run** ou pressione `Ctrl+Enter` (Windows/Linux) ou `Cmd+Enter` (Mac)

### Opção 2: Script Simplificado
1. Acesse o **Supabase Dashboard** do seu projeto
2. Vá em **SQL Editor**
3. Abra o arquivo `ensure_user_activity_simple.sql`
4. Cole todo o conteúdo no editor SQL
5. Clique em **Run**

## O que cada script faz:

### Script Completo (`ensure_user_activity_table.sql`)
- ✅ Cria a tabela `user_activity` se não existir
- ✅ Cria índices para melhorar performance
- ✅ Garante que `created_at` seja preenchido automaticamente
- ✅ Cria funções RPC necessárias (`increment_affiliate_click`, `get_weekly_activity`, `get_tab_visit_counts`)
- ✅ Configura Row Level Security (RLS) corretamente
- ✅ Mostra estatísticas da tabela após execução

### Script Simplificado (`ensure_user_activity_simple.sql`)
- ✅ Cria a tabela `user_activity` se não existir
- ✅ Cria índices essenciais
- ✅ Configura Row Level Security (RLS) básico
- ✅ Mostra resumo da tabela

## Verificação

Após executar o script, você deve ver uma mensagem de sucesso e estatísticas da tabela.

Para verificar manualmente se está funcionando:
```sql
SELECT 
    event_type,
    COUNT(*) as total,
    MAX(created_at) as ultimo_acesso
FROM user_activity
WHERE event_type = 'page_view'
GROUP BY event_type;
```

## Estrutura da Tabela

A tabela `user_activity` deve ter as seguintes colunas:
- `id` - BIGSERIAL (chave primária)
- `event_type` - TEXT (ex: 'page_view', 'affiliate_click')
- `session_id` - TEXT (ID da sessão do usuário)
- `details` - JSONB (detalhes do evento)
- `created_at` - TIMESTAMPTZ (data/hora de criação, automático)

## Notas Importantes

⚠️ **O script completo pode falhar se as funções RPC já existirem com assinaturas diferentes.** Se isso acontecer, você pode:
1. Executar apenas o script simplificado primeiro
2. Depois executar as funções RPC individualmente se necessário

✅ **Os scripts são seguros** - Eles usam `CREATE TABLE IF NOT EXISTS` e `CREATE INDEX IF NOT EXISTS`, então não vão sobrescrever dados existentes.

## Depois de Executar

1. Teste acessando a página principal do site
2. Vá para o admin e verifique se os contadores estão aparecendo
3. Recarregue a página do admin e verifique se os números são mantidos

