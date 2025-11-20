# 🚀 Deploy do EcoKambio para VPS Contabo

## 📋 Pré-requisitos

- ✅ Servidor VPS Contabo: `212.90.120.135`
- ✅ Domínio: `ecokambio.com` (Namecheap)
- ✅ Repositório: https://github.com/paulokakoma/cambioao
- ✅ Credenciais Supabase

## 🎯 Passos Rápidos

### 1. Configurar DNS no Namecheap

Adicionar os seguintes registros A:

| Host | Valor |
|------|-------|
| @ | 212.90.120.135 |
| admin | 212.90.120.135 |
| www | 212.90.120.135 |

### 2. Configurar Servidor VPS

```bash
# Conectar ao servidor
ssh root@212.90.120.135

# Executar setup inicial
curl -fsSL https://raw.githubusercontent.com/paulokakoma/cambioao/main/setup-server.sh | bash
```

OU manualmente:

```bash
# Atualizar sistema
apt update && apt upgrade -y

# Instalar Docker
curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh

# Instalar Docker Compose e Nginx
apt install docker-compose nginx certbot python3-certbot-nginx -y

# Configurar firewall
apt install ufw -y
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable

# Clonar repositório
cd /opt
git clone https://github.com/paulokakoma/cambioao.git
cd cambioao
```

### 3. Configurar Variáveis de Ambiente

```bash
cd /opt/cambioao
nano .env
```

Copiar conteúdo de `.env.example` e preencher com valores reais.

### 4. Configurar Nginx

```bash
# Copiar configuração
cp nginx/ecokambio.conf /etc/nginx/sites-available/ecokambio

# Ativar site
ln -s /etc/nginx/sites-available/ecokambio /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Testar e recarregar
nginx -t
systemctl reload nginx
```

### 5. Configurar SSL

```bash
certbot --nginx -d ecokambio.com -d www.ecokambio.com -d admin.ecokambio.com
```

### 6. Iniciar Aplicação

```bash
cd /opt/cambioao
docker-compose -f docker-compose.prod.yml build
docker-compose -f docker-compose.prod.yml up -d
```

### 7. Verificar

```bash
# Ver logs
docker logs cambioao-app-prod -f

# Ver status
docker ps
```

## 🔄 Atualizações Futuras

Para fazer deploy de novas versões:

```bash
# No seu computador local
./deploy.sh
```

Ou manualmente no servidor:

```bash
cd /opt/cambioao
git pull origin main
docker-compose -f docker-compose.prod.yml build
docker-compose -f docker-compose.prod.yml up -d
```

## 📊 Comandos Úteis

```bash
# Ver logs
docker logs cambioao-app-prod -f

# Reiniciar aplicação
docker-compose -f docker-compose.prod.yml restart

# Parar aplicação
docker-compose -f docker-compose.prod.yml down

# Ver uso de recursos
docker stats

# Limpar imagens antigas
docker image prune -f
```

## 🌐 Acessos

- **Site Principal**: https://ecokambio.com
- **Painel Admin**: https://admin.ecokambio.com/login
- **Senha Admin**: (usar hash configurado no .env)

## 📝 Notas Importantes

1. Certificar que `.env` nunca é commitado ao Git
2. Fazer backup do `.env` do servidor
3. Renovação SSL é automática via Certbot
4. Monitorar logs regularmente
5. Configurar backups do volume de sessões se necessário

## 🆘 Troubleshooting

### Aplicação não inicia

```bash
docker logs cambioao-app-prod
```

### Nginx não funciona

```bash
nginx -t
tail -f /var/log/nginx/error.log
```

### SSL não renova

```bash
certbot renew --dry-run
systemctl status certbot.timer
```

## 📞 Suporte

Para mais detalhes, consultar `implementation_plan.md` no diretório raiz.
