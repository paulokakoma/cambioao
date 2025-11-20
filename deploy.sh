#!/bin/bash

# Script de Deploy Automatizado para EcoKambio
# Servidor: 212.90.120.135
# Domínio: ecokambio.com

set -e  # Parar em caso de erro

echo "🚀 Iniciando deploy do EcoKambio..."

# Cores para output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Verificar se está no diretório correto
if [ ! -f "package.json" ]; then
    echo -e "${RED}❌ Erro: Execute este script no diretório raiz do projeto${NC}"
    exit 1
fi

# Diretório do projeto no servidor
PROJECT_DIR="/opt/cambioao"

echo -e "${YELLOW}📦 Passo 1: Fazer push das alterações para o GitHub...${NC}"
read -p "Deseja fazer commit e push? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    git add .
    read -p "Mensagem do commit: " commit_msg
    git commit -m "$commit_msg"
    git push origin main
    echo -e "${GREEN}✅ Push concluído${NC}"
else
    echo -e "${YELLOW}⚠️  Pulando push para o GitHub${NC}"
fi

echo -e "${YELLOW}📡 Passo 2: Conectando ao servidor...${NC}"
ssh root@212.90.120.135 << 'ENDSSH'
    set -e
    
    echo "📂 Navegando para o diretório do projeto..."
    cd /opt/cambioao
    
    echo "📥 Fazendo pull das alterações..."
    git pull origin main
    
    echo "🔨 Fazendo rebuild da imagem Docker..."
    docker-compose -f docker-compose.prod.yml build
    
    echo "🔄 Reiniciando aplicação..."
    docker-compose -f docker-compose.prod.yml down
    docker-compose -f docker-compose.prod.yml up -d
    
    echo "🧹 Limpando imagens antigas..."
    docker image prune -f
    
    echo "📊 Status dos containers:"
    docker ps
    
    echo ""
    echo "✅ Deploy concluído com sucesso!"
    echo "📝 Ver logs com: docker logs cambioao-app-prod -f"
ENDSSH

echo -e "${GREEN}✨ Deploy finalizado!${NC}"
echo ""
echo "🔗 Acessos:"
echo "   - Site: https://ecokambio.com"
echo "   - Admin: https://admin.ecokambio.com/login"
echo ""
echo "📊 Para ver logs:"
echo "   ssh root@212.90.120.135 'docker logs cambioao-app-prod -f'"
