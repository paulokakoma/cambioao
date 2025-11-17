# =================================
# Build Stage
# =================================
# Usar uma imagem base oficial do Node.js para construir as dependências
FROM node:18-alpine AS builder

# Define o diretório de trabalho dentro do contêiner
WORKDIR /usr/src/app

# Copia os arquivos de definição de dependências
COPY package*.json ./

# Instala apenas as dependências de produção
RUN npm ci --omit=dev

# =================================
# Production Stage
# =================================
# Começa com uma nova imagem base limpa para um tamanho menor e mais segurança
FROM node:18-alpine

WORKDIR /usr/src/app

# Copia as dependências de produção do estágio 'builder'
COPY --from=builder /usr/src/app/node_modules ./node_modules
COPY --from=builder /usr/src/app/package*.json ./

# Copia o restante do código da aplicação para o diretório de trabalho
COPY . .

# Troca para um usuário não-root por questões de segurança
USER node

# Expõe a porta em que a aplicação será executada
EXPOSE 3000

# Comando para iniciar a aplicação em produção
CMD [ "node", "server.js" ]