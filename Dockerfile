# --- Estágio 1: Dependências ---
# Instala todas as dependências (incluindo devDependencies para o build)
FROM node:20-alpine AS deps
WORKDIR /usr/src/app
COPY package.json package-lock.json ./
RUN npm ci

# --- Estágio 2: Builder ---
# Constrói os assets (CSS) e remove as dependências de desenvolvimento
FROM node:20-alpine AS builder
WORKDIR /usr/src/app
COPY --from=deps /usr/src/app/node_modules ./node_modules
COPY . .
RUN npx tailwindcss -i ./public/css/input.css -o ./public/css/output.css --minify
RUN npm prune --production

# --- Estágio 3: Produção ---
# Cria a imagem final, leve e segura para produção
FROM node:20-alpine

# Cria um usuário e grupo não-root para a aplicação
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Define o diretório de trabalho
WORKDIR /usr/src/app

# Copia as dependências de produção do estágio 'builder'
COPY --from=builder /usr/src/app/node_modules ./node_modules

# Copia os arquivos da aplicação (código fonte, assets públicos e privados)
COPY --from=builder /usr/src/app/server.js ./
COPY --from=builder /usr/src/app/public ./public
COPY --from=builder /usr/src/app/private ./private

# Define o proprietário dos arquivos para o usuário da aplicação
RUN chown -R appuser:appgroup .

# Muda para o usuário não-root
USER appuser

EXPOSE 3000
CMD [ "node", "server.js" ]