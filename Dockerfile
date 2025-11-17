# --- Estágio 1: Dependências ---
# Instala todas as dependências (dev e prod)
FROM node:20-alpine AS deps
WORKDIR /usr/src/app
COPY package.json package-lock.json ./
RUN npm ci

# --- Estágio 2: Builder ---
# Constrói os assets (CSS) e remove as dependências de desenvolvimento
FROM node:20-alpine AS builder
WORKDIR /usr/src/app
# Copia as dependências do estágio anterior
COPY --from=deps /usr/src/app/node_modules ./node_modules
# Copia o código fonte
COPY . .
# Gera o CSS do Tailwind
RUN npx tailwindcss -i ./public/css/input.css -o ./public/css/output.css --minify
# Remove as dependências de desenvolvimento para ter uma pasta node_modules limpa
RUN npm prune --production

# --- Estágio 2: Produção ---
# Imagem final, leve e segura
FROM node:20-alpine
# Adiciona um usuário não-root para segurança
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser
WORKDIR /usr/src/app
# Copia os artefatos do build
COPY --from=builder /usr/src/app/public ./public
COPY --from=builder /usr/src/app/views ./views
COPY --from=builder /usr/src/app/server.js ./
COPY --from=builder /usr/src/app/package*.json ./
# Copia apenas as dependências de produção
COPY --from=builder /usr/src/app/node_modules ./node_modules
# Expõe a porta que a aplicação usa
EXPOSE 3000
# Comando para iniciar o servidor em modo de produção
CMD [ "node", "server.js" ]