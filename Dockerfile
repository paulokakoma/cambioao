# ---- Estágio de Dependências (dependencies) ----
# Use uma versão específica do Node.js para consistência.
# A versão 20-alpine é leve e recomendada.
FROM node:20-alpine AS dependencies

# Define o diretório de trabalho dentro do contêiner
WORKDIR /usr/src/app

# Copia o package.json e o package-lock.json (ou yarn.lock, etc.)
COPY package*.json ./

# Instala apenas as dependências de produção.
# Isso ajuda a manter a imagem final pequena.
RUN npm install --omit=dev

# ---- Estágio Final (production) ----
# Começa a partir de uma imagem base limpa
FROM node:20-alpine

ENV NODE_ENV=production

# Define o diretório de trabalho
WORKDIR /usr/src/app

# Copia as dependências de produção do estágio anterior
COPY --from=dependencies /usr/src/app/node_modules ./node_modules

# Copia o restante do código da sua aplicação
COPY . .

# Expõe a porta que a sua aplicação usa (a mesma do docker-compose.prod.yml)
EXPOSE 3000

# Comando para iniciar a sua aplicação
CMD [ "npm", "start" ]