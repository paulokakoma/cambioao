# Currency Exchange Application

Aplicação de câmbio de moedas com sistema de administração separado por subdomínios.

## 🚀 Configuração de Subdomínios

A aplicação utiliza dois domínios separados:

- **Domínio Principal**: Página pública para os utilizadores
- **Subdomínio Admin**: Painel de administração (`admin.`)

### Desenvolvimento Local

#### Navegadores Modernos (Chrome, Edge, Firefox)
Os navegadores modernos suportam `admin.localhost` automaticamente. Basta aceder:

- 📱 **Página Principal**: `http://localhost:3000`
- 🔐 **Admin**: `http://admin.localhost:3000`

#### Navegadores que não suportam admin.localhost
Se o seu navegador não suportar `admin.localhost`, adicione ao ficheiro `/etc/hosts`:

```bash
sudo nano /etc/hosts
```

Adicione esta linha:
```
127.0.0.1    admin.localhost
```

Depois de guardar, aceda a `http://admin.localhost:3000`

### Produção

Para produção, configure os registos DNS:

1. **Domínio Principal**: Configure o registo A para `dominio.com`
2. **Subdomínio Admin**: Configure o registo A ou CNAME para `admin.dominio.com`

Ambos devem apontar para o mesmo IP do servidor.

#### Variável de Ambiente Opcional

Em produção, se quiser compartilhar cookies entre subdomínios, defina no `.env`:

```env
COOKIE_DOMAIN=.dominio.com
```

O ponto (.) no início permite que os cookies sejam compartilhados entre subdomínios.

## 📦 Instalação

```bash
npm install
```

## 🔧 Variáveis de Ambiente

Crie um ficheiro `.env` na raiz do projeto com as seguintes variáveis:

```env
# Porta do servidor
PORT=3000

# Ambiente (production ou deixe vazio para development)
NODE_ENV=production

# Supabase
SUPABASE_URL=sua_url_do_supabase
SUPABASE_SERVICE_KEY=sua_service_key
SUPABASE_ANON_KEY=sua_anon_key

# Autenticação Admin
ADMIN_PASSWORD_HASH=hash_da_senha_admin
SESSION_SECRET=segredo_para_sessões

# Caminho secreto para admin (opcional, padrão: /admin)
ADMIN_SECRET_PATH=/admin

# Domínio para cookies em produção (opcional)
COOKIE_DOMAIN=.dominio.com
```

### Gerar Hash da Senha Admin

Execute o script fornecido:

```bash
node hash-password.js
```

## 🏃 Executar

### Desenvolvimento

```bash
npm run dev
```

O servidor irá iniciar e mostrar as URLs disponíveis:
- Página Principal: `http://localhost:3000`
- Admin: `http://admin.localhost:3000`

### Produção

```bash
npm start
```

## 📁 Estrutura do Projeto

```
├── public/          # Ficheiros públicos (página principal)
│   ├── index.html
│   ├── login.html
│   └── ...
├── private/         # Ficheiros privados (admin)
│   └── admin.html
├── server.js        # Servidor Express
└── .env            # Variáveis de ambiente (não versionado)
```

## 🔐 Acesso Admin

1. Aceda ao subdomínio admin: `http://admin.localhost:3000` (dev) ou `http://admin.dominio.com` (prod)
2. Será redirecionado para `/login` se não estiver autenticado
3. Introduza a senha de administrador configurada

## 🛠️ Tecnologias

- **Express.js** - Framework web
- **Supabase** - Base de dados e autenticação
- **WebSocket (ws)** - Comunicação em tempo real
- **Tailwind CSS** - Estilização
- **Multer** - Upload de ficheiros
