const CACHE_NAME = 'ecokambio-cache-v1';
const URLS_TO_CACHE = [
  '/',
  '/index.html',
  '/sobre',
  '/termos',
  '/privacidade',
  '/visa',
  '/css/output.css',
  '/js/main.js',
  '/assets/main-logo.svg',
  '/assets/favicon.ico',
  '/assets/favicon.svg',
  '/assets/apple-touch-icon.png',
  '/assets/icon-192x192.png',
  '/assets/icon-512x512.png',
  'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap'
];

// Evento de instalação: abre o cache e adiciona os arquivos principais.
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Cache aberto');
        return cache.addAll(URLS_TO_CACHE);
      })
  );
});

// Evento de fetch: intercepta as requisições.
self.addEventListener('fetch', event => {
  // Ignora requisições que não são GET (ex: POST para APIs)
  if (event.request.method !== 'GET') {
    return;
  }

  // Ignora requisições para a API para garantir dados sempre atualizados.
  if (event.request.url.includes('/api/')) {
    return;
  }

  event.respondWith(
    caches.match(event.request)
      .then(response => {
        // Se o recurso estiver no cache, retorna-o. Senão, busca na rede.
        return response || fetch(event.request);
      })
  );
});