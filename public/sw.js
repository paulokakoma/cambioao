const CACHE_NAME = 'ecokambio-cache-v1';

// Lista de ficheiros essenciais para a aplicação funcionar offline.
const urlsToCache = [
  '/',
  '/index.html',
  '/about.html',
  '/visa.html',
  '/termos.html',
  '/privacidade.html',
  '/details.html',
  '/css/output.css',
  '/js/main.js',
  '/assets/main-logo.svg',
  '/assets/favicon.svg',
  '/assets/visa.png',
  '/assets/error-state.svg',
  '/assets/social-share-banner.png',
  'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap'
];

// Evento 'install': é acionado quando o service worker é instalado.
self.addEventListener('install', event => {
  console.log('[Service Worker] Instalando...');
  // Espera até que a cache seja aberta e todos os ficheiros essenciais sejam adicionados.
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('[Service Worker] Cache aberta. Adicionando ficheiros essenciais.');
        return cache.addAll(urlsToCache);
      })
      .then(() => {
        console.log('[Service Worker] Ficheiros essenciais adicionados à cache. Instalação completa.');
        return self.skipWaiting(); // Força o novo service worker a tornar-se ativo imediatamente.
      })
  );
});

// Evento 'activate': é acionado quando o service worker é ativado.
self.addEventListener('activate', event => {
  console.log('[Service Worker] Ativado.');
  // Limpa caches antigas que não correspondem ao CACHE_NAME atual.
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cache => {
          if (cache !== CACHE_NAME) {
            console.log('[Service Worker] A limpar cache antiga:', cache);
            return caches.delete(cache);
          }
        })
      );
    })
  );
});

// Evento 'fetch': é acionado para cada pedido de rede feito pela página.
self.addEventListener('fetch', event => {
  // Estratégia "Cache First": tenta responder a partir da cache primeiro.
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        // Se o recurso estiver na cache, retorna-o.
        // Caso contrário, faz o pedido à rede.
        return response || fetch(event.request);
      })
  );
});