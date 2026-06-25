const CACHE_NAME = 'anb-v1';
const ASSETS_TO_CACHE = [
  '/index.html',
  '/manifest.json'
];

// Install event
self.addEventListener('install', event => {
  console.log('Service Worker installing...');
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      console.log('Caching assets:', ASSETS_TO_CACHE);
      return cache.addAll(ASSETS_TO_CACHE).catch(err => {
        console.warn('Cache error (non-critical):', err);
        // Continue without caching - network will serve files
      });
    })
  );
  self.skipWaiting();
});

// Activate event
self.addEventListener('activate', event => {
  console.log('Service Worker activating...');
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME) {
            console.log('Deleting old cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  self.clients.claim();
});

// Fetch event - Network first strategy
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  
  // Skip non-GET requests
  if (event.request.method !== 'GET') {
    return;
  }

  // Skip chrome extensions and non-http requests
  if (!url.protocol.startsWith('http')) {
    return;
  }

  // For API calls (Supabase), use network first
  if (url.hostname.includes('supabase') || url.pathname.includes('api')) {
    event.respondWith(
      fetch(event.request)
        .then(response => {
          console.log('API response:', url.href);
          return response;
        })
        .catch(err => {
          console.warn('API fetch failed:', err);
          // Return index.html as fallback
          return caches.match('/index.html').catch(() => {
            return new Response('Offline - Please check your connection', {
              status: 503,
              statusText: 'Service Unavailable'
            });
          });
        })
    );
    return;
  }

  // For HTML/CSS/JS, try network first, fall back to cache
  event.respondWith(
    fetch(event.request)
      .then(response => {
        // Only cache successful responses
        if (response.status === 200) {
          const clonedResponse = response.clone();
          caches.open(CACHE_NAME).then(cache => {
            cache.put(event.request, clonedResponse);
          });
        }
        return response;
      })
      .catch(err => {
        console.warn('Fetch failed, trying cache:', url.href);
        // Try cache as fallback
        return caches.match(event.request)
          .then(cachedResponse => {
            if (cachedResponse) {
              return cachedResponse;
            }
            // If not in cache and offline, return index.html
            if (url.pathname !== '/index.html') {
              return caches.match('/index.html');
            }
            return new Response('Offline', { status: 503 });
          })
          .catch(() => {
            return new Response('Service Worker Error', { status: 500 });
          });
      })
  );
});
