// ANB FinAdmin Pro - Service Worker v3.94
// تاريخ الإنشاء: 26 يونيو 2026 (محدّث 04 يوليو 2026 - إزالة سرّ R2 المسرَّب من الكود)
// الغرض: تفعيل PWA والعمل بدون إنترنت

const CACHE_NAME = 'anb-finadmin-v3.94';
const urlsToCache = [
  './',
  './index.html',
  './manifest.json'
];

// تثبيت Service Worker
self.addEventListener('install', event => {
  console.log('🔧 Service Worker installing v3.94...');
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      console.log('✅ Cache opened v3.94');
      return cache.addAll(urlsToCache).catch(err => {
        console.log('⚠️ Some URLs failed to cache (offline-first strategy applied)');
      });
    })
  );
  self.skipWaiting();
});

// تفعيل Service Worker
self.addEventListener('activate', event => {
  console.log('🚀 Service Worker activating v3.94...');
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME) {
            console.log('🗑️ Deleting old cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  self.clients.claim();
});

// استراتيجية التخزين: Network First, Fallback to Cache
self.addEventListener('fetch', event => {
  // تخطي الطلبات غير GET
  if (event.request.method !== 'GET') {
    return;
  }

  event.respondWith(
    fetch(event.request)
      .then(response => {
        // احفظ النسخة الناجحة
        if (response && response.status === 200) {
          const responseToCache = response.clone();
          caches.open(CACHE_NAME).then(cache => {
            cache.put(event.request, responseToCache);
          });
        }
        return response;
      })
      .catch(error => {
        // استخدم النسخة المخزنة عند الفشل
        console.log('📡 Network error, trying cache:', event.request.url);
        return caches.match(event.request).then(response => {
          if (response) {
            console.log('✅ Served from cache:', event.request.url);
            return response;
          }
          // إذا لم تكن في الـ cache، أرجع الصفحة الرئيسية
          return caches.match('./index.html');
        });
      })
  );
});

// تعامل مع رسائل من الصفحة
self.addEventListener('message', event => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

console.log('✨ ANB FinAdmin Service Worker Loaded v3.94 - Cache Updated!');
