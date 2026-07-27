// ANB FinAdmin Pro - Service Worker v4.09
// تاريخ الإنشاء: 26 يونيو 2026 (محدّث 27 يوليو 2026 - إضافة استقبال إشعارات Push حقيقية)
// الغرض: تفعيل PWA والعمل بدون إنترنت + استقبال إشعارات Push

const CACHE_NAME = 'anb-finadmin-v4.09';
const urlsToCache = [
  './',
  './index.html',
  './manifest.json'
];

// تثبيت Service Worker
self.addEventListener('install', event => {
  console.log('🔧 Service Worker installing v4.08...');
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      console.log('✅ Cache opened v4.08');
      return cache.addAll(urlsToCache).catch(err => {
        console.log('⚠️ Some URLs failed to cache (offline-first strategy applied)');
      });
    })
  );
  self.skipWaiting();
});

// تفعيل Service Worker
self.addEventListener('activate', event => {
  console.log('🚀 Service Worker activating v4.08...');
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

// ⭐ استقبال إشعار Push حقيقي وصل من الخادم (worker.js) - يعرضه كنافذة نظام
// حتى لو كان التطبيق مغلقًا تمامًا (هذا هو الفرق عن التذكيرات الداخلية القديمة)
self.addEventListener('push', event => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch (e) {}
  const title = data.title || 'ANB Financial Services';
  const options = {
    body: data.body || '',
    data: { url: data.url || './' },
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

// عند الضغط على الإشعار: يفتح التطبيق، أو يُركِّز على تبويب مفتوح له بالفعل بدل فتح نسخة ثانية
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || './';
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clientList => {
      for (const c of clientList) {
        if ('focus' in c) return c.focus();
      }
      if (self.clients.openWindow) return self.clients.openWindow(url);
    })
  );
});

console.log('✨ ANB FinAdmin Service Worker Loaded v4.08 - Cache Updated!');
