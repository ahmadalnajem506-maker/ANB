export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-File-Name',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // رفع ملف جديد (يتطلب مفتاح سري)
    if (request.method === 'POST' && url.pathname === '/upload') {
      const auth = request.headers.get('Authorization');
      if (auth !== `Bearer ${env.UPLOAD_SECRET}`) {
        return new Response('Unauthorized', { status: 401, headers: corsHeaders });
      }

      const contentLength = request.headers.get('Content-Length');
      if (contentLength && parseInt(contentLength) > 8 * 1024 * 1024) {
        return new Response('File too large (max 8MB)', { status: 413, headers: corsHeaders });
      }

      const fileName = (request.headers.get('X-File-Name') || 'file').replace(/[^a-zA-Z0-9._-]/g, '_');
      const contentType = request.headers.get('Content-Type') || 'application/octet-stream';

      const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
      if (!allowedTypes.includes(contentType)) {
        return new Response('File type not allowed', { status: 415, headers: corsHeaders });
      }

      const key = `${Date.now()}-${crypto.randomUUID()}-${fileName}`;
      await env.ANB_FILES.put(key, request.body, {
        httpMetadata: { contentType },
      });

      return new Response(JSON.stringify({ key, url: `${url.origin}/file/${key}` }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // استرجاع ملف (بلا حاجة لمفتاح - الرابط نفسه عشوائي يصعب تخمينه)
    if (request.method === 'GET' && url.pathname.startsWith('/file/')) {
      const key = url.pathname.replace('/file/', '');
      const object = await env.ANB_FILES.get(key);
      if (!object) {
        return new Response('Not found', { status: 404, headers: corsHeaders });
      }
      const headers = new Headers(corsHeaders);
      object.writeHttpMetadata(headers);
      headers.set('etag', object.httpEtag);
      return new Response(object.body, { headers });
    }

    return new Response('ANB File Worker is running', { status: 200, headers: corsHeaders });
  },
};
