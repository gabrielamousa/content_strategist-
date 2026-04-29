/**
 * Cloudflare Worker — Recebe webhook da Eduzz
 * Envia Purchase para Meta CAPI e repassa para N8N
 *
 * Variáveis de ambiente necessárias (configure no painel Cloudflare):
 *   META_PIXEL_ID    → ID do seu pixel Facebook
 *   META_CAPI_TOKEN  → Token de acesso da API de Conversões
 *   N8N_WEBHOOK_URL  → URL do webhook no N8N
 */

export default {
  async fetch(request, env) {

    // Aceita apenas POST em /webhook/eduzz
    const url = new URL(request.url);
    if (request.method !== 'POST' || url.pathname !== '/webhook/eduzz') {
      return new Response('Not found', { status: 404 });
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return new Response('Invalid JSON', { status: 400 });
    }

    // ── Extrai dados do payload da Eduzz ──────────────────────────
    // Eduzz pode enviar os dados em formatos aninhados ou planos
    const customer      = body.customer || {};
    const product       = body.product  || {};
    const invoice       = body.invoice  || body.order || {};

    const customerEmail = customer.email       || body.customer_email || '';
    const customerName  = customer.name        || body.customer_name  || '';
    const productValue  = parseFloat(
                            invoice.value      ||
                            body.product_value ||
                            body.value         || 0);
    const transactionId = invoice.id           ||
                          body.transaction_id  ||
                          body.order_id        || '';

    // trk3 = purchaseEventId gerado na página de vendas
    // trk  = fbc  |  trk2 = fbp
    const eventId = body.trk3 || body.utm_content || ('srv_' + Date.now());
    const fbc     = body.trk  || '';
    const fbp     = body.trk2 || '';

    // ── 1. Envia Purchase para Meta CAPI ──────────────────────────
    const capiPayload = {
      data: [{
        event_name:  'Purchase',
        event_time:  Math.floor(Date.now() / 1000),
        event_id:    eventId,   // mesmo ID do pixel → Facebook deduplica
        event_source_url: 'https://clubeinsta30.com.br/obrigado',
        action_source: 'website',
        user_data: {
          em:  customerEmail ? [await sha256(customerEmail.toLowerCase().trim())] : [],
          fbc: fbc,
          fbp: fbp,
          client_ip_address: request.headers.get('CF-Connecting-IP') || '',
          client_user_agent: request.headers.get('User-Agent') || '',
        },
        custom_data: {
          value:        productValue || 47.00,
          currency:     'BRL',
          content_ids:  [body.product_id || 'clube-insta30ai'],
          content_type: 'product',
          order_id:     transactionId,
        }
      }],
      test_event_code: env.META_TEST_CODE || undefined
    };

    const capiRes = await fetch(
      `https://graph.facebook.com/v19.0/${env.META_PIXEL_ID}/events?access_token=${env.META_CAPI_TOKEN}`,
      {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(capiPayload)
      }
    );

    const capiData = await capiRes.json();

    // ── 2. Repassa para N8N ───────────────────────────────────────
    if (env.N8N_WEBHOOK_URL) {
      await fetch(env.N8N_WEBHOOK_URL, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({
          event:          'purchase_server',
          event_id:       eventId,
          transaction_id: transactionId,
          customer_email: customerEmail,
          customer_name:  customerName,
          product_value:  productValue,
          fbc:            fbc,
          fbp:            fbp,
          capi_response:  capiData,
          raw_payload:    body
        })
      }).catch(() => {});
    }

    return new Response(JSON.stringify({ status: 'ok', capi: capiData }), {
      status:  200,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Função auxiliar para hash SHA-256 (exigido pela Meta CAPI)
async function sha256(text) {
  const encoded = new TextEncoder().encode(text);
  const hash    = await crypto.subtle.digest('SHA-256', encoded);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}
