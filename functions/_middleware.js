function unauthorized() {
  return new Response("Unauthorized", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Restricted", charset="UTF-8"',
      "Cache-Control": "no-store",
    },
  });
}

function parseBasicAuth(authHeader) {
  const [scheme, encoded] = authHeader.split(" ");
  if (scheme !== "Basic" || !encoded) return null;

  const decoded = atob(encoded);
  const idx = decoded.indexOf(":");
  if (idx === -1) return null;

  const user = decoded.slice(0, idx);
  const pass = decoded.slice(idx + 1);
  return { user, pass };
}

export async function onRequest(context) {
  const { request, env } = context;

  const BASIC_USER = env.BASIC_USER;
  const BASIC_PASS = env.BASIC_PASS;

  // Se você esquecer de setar os secrets, tranca tudo.
  if (!BASIC_USER || !BASIC_PASS) return unauthorized();

  const auth = request.headers.get("Authorization");
  if (!auth) return unauthorized();

  const creds = parseBasicAuth(auth);
  if (!creds) return unauthorized();

  if (creds.user !== BASIC_USER || creds.pass !== BASIC_PASS) {
    return unauthorized();
  }

  return context.next();
}
