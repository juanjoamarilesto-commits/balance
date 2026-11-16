// Edge Function: google-calendar  (ETAPA 1 OAuth + ETAPA 2 sincronizacion bidireccional)
// Rutas:  POST /start   POST /status   POST /disconnect   POST /sync   GET /callback (la llama Google)
// Desplegar SIN verificacion JWT del gateway (el callback no trae JWT);
// las rutas de usuario validan el JWT aqui dentro.
import { createClient } from 'npm:@supabase/supabase-js@2.45.4';

const env = (k: string) => Deno.env.get(k) ?? '';
const SUPABASE_URL = env('SUPABASE_URL');
const CLIENT_ID = env('GOOGLE_CLIENT_ID');
const CLIENT_SECRET = env('GOOGLE_CLIENT_SECRET');
const APP_URL = env('APP_URL').replace(/\/$/, '');
const REDIRECT_URI = `${SUPABASE_URL}/functions/v1/google-calendar/callback`;
const CAL_SCOPE = 'https://www.googleapis.com/auth/calendar.events';
const SCOPES = ['openid', 'email', CAL_SCOPE];

// Cliente con service_role: SOLO existe aqui, en el servidor.
const admin = createClient(SUPABASE_URL, env('SUPABASE_SERVICE_ROLE_KEY'), { auth: { persistSession: false } });

const cors = {
  'Access-Control-Allow-Origin': APP_URL || '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (b: unknown, status = 200) =>
  new Response(JSON.stringify(b), { status, headers: { ...cors, 'Content-Type': 'application/json' } });

/* ---------- utilidades de cifrado y firma ---------- */
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64url = (u: Uint8Array) => b64(u).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64url = (s: string) => unb64(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));

const aesKey = () => crypto.subtle.importKey('raw', unb64(env('TOKEN_ENCRYPTION_KEY')), 'AES-GCM', false, ['encrypt', 'decrypt']);
async function encrypt(text: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(), enc.encode(text)));
  const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12);
  return b64(out);
}
async function decrypt(s: string) {
  const raw = unb64(s);
  return dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12) }, await aesKey(), raw.slice(12)));
}
const hmacKey = () => crypto.subtle.importKey('raw', enc.encode(env('STATE_SIGNING_KEY')), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);

// state = payload firmado (usuario + expiracion 10 min + nonce): anti-CSRF
async function makeState(uid: string) {
  const p = b64url(enc.encode(JSON.stringify({ uid, exp: Date.now() + 10 * 60 * 1000, n: crypto.randomUUID() })));
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(), enc.encode(p)));
  return `${p}.${b64url(sig)}`;
}
async function readState(st: string): Promise<{ uid: string } | null> {
  try {
    const [p, sig] = st.split('.');
    if (!p || !sig) return null;
    if (!(await crypto.subtle.verify('HMAC', await hmacKey(), unb64url(sig), enc.encode(p)))) return null;
    const d = JSON.parse(dec.decode(unb64url(p)));
    return d.exp > Date.now() && d.uid ? d : null;
  } catch { return null; }
}

async function userFrom(req: Request) {
  const token = (req.headers.get('Authorization') ?? '').replace(/^Bearer\s+/i, '');
  if (!token) return null;
  const { data, error } = await admin.auth.getUser(token);
  return error ? null : data.user;
}

/* ---------- rutas OAuth (etapa 1) ---------- */
async function start(userId: string) {
  if (!CLIENT_ID || !CLIENT_SECRET) return json({ error: 'Falta configurar los secretos de Google en Supabase' }, 500);
  const params = new URLSearchParams({
    client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, response_type: 'code',
    scope: SCOPES.join(' '), access_type: 'offline',
    prompt: 'consent select_account',          // elegir cuenta + garantizar refresh_token
    state: await makeState(userId),
  });
  return json({ url: 'https://accounts.google.com/o/oauth2/v2/auth?' + params });
}

async function callback(req: Request) {
  const q = new URL(req.url).searchParams;
  const back = (r: string) => Response.redirect(`${APP_URL}/?gcal=${r}#app`, 302);
  if (q.get('error')) return back('denied');
  const st = await readState(q.get('state') ?? '');
  if (!st) return back('invalid_state');
  const code = q.get('code');
  if (!code) return back('error');

  const tr = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ code, client_id: CLIENT_ID, client_secret: CLIENT_SECRET, redirect_uri: REDIRECT_URI, grant_type: 'authorization_code' }),
  });
  const tok = await tr.json();
  if (!tr.ok || !tok.access_token) { console.error('token_error', tok.error); return back('token_error'); }

  const scopes: string[] = (tok.scope ?? '').split(' ');
  if (!scopes.includes(CAL_SCOPE)) return back('missing_scope');

  // Si Google no reenvia refresh_token, conserva el anterior
  const { data: prev } = await admin.from('calendar_connections').select('refresh_token_encrypted').eq('user_id', st.uid).maybeSingle();
  const refreshEnc = tok.refresh_token ? await encrypt(tok.refresh_token) : prev?.refresh_token_encrypted;
  if (!refreshEnc) return back('no_refresh');

  const ui = await fetch('https://openidconnect.googleapis.com/v1/userinfo', { headers: { Authorization: `Bearer ${tok.access_token}` } });
  const email = ui.ok ? (await ui.json()).email ?? null : null;

  const { error } = await admin.from('calendar_connections').upsert({
    user_id: st.uid, google_email: email, calendar_id: 'primary',
    access_token_encrypted: await encrypt(tok.access_token), refresh_token_encrypted: refreshEnc,
    token_expires_at: new Date(Date.now() + (tok.expires_in ?? 3600) * 1000).toISOString(),
    granted_scopes: scopes, sync_token: null, sync_error: null,   // sync_token null => proxima sync = completa
    connected_at: new Date().toISOString(), updated_at: new Date().toISOString(),
  });
  if (error) { console.error('db_error', error.message); return back('db_error'); }
  return back('connected');
}

// El frontend lee last_synced_at y sync_error desde aqui
async function status(userId: string) {
  const { data } = await admin.from('calendar_connections').select('google_email, connected_at, last_synced_at, sync_error').eq('user_id', userId).maybeSingle();
  return json({
    connected: !!data, google_email: data?.google_email ?? null, connected_at: data?.connected_at ?? null,
    last_synced_at: data?.last_synced_at ?? null, sync_error: data?.sync_error ?? null,
  });
}

async function disconnect(userId: string) {
  const { data } = await admin.from('calendar_connections').select('refresh_token_encrypted').eq('user_id', userId).maybeSingle();
  if (data?.refresh_token_encrypted) {
    try {   // revoca el permiso en Google (si falla, igual borramos la conexion local)
      await fetch('https://oauth2.googleapis.com/revoke', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: await decrypt(data.refresh_token_encrypted) }),
      });
    } catch (e) { console.error('revoke', e); }
  }
  const { error } = await admin.from('calendar_connections').delete().eq('user_id', userId);
  if (error) throw error;
  return json({ ok: true });
}

// Renovacion automatica del access token (lo usa la sincronizacion)
async function getAccessToken(userId: string): Promise<string> {
  const { data } = await admin.from('calendar_connections').select('access_token_encrypted, refresh_token_encrypted, token_expires_at').eq('user_id', userId).single();
  if (data!.token_expires_at && new Date(data!.token_expires_at).getTime() - Date.now() > 60_000) return await decrypt(data!.access_token_encrypted);
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET, refresh_token: await decrypt(data!.refresh_token_encrypted), grant_type: 'refresh_token' }),
  });
  const t = await r.json();
  if (!r.ok) throw new Error('refresh_failed:' + (t.error ?? r.status));   // p. ej. invalid_grant => pedir reconexion
  await admin.from('calendar_connections').update({
    access_token_encrypted: await encrypt(t.access_token),
    token_expires_at: new Date(Date.now() + (t.expires_in ?? 3600) * 1000).toISOString(), updated_at: new Date().toISOString(),
  }).eq('user_id', userId);
  return t.access_token;
}

/* =====================================================================
   ETAPA 2: sincronizacion bidireccional
   Orden: 1) Balance -> Google (cambios pendientes)  2) Google -> Balance (syncToken)
   Reglas:
   - Duplicados: indice unico (user_id, calendar_event_id) + ID de evento determinista
     (el UUID de la cita sin guiones) => crear dos veces nunca duplica en Google.
   - Conflictos: gana la modificacion mas reciente (updated_at local vs "updated" de Google).
   - Eliminados: la cita local se marca con deleted_at (no se borra la fila).
   - Un fallo en una cita no detiene la sincronizacion; queda 'pending' y se reintenta.
   - Google: la sync COMPLETA y las incrementales usan los mismos parametros compatibles con
     syncToken (singleEvents, showDeleted, maxResults). NUNCA se envian timeMin/timeMax/updatedMin/q.
     La ventana de fechas (30 dias atras / 400 adelante) se aplica LOCALMENTE al importar.
   ===================================================================== */
const GAPI = 'https://www.googleapis.com/calendar/v3';
const DAY = 86_400_000;
const TZ = 'America/Bogota';
const IMPORT_BACK = 30 * DAY;        // solo se IMPORTAN citas que terminan desde 30 dias antes...
const IMPORT_FWD = 400 * DAY;        // ...y que empiezan hasta 400 dias adelante (filtro local, no en la API)
const FULL_RESYNC_MS = 30 * DAY;     // sync completa periodica: trae lo que entro en la ventana futura

class ReconnectError extends Error {}
const ms = (s: unknown) => Date.parse(String(s ?? '')) || 0;
const nowIso = () => new Date().toISOString();

async function gapi(token: string, method: string, path: string, query: Record<string, unknown> = {}, body?: unknown, extra: Record<string, string> = {}) {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== null) qs.set(k, String(v));
  const q = qs.toString();
  const url = `${GAPI}/${path}${q ? '?' + q : ''}`;
  for (let i = 0; ; i++) {
    const r = await fetch(url, {
      method,
      headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}), ...extra },
      body: body ? JSON.stringify(body) : undefined,
    });
    if ((r.status === 429 || r.status >= 500) && i < 2) { await new Promise((res) => setTimeout(res, 800 * (i + 1))); continue; }
    if (r.status === 401) throw new ReconnectError('google_401');
    const data = r.status === 204 ? null : await r.json().catch(() => null);
    return { status: r.status, ok: r.ok, data: data as any };
  }
}

// Balance -> formato Google. Los all-day se guardan como fecha + 'T12:00:00Z' (asi lo espera el frontend)
const toGoogle = (a: any) => a.all_day
  ? { summary: a.title, location: a.location || null, start: { date: String(a.start_at).slice(0, 10) }, end: { date: String(a.end_at).slice(0, 10) } }
  : {
    summary: a.title, location: a.location || null,
    start: { dateTime: new Date(a.start_at).toISOString(), timeZone: a.timezone || TZ },
    end: { dateTime: new Date(a.end_at).toISOString(), timeZone: a.timezone || TZ },
  };

// Google -> columnas de appointments
function fromGoogle(g: any) {
  const allDay = !!g.start?.date;
  const s = allDay ? `${g.start.date}T12:00:00.000Z` : new Date(g.start.dateTime).toISOString();
  let e = allDay
    ? `${g.end?.date ?? g.start.date}T12:00:00.000Z`
    : g.end?.dateTime ? new Date(g.end.dateTime).toISOString() : new Date(ms(s) + 36e5).toISOString();
  if (!(ms(e) > ms(s))) e = new Date(ms(s) + (allDay ? DAY : 36e5)).toISOString();
  return {
    title: g.summary || '(Sin título)', location: g.location || null,
    start_at: s, end_at: e, all_day: allDay, timezone: g.start?.timeZone || TZ,
    calendar_event_id: g.id, google_etag: g.etag ?? null, google_updated_at: g.updated ?? null,
    updated_at: g.updated ?? nowIso(), sync_status: 'synced', deleted_at: null,
  };
}

const evPath = (cal: string, id?: string) => `calendars/${encodeURIComponent(cal)}/events${id ? '/' + encodeURIComponent(id) : ''}`;
const NOMAIL = { sendUpdates: 'none' };   // nunca enviar correos a invitados desde la sync

// Marca la cita como sincronizada SOLO si no cambio mientras sincronizabamos (si cambio, sigue 'pending')
async function markSynced(uid: string, row: any, g: any | null) {
  const ids = g ? { calendar_event_id: g.id, google_etag: g.etag ?? null, google_updated_at: g.updated ?? null } : {};
  const { data, error } = await admin.from('appointments').update({ ...ids, sync_status: 'synced' })
    .eq('id', row.id).eq('user_id', uid).eq('updated_at', row.updated_at).select('id');
  if (error) throw error;
  if (!data?.length && g) {
    const r2 = await admin.from('appointments').update(ids).eq('id', row.id).eq('user_id', uid);
    if (r2.error) throw r2.error;
  }
}

const randomEventId = () => crypto.randomUUID().replace(/-/g, '');

/* ---------- 1) Balance -> Google ---------- */
async function pushOne(uid: string, token: string, cal: string, row: any) {
  // Eliminar
  if (row.deleted_at) {
    if (row.calendar_event_id) {
      const r = await gapi(token, 'DELETE', evPath(cal, row.calendar_event_id), NOMAIL);
      if (!r.ok && r.status !== 404 && r.status !== 410) throw new Error('google_delete:' + r.status);
    }
    await markSynced(uid, row, null);   // la fila queda como "tumba" (conserva calendar_event_id para ignorar el eco de Google)
    return;
  }

  // Crear (ID determinista => idempotente)
  const create = async (fresh: boolean): Promise<any> => {
    const det = String(row.id).replace(/-/g, '').toLowerCase();
    const id = !fresh && /^[0-9a-f]{32}$/.test(det) ? det : randomEventId();
    const body: any = { ...toGoogle(row), id };
    if (!body.location) delete body.location;
    let r = await gapi(token, 'POST', evPath(cal), NOMAIL, body);
    if (r.status === 409) {   // ya existe (reintento o sync concurrente): se actualiza en vez de duplicar
      r = await gapi(token, 'PATCH', evPath(cal, id), NOMAIL, toGoogle(row));
      if ((r.status === 404 || r.status === 410) && !fresh) return create(true);
    }
    if (!r.ok) throw new Error('google_create:' + r.status);
    return r.data;
  };

  if (!row.calendar_event_id) { await markSynced(uid, row, await create(false)); return; }

  // Actualizar con If-Match (detecta que Google cambio el evento a la vez)
  let r = await gapi(token, 'PATCH', evPath(cal, row.calendar_event_id), NOMAIL, toGoogle(row), row.google_etag ? { 'If-Match': row.google_etag } : {});
  if (r.status === 412) {
    const cur = await gapi(token, 'GET', evPath(cal, row.calendar_event_id));
    if (cur.ok && cur.data?.status !== 'cancelled') {
      if (ms(cur.data.updated) > ms(row.updated_at)) {      // Google es mas reciente => gana Google
        const { error } = await admin.from('appointments').update(fromGoogle(cur.data)).eq('id', row.id).eq('user_id', uid);
        if (error) throw error;
        return;
      }
      r = await gapi(token, 'PATCH', evPath(cal, row.calendar_event_id), NOMAIL, toGoogle(row));   // gana Balance
    } else r = { status: 410, ok: false, data: null };
  }
  // Evento borrado en Google pero editado aqui: se conserva el dato y se vuelve a crear
  if (r.status === 404 || r.status === 410 || (r.ok && r.data?.status === 'cancelled')) { await markSynced(uid, row, await create(true)); return; }
  if (!r.ok) throw new Error('google_patch:' + r.status);
  await markSynced(uid, row, r.data);
}

async function push(uid: string, token: string, cal: string, stats: { pushed: number; errors: number }) {
  const { data: rows, error } = await admin.from('appointments').select('*').eq('user_id', uid)
    .or('sync_status.is.null,sync_status.neq.synced').order('updated_at').limit(200);
  if (error) throw error;
  for (const row of rows ?? []) {
    try { await pushOne(uid, token, cal, row); stats.pushed++; }
    catch (e) {
      if (e instanceof ReconnectError) throw e;
      console.error('push', row.id, (e as any)?.message ?? e);
      stats.errors++;     // queda 'pending' y se reintenta en la proxima sync
    }
  }
}

/* ---------- 2) Google -> Balance ---------- */
async function insertGoogleRow(uid: string, row: any) {
  const { error } = await admin.from('appointments').insert({ ...row, user_id: uid, origin: 'google' });
  if (error && error.code === '23505') {   // otra sync lo inserto primero: actualizar
    const r2 = await admin.from('appointments').update(row).eq('user_id', uid).eq('calendar_event_id', row.calendar_event_id);
    if (r2.error) throw r2.error;
  } else if (error) throw error;
}

type Ctx = { seen: Set<string>; maxStart: number };   // ids consultados y el inicio mas lejano consultado
async function applyPage(uid: string, items: any[], ctx: Ctx, stats: { pulled: number }) {
  const evs = items.filter((g) => g?.id && g.eventType !== 'workingLocation' && g.eventType !== 'birthday');
  const existing = new Map<string, any>();
  for (let i = 0; i < evs.length; i += 100) {
    const { data, error } = await admin.from('appointments').select('*').eq('user_id', uid)
      .in('calendar_event_id', evs.slice(i, i + 100).map((g) => g.id));
    if (error) throw error;
    for (const r of data ?? []) existing.set(r.calendar_event_id, r);
  }
  const inserts: any[] = [], updates: Array<{ id: string; patch: any }> = [];
  const t = Date.now();

  for (const g of evs) {
    const cancelled = g.status === 'cancelled';
    if (!cancelled) {
      ctx.seen.add(g.id);   // "consultado", aunque luego no se importe por estar fuera de la ventana local
      ctx.maxStart = Math.max(ctx.maxStart, ms(g.start?.date ? `${g.start.date}T12:00:00.000Z` : g.start?.dateTime));
    }
    const loc = existing.get(g.id);
    if (!loc) {
      if (cancelled || !g.start) continue;
      const row = fromGoogle(g);
      if (ms(row.end_at) >= t - IMPORT_BACK && ms(row.start_at) <= t + IMPORT_FWD) inserts.push(row);   // ventana local
      continue;
    }
    const pending = loc.sync_status !== 'synced', tomb = !!loc.deleted_at;
    const gU = ms(g.updated), lU = ms(loc.updated_at);

    if (cancelled) {
      if (tomb) { if (pending) updates.push({ id: loc.id, patch: { sync_status: 'synced' } }); continue; }
      if (pending && lU > gU) continue;   // edicion local mas reciente: pushOne la recreara
      updates.push({ id: loc.id, patch: { deleted_at: nowIso(), sync_status: 'synced', updated_at: g.updated ?? nowIso() } });
      continue;
    }
    if (!g.start) continue;
    if (!pending && !tomb && loc.google_etag === g.etag) continue;   // eco de nuestro propio cambio
    if (pending && lU >= gU) continue;                               // gana lo local (se enviara)
    if (tomb && !pending && gU <= lU) continue;                      // borrado local ya enviado
    updates.push({ id: loc.id, patch: fromGoogle(g) });
  }

  if (inserts.length) {
    const { error } = await admin.from('appointments').insert(inserts.map((r) => ({ ...r, user_id: uid, origin: 'google' })));
    if (error) for (const r of inserts) await insertGoogleRow(uid, r);   // choque de duplicados: fila a fila
  }
  for (let i = 0; i < updates.length; i += 10) {
    await Promise.all(updates.slice(i, i + 10).map(async (u) => {
      const { error } = await admin.from('appointments').update(u.patch).eq('id', u.id).eq('user_id', uid);
      if (error) throw error;
    }));
  }
  stats.pulled += inserts.length + updates.length;
}

// Tras una sync COMPLETA: una cita ya sincronizada que Google no devolvio se marca eliminada.
// Solo se evaluan citas dentro del rango REALMENTE consultado, con el mismo criterio que la ventana
// de importacion: terminan desde (ahora - 30 dias) y empiezan hasta el inicio mas lejano devuelto por Google. Lo que queda fuera de ese rango no se toca.
async function reconcile(uid: string, ctx: Ctx, minIso: string) {
  if (!ctx.maxStart) return;   // Google no devolvio eventos activos: no se borra nada por precaucion
  const maxIso = new Date(ctx.maxStart).toISOString();
  const missing: string[] = [];
  for (let from = 0; ; from += 1000) {
    const { data, error } = await admin.from('appointments').select('id, calendar_event_id').eq('user_id', uid)
      .is('deleted_at', null).not('calendar_event_id', 'is', null).eq('sync_status', 'synced')
      .gte('end_at', minIso).lte('start_at', maxIso).order('id').range(from, from + 999);
    if (error) throw error;
    for (const r of data ?? []) if (!ctx.seen.has(r.calendar_event_id)) missing.push(r.id);
    if (!data || data.length < 1000) break;
  }
  for (let i = 0; i < missing.length; i += 100) {
    const { error } = await admin.from('appointments').update({ deleted_at: nowIso(), updated_at: nowIso(), sync_status: 'synced' })
      .eq('user_id', uid).in('id', missing.slice(i, i + 100));
    if (error) throw error;
  }
}

// sync_token se guarda como "<epoch_ms_sync_completa>:<syncToken de Google>"
async function pull(uid: string, token: string, cal: string, stored: string | null, stats: { pulled: number }) {
  const i = (stored ?? '').indexOf(':');
  let fullAt = i > 0 ? Number(stored!.slice(0, i)) : 0;
  let useToken: string | null = i > 0 && fullAt && Date.now() - fullAt < FULL_RESYNC_MS ? stored!.slice(i + 1) : null;

  for (let attempt = 0; attempt < 2; attempt++) {
    const full = !useToken, t0 = Date.now();
    const ctx: Ctx = { seen: new Set<string>(), maxStart: 0 };
    let pageToken: string | undefined, next: string | undefined, gone = false;
    do {
      // Mismos parametros en la sync completa y en las incrementales; sin timeMin/timeMax.
      const q: Record<string, unknown> = { singleEvents: true, showDeleted: true, maxResults: 250, pageToken };
      if (useToken) q.syncToken = useToken;
      const r = await gapi(token, 'GET', evPath(cal), q);
      if (r.status === 410) { gone = true; break; }          // syncToken vencido => sync completa
      if (!r.ok) throw new Error('google_list:' + r.status);
      await applyPage(uid, r.data.items ?? [], ctx, stats);
      pageToken = r.data.nextPageToken; next = r.data.nextSyncToken;   // el token llega en la ULTIMA pagina
    } while (pageToken);
    if (gone) { useToken = null; continue; }
    if (!next) throw new Error('sin_nextSyncToken');
    if (full) { await reconcile(uid, ctx, new Date(t0 - IMPORT_BACK).toISOString()); fullAt = t0; }
    return `${fullAt}:${next}`;
  }
  throw new Error('sync_completa_fallida');
}

async function sync(userId: string) {
  const { data: conn } = await admin.from('calendar_connections').select('calendar_id, sync_token').eq('user_id', userId).maybeSingle();
  if (!conn) return json({ error: 'Google Calendar no está conectado' }, 400);
  const cal = conn.calendar_id || 'primary';
  const setErr = (m: string) => admin.from('calendar_connections').update({ sync_error: m, updated_at: nowIso() }).eq('user_id', userId);
  try {
    const token = await getAccessToken(userId);
    const stats = { pushed: 0, pulled: 0, errors: 0 };
    await push(userId, token, cal, stats);
    const nextToken = await pull(userId, token, cal, conn.sync_token, stats);
    await admin.from('calendar_connections').update({
      sync_token: nextToken, last_synced_at: nowIso(), updated_at: nowIso(),
      sync_error: stats.errors ? `${stats.errors} cita(s) no se pudieron enviar a Google. Se reintentará.` : null,
    }).eq('user_id', userId);
    return json({ ok: true, ...stats });
  } catch (e) {
    const msg = String((e as any)?.message ?? e);
    if (e instanceof ReconnectError || msg.includes('invalid_grant')) {
      await setErr('Google revocó el acceso. Vuelve a conectar Google Calendar.');
      return json({ error: 'reconnect' }, 401);
    }
    console.error('sync', msg);
    await setErr('No se pudo sincronizar con Google. Se reintentará.');
    return json({ error: 'No se pudo sincronizar' }, 500);
  }
}

/* ---------- router ---------- */
Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });
  const route = new URL(req.url).pathname.split('/').filter(Boolean).pop();
  try {
    if (route === 'callback') return await callback(req);
    const user = await userFrom(req);
    if (!user) return json({ error: 'No autorizado' }, 401);
    if (route === 'start') return await start(user.id);
    if (route === 'status') return await status(user.id);
    if (route === 'disconnect') return await disconnect(user.id);
    if (route === 'sync') return await sync(user.id);
    return json({ error: 'Ruta no encontrada' }, 404);
  } catch (e) {
    console.error(e);
    return json({ error: 'Error interno' }, 500);
  }
});