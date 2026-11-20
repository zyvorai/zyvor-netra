// The dashboard session is an HttpOnly cookie set by the controller.
// The bearer is not written to localStorage or sessionStorage: those are
// readable by any script on the page.
export async function openSession(token: string): Promise<boolean> {
  const r = await fetch('/api/v1/session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ token }),
  });
  return r.ok;
}

export function clearSession(): void {
  try {
    localStorage.removeItem('netra-token');
  } catch {
    /* private mode or a torn-down test environment */
  }
  void fetch('/api/v1/session', { method: 'DELETE' }).catch(() => {});
}

export async function sessionAlive(): Promise<boolean> {
  let legacy = '';
  try {
    legacy = localStorage.getItem('netra-token') || '';
  } catch {
    legacy = '';
  }
  if (legacy) {
    const opened = await openSession(legacy);
    try {
      localStorage.removeItem('netra-token');
    } catch {
      /* ignore */
    }
    if (!opened) return false;
  }
  try {
    const r = await fetch('/api/v1/whoami', { headers: { Accept: 'application/json' } });
    return r.ok;
  } catch {
    return false;
  }
}

function headers(extra: Record<string, string> = {}) {
  return { ...extra };
}

/** The controller answers failures as {"error":"…"}; show the message, not the JSON envelope. */
export function errorMessage(body: string): string {
  const text = body.trim();
  if (text.startsWith('{')) {
    try {
      const parsed = JSON.parse(text);
      const msg = typeof parsed?.error === 'string' ? parsed.error : typeof parsed?.message === 'string' ? parsed.message : '';
      if (msg) return msg;
    } catch {
      /* not JSON after all — fall through to the raw text */
    }
  }
  return text;
}

export async function api<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
  const r = await fetch(path, { ...init, headers: headers((init.headers as Record<string, string>) || {}) });
  if (!r.ok) {
    if (r.status === 401) {
      clearSession();
      window.dispatchEvent(new Event('netra-auth-expired'));
    }
    throw new Error(errorMessage(await r.text()) || r.statusText);
  }
  return r.json();
}

export function streamURL(path: string) {
  return path;
}

export function authHeaders() {
  return headers();
}

/** Same-origin WebSocket. The session cookie is sent on the handshake; the token is not put in the query string. */
export function wsURL(path: string) {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  return new URL(path, `${proto}//${location.host}`).toString();
}
