// Frontend-only login gate over Netra's single shared-bearer-token backend
// model (internal/api/server.go: Server.apiKey / bearer() / auth() — there is
// no per-user backend concept). The username is cosmetic; the password is the
// NETRA_API_KEY bearer. There is no built-in or default credential: the key is
// whatever the operator set, or the random one deploy-remote.sh minted
// (~/.netra/api-key on the host).
import { clearSession } from './api';

const USERNAME = 'admin';

/**
 * Bearer tokens to try for this login, in order.
 * Empty means reject before any network call (wrong username / empty password).
 */
export function bearerCandidates(username: string, password: string): string[] {
  if (username !== USERNAME || password === '') return [];
  return [password];
}

/** @deprecated Prefer bearerCandidates + a live probe; kept for unit tests. */
export function checkCredentials(username: string, password: string): string | null {
  const c = bearerCandidates(username, password);
  return c[0] ?? null;
}

export function logout(): void {
  clearSession();
}
