import { useEffect, useState } from 'react';
import { api } from '../api';
import { readRoute, routeHash, type Route, type Scope } from '../lib/investigation';
export function navigate(page: Route['page'], patch: Partial<Scope> = {}) {
  window.location.hash = routeHash(page, { ...readRoute(window.location.hash).scope, ...patch });
}
export function useRoute() {
  const [route, setRoute] = useState(() => readRoute(window.location.hash));
  useEffect(() => { const sync = () => setRoute(readRoute(window.location.hash)); window.addEventListener('hashchange', sync); return () => window.removeEventListener('hashchange', sync); }, []);
  return route;
}
export function useSnapshot<T>(path: string, paused = false) {
  const [state, setState] = useState<{ data?: T; error?: string; updatedAt?: string; loading: boolean }>({ loading: true });
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    if (paused) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const controller = new AbortController();
    async function load() {
      try {
        const data = await api<T>(path, { signal: controller.signal });
        if (alive) setState({ data, loading: false, updatedAt: new Date().toISOString() });
      } catch (e) {
        if (alive) setState(old => ({ ...old, loading: false, error: String(e) }));
      } finally { if (alive) timer = setTimeout(load, 10000); }
    }
    void load();
    return () => { alive = false; controller.abort(); clearTimeout(timer); };
  }, [path, paused, revision]);
  return { ...state, refresh: () => setRevision(v => v + 1) };
}
