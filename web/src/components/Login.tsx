import { useEffect, useState } from 'react';
import { bearerCandidates } from '../auth';
import { openSession } from '../api';

const WRONG = 'Wrong username or password.';

/** Probe that the bearer is accepted — must be JSON API, not SPA HTML. */
async function probeBearer(bearer: string): Promise<'ok' | 'unauthorized' | 'unreachable'> {
  try {
    const r = await fetch('/api/v1/fleet', {
      headers: {
        Authorization: `Bearer ${bearer}`,
        Accept: 'application/json',
      },
    });
    if (r.status === 401) return 'unauthorized';
    const ct = r.headers.get('content-type') || '';
    if (!r.ok || !ct.includes('application/json')) return 'unreachable';
    return 'ok';
  } catch {
    return 'unreachable';
  }
}

export default function Login({
  onLogin,
  initialError = '',
}: {
  onLogin: () => void;
  initialError?: string;
}) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(initialError);
  const [busy, setBusy] = useState(false);
  const host = window.location.host || window.location.hostname;

  useEffect(() => {
    if (initialError) setError(initialError);
  }, [initialError]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const user = username.trim();
    const candidates = bearerCandidates(user, password);
    if (!candidates.length) {
      setError(WRONG);
      return;
    }
    setBusy(true);
    setError('');
    let sawUnauthorized = false;
    try {
      for (const bearer of candidates) {
        const result = await probeBearer(bearer);
        if (result === 'ok') {
          if (!(await openSession(bearer))) {
            setError('Could not start a session. Check the URL and try again.');
            return;
          }
          onLogin();
          return;
        }
        if (result === 'unauthorized') sawUnauthorized = true;
      }
      setError(sawUnauthorized ? WRONG : 'Could not reach the controller. Check the URL and try again.');
    } catch {
      setError('Could not reach the controller. Check the URL and try again.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-shell">
      <div className="login-info">
        <img src="/zyvor-mark.svg" alt="Zyvor" className="login-logo" />
        <p className="eyebrow">Netra · Zyvor</p>
        <h1>See the network. Diagnose it. Contain it.</h1>
        <p>
          Netra runs its own eBPF datapath for workload flows, TCP health, DNS timing, socket identity, and leased
          emergency controls — a standalone control plane for Kubernetes networking.
        </p>
        <p className="login-host">
          Connecting to <code>{host}</code>
        </p>
      </div>
      <form className="card login-card" onSubmit={submit} noValidate>
        <h1>Sign in.</h1>
        <label className="tokenbox">
          Username
          <input
            value={username}
            onChange={(e) => {
              setUsername(e.target.value);
              if (error) setError('');
            }}
            autoFocus
            autoComplete="username"
            disabled={busy}
            aria-invalid={Boolean(error)}
          />
        </label>
        <label className="tokenbox">
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
              if (error) setError('');
            }}
            autoComplete="current-password"
            disabled={busy}
            aria-invalid={Boolean(error)}
          />
        </label>
        {error ? (
          <p className="login-error" role="alert" aria-live="assertive">
            {error}
          </p>
        ) : null}
        <button type="submit" className="primary" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  );
}
