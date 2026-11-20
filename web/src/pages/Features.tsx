import { useEffect, useState } from 'react';
import { api } from '../api';
import PagePulse from '../components/kit/PagePulse';
import { TableWrap } from '../components/Toolbar';

type FeatureStatus = {
  id: string;
  title: string;
  description: string;
  scope: string;
  helmSet: string;
  cli: string;
  enabled: boolean;
  source: string;
  note?: string;
};

type FeaturesResponse = {
  features: FeatureStatus[];
  summary?: { on: number; off: number; unknown: number };
  note?: string;
};

export default function Features() {
  const [data, setData] = useState<FeaturesResponse>();
  const [err, setErr] = useState('');
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState('');

  async function refresh() {
    try {
      const r = await api<FeaturesResponse>('/api/v1/features');
      setData(r);
      setErr('');
    } catch (e) {
      setErr(String(e));
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function toggle(f: FeatureStatus, enabled: boolean) {
    const action = enabled ? 'enable' : 'disable';
    if (!confirm(`${action} “${f.title}”?\n\nThis patches live Deployment/DaemonSet env (risk: high).\nPrefer durable: ${f.cli.replace('enable', action)} --yes`)) {
      return;
    }
    setBusy(f.id);
    setMsg('');
    try {
      await api(`/api/v1/features/${encodeURIComponent(f.id)}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Netra-Confirm-Risk': 'high',
        },
        body: JSON.stringify({ enabled }),
      });
      setMsg(`${f.id} → ${enabled ? 'on' : 'off'} (pod may restart). Helm remains source of truth.`);
      await refresh();
    } catch (e) {
      setMsg(String(e));
    } finally {
      setBusy('');
    }
  }

  const rows = data?.features || [];

  const on = data?.summary?.on ?? 0;
  const total = on + (data?.summary?.off ?? 0) + (data?.summary?.unknown ?? 0);
  return (
    <div className="grid">
      <PagePulse
        headline={data ? `${on} of ${total} capabilities enabled.` : undefined}
        tick={data}
        error={err || undefined}
        figures={[
          { label: 'on', value: data ? on : undefined, tone: data ? 'ok' : undefined },
          { label: 'off', value: data ? (data.summary?.off ?? 0) : undefined },
          { label: 'unknown', value: data ? (data.summary?.unknown ?? 0) : undefined, tone: data && (data.summary?.unknown ?? 0) ? 'warn' : undefined },
        ]}
      />
      <section className="card span3">
        <p className="eyebrow">CAPABILITY FLAGS</p>
        <h2 className="card-title">Install-time features</h2>
        <p>
          Toggle observe-only detectors, optional integrations, and agent coverage. This does not flip enforce mode or
          apply deny rules. Durable desired state: <code>netractl features enable NAME --yes</code> (Helm).
        </p>
        {err && <p className="warning">{err}</p>}
        {msg && <p className="warning">{msg}</p>}
      </section>

      <section className="card span3">
        <TableWrap><table className="table">
          <thead>
            <tr>
              <th>Feature</th>
              <th>Scope</th>
              <th>State</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => {
              const state = f.source === 'unknown' ? '?' : f.enabled ? 'on' : 'off';
              const agentOnly = f.id === 'agent';
              return (
                <tr key={f.id}>
                  <td>
                    <strong>{f.title}</strong>
                    <div className="muted">{f.description}</div>
                    <code className="muted">{f.cli}</code>
                    {f.note && <div className="muted">{f.note}</div>}
                  </td>
                  <td>{f.scope}</td>
                  <td>{state}</td>
                  <td>
                    {!agentOnly && (
                      <>
                        <button
                          className="primary"
                          disabled={busy === f.id || f.enabled}
                          onClick={() => void toggle(f, true)}
                        >
                          Enable
                        </button>{' '}
                        <button disabled={busy === f.id || (!f.enabled && f.source !== 'unknown')} onClick={() => void toggle(f, false)}>
                          Disable
                        </button>
                      </>
                    )}
                    {agentOnly && <span className="muted">CLI / Helm only</span>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table></TableWrap>
      </section>
    </div>
  );
}
