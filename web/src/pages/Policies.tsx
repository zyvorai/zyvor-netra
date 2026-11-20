import { useEffect, useState } from 'react';
import { api, authHeaders } from '../api';
import Reveal from '../components/Reveal';
import PagePulse from '../components/kit/PagePulse';
import { countTone } from '../components/kit/tone';


const sample = JSON.stringify(
  {
    apiVersion: 'cilium.io/v2',
    kind: 'CiliumNetworkPolicy',
    metadata: { name: 'payments-egress', namespace: 'default' },
    spec: {
      endpointSelector: { matchLabels: { app: 'payments' } },
      egress: [
        {
          toFQDNs: [{ matchName: 'api.example.com' }],
          toPorts: [{ ports: [{ port: '443', protocol: 'TCP' }] }],
        },
      ],
    },
  },
  null,
  2,
);

type PlanResponse = {
  plan: {
    risk: string;
    changes: string[];
    warnings: string[];
    addedDestinations: string[];
    removedDestinations: string[];
    exists: boolean;
    selectorChanged: boolean;
  };
  dryRun: { passed: boolean; error?: string };
  receipt?: { token: string; expiresAt: string } | null;
};

type SimulationResponse = {
  namespace: string;
  name: string;
  governedSources: number;
  results: { source: string; target: string; protocol: string; port?: number; verdict: string; reason: string }[];
  caveat: string;
  note?: string;
};

type GitOpsStatus = {
  lastRun: string;
  dir: string;
  autoApply: boolean;
  manifests: { path: string; namespace: string; name: string; manifest?: any; drifted: boolean; applied: boolean; error?: string; note?: string; plan?: { risk: string } }[];
  loadErrors?: string[];
};

type Revision = {
  id: number;
  at: string;
  actor: string;
  namespace: string;
  name: string;
  action: string;
  manifest: any;
};

const GITOPS_HINT = 'GitOps is not enabled (set NETRA_GITOPS_DIR)';

/** The controller's own error often already says this; only append it when it adds something. */
export function gitopsHint(raw: string): string {
  const detail = raw.replace(/^Error:\s*/, '').trim();
  return !detail || detail.includes(GITOPS_HINT) ? detail || GITOPS_HINT : `${GITOPS_HINT} — ${detail}`;
}

export default function Policies() {
  const [ns, setNs] = useState('default');
  const [list, setList] = useState<any>(undefined);
  const [text, setText] = useState(sample);
  const [msg, setMsg] = useState('');
  const [plan, setPlan] = useState<PlanResponse | null>(null);
  const [simulation, setSimulation] = useState<SimulationResponse | null>(null);
  const [gitopsStatus, setGitopsStatus] = useState<GitOpsStatus | null>(null);
  const [gitopsMsg, setGitopsMsg] = useState('');
  const [history, setHistory] = useState<Revision[]>([]);
  const [historyTarget, setHistoryTarget] = useState<{ namespace: string; name: string } | null>(null);
  const [builder, setBuilder] = useState({ name: 'payments-egress', selectorKey: 'app', selectorValue: 'payments', kind: 'fqdn', to: 'api.example.com', port: '443', protocol: 'TCP', includeDns: true });

  const refresh = () =>
    api(`/api/v1/policies?namespace=${encodeURIComponent(ns)}`)
      .then(setList)
      .catch((e) => setMsg(String(e)));

  useEffect(() => {
    void refresh();
  }, [ns]);

  const refreshGitOps = () =>
    api<GitOpsStatus>('/api/v1/policies/gitops/status')
      .then((x) => { setGitopsStatus(x); setGitopsMsg(''); })
      .catch((e) => { setGitopsStatus(null); setGitopsMsg(String(e)); });

  useEffect(() => {
    void refreshGitOps();
    const t = setInterval(refreshGitOps, 20000);
    return () => clearInterval(t);
  }, []);

  async function gitopsResync(manifest: string, confirmRisk?: string) {
    try {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (confirmRisk) headers['X-Netra-Confirm-Risk'] = confirmRisk;
      await api('/api/v1/policies/gitops/resync', { method: 'POST', headers, body: manifest });
      setMsg('GitOps resync applied.');
      await refreshGitOps();
      await refresh();
    } catch (e) {
      setMsg(String(e));
    }
  }

  async function loadHistory(namespace: string, name: string) {
    try {
      const x = await api<any>(`/api/v1/policies/history?namespace=${encodeURIComponent(namespace)}&name=${encodeURIComponent(name)}&limit=50`);
      setHistory(x.items || []);
      setHistoryTarget({ namespace, name });
    } catch (e) {
      setMsg(String(e));
    }
  }

  async function buildGuided() {
    try {
      const destinations = builder.to.split(',').map((x) => x.trim()).filter(Boolean);
      const body = {
        name: builder.name,
        namespace: ns,
        selector: builder.selectorKey && builder.selectorValue ? { [builder.selectorKey]: builder.selectorValue } : {},
        kind: builder.kind,
        to: destinations,
        port: builder.port ? Number(builder.port) : 0,
        protocol: builder.protocol,
        includeDns: builder.includeDns,
      };
      const x = await api('/api/v1/policies/build', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      setText(JSON.stringify(x, null, 2));
      setPlan(null);
      setMsg('Guided policy generated. Run Preflight before apply.');
    } catch (e) {
      setMsg(String(e));
    }
  }

  async function preflight() {
    try {
      const x = await api<PlanResponse>('/api/v1/policies/plan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: text,
      });
      setPlan(x);
      setMsg(x.dryRun.passed ? 'Preflight passed. The apply receipt is valid for five minutes and only for these exact policy bytes.' : 'Preflight found a Kubernetes dry-run failure.');
    } catch (e) {
      setPlan(null);
      setMsg(String(e));
    }
  }

  async function simulate() {
    try {
      const x = await api<SimulationResponse>('/api/v1/policies/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: text,
      });
      setSimulation(x);
      setMsg('Simulated against observed traffic — additive evidence, not a substitute for Preflight.');
    } catch (e) {
      setSimulation(null);
      setMsg(String(e));
    }
  }

  async function removePolicy(namespace: string, name: string) {
    if (!confirm(`Delete CiliumNetworkPolicy ${namespace}/${name}? A rollback checkpoint will be retained by this controller.`)) return;
    try {
      await api(`/api/v1/policies/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}`, { method: 'DELETE' });
      setMsg(`Deleted ${namespace}/${name}; rollback checkpoint recorded.`);
      setPlan(null);
      await refresh();
      await loadHistory(namespace, name);
    } catch (e) {
      setMsg(String(e));
    }
  }

  async function apply(dry: boolean) {
    try {
      if (!dry) {
        if (!plan?.dryRun?.passed || !plan.receipt?.token) {
          setMsg('Run Preflight before applying. A valid server receipt is required.');
          return;
        }
        const risk = plan.plan.risk.toLowerCase();
        if ((risk === 'high' || risk === 'critical') && !confirm(`Preflight risk is ${risk.toUpperCase()}. Apply this Cilium policy anyway?`)) return;
      }
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (!dry && plan?.receipt?.token) {
        headers['X-Netra-Plan-Token'] = plan.receipt.token;
        const risk = plan.plan.risk.toLowerCase();
        if (risk === 'high' || risk === 'critical') headers['X-Netra-Confirm-Risk'] = risk;
      }
      const x = await api(`/api/v1/policies/apply?dryRun=${dry}`, {
        method: 'POST',
        headers,
        body: text,
      });
      setMsg(dry ? 'Server dry-run passed.' : 'Policy applied; previous and applied revisions recorded.');
      setText(JSON.stringify(x, null, 2));
      if (!dry) {
        let parsed: any;
        try { parsed = JSON.parse(text); } catch { parsed = undefined; }
        setPlan(null);
        await refresh();
        if (parsed?.metadata?.name) await loadHistory(parsed.metadata.namespace || 'default', parsed.metadata.name);
      }
    } catch (e) {
      setMsg(String(e));
    }
  }

  async function exportHistory() {
    try {
      const r = await fetch('/api/v1/policies/history/export', { headers: authHeaders() });
      if (!r.ok) throw new Error((await r.text()) || r.statusText);
      const blob = await r.blob();
      const href = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = href;
      a.download = `netra-policy-history-${new Date().toISOString().replaceAll(':', '-')}.json`;
      a.click();
      URL.revokeObjectURL(href);
      setMsg('Policy history archive exported.');
    } catch (e) {
      setMsg(String(e));
    }
  }

  async function importHistory(file: File | undefined) {
    if (!file) return;
    if (!confirm('Import policy revision history from this archive? This does not apply any Cilium policy.')) return;
    try {
      const body = await file.text();
      const result = await api<any>('/api/v1/policies/history/import?mode=merge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      setMsg(`Imported ${result.imported || 0} revision(s).`);
      if (historyTarget) await loadHistory(historyTarget.namespace, historyTarget.name);
    } catch (e) {
      setMsg(String(e));
    }
  }

  async function rollback(revision: Revision) {
    const namespace = revision.namespace;
    const name = revision.name;
    try {
      const preview = await api<any>(`/api/v1/policies/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}/rollback/${revision.id}?dryRun=true`, { method: 'POST' });
      if (!preview.dryRun?.passed) {
        setMsg('Rollback dry-run failed. The saved revision was not applied.');
        return;
      }
      const risk = String(preview.plan?.risk || 'low').toLowerCase();
      const detail = (preview.plan?.changes || []).join('\n• ');
      if (!confirm(`Rollback ${namespace}/${name} to revision #${revision.id}?\nRisk: ${risk.toUpperCase()}${detail ? `\n• ${detail}` : ''}`)) return;
      const q = risk === 'high' || risk === 'critical' ? `?confirmRisk=${encodeURIComponent(risk)}` : '';
      const restored = await api<any>(`/api/v1/policies/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}/rollback/${revision.id}${q}`, { method: 'POST' });
      setText(JSON.stringify(restored, null, 2));
      setPlan(null);
      setMsg(`Rolled back ${namespace}/${name} to revision #${revision.id}.`);
      await refresh();
      await loadHistory(namespace, name);
    } catch (e) {
      setMsg(String(e));
    }
  }

  const policyCount = list?.items?.length ?? 0;
  const manifests = gitopsStatus?.manifests || [];
  const drifted = manifests.filter((m) => m.drifted).length;
  const gitopsErrors = manifests.filter((m) => m.error).length + (gitopsStatus?.loadErrors?.length || 0);
  return (
    <div className="grid">
      <PagePulse
        headline={list ? (drifted ? `${drifted} GitOps manifest${drifted === 1 ? '' : 's'} drifted from the cluster.` : `${policyCount} polic${policyCount === 1 ? 'y' : 'ies'} in ${ns}.`) : undefined}
        tone={drifted || gitopsErrors ? 'warn' : undefined}
        tick={list ?? gitopsStatus}
        figures={[
          { label: `policies in ${ns}`, value: list ? policyCount : undefined },
          { label: 'GitOps manifests', value: gitopsStatus ? manifests.length : '—' },
          { label: 'drifted', value: gitopsStatus ? drifted : '—', tone: gitopsStatus ? countTone(drifted) : undefined },
          { label: 'GitOps errors', value: gitopsStatus ? gitopsErrors : '—', tone: gitopsStatus ? (gitopsErrors ? 'bad' : 'ok') : undefined },
          { label: 'auto-apply', value: gitopsStatus ? (gitopsStatus.autoApply ? 'on' : 'off') : '—' },
        ]}
      />
      <section className="card span3">
        <p className="eyebrow">WORKBENCH</p>
        <h2 className="card-title">Plan, dry-run, apply</h2>
        <p className="warning">Selecting an endpoint with egress policy can place it into egress default-deny. Preflight compares the live policy, runs Kubernetes dry-run, then issues a five-minute one-shot receipt bound to the exact candidate.</p>
        <div className="toolbar">
          <input aria-label="Namespace" value={ns} onChange={(e) => setNs(e.target.value)} />
          <button className="btn-refresh" onClick={refresh}>Refresh</button>
          <button className="btn-secondary" onClick={preflight}>Preflight</button>
          <button className="btn-secondary" onClick={simulate}>Simulate against observed traffic</button>
          <button className="btn-secondary" onClick={() => apply(true)}>Server dry-run</button>
          <button className="primary" onClick={() => apply(false)}>Apply CRD</button>
        </div>
        {msg && <p className={/^error/i.test(msg) ? 'warning' : undefined}>{msg}</p>}
      </section>

      <section className="card span2">
        <p className="eyebrow">GUIDED BUILDER</p>
        <h2 className="card-title">Common egress rule</h2>
        <div className="buildergrid">
          <label>Name<input value={builder.name} onChange={(e) => setBuilder({ ...builder, name: e.target.value })} /></label>
          <label>Selector key<input value={builder.selectorKey} onChange={(e) => setBuilder({ ...builder, selectorKey: e.target.value })} /></label>
          <label>Selector value<input value={builder.selectorValue} onChange={(e) => setBuilder({ ...builder, selectorValue: e.target.value })} /></label>
          <label>Destination type<select value={builder.kind} onChange={(e) => setBuilder({ ...builder, kind: e.target.value })}><option value="fqdn">FQDN</option><option value="cidr">CIDR</option><option value="entity">Entity</option></select></label>
          <label>Destination(s)<input value={builder.to} onChange={(e) => setBuilder({ ...builder, to: e.target.value })} placeholder="comma separated" /></label>
          <label>Port<input value={builder.port} onChange={(e) => setBuilder({ ...builder, port: e.target.value })} inputMode="numeric" /></label>
          <label>Protocol<select value={builder.protocol} onChange={(e) => setBuilder({ ...builder, protocol: e.target.value })}><option>TCP</option><option>UDP</option></select></label>
          <label className="check"><input type="checkbox" checked={builder.includeDns} onChange={(e) => setBuilder({ ...builder, includeDns: e.target.checked })} />Allow kube-dns</label>
        </div>
        <button className="primary buildbutton" onClick={buildGuided}>Generate CNP</button>
      </section>

      <section className="card">
        <p className="eyebrow">ADVANCED</p>
        <h2 className="card-title">CiliumNetworkPolicy JSON</h2>
        <textarea
          aria-label="CiliumNetworkPolicy JSON"
          className="codeedit"
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            setPlan(null);
          }}
        />
      </section>

      <section className="card">
        <h2 className="card-title">Preflight plan</h2>
        {!plan && <p>Run Preflight to compare this candidate with the live CiliumNetworkPolicy.</p>}
        {plan && (
          <>
            <div className={`risk risk-${plan.plan.risk.toLowerCase()}`}><b>{plan.plan.risk.toUpperCase()}</b><span>{plan.dryRun.passed ? 'Kubernetes dry-run passed' : 'Kubernetes dry-run failed'}</span></div>
            {(plan.plan.changes || []).map((x) => <p key={x}>• {x}</p>)}
            {(plan.plan.warnings || []).map((x) => <p className="warning" key={x}>{x}</p>)}
            {(plan.plan.addedDestinations || []).length > 0 && <p><b>Added:</b> {plan.plan.addedDestinations.join(', ')}</p>}
            {(plan.plan.removedDestinations || []).length > 0 && <p><b>Removed:</b> {plan.plan.removedDestinations.join(', ')}</p>}
            {plan.receipt && <p><b>Apply receipt:</b> expires {new Date(plan.receipt.expiresAt).toLocaleTimeString()}</p>}
            {plan.dryRun.error && <p className="warning">{plan.dryRun.error}</p>}
          </>
        )}
      </section>

      <section className="card span2">
        <p className="eyebrow">GITOPS</p>
        <h2 className="card-title">Reconciler status</h2>
        {gitopsMsg && !gitopsStatus && <p className="empty-state">{gitopsHint(gitopsMsg)}</p>}
        {gitopsStatus && (
          <>
            <p><small>dir {gitopsStatus.dir} · auto-apply {gitopsStatus.autoApply ? 'on' : 'off'} · last run {gitopsStatus.lastRun ? new Date(gitopsStatus.lastRun).toLocaleString() : 'never'}</small></p>
            {(gitopsStatus.loadErrors || []).map((e, i) => <p className="warning" key={i}>{e}</p>)}
            <div className="list">
              {(gitopsStatus.manifests || []).map((m, i) => (
                <div className={`insightrow ${m.error ? 'warning' : m.drifted ? 'warning' : m.applied ? 'low' : 'info'}`} key={i}>
                  <b>{m.namespace}/{m.name}</b>
                  <span>{m.applied ? 'applied' : m.drifted ? 'drifted' : m.plan?.risk ? `${m.plan.risk} risk` : '—'}</span>
                  <small>{m.error || m.note}</small>
                  {(m.drifted || (m.plan && (m.plan.risk === 'high' || m.plan.risk === 'critical'))) && m.manifest && (
                    <button className="btn-secondary" onClick={() => gitopsResync(JSON.stringify(m.manifest), m.plan?.risk)}>
                      Resync{m.plan?.risk ? ` (confirm ${m.plan.risk})` : ''}
                    </button>
                  )}
                </div>
              ))}
              {!(gitopsStatus.manifests || []).length && <p className="empty-state">No manifests found under {gitopsStatus.dir}.</p>}
            </div>
          </>
        )}
      </section>

      <section className="card">
        <h2 className="card-title">Simulation against observed traffic</h2>
        {!simulation && <p>Run "Simulate against observed traffic" to check this candidate's egress rules against the live dependency graph — additive evidence alongside Preflight, not a replacement for it.</p>}
        {simulation && (
          <>
            <p><small>{simulation.caveat}</small></p>
            {simulation.note && <p className="empty-state">{simulation.note}</p>}
            {!simulation.note && (
              <div className="list">
                {(simulation.results || []).map((r, i) => (
                  <div className={`insightrow ${r.verdict === 'denied' ? 'warning' : r.verdict === 'unverified' ? 'info' : 'low'}`} key={i}>
                    <b>{r.verdict}</b>
                    <span className="truncate" title={r.target} aria-label={r.target}>{r.target}</span>
                    <code>{r.protocol}{r.port ? `/${r.port}` : ''}</code>
                    <small>{r.reason}</small>
                  </div>
                ))}
                {!(simulation.results || []).length && <p className="empty-state">No observed edges from a workload this selector governs yet.</p>}
              </div>
            )}
          </>
        )}
      </section>

      <section className="card">
        <h2 className="card-title">Existing policies</h2>
        <div className="list">
          {list?.items?.length ? list.items.map((x: any) => (
            <div className="policyrow" key={x.metadata?.name}>
              <button onClick={() => { setText(JSON.stringify(x, null, 2)); setPlan(null); void loadHistory(x.metadata?.namespace || ns, x.metadata?.name); }}>
                <b>{x.metadata?.name}</b><span>{x.metadata?.namespace}</span>
              </button>
              <button className="btn-diag" onClick={() => loadHistory(x.metadata?.namespace || ns, x.metadata?.name)}>History</button>
              <button className="policydelete" onClick={() => removePolicy(x.metadata?.namespace || ns, x.metadata?.name)}>Delete</button>
            </div>
          )) : <p className="empty-state">No policies loaded.</p>}
        </div>
      </section>

      <Reveal className="card span3">
        <p className="eyebrow">DURABLE REVISION SAFETY NET</p>
        <div className="toolbar">
          <button className="btn-secondary" onClick={exportHistory}>Export history</button>
          <label className="buttonlike btn-secondary">Import history<input type="file" accept="application/json,.json" hidden onChange={(e) => void importHistory(e.target.files?.[0])} /></label>
        </div>
        <h2 className="card-title">{historyTarget ? `${historyTarget.namespace}/${historyTarget.name}` : 'Select a policy to inspect history'}</h2>
        {!history.length && <p className="empty-state">No Netra-managed revisions recorded for this policy yet. History begins when Netra applies, deletes, or rolls back the policy.</p>}
        <div className="revisionlist">
          {history.map((r) => (
            <div className="revisionrow" key={r.id}>
              <span>#{r.id}</span><b>{r.action}</b><span>{new Date(r.at).toLocaleString()}</span><span>{r.actor}</span>
              <button className="btn-secondary" onClick={() => { setText(JSON.stringify(r.manifest, null, 2)); setPlan(null); }}>Load</button>
              <button className="btn-warn" onClick={() => rollback(r)}>Rollback</button>
            </div>
          ))}
        </div>
      </Reveal>
    </div>
  );
}
