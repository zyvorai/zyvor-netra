import { useState } from 'react';
import { api } from '../api';
import ExplainFinding from '../components/ExplainFinding';
import PagePulse from '../components/kit/PagePulse';
import Section from '../components/kit/Section';
import { ToneDot, type Tone } from '../components/kit/tone';
import { ListEmpty } from '../components/Toolbar';
import { SearchX } from 'lucide-react';
import {
  buildExplainReport,
  emptyExplainScope,
  parseExplainScope,
  type ExplainAgentStatus,
  type ExplainReport,
  type ExplainScope,
} from '../lib/explain';

const KIND_TONE: Record<string, Tone> = { 'observed-block': 'bad', 'tcp-loss-signal': 'warn' };

const KIND_LABEL: Record<string, string> = {
  'observed-block': 'Observed block',
  'network-event': 'Network event',
  'tcp-established': 'TCP established',
  'tcp-loss-signal': 'TCP loss signal',
  'dns-counters': 'DNS counters',
};

export default function Explain() {
  const [form, setForm] = useState<ExplainScope>(emptyExplainScope);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [report, setReport] = useState<ExplainReport | null>(null);

  function set<K extends keyof ExplainScope>(key: K, value: ExplainScope[K]) {
    setForm((f) => ({ ...f, [key]: value }));
  }

  async function run() {
    setError('');
    setReport(null);
    const parsed = parseExplainScope(form);
    if ('error' in parsed) {
      setError(parsed.error);
      return;
    }
    setLoading(true);
    try {
      const res = await api<{ items: ExplainAgentStatus[] }>('/api/v1/agents');
      setReport(buildExplainReport(res.items || [], parsed.scope, new Date()));
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="grid">
      <Section
        reveal={false}
        eyebrow="Explain a connection"
        title="Scope this check"
        lede={'Passive, read-only evidence from the same agent reports the controller already holds — no active probes, DNS lookups, or policy changes. Provide a selector, or explicitly check "examine every node."'}
      >
        <div className="ruleform">
          <input aria-label="Namespace" value={form.namespace} onChange={(e) => set('namespace', e.target.value)} placeholder="namespace" />
          <input aria-label="Pod" value={form.pod} onChange={(e) => set('pod', e.target.value)} placeholder="pod, or namespace/pod" />
          <input aria-label="Node" value={form.node} onChange={(e) => set('node', e.target.value)} placeholder="node (required with PID)" />
          <input aria-label="PID" value={form.pid} onChange={(e) => set('pid', e.target.value)} placeholder="PID" inputMode="numeric" />
          <input aria-label="Container ID" value={form.container} onChange={(e) => set('container', e.target.value)} placeholder="exact reported container ID" />
          <input aria-label="Destination" value={form.destination} onChange={(e) => set('destination', e.target.value)} placeholder="IP or IP:port" />
          <input aria-label="DNS name" value={form.dns} onChange={(e) => set('dns', e.target.value)} placeholder="observed DNS query name" />
          <label>
            Limit{' '}
            <input
              aria-label="Limit"
              value={form.limit}
              onChange={(e) => set('limit', Number(e.target.value) || 0)}
              inputMode="numeric"
              style={{ width: 70 }}
            />
          </label>
          <label>
            Max age (min){' '}
            <input
              aria-label="Max agent report age in minutes"
              value={form.maxAgeMinutes}
              onChange={(e) => set('maxAgeMinutes', Number(e.target.value) || 0)}
              inputMode="numeric"
              style={{ width: 70 }}
            />
          </label>
          <label>
            <input type="checkbox" checked={form.all} onChange={(e) => set('all', e.target.checked)} /> examine every node
          </label>
          <button className="primary" onClick={run} disabled={loading}>
            {loading ? 'Explaining…' : 'Explain'}
          </button>
        </div>
        {error && <p className="warning">{error}</p>}
      </Section>

      {report && (
        <PagePulse
          live={false}
          headline={report.status === 'evidence-found' ? 'Evidence found' : 'No matching evidence'}
          tone={report.findings.some((f) => f.kind === 'observed-block') ? 'bad' : undefined}
          figures={[
            { label: 'agents considered', value: report.agentsConsidered },
            { label: 'agents excluded', value: report.agentsExcluded, tone: report.agentsExcluded ? 'warn' : undefined },
            { label: 'findings', value: report.findingsTotal },
            { label: 'showing', value: report.findings.length },
          ]}
        />
      )}

      {report && (
        <Section
          eyebrow="Result"
          title={`${report.findingsTotal} finding${report.findingsTotal === 1 ? '' : 's'}`}
          about={report.limitations.map((l) => <p key={l}>{l}</p>)}
        >
          {report.truncated && <p className="warning">Output truncated; narrow the scope or increase the limit.</p>}
          {report.findingsTotal === 0 && (
            <ListEmpty
              compact
              icon={SearchX}
              title="No matching evidence."
              description="Check selectors, agent freshness, hook coverage, and whether the application attempted a connection."
            />
          )}
          {report.findings.length > 0 && (
            <div className="recommendations">
              {report.findings.map((f, i) => (
                <details key={`${f.kind}-${f.node}-${i}`} className="recommendation">
                  <summary>
                    <b><ToneDot tone={KIND_TONE[f.kind] || 'ok'} />{KIND_LABEL[f.kind] || f.kind}</b>
                    <span>
                      {f.node} · {f.namespace || '—'}/{f.pod || '—'}
                    </span>
                  </summary>
                  <p>{f.evidence}</p>
                  <p>Next: {f.nextCheck}</p>
                  <ExplainFinding
                    page="explain"
                    kind={f.kind}
                    subject={`${f.namespace || ''}/${f.pod || ''}@${f.node || ''}`}
                    message={f.evidence}
                  />
                </details>
              ))}
            </div>
          )}
        </Section>
      )}
    </div>
  );
}
