// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useState } from 'react';
import { authHeaders } from '../api';
import PagePulse from '../components/kit/PagePulse';
import { bundleFileName, verifySummary, bundleQuery, bundleSections, headline, rowCount, truncatedLists, type BundleDoc } from '../lib/incidentBundle';

export default function IncidentBundle() {
  const [doc, setDoc] = useState<BundleDoc>();
  // The raw text is what gets downloaded, so large counters keep their exact digits.
  const [raw, setRaw] = useState('');
  const [minutes, setMinutes] = useState(15);
  const [node, setNode] = useState('');
  const [mask, setMask] = useState('');
  const [exclude, setExclude] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [tick, setTick] = useState(0);
  const [verifyMsg, setVerifyMsg] = useState('');
  const [reportMd, setReportMd] = useState('');

  const postBundle = (path: string, accept: string) =>
    fetch(path, { method: 'POST', headers: { ...authHeaders(), 'Content-Type': 'application/json', Accept: accept }, body: raw }).then(async (r) => {
      const text = await r.text();
      if (!r.ok) {
        let msg = text;
        try {
          msg = JSON.parse(text).error || text;
        } catch {
          /* plain text error */
        }
        throw new Error(msg || r.statusText);
      }
      return text;
    });

  const verify = () => {
    if (!raw) return;
    setBusy(true);
    postBundle('/api/v1/incident/verify', 'application/json')
      .then((t) => setVerifyMsg(verifySummary(JSON.parse(t))))
      .then(() => setErr(''))
      .catch((e) => setErr(String(e.message || e)))
      .finally(() => setBusy(false));
  };

  const render = () => {
    if (!raw) return;
    setBusy(true);
    postBundle('/api/v1/incident/report?format=markdown', 'text/markdown')
      .then((t) => setReportMd(t))
      .then(() => setErr(''))
      .catch((e) => setErr(String(e.message || e)))
      .finally(() => setBusy(false));
  };

  const build = () => {
    setBusy(true);
    fetch(`/api/v1/incident/bundle?${bundleQuery(minutes, node, exclude, mask)}`, { headers: authHeaders() })
      .then(async (r) => {
        const text = await r.text();
        if (!r.ok) {
          let msg = text;
          try {
            msg = JSON.parse(text).error || text;
          } catch {
            /* plain text error */
          }
          throw new Error(msg || r.statusText);
        }
        setRaw(text);
        setVerifyMsg('');
        setReportMd('');
        setDoc(JSON.parse(text) as BundleDoc);
        setErr('');
        setTick(Date.now());
      })
      .catch((e) => setErr(String(e.message || e)))
      .finally(() => setBusy(false));
  };

  const download = () => {
    if (!doc || !raw) return;
    const blob = new Blob([raw + '\n'], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = bundleFileName(doc);
    a.click();
    URL.revokeObjectURL(url);
  };

  const trunc = truncatedLists(doc);
  const timeline = (doc?.sections?.timeline?.entries as { at?: string; category?: string; severity?: string; node?: string; summary?: string; ref?: string }[]) || [];

  return (
    <div className="grid">
      <PagePulse
        tick={tick || undefined}
        error={err || undefined}
        tone={doc ? (trunc.length ? 'warn' : 'ok') : undefined}
        headline={doc ? headline(doc) : undefined}
        figures={[
          { label: 'sections', value: doc ? bundleSections.length - (doc.redaction?.excludedSections?.length || 0) : 0 },
          { label: 'truncated', value: trunc.length, tone: trunc.length ? 'warn' : undefined },
          { label: 'timeline', value: timeline.length },
        ]}
      />

      <section className="card span3">
        <p className="eyebrow">FLIGHT RECORDER</p>
        <h2 className="card-title">Incident bundle</h2>
        <p>
          One portable, redacted, hash-chained document of what the network looked like in the last N minutes, built from stores Netra already keeps.
          It adds no collector and holds no payload, command line, Secret or URL query string. Read-only. The same bundle is available as{' '}
          <code>netractl incident bundle</code> and the <code>netra_incident_bundle</code> MCP tool; check one offline with <code>netractl incident verify</code>.
        </p>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginTop: '0.75rem', alignItems: 'center' }}>
          <label>
            Minutes{' '}
            <input type="number" min={1} max={1440} value={minutes} onChange={(e) => setMinutes(Number(e.target.value))} style={{ width: '6rem' }} />
          </label>
          <label>
            Node <input value={node} onChange={(e) => setNode(e.target.value)} placeholder="all nodes" />
          </label>
          <label>
            Mask IPs{' '}
            <select value={mask} onChange={(e) => setMask(e.target.value)}>
              <option value="">no</option>
              <option value="ips">pseudonyms</option>
              <option value="prefix">prefix-preserving</option>
            </select>
          </label>
          <button type="button" onClick={build} disabled={busy}>
            {busy ? 'Building…' : 'Build bundle'}
          </button>
          <button type="button" onClick={download} disabled={!doc}>
            Download JSON
          </button>
          <button type="button" onClick={verify} disabled={!doc || busy}>
            Verify
          </button>
          <button type="button" onClick={render} disabled={!doc || busy}>
            Incident report
          </button>
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginTop: '0.5rem' }}>
          <span>Leave out:</span>
          {bundleSections.map((s) => (
            <label key={s}>
              <input
                type="checkbox"
                checked={exclude.includes(s)}
                onChange={(e) => setExclude(e.target.checked ? [...exclude, s] : exclude.filter((x) => x !== s))}
              />{' '}
              {s}
            </label>
          ))}
        </div>
        {err && <p className="warning">{err}</p>}
        {verifyMsg && <p className="empty-state">{verifyMsg}</p>}
      </section>

      {reportMd && (
        <section className="card span3">
          <p className="eyebrow">INCIDENT REPORT DRAFT</p>
          <h2 className="card-title">Derived from the bundle above</h2>
          <p className="empty-state">Temporal order is not proof of cause. The draft adds no data; it only restates the verified bundle.</p>
          <pre style={{ whiteSpace: 'pre-wrap', overflowX: 'auto' }}>{reportMd}</pre>
        </section>
      )}

      {doc && (
        <>
          <section className="card span3">
            <p className="eyebrow">CONTENTS</p>
            <h2 className="card-title">
              {doc.schema} · {doc.identity?.scope === 'node' ? `node ${doc.identity?.node}` : 'cluster'} · {doc.identity?.mode} · {doc.identity?.version}
            </h2>
            <div className="list">
              {bundleSections.map((s) => {
                const sec = doc.sections?.[s];
                return (
                  <div className="agent wide" key={s}>
                    <b>{s}</b>
                    <span className={`severity-badge ${sec?.excluded ? 'info' : sec?.available ? 'info' : 'warning'}`}>
                      {sec?.excluded ? 'excluded' : sec?.available ? `${rowCount(sec)} rows` : 'unavailable'}
                    </span>
                    <small>{sec?.note || ''}</small>
                  </div>
                );
              })}
            </div>
            {trunc.length > 0 && (
              <>
                <h3>Truncated to fit the bounds</h3>
                <ul>
                  {trunc.map((t, i) => (
                    <li key={i}>
                      {t.section}.{t.list}: kept {t.kept} of {t.total}
                    </li>
                  ))}
                </ul>
              </>
            )}
          </section>

          <section className="card span3">
            <p className="eyebrow">REDACTION</p>
            <h2 className="card-title">What was removed or masked</h2>
            <p>
              {doc.redaction?.approach} IP masking: <b>{doc.redaction?.maskIps}</b>.
            </p>
            <ul>
              {(doc.redaction?.applied || []).map((a) => (
                <li key={a.rule}>
                  {a.rule}: {a.count}
                </li>
              ))}
              {(doc.redaction?.applied || []).length === 0 && <li>No string needed scrubbing in this window.</li>}
            </ul>
            <h3>Never included</h3>
            <ul>
              {(doc.redaction?.neverIncluded || []).map((n) => (
                <li key={n.section}>
                  {n.section}: {n.fields.join(', ')}
                </li>
              ))}
            </ul>
            <p className="empty-state">Integrity head {doc.integrity?.head}. A hash chain shows tampering; it is not a signature.</p>
          </section>

          <section className="card span3">
            <p className="eyebrow">TIMELINE</p>
            <h2 className="card-title">What changed in the window</h2>
            {timeline.length === 0 && <p className="empty-state">Nothing recorded in this window.</p>}
            <div className="list">
              {timeline.map((e, i) => (
                <div className="agent wide" key={i}>
                  <b>{e.summary}</b>
                  <span className={`severity-badge ${e.severity === 'critical' ? 'critical' : e.severity === 'warning' ? 'warning' : 'info'}`}>{e.category}</span>
                  <small>{[e.at ? new Date(e.at).toLocaleTimeString() : 'state', e.node, e.ref].filter(Boolean).join(' · ')}</small>
                </div>
              ))}
            </div>
          </section>
        </>
      )}
    </div>
  );
}
