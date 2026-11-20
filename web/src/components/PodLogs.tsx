import { useEffect, useRef, useState } from 'react';
import { authHeaders } from '../api';
import TerminalFrame from './TerminalFrame';

type Props = {
  namespace: string;
  name: string;
  containers?: { name: string; ready?: boolean }[];
  defaultContainer?: string;
};

export default function PodLogs({ namespace, name, containers = [], defaultContainer }: Props) {
  const [container, setContainer] = useState(defaultContainer || containers[0]?.name || '');
  const [lines, setLines] = useState<string[]>([]);
  const [running, setRunning] = useState(false);
  const [err, setErr] = useState('');
  const ctrl = useRef<AbortController | undefined>(undefined);
  const preRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    setContainer(defaultContainer || containers[0]?.name || '');
  }, [namespace, name, defaultContainer, containers]);

  useEffect(() => () => ctrl.current?.abort(), []);

  useEffect(() => {
    if (preRef.current) preRef.current.scrollTop = preRef.current.scrollHeight;
  }, [lines]);

  function stop() {
    ctrl.current?.abort();
    ctrl.current = undefined;
    setRunning(false);
  }

  async function start() {
    stop();
    setLines([]);
    setErr('');
    setRunning(true);
    const c = new AbortController();
    ctrl.current = c;
    const q = new URLSearchParams({ follow: 'true', tailLines: '500' });
    if (container) q.set('container', container);
    try {
      const r = await fetch(
        `/api/v1/pods/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}/logs?${q}`,
        { headers: authHeaders(), signal: c.signal }
      );
      if (!r.ok) throw new Error(await r.text());
      if (!r.body) throw new Error('no response body');
      const rd = r.body.getReader();
      const dec = new TextDecoder();
      let buf = '';
      for (;;) {
        const res = await rd.read();
        if (res.done) break;
        buf += dec.decode(res.value, { stream: true });
        let i;
        while ((i = buf.indexOf('\n\n')) >= 0) {
          const part = buf.slice(0, i);
          buf = buf.slice(i + 2);
          const ev = part.split('\n').find((v) => v.startsWith('event: '))?.slice(7);
          const dataLine = part.split('\n').find((v) => v.startsWith('data: '));
          if (!dataLine) continue;
          const raw = dataLine.slice(6);
          if (ev === 'log') {
            try {
              const line = JSON.parse(raw) as string;
              setLines((old) => [...old, line].slice(-2000));
            } catch {
              setLines((old) => [...old, raw].slice(-2000));
            }
          } else if (ev === 'error') {
            setErr(raw.replace(/^"|"$/g, ''));
          }
        }
      }
    } catch (e: any) {
      if (e?.name !== 'AbortError') setErr(String(e?.message || e));
    } finally {
      setRunning(false);
    }
  }

  return (
    <section className="card span3">
      <h2 className="card-title">
        Logs · {namespace}/{name}
      </h2>
      <div className="toolbar">
        {containers.length > 0 && (
          <label>
            Container{' '}
            <select value={container} onChange={(e) => setContainer(e.target.value)}>
              {containers.map((c) => (
                <option key={c.name} value={c.name}>
                  {c.name}
                </option>
              ))}
            </select>
          </label>
        )}
        {!running ? (
          <button className="btn-refresh" onClick={() => void start()}>
            Follow logs
          </button>
        ) : (
          <button className="danger" onClick={stop}>Stop</button>
        )}
      </div>
      {err && <p>{err}</p>}
      <TerminalFrame title={`kubectl logs -f ${name}`}>
        <pre ref={preRef} className="console-log">
          {lines.length ? lines.join('\n') : running ? 'waiting…' : 'Start follow to stream logs.'}
        </pre>
      </TerminalFrame>
    </section>
  );
}
