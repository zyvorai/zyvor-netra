import { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import { wsURL } from '../api';
import TerminalFrame from './TerminalFrame';

type Props = {
  namespace: string;
  name: string;
  containers?: { name: string; ready?: boolean }[];
  defaultContainer?: string;
};

export default function PodExec({ namespace, name, containers = [], defaultContainer }: Props) {
  const [container, setContainer] = useState(defaultContainer || containers[0]?.name || '');
  const [connected, setConnected] = useState(false);
  const [err, setErr] = useState('');
  const hostRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    setContainer(defaultContainer || containers[0]?.name || '');
  }, [namespace, name, defaultContainer, containers]);

  useEffect(() => {
    return () => disconnect();
  }, []);

  function disconnect() {
    wsRef.current?.close();
    wsRef.current = null;
    termRef.current?.dispose();
    termRef.current = null;
    fitRef.current = null;
    setConnected(false);
  }

  function connect() {
    disconnect();
    setErr('');
    if (!hostRef.current) return;
    const rootStyle = getComputedStyle(document.documentElement);
    const term = new Terminal({
      cursorBlink: true,
      fontSize: 13,
      theme: {
        background: rootStyle.getPropertyValue('--terminal-bg').trim() || '#0d0d0f',
        foreground: rootStyle.getPropertyValue('--terminal-text').trim() || '#f5f5f7',
      },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(hostRef.current);
    fit.fit();
    termRef.current = term;
    fitRef.current = fit;

    const q = new URLSearchParams({ command: '/bin/sh' });
    if (container) q.set('container', container);
    const ws = new WebSocket(wsURL(`/api/v1/pods/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}/exec?${q}`));
    ws.binaryType = 'arraybuffer';
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      const sendResize = () => {
        if (!fitRef.current || ws.readyState !== WebSocket.OPEN) return;
        fitRef.current.fit();
        ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
      };
      sendResize();
      window.addEventListener('resize', sendResize);
      ws.addEventListener('close', () => window.removeEventListener('resize', sendResize));
    };
    ws.onmessage = (ev) => {
      if (typeof ev.data === 'string') term.write(ev.data);
      else term.write(new Uint8Array(ev.data as ArrayBuffer));
    };
    ws.onerror = () => setErr('WebSocket error');
    ws.onclose = () => setConnected(false);

    term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(data);
    });
  }

  return (
    <section className="card span3">
      <h2 className="card-title">
        Shell · {namespace}/{name}
      </h2>
      <div className="toolbar">
        {containers.length > 0 && (
          <label>
            Container{' '}
            <select value={container} onChange={(e) => setContainer(e.target.value)} disabled={connected}>
              {containers.map((c) => (
                <option key={c.name} value={c.name}>
                  {c.name}
                </option>
              ))}
            </select>
          </label>
        )}
        {!connected ? (
          <button className="primary" onClick={connect}>
            Connect
          </button>
        ) : (
          <button className="btn-secondary" onClick={disconnect}>Disconnect</button>
        )}
      </div>
      {err && <p>{err}</p>}
      <TerminalFrame title={`kubectl exec -it ${name} -- /bin/sh`}>
        <div ref={hostRef} className="xterm-host" />
      </TerminalFrame>
    </section>
  );
}
