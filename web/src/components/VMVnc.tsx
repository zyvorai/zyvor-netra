import { useEffect, useRef, useState } from 'react';
import { wsURL } from '../api';

// @novnc/novnc ships CJS without types
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type RFBInstance = { disconnect: () => void; scaleViewport: boolean; resizeSession: boolean };

type Props = { namespace: string; name: string };

export default function VMVnc({ namespace, name }: Props) {
  const [connected, setConnected] = useState(false);
  const [err, setErr] = useState('');
  const screenRef = useRef<HTMLDivElement>(null);
  const rfbRef = useRef<RFBInstance | null>(null);

  useEffect(() => () => disconnect(), []);

  function disconnect() {
    try {
      rfbRef.current?.disconnect();
    } catch {
      /* ignore */
    }
    rfbRef.current = null;
    setConnected(false);
  }

  async function connect() {
    disconnect();
    setErr('');
    if (!screenRef.current) return;
    try {
      const mod = await import('@novnc/novnc/lib/rfb.js');
      const RFB = (mod as { default: new (target: HTMLElement, url: string, options?: object) => RFBInstance }).default;
      const url = wsURL(`/api/v1/vms/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}/vnc`);
      const rfb = new RFB(screenRef.current, url);
      rfb.scaleViewport = true;
      rfb.resizeSession = true;
      rfbRef.current = rfb;
      setConnected(true);
    } catch (e: any) {
      setErr(String(e?.message || e));
      setConnected(false);
    }
  }

  return (
    <section className="card span3">
      <h2 className="card-title">
        VNC · {namespace}/{name}
      </h2>
      <div className="toolbar">
        {!connected ? (
          <button className="primary" onClick={() => void connect()}>
            Connect VNC
          </button>
        ) : (
          <button className="btn-secondary" onClick={disconnect}>Disconnect</button>
        )}
      </div>
      {err && <p>{err}</p>}
      <div ref={screenRef} className="vnc-screen" />
    </section>
  );
}
