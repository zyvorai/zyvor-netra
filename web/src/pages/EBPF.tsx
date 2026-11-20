import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import { ruleTypeClass } from '../lib/ebpfRules';
import Reveal from '../components/Reveal';
import PagePulse from '../components/kit/PagePulse';
import { countTone } from '../components/kit/tone';

import DenyCensus from '../components/DenyCensus';
import LeaseClock from '../components/LeaseClock';
import WatchlistMatch from '../components/WatchlistMatch';

type UnifiedRule = { id?: string; type: string; value: string; detail: string; extra: string; created?: string; raw?: any; del?: () => void };

// Fields relevant to each rule type, used to build both the inline edit
// form and the PATCH body — mirrors the shape internal/api/server.go's
// ebpfRulePatch expects per type.
const EDIT_FIELDS: Record<string, string[]> = {
  ip4: ['ip'], ip6: ['ip'],
  cidr: ['cidr', 'direction'],
  port: ['protocol', 'port', 'direction'],
  uid: ['uid'],
  dns: ['name'], sni: ['name'], process: ['name'],
  rate: ['destination', 'pps', 'bps'],
};

export default function EBPF() {
  const [cfg, setCfg] = useState<any>();
  const [agents, setAgents] = useState<any[]>([]);
  const [caps, setCaps] = useState<any>();
  const [shieldDiag, setShieldDiag] = useState<any>();
  const [err, setErr] = useState('');
  const [lease, setLease] = useState('15m');
  const [ip, setIP] = useState('');
  const [ipDir, setIPDir] = useState('egress');
  const [synDropIP, setSynDropIP] = useState('');
  const [synDropDir, setSynDropDir] = useState('egress');
  const [synDropCIDR, setSynDropCIDR] = useState('');
  const [synDropCIDRDir, setSynDropCIDRDir] = useState('egress');
  const [cidr, setCIDR] = useState('');
  const [cidrDir, setCIDRDir] = useState('egress');
  const [port, setPort] = useState('443');
  const [proto, setProto] = useState('TCP');
  const [portDir, setPortDir] = useState('egress');
  const [uid, setUID] = useState('');
  const [allowUID, setAllowUID] = useState('');
  const [dns, setDNS] = useState('');
  const [sni, setSNI] = useState('');
  const [processName, setProcessName] = useState('');
  const [capabilityName, setCapabilityName] = useState('CAP_NET_RAW');
  const [allowProc, setAllowProc] = useState('');
  const [rateIP, setRateIP] = useState('');
  const [pps, setPPS] = useState('1000');
  const [bps, setBPS] = useState('');
  const [allowIP, setAllowIP] = useState('');
  const [allowCIDR, setAllowCIDR] = useState('');
  const [allowCIDRDir, setAllowCIDRDir] = useState('egress');
  const [allowPort, setAllowPort] = useState('443');
  const [allowProto, setAllowProto] = useState('TCP');
  const [allowPortDir, setAllowPortDir] = useState('egress');
  const [ipv6Diag, setIpv6Diag] = useState<any>();
  const [ifaceFlows, setIfaceFlows] = useState<any[]>([]);
  const [eventType, setEventType] = useState('all');
  const [workloads, setWorkloads] = useState<any[]>([]);
  const [scopeNS, setScopeNS] = useState('');
  const [scopePod, setScopePod] = useState('');
  const [scopeKind, setScopeKind] = useState('');
  const [scopeWorkload, setScopeWorkload] = useState('');
  const [scopeLabel, setScopeLabel] = useState('');
  const [scopePreview, setScopePreview] = useState<any>();
  const [topology, setTopology] = useState<any[]>([]);
  const [shieldMode, setShieldMode] = useState('off');
  const [shieldProtectAll, setShieldProtectAll] = useState(false);
  const [shieldSyn, setShieldSyn] = useState('0');
  const [shieldUdp, setShieldUdp] = useState('0');
  const [shieldIcmp, setShieldIcmp] = useState('0');
  const [shieldOther, setShieldOther] = useState('0');
  const [shieldBurst, setShieldBurst] = useState('2');
  const [shieldIP, setShieldIP] = useState('');
  const [shieldIPv6, setShieldIPv6] = useState('');
  const [npSelNS, setNpSelNS] = useState('');
  const [npSelPod, setNpSelPod] = useState('');
  const [npSelLabel, setNpSelLabel] = useState('');
  const [npPeer, setNpPeer] = useState('');
  const [npPort, setNpPort] = useState('');
  const [npProto, setNpProto] = useState('TCP');
  const [npDir, setNpDir] = useState('egress');
  const [npAction, setNpAction] = useState('allow');
  const [crlSelNS, setCrlSelNS] = useState('');
  const [crlSelPod, setCrlSelPod] = useState('');
  const [crlSelLabel, setCrlSelLabel] = useState('');
  const [crlPerSecond, setCrlPerSecond] = useState('');
  const [ddSelNS, setDdSelNS] = useState('');
  const [ddSelPod, setDdSelPod] = useState('');
  const [ddSelLabel, setDdSelLabel] = useState('');
  const [ddLease, setDdLease] = useState('5m');
  const [ddPlan, setDdPlan] = useState<any>(null);
  const [ruleList, setRuleList] = useState<any[]>([]);
  const [editingId, setEditingId] = useState('');
  const [editForm, setEditForm] = useState<Record<string, string>>({});
  const [historyId, setHistoryId] = useState('');
  const [history, setHistory] = useState<any[]>([]);

  // silent=true is used by the 5s background poll: a routine poll succeeding
  // should not erase an error the user hasn't had a chance to see yet, and a
  // transient poll failure shouldn't flash a scary banner every 5s. Explicit
  // loads (initial mount, after a mutating action) still surface load errors.
  // allSettled, not all: this page is the emergency control, so the rules (config) must render
  // even when an optional feed is down. /api/v1/ebpf/workloads needs the Kubernetes API; with
  // Promise.all its failure left the whole page unpopulated (no rules, no lease state) on a
  // controller that had lost the API server. Each feed applies on its own; the first failure is
  // still shown, and a failed config load is reported as such.
  const load = (silent?: boolean) => Promise.allSettled([
    api<any>('/api/v1/ebpf/config'),
    api<any>('/api/v1/agents'),
    api<any>('/api/v1/ebpf/capabilities'),
    api<any>('/api/v1/ebpf/workloads'),
    api<any>('/api/v1/ebpf/topology?limit=50'),
    api<any>('/api/v1/ebpf/shield?limit=1'),
    api<any>('/api/v1/ebpf/rules'),
    api<any>('/api/v1/ebpf/ipv6?limit=50'),
    api<any>('/api/v1/ebpf/interfaces?limit=10'),
  ]).then((rs) => {
    const val = (i: number): any => (rs[i].status === 'fulfilled' ? (rs[i] as PromiseFulfilledResult<any>).value : undefined);
    if (val(0) !== undefined) setCfg(val(0));
    if (val(1) !== undefined) setAgents(val(1).items || []);
    if (val(2) !== undefined) setCaps(val(2));
    if (val(3) !== undefined) setWorkloads(val(3).items || []);
    if (val(4) !== undefined) setTopology(val(4).items || []);
    if (val(5) !== undefined) setShieldDiag(val(5));
    if (val(6) !== undefined) setRuleList(val(6).items || []);
    if (val(7) !== undefined) setIpv6Diag(val(7));
    if (val(8) !== undefined) setIfaceFlows(val(8).nodes || []);
    const failed = rs.filter((r): r is PromiseRejectedResult => r.status === 'rejected');
    if (!silent) setErr(failed.length ? String(failed[0].reason) : '');
  });

  useEffect(() => { load(); const t = setInterval(() => load(true), 5000); return () => clearInterval(t); }, []);

  // Sync the shield form from server state only when the server's config
  // actually changed (generation bump), not on every 5s poll — otherwise
  // an in-progress edit would get stomped before the user hits Apply.
  useEffect(() => {
    if (!cfg?.shield) return;
    setShieldMode(cfg.shield.mode || 'off');
    setShieldProtectAll(!!cfg.shield.protectAll);
    setShieldSyn(String(cfg.shield.synPps || 0));
    setShieldUdp(String(cfg.shield.udpPps || 0));
    setShieldIcmp(String(cfg.shield.icmpPps || 0));
    setShieldOther(String(cfg.shield.otherPps || 0));
    setShieldBurst(String(cfg.shield.burstSeconds || 0));
  }, [cfg?.shield?.generation]);

  async function call(path: string, method: string, body?: any) {
    try {
      await api(path, { method, headers: body ? { 'Content-Type': 'application/json' } : undefined, body: body ? JSON.stringify(body) : undefined });
      await load();
    } catch (e) { setErr(String(e)); }
  }

  async function mode(m: string) {
    if (m === 'enforce' && !confirm(`Enable standalone eBPF enforcement for ${lease}? It automatically returns to observe mode when the lease or controller failsafe expires.`)) return;
    await call(`/api/v1/ebpf/mode${m === 'enforce' ? `?lease=${encodeURIComponent(lease)}` : ''}`, 'PUT', { mode: m });
  }

  function candidateScope() {
    const labels: Record<string,string> = {};
    if (scopeLabel.trim()) {
      const [k, ...rest] = scopeLabel.split('=');
      if (!k || !rest.length) throw new Error('Label selector must be key=value');
      labels[k.trim()] = rest.join('=').trim();
    }
    const scope: any = { namespace: scopeNS.trim(), pod: scopePod.trim(), workloadKind: scopeKind.trim(), workloadName: scopeWorkload.trim(), labels };
    if (!scope.namespace && !scope.pod && !scope.workloadKind && !scope.workloadName && !Object.keys(labels).length) throw new Error('Choose at least one workload selector');
    return scope;
  }
  async function applyScope(selected: boolean) {
    if (!selected) return call('/api/v1/ebpf/scope', 'PUT', { mode: 'all', scopes: [] });
    try { await call('/api/v1/ebpf/scope', 'PUT', { mode: 'selected', scopes: [candidateScope()] }); } catch (e) { setErr(String(e)); }
  }
  async function previewScope() {
    try { setScopePreview(await api('/api/v1/ebpf/scope/preview', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ scopes:[candidateScope()] }) })); setErr(''); } catch (e) { setErr(String(e)); }
  }

  function shieldBody(overrides: any = {}) {
    return {
      mode: shieldMode, protectAll: shieldProtectAll, protectedIpv4: cfg?.shield?.protectedIpv4 || [],
      protectedIpv6: cfg?.shield?.protectedIpv6 || [],
      synPps: Number(shieldSyn) || 0, udpPps: Number(shieldUdp) || 0, icmpPps: Number(shieldIcmp) || 0,
      otherPps: Number(shieldOther) || 0, burstSeconds: Number(shieldBurst) || 0, ...overrides,
    };
  }
  async function applyShield() {
    if (shieldMode === 'enforce' && !confirm('Enable Shield enforce mode? This will drop traffic exceeding configured PPS thresholds for protected IPs.')) return;
    await call('/api/v1/ebpf/shield', 'PUT', shieldBody());
  }
  function addShieldIP() {
    if (!shieldIP.trim()) return;
    const ips = Array.from(new Set([...(cfg?.shield?.protectedIpv4 || []), shieldIP.trim()]));
    call('/api/v1/ebpf/shield', 'PUT', shieldBody({ protectedIpv4: ips }));
    setShieldIP('');
  }
  function delShieldIP(x: string) {
    call('/api/v1/ebpf/shield', 'PUT', shieldBody({ protectedIpv4: (cfg?.shield?.protectedIpv4 || []).filter((y: string) => y !== x) }));
  }
  function addShieldIPv6() {
    if (!shieldIPv6.trim()) return;
    const ips = Array.from(new Set([...(cfg?.shield?.protectedIpv6 || []), shieldIPv6.trim()]));
    call('/api/v1/ebpf/shield', 'PUT', shieldBody({ protectedIpv6: ips }));
    setShieldIPv6('');
  }
  function delShieldIPv6(x: string) {
    call('/api/v1/ebpf/shield', 'PUT', shieldBody({ protectedIpv6: (cfg?.shield?.protectedIpv6 || []).filter((y: string) => y !== x) }));
  }
  function toggleNetPol() {
    const next = !cfg?.netPolEnabled;
    if (next && !confirm('Enabling NetPol enforcement may block previously-allowed traffic for workloads without matching allow rules.')) return;
    call('/api/v1/ebpf/netpol/config', 'PUT', { enabled: next });
  }

  function selectorFrom(ns: string, pod: string, label: string) {
    const sel: any = {};
    if (ns.trim()) sel.namespace = ns.trim();
    if (pod.trim()) sel.pod = pod.trim();
    if (label.trim()) {
      const [k, ...rest] = label.split('=');
      if (k && rest.length) sel.labels = { [k.trim()]: rest.join('=').trim() };
    }
    return sel;
  }
  function toggleNetPolV2() {
    call('/api/v1/ebpf/netpol/v2/config', 'PUT', { enabled: !cfg?.netPolV2Enabled });
  }
  async function addNetPolRule() {
    if (!npPeer.trim() && !npPort.trim()) {
      setErr('peer IPv4 or port is required (leave peer blank for a port-only rule)');
      return;
    }
    try {
      await api('/api/v1/ebpf/netpol/rules', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ selector: selectorFrom(npSelNS, npSelPod, npSelLabel), peerIpv4: npPeer, port: npPort ? Number(npPort) : undefined, protocol: npProto, direction: npDir, action: npAction }),
      });
      setNpPeer('');
      await load();
    } catch (e) { setErr(String(e)); }
  }
  function delNetPolRule(id: string) {
    call('/api/v1/ebpf/netpol/rules/' + encodeURIComponent(id), 'DELETE');
  }
  async function addConnRateLimit() {
    try {
      await api('/api/v1/ebpf/conn-rate-limit', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ selector: selectorFrom(crlSelNS, crlSelPod, crlSelLabel), perSecond: Number(crlPerSecond) }),
      });
      setCrlPerSecond('');
      await load();
    } catch (e) { setErr(String(e)); }
  }
  function delConnRateLimit(id: string) {
    call('/api/v1/ebpf/conn-rate-limit/' + encodeURIComponent(id), 'DELETE');
  }
  async function planDefaultDeny(enabled: boolean) {
    const body: any = { selector: selectorFrom(ddSelNS, ddSelPod, ddSelLabel), enabled };
    if (enabled) body.lease = ddLease;
    try {
      const res = await api<any>('/api/v1/ebpf/netpol/default-deny/plan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      setDdPlan({ ...res, body });
      setErr('');
    } catch (e) { setErr(String(e)); setDdPlan(null); }
  }
  async function applyDefaultDeny() {
    if (!ddPlan) return;
    if ((ddPlan.risk === 'high' || ddPlan.risk === 'critical') && !confirm(`Preflight risk is ${String(ddPlan.risk).toUpperCase()}. Apply this default-deny change anyway?`)) return;
    try {
      // Re-send the exact body object plan hashed — never rebuild it —
      // since the preflight token is bound to that exact byte sequence.
      await api('/api/v1/ebpf/netpol/default-deny', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-Netra-Plan-Token': ddPlan.receipt?.token, 'X-Netra-Confirm-Risk': ddPlan.risk },
        body: JSON.stringify(ddPlan.body),
      });
      setDdPlan(null);
      await load();
    } catch (e) { setErr(String(e)); }
  }
  async function deactivateDefaultDeny(selector: any) {
    if (!confirm('Deactivate default-deny for this selector? Traffic reverts to fail-open immediately.')) return;
    // Deactivation is always risk "low" and needs no operator confirmation,
    // but the API still requires a fresh preflight token for every
    // default-deny mutation — plan then immediately apply with it.
    const body = { selector, enabled: false };
    try {
      const res = await api<any>('/api/v1/ebpf/netpol/default-deny/plan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      await api('/api/v1/ebpf/netpol/default-deny', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-Netra-Plan-Token': res.receipt?.token },
        body: JSON.stringify(body),
      });
      await load();
    } catch (e) { setErr(String(e)); }
  }

  function startEdit(r: any) {
    setHistoryId('');
    setEditingId(r.id);
    setEditForm({
      ip: r.value || '', name: r.value || '', uid: r.value || '',
      cidr: r.cidr || '', direction: r.direction || 'egress', protocol: r.protocol || 'TCP',
      port: r.port ? String(r.port) : '', destination: r.destination || '', pps: r.pps ? String(r.pps) : '', bps: r.bps ? String(r.bps) : '',
    });
  }
  function cancelEdit() { setEditingId(''); }
  async function saveEdit(type: string) {
    const body: any = {};
    for (const f of EDIT_FIELDS[type] || []) {
      body[f] = (f === 'port' || f === 'pps' || f === 'bps' || f === 'uid') ? Number(editForm[f] || 0) : editForm[f];
    }
    try {
      await api(`/api/v1/ebpf/rules/${encodeURIComponent(editingId)}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      setEditingId('');
      await load();
    } catch (e) { setErr(String(e)); }
  }
  async function toggleHistory(id: string) {
    if (historyId === id) { setHistoryId(''); return; }
    setEditingId('');
    setHistoryId(id);
    try { setHistory((await api<any>(`/api/v1/ebpf/rules/${encodeURIComponent(id)}/history`)).items || []); } catch (e) { setErr(String(e)); }
  }
  async function rollback(id: string, revision: number) {
    if (!confirm('Undo this edit? This restores the value it had before this revision.')) return;
    try {
      await api(`/api/v1/ebpf/rules/${encodeURIComponent(id)}/rollback/${revision}`, { method: 'POST' });
      setHistory((await api<any>(`/api/v1/ebpf/rules/${encodeURIComponent(id)}/history`)).items || []);
      await load();
    } catch (e) { setErr(String(e)); }
  }

  const events = useMemo(() => agents
    .flatMap(a => (a.events || []).map((e: any) => ({ ...e, node: a.node })))
    .sort((a, b) => Date.parse(b.observedAt) - Date.parse(a.observedAt))
    .filter((e: any) => eventType === 'all' || e.type === eventType)
    .slice(0, 220), [agents, eventType]);
  const stats = useMemo(() => agents
    .flatMap(a => (a.stats || []).map((s: any) => ({ ...s, node: a.node })))
    .sort((a, b) => (b.packets || 0) - (a.packets || 0)).slice(0, 160), [agents]);

  const rules = useMemo<UnifiedRule[]>(() => {
    const out: UnifiedRule[] = ruleList.map((r: any) => ({
      id: r.id, type: r.type, raw: r,
      value: r.type === 'cidr' || r.type === 'allow-cidr' ? r.cidr : r.type === 'port' || r.type === 'allow-port' ? `${r.protocol}/${r.port}` : r.type === 'rate' ? r.destination : r.value,
      detail: r.direction || '', extra: r.type === 'rate' ? `${r.pps || 0}pps${r.bps ? ` · ${r.bps}Bps` : ''}` : '',
      created: r.createdBy ? `${r.createdBy} · ${new Date(r.createdAt).toLocaleString()}` : '',
      del: () => { if (confirm(`Delete this ${r.type} rule?`)) call('/api/v1/ebpf/rules/' + encodeURIComponent(r.id), 'DELETE'); },
    }));
    if (cfg?.shield?.mode && cfg.shield.mode !== 'off') out.push({ type: 'shield', value: cfg.shield.protectAll ? 'all traffic' : `${(cfg.shield.protectedIpv4 || []).length} protected IPs`, detail: cfg.shield.mode, extra: '' });
    if (cfg?.netPolEnabled) out.push({ type: 'netpol', value: `${(cfg.netPolDenies || []).length} deny entries`, detail: 'enabled', extra: '' });
    if (cfg?.netPolV2Enabled) out.push({ type: 'netpol-v2', value: `${(cfg.netPolRules || []).length} rules · ${(cfg.netPolDefaultDenies || []).length} default-deny`, detail: 'enabled', extra: '' });
    return out.sort((a, b) => a.type === b.type ? a.value.localeCompare(b.value) : a.type.localeCompare(b.type));
  }, [ruleList, cfg?.shield, cfg?.netPolEnabled, cfg?.netPolDenies, cfg?.netPolV2Enabled, cfg?.netPolRules, cfg?.netPolDefaultDenies]);

  function cap(count: number, limit: number | undefined) {
    if (!limit) return null;
    return <p className={count / limit > 0.9 ? 'warning' : ''}>{count} / {limit} rules</p>;
  }

  const enforcing = cfg?.mode === 'enforce';
  const leaseLeft = cfg?.enforceUntil ? Math.max(0, Math.round((new Date(cfg.enforceUntil).getTime() - Date.now()) / 60000)) : undefined;
  return <div className="grid">
    <PagePulse
      headline={cfg ? (enforcing ? `Enforcing ${rules.length} rule${rules.length === 1 ? '' : 's'} under a lease.` : rules.length ? `Observing — ${rules.length} rule${rules.length === 1 ? '' : 's'} staged, none blocking.` : 'Observing. No rules configured.') : undefined}
      tone={cfg ? (enforcing ? 'warn' : undefined) : undefined}
      tick={cfg}
      error={err || undefined}
      figures={[
        { label: 'mode', value: cfg ? (cfg.mode || 'observe') : undefined, tone: cfg ? (enforcing ? 'warn' : 'ok') : undefined },
        { label: 'lease left', value: cfg ? (leaseLeft !== undefined && enforcing ? `${leaseLeft} min` : '—') : undefined },
        { label: 'rules', value: cfg ? rules.length : undefined },
        { label: 'scope', value: cfg ? (cfg.scopeMode || 'all') : undefined, tone: cfg && cfg.scopeMode === 'selected' ? 'warn' : undefined },
        { label: 'agents', value: cfg ? agents.length : undefined, tone: cfg ? countTone(agents.length === 0 ? 1 : 0) : undefined },
      ]}
    />
    {err && <p className="warning" style={{ gridColumn: '1 / -1' }}>{err}</p>}
    <section className="card span3">
      <p className="eyebrow">FIREWALL RULES</p>
      <h2 className="card-title">All configured rules</h2>
      {rules.length === 0 && <p className="empty-state">No firewall rules configured.</p>}
      {rules.length > 0 && <div className="datatable-scroll">
        <div className="datahead rules"><span>TYPE</span><span>VALUE</span><span>DETAIL</span><span>CREATED</span><span>ACTIONS</span></div>
        {rules.map((r, i) => (
          <div key={r.id || (r.type + r.value + i)}>
            <div className="datarow rules">
              <span className={ruleTypeClass(r.type)}>{r.type}</span><span className="truncate" title={r.value} aria-label={r.value}>{r.value}</span><span>{r.detail}{r.extra}</span><span>{r.created || '—'}</span>
              <span>
                {r.id && <button className="btn-secondary" onClick={() => startEdit(r.raw)}>edit</button>}
                {r.id && <button className="btn-diag" onClick={() => toggleHistory(r.id!)}>history</button>}
                {r.del && <button className="danger" onClick={r.del}>delete</button>}
              </span>
            </div>
            {editingId === r.id && <div className="datarow rules">
              <div style={{ gridColumn: '1 / -1' }} className="ruleform">
                {(EDIT_FIELDS[r.type] || []).map(f => {
                  if (f === 'direction') return <select key={f} aria-label={f} value={editForm.direction} onChange={e => setEditForm({ ...editForm, direction: e.target.value })}><option>egress</option><option>ingress</option><option>both</option></select>;
                  if (f === 'protocol') return <select key={f} aria-label={f} value={editForm.protocol} onChange={e => setEditForm({ ...editForm, protocol: e.target.value })}><option>TCP</option><option>UDP</option><option>ANY</option></select>;
                  return <input key={f} value={editForm[f] || ''} onChange={e => setEditForm({ ...editForm, [f]: e.target.value })} placeholder={f} aria-label={f} inputMode={(f === 'port' || f === 'pps' || f === 'bps' || f === 'uid') ? 'numeric' : undefined} />;
                })}
                <button className="primary" onClick={() => saveEdit(r.type)}>Save</button>
                <button className="btn-secondary" onClick={cancelEdit}>Cancel</button>
              </div>
            </div>}
            {historyId === r.id && <div className="datarow rules">
              <div style={{ gridColumn: '1 / -1' }}>
                {history.length === 0 && <p className="empty-state">No edit history for this rule.</p>}
                {history.map((h: any) => (
                  <div key={h.id} className="agent wide">
                    <b>{new Date(h.at).toLocaleString()}</b><span>{h.actor}</span>
                    <small><code>{JSON.stringify(h.before)}</code> → <code>{JSON.stringify(h.after)}</code></small>
                    <button className="btn-warn" onClick={() => rollback(r.id!, h.id)}>undo this edit</button>
                  </div>
                ))}
              </div>
            </div>}
          </div>
        ))}
      </div>}
    </section>

    <section className="card span3"><p className="eyebrow">ENFORCEMENT LEASE</p><h2 className="card-title">Observe or time-boxed enforce</h2><p>Blocking requires an explicit lease. Netra owns only <code>/sys/fs/bpf/netra</code>.</p><div className="toolbar"><button className={cfg?.mode === 'observe' ? 'btn-success' : 'btn-secondary'} onClick={() => mode('observe')}>Observe</button><input aria-label="Enforcement lease duration" value={lease} onChange={e => setLease(e.target.value)} title="1m–24h"/><button className={cfg?.mode === 'enforce' ? 'danger' : 'btn-warn'} onClick={() => mode('enforce')}>Enforce lease</button></div>{cfg?.enforceUntil && <p className="warning">Lease expires: {new Date(cfg.enforceUntil).toLocaleString()}</p>}</section>

    <section className="card span3"><p className="eyebrow">WORKLOAD SCOPE</p><h2 className="card-title">Observe the node. Enforce only the workloads you choose.</h2><p>In <b>selected</b> mode, blocking runs only on cgroup/socket hooks whose cgroup resolves to a matching Kubernetes pod. TCX/XDP remain observation-only because they do not carry a reliable workload cgroup identity.</p><div className="ruleform"><input aria-label="Namespace" value={scopeNS} onChange={e => setScopeNS(e.target.value)} placeholder="namespace, e.g. payments"/><input aria-label="Pod" value={scopePod} onChange={e => setScopePod(e.target.value)} placeholder="pod (optional)"/><input aria-label="Owner kind" value={scopeKind} onChange={e => setScopeKind(e.target.value)} placeholder="owner kind, e.g. ReplicaSet"/><input aria-label="Owner name" value={scopeWorkload} onChange={e => setScopeWorkload(e.target.value)} placeholder="owner name (optional)"/><input aria-label="Label selector" value={scopeLabel} onChange={e => setScopeLabel(e.target.value)} placeholder="label key=value (optional)"/><button className="btn-secondary" onClick={previewScope}>Preview</button><button className={cfg?.scopeMode !== 'selected' ? 'btn-success' : 'btn-secondary'} onClick={() => applyScope(false)}>All cgroups</button><button className={cfg?.scopeMode === 'selected' ? 'danger' : 'btn-warn'} onClick={() => applyScope(true)}>Selected workloads</button></div>{scopePreview && <p><b>{scopePreview.count}</b> of {scopePreview.totalPods} pods match this preview.</p>}<p className={cfg?.scopeMode === 'selected' ? 'warning' : ''}>Current: <b>{cfg?.scopeMode || 'all'}</b> · {(cfg?.workloadScopes || []).length} configured scope(s) · {workloads.length} pods discovered.</p><div className="chips">{(cfg?.workloadScopes || []).map((x:any, i:number) => <span key={i}>{x.namespace || '*'} / {x.pod || x.workloadName || '*'} {x.labels && Object.keys(x.labels).length ? JSON.stringify(x.labels) : ''}</span>)}</div></section>

    <Reveal className="section-divider">
      <h2>Deny rules</h2>
      <p>Fast-path exact-match and prefix deny lists — lease-bound, fail-open.</p>
    </Reveal>

    <section className="card"><p className="eyebrow">EXACT IP</p><h3>IPv4 + IPv6 deny</h3>{cap((cfg?.blockedIPv4?.length||0), caps?.limits?.exactIPv4)}<div className="ruleform"><input aria-label="IP address" value={ip} onChange={e => setIP(e.target.value)} placeholder="203.0.113.10 or 2001:db8::1"/><select aria-label="Deny direction" value={ipDir} onChange={e => setIPDir(e.target.value)}><option>egress</option><option>ingress</option><option>both</option></select><button className="primary" onClick={() => call('/api/v1/ebpf/deny', 'POST', { ip, direction: ipDir })}>Add</button></div><div className="chips">{[...(cfg?.blockedIPv4 || []), ...(cfg?.blockedIPv6 || [])].map((x: string) => <button key={x} aria-label={`Remove ${x}`} onClick={() => call('/api/v1/ebpf/deny/' + encodeURIComponent(x), 'DELETE')}>{x} ×</button>)}{(cfg?.blockedIngressIPv4 || []).map((x: string) => <button key={'in-'+x} aria-label={`Remove ingress ${x}`} onClick={() => call('/api/v1/ebpf/deny/' + encodeURIComponent(x), 'DELETE')}>ingress · {x} ×</button>)}{(cfg?.blockedIngressIPv6 || []).map((x: string) => <button key={'in6-'+x} aria-label={`Remove ingress ${x}`} onClick={() => call('/api/v1/ebpf/deny/' + encodeURIComponent(x), 'DELETE')}>ingress · {x} ×</button>)}</div></section>
    <section className="card"><p className="eyebrow">SYN-DROP MODE</p><h3>Block new connections, allow established</h3><p>Flags an <b>existing</b> exact-IP deny entry above so only a genuinely new TCP connection attempt is dropped — any other TCP packet for that address+direction is allowed through instead of unconditionally dropped. Has no effect without a matching deny entry for the same address+direction.</p>{cap((cfg?.synDrop?.length||0), 4096)}<div className="ruleform"><input aria-label="SYN-drop IP address" value={synDropIP} onChange={e => setSynDropIP(e.target.value)} placeholder="203.0.113.10 or 2001:db8::1"/><select aria-label="SYN-drop direction" value={synDropDir} onChange={e => setSynDropDir(e.target.value)}><option>egress</option><option>ingress</option></select><button className="primary" onClick={() => call('/api/v1/ebpf/syn-drop', 'POST', { address: synDropIP, direction: synDropDir })}>Flag SYN-drop</button></div><div className="chips">{(cfg?.synDrop || []).length === 0 && <span>No SYN-drop flags configured.</span>}{(cfg?.synDrop || []).map((x: any) => <button key={x.address + x.direction} aria-label={`Remove SYN-drop ${x.direction} ${x.address}`} onClick={() => call('/api/v1/ebpf/syn-drop/delete', 'POST', x)}>{x.direction} · {x.address} ×</button>)}</div>
      <p>Flags an <b>existing</b> CIDR deny entry above the same way, for a whole range instead of one address.</p>{cap((cfg?.synDropCidr?.length||0), 8192)}<div className="ruleform"><input aria-label="SYN-drop CIDR" value={synDropCIDR} onChange={e => setSynDropCIDR(e.target.value)} placeholder="203.0.113.0/24 or 2001:db8::/32"/><select aria-label="SYN-drop CIDR direction" value={synDropCIDRDir} onChange={e => setSynDropCIDRDir(e.target.value)}><option>egress</option><option>ingress</option></select><button className="primary" onClick={() => call('/api/v1/ebpf/syn-drop-cidr', 'POST', { cidr: synDropCIDR, direction: synDropCIDRDir })}>Flag SYN-drop CIDR</button></div><div className="chips">{(cfg?.synDropCidr || []).length === 0 && <span>No SYN-drop CIDR flags configured.</span>}{(cfg?.synDropCidr || []).map((x: any) => <button key={x.cidr + x.direction} aria-label={`Remove SYN-drop CIDR ${x.direction} ${x.cidr}`} onClick={() => call('/api/v1/ebpf/syn-drop-cidr/delete', 'POST', x)}>{x.direction} · {x.cidr} ×</button>)}</div></section>
    <section className="card"><p className="eyebrow">EXACT IP</p><h3>Allow-exception</h3><p>Wins over the deny-list, CIDR, port, and rate controls above for a matching destination. Does not itself enable enforce mode.</p><div className="toolbar"><input aria-label="Allow-exception IP address" value={allowIP} onChange={e => setAllowIP(e.target.value)} placeholder="203.0.113.10 or 2001:db8::1"/><button className="primary" onClick={() => call('/api/v1/ebpf/allow', 'POST', { ip: allowIP })}>Add</button></div><div className="chips">{[...(cfg?.allowedIPv4 || []), ...(cfg?.allowedIPv6 || [])].map((x: string) => <button key={x} aria-label={`Remove ${x}`} onClick={() => call('/api/v1/ebpf/allow/' + encodeURIComponent(x), 'DELETE')}>{x} ×</button>)}</div></section>
    <section className="card"><p className="eyebrow">CIDR</p><h3>Ingress / egress prefixes</h3>{cap((cfg?.blockedCidrs?.length||0), caps?.limits?.cidr)}<div className="ruleform"><input aria-label="CIDR" value={cidr} onChange={e => setCIDR(e.target.value)} placeholder="10.0.0.0/8 or 2001:db8::/32"/><select aria-label="CIDR direction" value={cidrDir} onChange={e => setCIDRDir(e.target.value)}><option>egress</option><option>ingress</option><option>both</option></select><button className="primary" onClick={() => call('/api/v1/ebpf/cidr', 'POST', { cidr, direction: cidrDir })}>Add CIDR</button></div><div className="chips">{(cfg?.blockedCidrs || []).map((x: any) => <button key={x.cidr + x.direction} aria-label={`Remove ${x.direction} ${x.cidr}`} onClick={() => call('/api/v1/ebpf/cidr/delete', 'POST', x)}>{x.direction} · {x.cidr} ×</button>)}</div></section>
    <section className="card"><p className="eyebrow">CIDR</p><h3>Allow-exception prefixes</h3><p>Wins over the deny-list, CIDR, port, and rate controls above for a matching destination. Does not itself enable enforce mode.</p><div className="ruleform"><input aria-label="Allow-exception CIDR" value={allowCIDR} onChange={e => setAllowCIDR(e.target.value)} placeholder="10.0.0.0/24 or 2001:db8::/48"/><select aria-label="Allow-exception CIDR direction" value={allowCIDRDir} onChange={e => setAllowCIDRDir(e.target.value)}><option>egress</option><option>ingress</option><option>both</option></select><button className="primary" onClick={() => call('/api/v1/ebpf/allow-cidr', 'POST', { cidr: allowCIDR, direction: allowCIDRDir })}>Add CIDR</button></div><div className="chips">{(cfg?.allowedCidrs || []).map((x: any) => <button key={x.cidr + x.direction} aria-label={`Remove ${x.direction} ${x.cidr}`} onClick={() => call('/api/v1/ebpf/allow-cidr/delete', 'POST', x)}>{x.direction} · {x.cidr} ×</button>)}</div></section>
    <section className="card"><p className="eyebrow">L4</p><h3>Port controls</h3>{cap((cfg?.blockedPorts?.length||0), caps?.limits?.ports)}<div className="ruleform"><select aria-label="Protocol" value={proto} onChange={e => setProto(e.target.value)}><option>TCP</option><option>UDP</option><option>ANY</option></select><input aria-label="Port number" value={port} onChange={e => setPort(e.target.value)} inputMode="numeric"/><select aria-label="Port direction" value={portDir} onChange={e => setPortDir(e.target.value)}><option>egress</option><option>ingress</option><option>both</option></select><button className="primary" onClick={() => call('/api/v1/ebpf/port', 'POST', { protocol: proto, port: Number(port), direction: portDir })}>Add port</button></div><div className="chips">{(cfg?.blockedPorts || []).map((x: any) => <button key={x.protocol + x.port + x.direction} aria-label={`Remove ${x.direction} ${x.protocol}/${x.port}`} onClick={() => call('/api/v1/ebpf/port/delete', 'POST', x)}>{x.direction} · {x.protocol}/{x.port} ×</button>)}</div></section>
    <section className="card"><p className="eyebrow">L4</p><h3>Allow-exception ports</h3><p>Wins over deny IP/CIDR/port/rate for that L4 port. Does not enable enforce mode.</p><div className="ruleform"><select aria-label="Allow protocol" value={allowProto} onChange={e => setAllowProto(e.target.value)}><option>TCP</option><option>UDP</option><option>ANY</option></select><input aria-label="Allow port number" value={allowPort} onChange={e => setAllowPort(e.target.value)} inputMode="numeric"/><select aria-label="Allow port direction" value={allowPortDir} onChange={e => setAllowPortDir(e.target.value)}><option>egress</option><option>ingress</option><option>both</option></select><button className="primary" onClick={() => call('/api/v1/ebpf/allow-port', 'POST', { protocol: allowProto, port: Number(allowPort), direction: allowPortDir })}>Add port</button></div><div className="chips">{(cfg?.allowedPorts || []).map((x: any) => <button key={'ap'+x.protocol + x.port + x.direction} aria-label={`Remove allow ${x.direction} ${x.protocol}/${x.port}`} onClick={() => call('/api/v1/ebpf/allow-port/delete', 'POST', x)}>{x.direction} · {x.protocol}/{x.port} ×</button>)}</div></section>

    <section className="card"><p className="eyebrow">IDENTITY</p><h3>UID socket deny</h3><p>Blocks new TCP connects and UDP sendmsg operations from a Linux UID while enforcement is leased.</p>{cap((cfg?.blockedUids?.length||0), caps?.limits?.uids)}<div className="toolbar"><input aria-label="UID" value={uid} onChange={e => setUID(e.target.value)} inputMode="numeric" placeholder="1000"/><button className="primary" onClick={() => call('/api/v1/ebpf/uid', 'POST', { uid: Number(uid) })}>Add UID</button></div><div className="chips">{(cfg?.blockedUids || []).map((x: number) => <button key={x} aria-label={`Remove uid ${x}`} onClick={() => call('/api/v1/ebpf/uid/' + x, 'DELETE')}>uid {x} ×</button>)}</div></section>
    <section className="card"><p className="eyebrow">IDENTITY</p><h3>Allow-exception UIDs</h3><p>This UID skips UID/comm denies at the socket hook. Does not enable enforce mode.</p><div className="toolbar"><input aria-label="Allow UID" value={allowUID} onChange={e => setAllowUID(e.target.value)} inputMode="numeric" placeholder="1000"/><button className="primary" onClick={() => call('/api/v1/ebpf/allow-uid', 'POST', { uid: Number(allowUID) })}>Add UID</button></div><div className="chips">{(cfg?.allowedUids || []).map((x: number) => <button key={'au'+x} aria-label={`Remove allow uid ${x}`} onClick={() => call('/api/v1/ebpf/allow-uid/' + x, 'DELETE')}>allow uid {x} ×</button>)}</div></section>
    <section className="card"><p className="eyebrow">PROCESS</p><h3>Linux comm deny</h3><p>Blocks new connect/sendmsg operations by exact process <code>comm</code> (maximum 15 bytes). Existing sockets are not terminated.</p>{cap((cfg?.blockedProcesses?.length||0), caps?.limits?.processes)}<div className="toolbar"><input aria-label="Process name" value={processName} onChange={e => setProcessName(e.target.value)} placeholder="curl" maxLength={15}/><button className="primary" onClick={() => call('/api/v1/ebpf/process', 'POST', { name: processName })}>Add process</button></div><div className="chips">{(cfg?.blockedProcesses || []).map((x: string) => <button key={x} aria-label={`Remove ${x}`} onClick={() => call('/api/v1/ebpf/process/delete', 'POST', { name: x })}>{x} ×</button>)}</div></section>
    <section className="card"><p className="eyebrow">PROCESS</p><h3>Allow-exception comm</h3><p>Exact 15-byte <code>comm</code> exception at the socket hook.</p><div className="toolbar"><input aria-label="Allow process name" value={allowProc} onChange={e => setAllowProc(e.target.value)} placeholder="coredns" maxLength={15}/><button className="primary" onClick={() => call('/api/v1/ebpf/allow-process', 'POST', { name: allowProc })}>Add process</button></div><div className="chips">{(cfg?.allowedProcesses || []).map((x: string) => <button key={'aproc'+x} aria-label={`Remove allow ${x}`} onClick={() => call('/api/v1/ebpf/allow-process/delete', 'POST', { name: x })}>allow {x} ×</button>)}</div></section>
    <section className="card"><p className="eyebrow">CAPABILITY</p><h3>Capability-gated socket deny</h3><p>Denies new connect/sendmsg attempts for any process with this Linux capability currently effective. <b>Agent-sourced, not a live kernel read</b>: the agent periodically scans <code>/proc</code> (requires <code>NETRA_PROCMETA_ENABLED</code>), so a capability change can take up to one sync interval to be reflected.</p>{cap((cfg?.deniedCapabilities?.length||0), caps?.limits?.capability)}<div className="toolbar"><select aria-label="Capability to deny" value={capabilityName} onChange={e => setCapabilityName(e.target.value)}><option>CAP_NET_RAW</option><option>CAP_NET_ADMIN</option></select><button className="primary" onClick={() => call('/api/v1/ebpf/capability', 'POST', { name: capabilityName })}>Deny capability</button></div><div className="chips">{(cfg?.deniedCapabilities || []).length === 0 && <span>No capability-gated deny entries.</span>}{(cfg?.deniedCapabilities || []).map((x: string) => <button key={x} aria-label={`Remove ${x}`} onClick={() => call('/api/v1/ebpf/capability/delete', 'POST', { name: x })}>{x} ×</button>)}</div></section>
    <section className="card"><p className="eyebrow">DNS</p><h3>Exact DNS-name deny</h3><p>Parses and blocks exact cleartext DNS queries over UDP/53. This does not inspect TCP DNS, DoT, or DoH.</p>{cap((cfg?.blockedDns?.length||0), caps?.limits?.dns)}<div className="toolbar"><input aria-label="DNS name" value={dns} onChange={e => setDNS(e.target.value)} placeholder="telemetry.example.com"/><button className="primary" onClick={() => call('/api/v1/ebpf/dns', 'POST', { name: dns })}>Add DNS</button></div><div className="chips">{(cfg?.blockedDns || []).map((x: string) => <button key={x} aria-label={`Remove ${x}`} onClick={() => call('/api/v1/ebpf/dns/delete', 'POST', { name: x })}>{x} ×</button>)}</div></section>
    <section className="card"><p className="eyebrow">SNI</p><h3>Exact TLS SNI deny</h3><p>Blocks connections whose TLS ClientHello Server Name Indication matches exactly. Best-effort parsing only.</p>{cap((cfg?.blockedSni?.length||0), caps?.limits?.sni)}<div className="toolbar"><input aria-label="SNI hostname" value={sni} onChange={e => setSNI(e.target.value)} placeholder="telemetry.example.com"/><button className="primary" onClick={() => call('/api/v1/ebpf/sni', 'POST', { name: sni })}>Add SNI</button></div><div className="chips">{(cfg?.blockedSni || []).map((x: string) => <button key={x} aria-label={`Remove ${x}`} onClick={() => call('/api/v1/ebpf/sni/delete', 'POST', { name: x })}>{x} ×</button>)}</div></section>

    <section className="card"><p className="eyebrow">RATE CONTROL</p><h3>Destination PPS/BPS ceiling</h3><p>Simple fixed-window IPv4 or IPv6 destination packet-rate and/or byte-rate guard — independent caps, set either or both. Intended as an emergency containment control, not QoS.</p>{cap((cfg?.rateLimits?.length||0), caps?.limits?.rate)}<div className="ruleform"><input aria-label="Rate limit destination IP" value={rateIP} onChange={e => setRateIP(e.target.value)} placeholder="203.0.113.20 or 2001:db8::1"/><input aria-label="Packets per second" value={pps} onChange={e => setPPS(e.target.value)} inputMode="numeric" placeholder="pps (optional)"/><input aria-label="Bytes per second" value={bps} onChange={e => setBPS(e.target.value)} inputMode="numeric" placeholder="bps (optional)"/><button className="primary" onClick={() => call('/api/v1/ebpf/rate', 'PUT', { destination: rateIP, pps: Number(pps || 0), bps: Number(bps || 0) })}>Set rate</button></div><div className="chips">{(cfg?.rateLimits || []).map((x: any) => <button key={x.destination} aria-label={`Remove ${x.destination}`} onClick={() => call('/api/v1/ebpf/rate/' + encodeURIComponent(x.destination), 'DELETE')}>{x.destination} · {x.pps || 0}pps{x.bps ? ` · ${x.bps}Bps` : ''} ×</button>)}</div></section>

    <Reveal className="section-divider">
      <h2>Advanced engines</h2>
      <p>DDoS shield and the two independent NetworkPolicy-style engines — each has its own enable toggle and state.</p>
    </Reveal>

    <section className="card span3"><p className="eyebrow">SHIELD</p><h3>DDoS per-source-class PPS shield</h3><p>Independent XDP-layer token-bucket limiter for SYN/UDP/ICMP/other floods, decoupled from the enforcement lease above. {shieldDiag?.summary && <>Live: {shieldDiag.summary.allowed||0} allowed · {shieldDiag.summary.dropped||0} dropped · {shieldDiag.summary.audited||0} audited.</>}</p><div className="ruleform"><select aria-label="Shield mode" value={shieldMode} onChange={e => setShieldMode(e.target.value)}><option value="off">off</option><option value="audit">audit</option><option value="enforce">enforce</option></select><label><input type="checkbox" checked={shieldProtectAll} onChange={e => setShieldProtectAll(e.target.checked)}/> protect all</label><input aria-label="SYN packets per second" value={shieldSyn} onChange={e => setShieldSyn(e.target.value)} inputMode="numeric" placeholder="SYN pps"/><input aria-label="UDP packets per second" value={shieldUdp} onChange={e => setShieldUdp(e.target.value)} inputMode="numeric" placeholder="UDP pps"/><input aria-label="ICMP packets per second" value={shieldIcmp} onChange={e => setShieldIcmp(e.target.value)} inputMode="numeric" placeholder="ICMP pps"/><input aria-label="Other packets per second" value={shieldOther} onChange={e => setShieldOther(e.target.value)} inputMode="numeric" placeholder="other pps"/><input aria-label="Burst seconds" value={shieldBurst} onChange={e => setShieldBurst(e.target.value)} inputMode="numeric" placeholder="burst s"/><button className="primary" onClick={applyShield}>Apply shield config</button></div>{!shieldProtectAll && <div className="toolbar"><input aria-label="Protected IPv4 address" value={shieldIP} onChange={e => setShieldIP(e.target.value)} placeholder="protected IPv4"/><button className="primary" onClick={addShieldIP}>Add protected IP</button></div>}<div className="chips">{(cfg?.shield?.protectedIpv4 || []).map((x: string) => <button key={x} aria-label={`Remove ${x}`} onClick={() => delShieldIP(x)}>{x} ×</button>)}</div>{!shieldProtectAll && <div className="toolbar"><input aria-label="Protected IPv6 address" value={shieldIPv6} onChange={e => setShieldIPv6(e.target.value)} placeholder="protected IPv6"/><button className="primary" onClick={addShieldIPv6}>Add protected IPv6</button></div>}<div className="chips">{(cfg?.shield?.protectedIpv6 || []).map((x: string) => <button key={x} aria-label={`Remove ${x}`} onClick={() => delShieldIPv6(x)}>{x} ×</button>)}</div></section>

    <section className="card span3"><p className="eyebrow">NETPOL</p><h3>Per-workload NetworkPolicy-style deny</h3><p>Legacy per-cgroup peer-deny engine, independent from the rules above and from NetPol v2 below. Rule authoring has no UI — toggle enforcement and review existing entries here.</p><div className="toolbar"><button className={cfg?.netPolEnabled ? 'danger' : 'btn-success'} onClick={toggleNetPol}>{cfg?.netPolEnabled ? 'Disable NetPol' : 'Enable NetPol'}</button></div><div className="chips">{(cfg?.netPolDenies || []).length === 0 && <span>No NetPol deny entries.</span>}{(cfg?.netPolDenies || []).map((x: any, i: number) => <span key={i}>{x.direction || 'both'} · cgroup {x.cgroupId} → {x.peerIpv4}{x.port ? ':' + x.port : ''} {x.protocol || ''}</span>)}</div></section>

    <section className="card span3">
      <p className="eyebrow">NETPOL V2</p><h3>Allow-list / default-deny per workload</h3>
      <p>An explicit <b>allow</b> rule here can override even the emergency deny-list above for that workload+peer — by design. Activating default-deny for a selector requires a plan step first; a workload with zero covering allow rules is refused.</p>
      <div className="toolbar"><button className={cfg?.netPolV2Enabled ? 'danger' : 'btn-success'} onClick={toggleNetPolV2}>{cfg?.netPolV2Enabled ? 'Disable NetPol v2' : 'Enable NetPol v2'}</button></div>

      <p className="eyebrow" style={{ marginTop: 18 }}>ALLOW / DENY RULES</p>
      {cap((cfg?.netPolRules?.length||0), caps?.limits?.netpolV2Rules)}
      <div className="ruleform">
        <input aria-label="Namespace" value={npSelNS} onChange={e => setNpSelNS(e.target.value)} placeholder="namespace" />
        <input aria-label="Pod" value={npSelPod} onChange={e => setNpSelPod(e.target.value)} placeholder="pod (optional)" />
        <input aria-label="Label selector" value={npSelLabel} onChange={e => setNpSelLabel(e.target.value)} placeholder="label key=value (optional)" />
        <input aria-label="Peer IPv4" value={npPeer} onChange={e => setNpPeer(e.target.value)} placeholder="peer IPv4 (blank = any, port-only)" />
        <input aria-label="Port" value={npPort} onChange={e => setNpPort(e.target.value)} inputMode="numeric" placeholder="port (required if peer blank)" />
        <select aria-label="Protocol" value={npProto} onChange={e => setNpProto(e.target.value)}><option>TCP</option><option>UDP</option><option>ANY</option></select>
        <select aria-label="Direction" value={npDir} onChange={e => setNpDir(e.target.value)}><option>egress</option><option>ingress</option><option>both</option></select>
        <select aria-label="Action" value={npAction} onChange={e => setNpAction(e.target.value)}><option value="allow">allow</option><option value="deny">deny</option></select>
        <button className="primary" onClick={addNetPolRule}>Add rule</button>
      </div>
      <div className="chips">
        {(cfg?.netPolRules || []).length === 0 && <span>No v2 rules configured.</span>}
        {(cfg?.netPolRules || []).map((x: any) => (
          <button key={x.id} aria-label={`Remove rule ${x.id}`} onClick={() => delNetPolRule(x.id)}>
            {x.action} · {x.selector?.namespace || '*'}/{x.selector?.pod || '*'} → {x.peerIpv4 || 'any'}{x.port ? ':' + x.port : ''} {x.protocol} ({x.direction}) ×
          </button>
        ))}
      </div>

      <p className="eyebrow" style={{ marginTop: 18 }}>DEFAULT-DENY ACTIVATION</p>
      {cap((cfg?.netPolDefaultDenies?.length||0), caps?.limits?.netpolV2DefaultDeny)}
      <div className="ruleform">
        <input aria-label="Namespace" value={ddSelNS} onChange={e => setDdSelNS(e.target.value)} placeholder="namespace" />
        <input aria-label="Pod" value={ddSelPod} onChange={e => setDdSelPod(e.target.value)} placeholder="pod (optional)" />
        <input aria-label="Label selector" value={ddSelLabel} onChange={e => setDdSelLabel(e.target.value)} placeholder="label key=value (optional)" />
        <input aria-label="Default-deny lease duration" value={ddLease} onChange={e => setDdLease(e.target.value)} placeholder="lease, e.g. 5m (1m-60m)" title="1m–60m" />
        <button className="btn-secondary" onClick={() => planDefaultDeny(true)}>Plan activation</button>
      </div>
      {ddPlan && (
        <div className={ddPlan.risk === 'critical' || ddPlan.risk === 'high' ? 'warning' : ''} style={{ marginTop: 10, padding: 12 }}>
          <p><b>Risk: {String(ddPlan.risk).toUpperCase()}</b> · {ddPlan.matchedWorkloads} matched workload(s) · {ddPlan.workloadsWithAllowRule} with a covering allow rule</p>
          <button className="danger" onClick={applyDefaultDeny}>Confirm and activate</button>
          <button className="btn-secondary" onClick={() => setDdPlan(null)}>Cancel</button>
        </div>
      )}
      <div className="chips">
        {(cfg?.netPolDefaultDenies || []).length === 0 && <p className="empty-state">No workloads currently in default-deny posture.</p>}
        {(cfg?.netPolDefaultDenies || []).map((x: any, i: number) => (
          <button key={i} aria-label={`Deactivate default-deny for ${x.selector?.namespace || '*'}/${x.selector?.pod || '*'}`} onClick={() => deactivateDefaultDeny(x.selector)}>
            {x.selector?.namespace || '*'}/{x.selector?.pod || '*'} · until {x.enabledUntil ? new Date(x.enabledUntil).toLocaleTimeString() : '—'} ×
          </button>
        ))}
      </div>
    </section>

    <section className="card span3">
      <p className="eyebrow">CONNECTION-RATE LIMIT</p>
      <h3>New TCP connections per second, per workload</h3>
      <p>Checked only on TCP <code>connect()</code> attempts (UDP is connectionless and excluded). When more than one rule matches a workload, the strictest (lowest) cap applies.</p>
      {cap((cfg?.connRateLimits?.length||0), caps?.limits?.connRateLimit)}
      <div className="ruleform">
        <input aria-label="Namespace" value={crlSelNS} onChange={e => setCrlSelNS(e.target.value)} placeholder="namespace" />
        <input aria-label="Pod" value={crlSelPod} onChange={e => setCrlSelPod(e.target.value)} placeholder="pod (optional)" />
        <input aria-label="Label selector" value={crlSelLabel} onChange={e => setCrlSelLabel(e.target.value)} placeholder="label key=value (optional)" />
        <input aria-label="Connections per second" value={crlPerSecond} onChange={e => setCrlPerSecond(e.target.value)} inputMode="numeric" placeholder="connections/sec" />
        <button className="primary" onClick={addConnRateLimit}>Add limit</button>
      </div>
      <div className="chips">
        {(cfg?.connRateLimits || []).length === 0 && <span>No connection-rate limits configured.</span>}
        {(cfg?.connRateLimits || []).map((x: any) => (
          <button key={x.id} aria-label={`Remove limit ${x.id}`} onClick={() => delConnRateLimit(x.id)}>
            {x.selector?.namespace || '*'}/{x.selector?.pod || '*'} ≤ {x.perSecond}/s ×
          </button>
        ))}
      </div>
    </section>

    <Reveal className="section-divider">
      <h2>Diagnostics</h2>
      <p>Read-only: datapath capabilities, recent events, exact counters, and node coverage.</p>
    </Reveal>

    <section className="card"><p className="eyebrow">CAPABILITIES</p><h3>Datapath capabilities</h3><p>{caps?.observability?.length || 0} observability classes and {caps?.enforcement?.length || 0} enforcement classes are exposed by this release.</p><div className="chips">{(caps?.hooks || []).map((x: string) => <span key={x}>{x}</span>)}</div></section>

    <section className="card span3">
      <p className="eyebrow">STANDALONE EBPF EVENTS</p>
      <div className="eventtools"><span>Recent flow, DNS, socket and block events</span><select aria-label="Event type filter" value={eventType} onChange={e => setEventType(e.target.value)}><option value="all">all</option><option value="flow">flow</option><option value="dns">dns</option><option value="connect">connect</option><option value="block">block</option></select></div>
      {events.length === 0 && <p className="empty-state">No events observed yet.</p>}
      {events.length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>TIME / NODE</span><span>TYPE</span><span>PROCESS</span><span>FLOW / DNS</span><span>ACTION</span></div>
        {events.map((e: any, i) => {
          const proc = e.namespace || e.pod ? `${e.namespace}/${e.pod} · ${e.comm || 'process?'} pid=${e.pid || 0}` : (e.comm ? `${e.comm} pid=${e.pid} uid=${e.uid}` : '—');
          const flow = e.dnsQuery || `${e.sourceIp || '—'}:${e.sourcePort || 0} → ${e.destinationIp || '—'}:${e.destinationPort || 0} ${e.protocol}`;
          return <div className="datarow obs" key={i}><span>{new Date(e.observedAt).toLocaleTimeString()} · {e.node}</span><span>{e.direction} {e.hook} · {e.type}</span><span className="truncate" title={proc} aria-label={proc}>{proc}</span><span className="truncate" title={flow} aria-label={flow}>{flow}</span><span className={e.action === 'blocked' ? 'blocked' : ''}>{e.action}{e.reason ? ` · ${e.reason}` : ''}</span></div>;
        })}
      </div>}
    </section>
    <section className="card span3">
      <p className="eyebrow">EXACT FLOW COUNTERS</p>
      {stats.length === 0 && <p className="empty-state">No flow counters yet.</p>}
      {stats.length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>NODE / HOOK</span><span>DIR</span><span>FLOW</span><span>PROTO</span><span>PACKETS / BYTES / BLOCKED</span></div>
        {stats.map((s: any, i) => {
          const who = `${s.node} · ${s.hook}${s.namespace ? ` · ${s.namespace}/${s.pod}` : ''}`;
          return <div className="datarow obs" key={i}><span className="truncate" title={who} aria-label={who}>{who}</span><span>{s.direction}</span><span>{s.sourceIp || '—'}:{s.sourcePort || 0} → {s.destinationIp}:{s.port}</span><span>{s.protocol}</span><span className={s.blocked ? 'blocked' : ''}>{s.packets} / {s.bytes} / {s.blocked}</span></div>;
        })}
      </div>}
    </section>
    <section className="card span3">
      <p className="eyebrow">WORKLOAD TOPOLOGY</p>
      {topology.length === 0 && <p className="empty-state">No workload network topology observed yet.</p>}
      {topology.length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD</span><span>NODE</span><span>DESTINATION</span><span>PROTO</span><span>PACKETS / BYTES / BLOCKED</span></div>
        {topology.map((e:any, i:number) => {
          const who = `${e.namespace}/${e.pod}${e.workloadName ? ` · ${e.workloadKind}/${e.workloadName}` : ''}`;
          return <div className="datarow obs" key={i}><span className="truncate" title={who} aria-label={who}>{who}</span><span>{e.node}</span><span>{e.destination}</span><span>{e.protocol}</span><span className={e.blocked ? 'blocked' : ''}>{e.packets} / {e.bytes} / {e.blocked}</span></div>;
        })}
      </div>}
    </section>
    <section className="card span3">
      <p className="eyebrow">IPV6 DIAGNOSTICS</p>
      <h3>Extension-header &amp; fragmentation visibility</h3>
      {ipv6Diag?.summary && <p>{ipv6Diag.summary.packets||0} IPv6 packets · {ipv6Diag.summary.extHeaderPackets||0} with extension headers · {ipv6Diag.summary.fragmented||0} fragmented · {ipv6Diag.summary.nonFirstFragments||0} non-first fragments · {ipv6Diag.summary.chainTruncated||0} chain-truncated.</p>}
      {(!ipv6Diag?.nodes || ipv6Diag.nodes.length === 0) && <p className="empty-state">No IPv6 extension-header activity observed yet.</p>}
      {ipv6Diag?.nodes?.length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>NODE</span><span>DIRECTION / HOOK</span><span>PACKETS</span><span>EXT-HDR PKTS</span><span>FRAGMENTED / NON-FIRST / TRUNCATED</span></div>
        {ipv6Diag.nodes.flatMap((n: any) => (n.extHeaders || []).map((h: any, i: number) =>
          <div className="datarow obs" key={n.node + i}><span>{n.node}</span><span>{h.direction} / {h.hook}</span><span>{h.packets}</span><span>{h.extHeaderPackets}</span><span>{h.fragmented} / {h.nonFirstFragments} / {h.chainTruncated}</span></div>
        ))}
      </div>}
    </section>
    <section className="card span3">
      <p className="eyebrow">INTERFACE FLOW ATTRIBUTION</p>
      <h3>Per-interface packet/byte/blocked counters</h3>
      {ifaceFlows.length === 0 && <p className="empty-state">No per-interface flow attribution observed yet.</p>}
      {ifaceFlows.length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>NODE</span><span>INTERFACE</span><span>PACKETS / BYTES / BLOCKED</span><span>TOP DESTINATIONS</span></div>
        {ifaceFlows.flatMap((n: any) => (n.interfaces || []).map((ifc: any, i: number) =>
          <div className="datarow obs" key={n.node + i}><span>{n.node}</span><span>{ifc.interface}</span><span className={ifc.blocked ? 'blocked' : ''}>{ifc.packets} / {ifc.bytes} / {ifc.blocked}</span><span className="truncate">{(ifc.topDestinations || []).map((d: any) => `${d.name} (${d.count})`).join(', ') || '—'}</span></div>
        ))}
      </div>}
    </section>
    <section className="card span3"><p className="eyebrow">NODE COVERAGE</p><h3>Attached hooks</h3>{agents.map(a => <div className="agent wide" key={a.node}><b>{a.node}</b><span>{a.stale ? 'stale' : a.mode}</span><span>{(a.hooks || []).join(', ') || '—'}</span><small>{(a.workloads || []).length} workload cgroups · {a.scopeMode || 'all'} scope ({a.selectedCgroups || 0} selected) · {a.cgroupPath || 'no cgroup'} · interfaces: {(a.interfaces || []).join(', ') || 'cgroup-only'} · XDP: {(a.xdpInterfaces || []).join(', ') || 'off'}</small></div>)}</section>
    <DenyCensus />
    <LeaseClock />
    <WatchlistMatch />
  </div>;
}
