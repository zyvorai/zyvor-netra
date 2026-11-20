export function endpointName(x:any){if(!x)return 'world';const pod=x.podName||x.workloads?.[0]?.name;return [x.namespace,pod].filter(Boolean).join('/')||x.identity?.toString()||'world'}
export function tuple(f:any){const ip=f?.IP||f?.ip||{};const l4=f?.l4||{};const tcp=l4.TCP||l4.tcp;const udp=l4.UDP||l4.udp;const p=tcp||udp||{};return `${ip.source||'?'}:${p.sourcePort||''} → ${ip.destination||'?'}:${p.destinationPort||''}`}
// verdictClass maps a Hubble/Cilium flow verdict to a .flowrow-scoped color
// class (see styles.css's .flowrow .verdict-* rules) — same "class family
// keyed off an enum" shape as Capture's PROTO_CLASS/dir-* classes.
export function verdictClass(verdict?:string):string{const v=(verdict||'').toUpperCase();if(v==='FORWARDED')return 'verdict-forwarded';if(v==='DROPPED')return 'verdict-dropped';if(v==='AUDIT'||v==='ERROR')return 'verdict-audit';return ''}
// protoNameClass is protoClass's text-keyed sibling for pages (Traffic.tsx)
// whose API already returns a protocol name string rather than Capture's
// numeric IP protocol field.
export function protoNameClass(name?:string):string{const p=(name||'').toUpperCase();if(p==='TCP')return 'proto-tcp';if(p==='UDP')return 'proto-udp';if(p==='ICMPV6')return 'proto-icmpv6';if(p==='ICMP')return 'proto-icmp';return 'proto-other'}
