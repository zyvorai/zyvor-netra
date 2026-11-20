"""The brochure's diagrams, drawn in code so they stay editable and consistent."""
from svg import *


def cw(w, size=10.5):
    """Approximate characters that fit a card body of width w at font size `size`."""
    return max(8, int((w - 24) / (size * 0.53)))


# ---------------------------------------------------------------- 1. how eBPF works
def ebpf_pipeline():
    o = []
    o.append(rect(258, 12, 452, 208, WARM, LINE, 1.2, 14, "5 4"))
    o.append(text(272, 32, "LINUX KERNEL", 10, 700, DEEP, spacing=1.2))
    boxes = [
        (8, 55, 108, 84, "1  Sensor source", "one small C file per sensor: bpf/netra_*.c", GREY, LINE),
        (134, 55, 108, 84, "2  clang", "compiles to BPF bytecode. One object runs on x86_64 and arm64", GREY, LINE),
        (274, 46, 150, 102, "3  Verifier", "proves the program ends, stays in bounds and reads only allowed memory. An unsafe program is refused, never run", PALE, SIG),
        (440, 55, 84, 84, "4  JIT", "native machine code", GREY, LINE),
        (540, 46, 160, 102, "5  Hook", "attached where the kernel already has one: cgroup, tc/TCX, tracepoint, uprobe", PALE, SIG),
    ]
    for x, y, w, h, t, b, f, s in boxes:
        o.append(card(x, y, w, h, t, b, cw(w, 9.5), f, s, size=9.5, tsize=11.5))
    for x1, x2 in [(116, 134), (242, 274), (424, 440), (524, 540)]:
        o.append(line(x1, 97, x2, 97, SOFT, 1.6, None, True))
    # maps
    o.append(card(380, 168, 320, 42, "Maps and ring buffers", "", 40, "#fff", SIG, tsize=11.5))
    o.append(text(392, 200, "shared memory: counters, rules, packet samples", 9.5, 400, SOFT))
    o.append(line(620, 148, 620, 168, SIG, 1.6, None, True, "o"))
    # boundary
    o.append(line(0, 238, 720, 238, SIG, 1.3, "6 5"))
    o.append(text(8, 253, "USER SPACE", 10, 700, DEEP, spacing=1.2))
    o.append(card(258, 262, 200, 62, "netra-agent (Go)", "reads maps in batches, parses, reports every ~3 s", cw(200, 9.5), "#fff", INK, size=9.5, tsize=11.5))
    o.append(card(500, 262, 200, 62, "netrad (Go)", "API, dashboard, alerts, state, leases", cw(200, 9.5), "#fff", INK, size=9.5, tsize=11.5))
    o.append(line(458, 293, 500, 293, SOFT, 1.6, None, True))
    o.append(line(420, 262, 420, 212, SIG, 1.5, "4 3", True, "o"))
    o.append(text(428, 254, "reads", 9, 700, DEEP))
    # promises
    px = 8
    o.append(text(px, 285, "Why this is safe to run on a node", 11, 700, INK))
    for i, s in enumerate(["No kernel module to build or load", "No change to your applications", "Observing programs never change a verdict", "Only leased rules can drop, and they fail open"]):
        o.append(circle(px + 5, 302 + i * 17 - 3, 3.2, SIG))
        o.append(text(px + 16, 302 + i * 17, s, 9.5, 400, SOFT))
    return svg(720, 372, "".join(o), "How an eBPF sensor gets from source to a kernel hook and back to the agent")


# ---------------------------------------------------------------- 2. the stack
def stack():
    o = []
    cx, cwid = 210, 300
    items = [
        ("Network interface + driver", "RX / TX rings", "grey"),
        ("XDP: earliest ingress", "CIDR / port drop, DDoS shield on interfaces you list", "dash"),
        ("TC / TCX ingress + egress", "edge TCP handshake and RTT, packet capture: on interfaces you choose", "dash"),
        ("IP layer, netfilter, conntrack", "where most kernel drops are decided", "grey"),
        ("cgroup_skb ingress + egress", "flows, TCP / UDP / ICMP, workload identity, leased deny", "on"),
        ("Sockets: connect, sendmsg, sockops", "process and UID context, RTT, retransmits", "on"),
        ("Application", "nginx, redis, your service: SSL_write / SSL_read", "grey"),
    ]
    ys = []
    for i, (t, b, k) in enumerate(items):
        y = 26 + i * 76
        ys.append(y)
        fill = PALE if k in ("on", "dash") else GREY
        stroke = SIG if k in ("on", "dash") else LINE
        dash = "6 4" if k == "dash" else None
        o.append(rect(cx, y, cwid, 56, fill, stroke, 1.6, 9, dash))
        o.append(text(cx + 12, y + 21, t, 11.5, 700))
        ln, _ = lines(cx + 12, y + 37, b, cw(cwid, 9.5) + 4, 9.5, 12, 400, SOFT)
        o.append(ln)
        if i < len(items) - 1:
            o.append(line(cx + cwid / 2, y + 56, cx + cwid / 2, y + 76, SOFT, 1.4, None, True))
    o.append(text(cx + cwid / 2, 14, "a packet's path (receive, top to bottom)", 9.5, 400, SOFT, "middle", italic=True))
    # left: read from /proc and /sys
    o.append(rect(4, 150, 190, 150, "#fff", LINE, 1.2, 9, "3 4"))
    o.append(text(14, 172, "Read by the agent", 11.5, 700))
    o.append(text(14, 187, "from /proc and /sys (no BPF)", 9.5, 400, SOFT))
    for i, s in enumerate(["softnet_stat: backlog, drops", "interface statistics", "qdisc stats (netlink)", "sysctls (read-only)"]):
        o.append(circle(20, 208 + i * 22, 2.8, DEEP))
        ln, _ = lines(30, 212 + i * 22, s, 31, 9.5, 11, 400, INK)
        o.append(ln)
    o.append(line(194, 210, cx, 26 + 3 * 76 + 28, DEEP, 1.2, "3 3"))
    # right: taps
    taps = [
        (196, 96, "kfree_skb tracepoint", "drop reason counts, and per-connection attribution: tuple + reason + the kernel function that dropped it", False, ys[3] + 28),
        (300, 74, "cgroup_skb sampler", "Redis, SQL, Kafka, HTTP/2, gRPC operation counts (counts only)", True, ys[4] + 28),
        (382, 62, "TCP tracepoints", "retransmits, resets, state changes per flow", False, ys[5] + 20),
        (452, 52, "inet_diag (netlink)", "accept-queue depth per listener", False, ys[5] + 40),
        (512, 74, "OpenSSL uprobes", "HTTPS operation counts, allowlisted processes only", True, ys[6] + 28),
    ]
    tx, tw = 530, 186
    for y, h, t, b, opt, ay in taps:
        o.append(rect(tx, y, tw, h, "#fff", SIG, 1.5, 9, "6 4" if opt else None))
        o.append(text(tx + 10, y + 18, t, 11, 700))
        ln, _ = lines(tx + 10, y + 33, b, cw(tw, 9) + 2, 9, 11, 400, SOFT)
        o.append(ln)
        o.append(line(tx, y + h / 2, cx + cwid, ay, SIG, 1.2, "3 3"))
    # dropped packet marker
    o.append(circle(cx + cwid - 4, ys[3] + 2, 9, RED))
    o.append(text(cx + cwid - 4, ys[3] + 6, "x", 12, 700, "#fff", "middle"))
    # legend
    ly = 604
    o.append(rect(2, ly, 22, 12, PALE, SIG, 1.6, 3))
    o.append(text(28, ly + 10, "on by default (a sensor a node cannot run reports why and the agent carries on)", 9, 400, SOFT))
    o.append(rect(2, ly + 20, 22, 12, PALE, SIG, 1.6, 3, "5 3"))
    o.append(text(28, ly + 30, "opt-in: off until you enable it, or attached only to interfaces you list", 9, 400, SOFT))
    o.append(rect(2, ly + 40, 22, 12, GREY, LINE, 1.2, 3))
    o.append(text(28, ly + 50, "the Linux stack as it is: Netra observes it, it does not replace it", 9, 400, SOFT))
    return svg(720, 664, "".join(o), "Where Netra's sensors sit in the Linux network stack")


# ---------------------------------------------------------------- 3. the incident timeline
LANES = {"KERNEL": (SIG, 0), "AGENT": (INK, 46), "CONTROLLER": (BLUE, 92), "OPERATOR": (GREEN, 138)}


def timeline():
    o = []
    steps = [
        ("KERNEL", "0", "t = 0", "Packets start dying on worker-3", "A firewall rule, a full queue or a bad NIC ring: the kernel frees packets and fires kfree_skb."),
        ("AGENT", "1", "~3 s", "Sensors read it and report", "Drop reasons, the drop's tuple and kernel function, TCP retransmits, softnet and qdisc counters."),
        ("CONTROLLER", "2", "<= 30 s", "The alert poller flags a critical drop signal", "Softnet drops over 1000, a drop-rate spike, or a critical Congestion Map stage."),
        ("CONTROLLER", "3", "same poll", "Auto-capture gate (opt-in) freezes the context", "Per-node cooldown, at most 5 at once. Sets a filtered capture: TCP, up to 1000 packets/s, 60 s."),
        ("AGENT", "4", "~3 s", "The agent pulls the capture request", "Writes the filter into the capture map and opens the ring buffer. Nothing is copied until now."),
        ("KERNEL", "5", "immediately", "The TCX capture program copies matching packets", "Only frames that match protocol, host and port, under the packet-rate cap, into a 16 MB ring buffer."),
        ("CONTROLLER", "6", "seconds", "Frames stream to the controller and to disk", "Live view for the operator, and a classic .pcap plus a context JSON written to the artifact store."),
        ("OPERATOR", "7", "minutes", "Triage with the evidence in hand", "Download the PCAP and context, read Drop Explain, the Congestion Map, the drop attribution and TCP events."),
        ("OPERATOR", "8", "your call", "Contain with a leased deny, then it lets go", "Deny preview, confirm, enforce for a lease of 1 minute to 24 hours. It reverts on its own."),
    ]
    x0, w, h, gap = 24, 452, 62, 12
    o.append(text(8, 12, "", 8))
    # lane legend
    lx = 24
    for name, (col, _) in LANES.items():
        c, cwid = chip(lx, 2, name, col)
        o.append(c)
        lx += cwid + 8
    y = 34
    prev = None
    for lane, n, when, title, body in steps:
        col, off = LANES[lane]
        x = x0 + off
        o.append(rect(x, y, w, h, "#fff", col, 1.8, 10))
        o.append(rect(x, y, 6, h, col, "none", 0, 3))
        o.append(badge(x + 24, y + 22, n, col, 12))
        o.append(text(x + 44, y + 21, title, 11.5, 700))
        ln, _ = lines(x + 44, y + 37, body, 74, 9.5, 11.5, 400, SOFT)
        o.append(ln)
        o.append(text(716, y + 24, when, 9.5, 700, DEEP, "end"))
        if prev is not None:
            px, py = prev
            o.append(path(f"M {px + 24} {py + h} L {px + 24} {y - 6} L {x + 24} {y - 6} L {x + 24} {y}", SOFT, 1.3, None, True))
        prev = (x, y)
        y += h + gap
    return svg(720, y + 4, "".join(o), "Timeline of a traffic-drop incident across kernel, agent, controller and operator")


# ---------------------------------------------------------------- 4. detect
def detect():
    o = []
    o.append(text(0, 12, "SENSORS (the agent, about every 3 s)", 9.5, 700, DEEP, spacing=1))
    sensors = [
        ("softnet, NIC and qdisc counters", "backlog, time-squeeze, ring drops"),
        ("kfree_skb drop reasons", "named by the running kernel"),
        ("Drop attribution", "tuple + reason + kernel function"),
        ("TCP events", "retransmits and resets per flow"),
        ("Listen queues", "accept-queue pressure per service"),
    ]
    for i, (t, b) in enumerate(sensors):
        y = 22 + i * 44
        o.append(rect(0, y, 236, 38, "#fff", SIG, 1.4, 8))
        o.append(text(10, y + 16, t, 10.5, 700))
        o.append(text(10, y + 30, b, 9, 400, SOFT))
        o.append(line(236, y + 19, 280, 122, SIG, 1.1, "3 3"))
    o.append(rect(280, 76, 170, 92, PALE, SIG, 1.8, 10))
    o.append(text(365, 100, "netrad alert poller", 11.5, 700, INK, "middle"))
    o.append(text(365, 116, "every 30 s", 9.5, 700, DEEP, "middle"))
    ln, _ = lines(365, 133, "joins the reports, ranks findings, de-duplicates (5 min cooldown)", 26, 9, 11, 400, SOFT, "middle")
    o.append(ln)
    o.append(text(482, 12, "CRITICAL TRIGGERS", 9.5, 700, DEEP, spacing=1))
    trig = [
        ("Softnet drops", "a critical count of 1000 or more"),
        ("Drop-rate spike", "more than 3x the rolling average, at least 50 (critical from 200)"),
        ("Congestion Map", "any stack stage that turns critical"),
    ]
    for i, (t, b) in enumerate(trig):
        y = 22 + i * 62
        o.append(rect(482, y, 238, 54, "#fff", LINE, 1.4, 8))
        o.append(text(494, y + 19, t, 11, 700))
        ln, _ = lines(494, y + 34, b, 40, 9, 11, 400, SOFT)
        o.append(ln)
        o.append(line(450, 122, 482, y + 27, SIG, 1.3, None, True, "o"))
    o.append(text(482, 214, "Warning-level signals never start a capture.", 9, 400, SOFT, italic=True))
    # example attribution card
    y = 246
    o.append(rect(0, y, 720, 84, "#171614", "#171614", 0, 10))
    o.append(text(14, y + 20, "DROP ATTRIBUTION", 9, 700, SIG, spacing=1.2))
    o.append(text(590, y + 20, "illustrative", 9, 400, "#8b847a", "start", italic=True))
    rows = [
        ("NETFILTER_DROP", "nft_do_chain [nf_tables]", "tcp 10.0.0.5:41722 -> 10.0.0.9:443", "1,204"),
        ("NO_SOCKET", "__udp4_lib_rcv", "udp 10.0.0.7:5353 -> 10.0.0.9:9", "86"),
    ]
    for i, (r, f, t, n) in enumerate(rows):
        yy = y + 42 + i * 19
        o.append(text(14, yy, r, 10, 700, "#ff8a4d", mono=True))
        o.append(text(150, yy, f, 10, 400, "#e9e2d8", mono=True))
        o.append(text(330, yy, t, 10, 400, "#e9e2d8", mono=True))
        o.append(text(706, yy, n, 10, 700, "#fff", "end", mono=True))
    return svg(720, 336, "".join(o), "What the sensors see, and what turns it into a critical alert")


# ---------------------------------------------------------------- 5. capture
def capture():
    o = []
    o.append(chip(0, 0, "eBPF BACKEND (default)", SIG)[0])
    row1 = [
        ("Packets", "on the interfaces you choose"),
        ("TCX program", "ingress and egress. One map lookup while idle. Never changes a verdict"),
        ("capture_spec", "protocol, host, port, snaplen, expiry: a filter is required"),
        ("capture_rate", "packets-per-second cap, checked before anything is copied"),
        ("Ring buffer", "16 MB, kernel to agent. Frames up to 9000 bytes"),
    ]
    xs = [0, 146, 292, 438, 584]
    for (t, b), x in zip(row1, xs):
        o.append(card(x, 26, 132, 104, t, b, cw(132, 9), PALE if t != "Packets" else GREY, SIG if t != "Packets" else LINE, size=9, tsize=11))
    for x in xs[:-1]:
        o.append(line(x + 132, 78, x + 146, 78, SIG, 1.6, None, True, "o"))
    # agent -> controller -> outputs
    o.append(card(584, 160, 132, 60, "netra-agent", "reads the ring buffer", cw(132, 9), "#fff", INK, size=9, tsize=11))
    o.append(line(650, 130, 650, 160, SIG, 1.6, None, True, "o"))
    o.append(card(400, 160, 150, 60, "netrad relay", "WebSocket, frames passed on unchanged", cw(150, 9), "#fff", INK, size=9, tsize=11))
    o.append(line(584, 190, 550, 190, SOFT, 1.6, None, True))
    o.append(card(120, 258, 200, 84, "Browser", "live view, packet decode, filter, export as .pcap, JSON or CSV", cw(200, 9.5), "#fff", INK, size=9.5, tsize=11.5))
    o.append(card(340, 258, 230, 84, "Auto-capture store", "on the controller: a classic .pcap plus a context.json, kept under size and count caps", cw(230, 9.5), "#fff", INK, size=9.5, tsize=11.5))
    o.append(path("M 475 220 L 475 240 L 220 240 L 220 258", SOFT, 1.4, None, True))
    o.append(path("M 475 220 L 475 240 L 455 240 L 455 258", SOFT, 1.4, None, True))
    # af_packet
    o.append(chip(0, 366, "AF_PACKET BACKEND (needs only CAP_NET_RAW)", DEEP)[0])
    o.append(card(0, 392, 250, 58, "Raw socket per interface", "a classic-BPF filter in the kernel", cw(250, 9.5), GREY, LINE, size=9.5, tsize=11.5))
    o.append(card(270, 392, 190, 58, "Userspace rate limit", "then the same frame format", cw(190, 9.5), GREY, LINE, size=9.5, tsize=11.5))
    o.append(line(250, 421, 270, 421, SOFT, 1.6, None, True))
    o.append(path("M 460 421 L 650 421 L 650 222", SOFT, 1.4, "5 4", True))
    o.append(text(470, 414, "same agent, same WebSocket, same .pcap", 9, 400, SOFT, italic=True))
    o.append(text(0, 146, "", 8))
    return svg(720, 458, "".join(o), "How packets get from the wire to a pcap: the eBPF and AF_PACKET paths")


# ---------------------------------------------------------------- 6. lease
def lease():
    o = []
    st = [
        ("OBSERVE", "default", "Nothing is dropped. Rules can be staged and inspected.", GREY, LINE),
        ("PLAN", "preview and confirm", "The deny preview shows which observed traffic the rule would have matched. It applies nothing.", "#fff", LINE),
        ("ENFORCE", "leased: 1 min to 24 h", "The deny drops packets. The default lease is 15 minutes.", PALE, SIG),
        ("REVERT", "fail open", "The lease ends and traffic flows again. Rules stay listed.", GREY, LINE),
    ]
    for i, (t, sub, b, f, s) in enumerate(st):
        x = i * 182
        o.append(rect(x, 0, 160, 96, f, s, 1.8, 10))
        o.append(text(x + 12, 22, t, 12, 700, DEEP if t == "ENFORCE" else INK))
        o.append(text(x + 12, 37, sub, 9, 700, SOFT))
        ln, _ = lines(x + 12, 53, b, 26, 9, 11, 400, SOFT)
        o.append(ln)
        if i < 3:
            o.append(line(x + 160, 48, x + 182, 48, SOFT, 1.6, None, True))
    # timeline bar
    y = 138
    o.append(text(0, y - 12, "TIME", 9, 700, DEEP, spacing=1.2))
    o.append(rect(0, y, 720, 22, GREY, GREY, 0, 6))
    o.append(rect(190, y, 330, 22, SIG, SIG, 0, 6))
    o.append(text(355, y + 15, "deny is dropping packets", 10.5, 700, "#fff", "middle"))
    o.append(text(95, y + 15, "observe", 10, 400, SOFT, "middle"))
    o.append(text(620, y + 15, "observe again: rules still listed", 10, 400, SOFT, "middle"))
    o.append(line(190, y + 22, 190, y + 40, INK, 1.2))
    o.append(text(190, y + 54, "operator confirms: lease granted", 9.5, 700, INK, "middle"))
    o.append(line(520, y + 22, 520, y + 40, INK, 1.2))
    o.append(text(520, y + 54, "lease expires: the node lets go on its own", 9.5, 700, INK, "middle"))
    # fail-open causes
    y2 = 232
    o.append(text(0, y2, "IT ALSO LETS GO WHEN", 9.5, 700, DEEP, spacing=1.2))
    causes = [
        ("The lease expires", "checked on the node itself, even if the controller is gone"),
        ("The controller is lost", "no refresh for NETRA_FAILSAFE_AFTER (60 s by default)"),
        ("The controller restarts", "an old lease is never resurrected from disk"),
        ("HA leadership changes", "the new leader starts in observe"),
    ]
    for i, (t, b) in enumerate(causes):
        x = i * 182
        o.append(rect(x, y2 + 12, 168, 64, "#fff", LINE, 1.4, 9))
        o.append(text(x + 10, y2 + 30, t, 10.5, 700))
        ln, _ = lines(x + 10, y2 + 44, b, 29, 8.5, 10.5, 400, SOFT)
        o.append(ln)
    return svg(720, 324, "".join(o), "The enforcement lease: observe, plan, enforce, revert")


# ---------------------------------------------------------------- 7. sampling
def sampling():
    o = []
    o.append(chip(0, 0, "HTTPS (opt-in, allowlisted processes)", SIG)[0])
    o.append(card(0, 26, 132, 84, "Application", "hands plaintext to SSL_write and SSL_read", cw(132, 9.5), GREY, LINE, size=9.5, tsize=11))
    o.append(card(152, 26, 168, 84, "Uprobe in libssl", "the kernel checks the process name against your list first. Others are never read", cw(168, 9), PALE, SIG, size=9, tsize=11))
    o.append(card(340, 26, 120, 84, "Ring buffer", "at most 128 bytes per call", cw(120, 9.5), "#fff", SIG, size=9.5, tsize=11))
    o.append(rect(480, 26, 240, 84, "#fff", INK, 2, 10))
    o.append(text(492, 46, "netra-agent parser", 11, 700))
    ln, _ = lines(492, 62, "keeps an operation name and a coarse outcome (GET, 200, 5xx). The bytes are dropped in memory", 40, 9, 11, 400, SOFT)
    o.append(ln)
    for x1, x2 in [(132, 152), (320, 340), (460, 480)]:
        o.append(line(x1, 68, x2, 68, SIG, 1.6, None, True, "o"))
    o.append(chip(0, 138, "CLEARTEXT PROTOCOLS (opt-in)", DEEP)[0])
    o.append(card(0, 164, 300, 62, "cgroup_skb sampler on the ports you configure", "Redis, PostgreSQL, MySQL, Kafka, HTTP/1, HTTP/2, gRPC. Rate-limited per flow", cw(300, 9), PALE, SIG, "5 3", size=9, tsize=10.5))
    o.append(path("M 300 195 L 400 195 L 400 110", SIG, 1.5, None, True, marker="o"))
    o.append(card(480, 136, 240, 56, "Counts, per role", "issued (your workloads) or served (your services)", cw(240, 9) + 2, "#fff", LINE, size=9, tsize=11))
    o.append(line(600, 110, 600, 136, SOFT, 1.6, None, True))
    o.append(card(480, 210, 240, 46, "API and /metrics", "counts only: never keys, SQL, paths or bodies", cw(240, 9) + 2, "#fff", LINE, size=9, tsize=11))
    o.append(line(600, 192, 600, 210, SOFT, 1.6, None, True))
    o.append(rect(0, 266, 720, 30, "#fff1f0", RED, 1.2, 8))
    o.append(text(360, 286, "Plaintext never leaves the agent's memory. The kernel counts what it sampled and what it skipped, so the counts can be scaled honestly.", 9.5, 700, RED, "middle"))
    return svg(720, 302, "".join(o), "How sampled protocol and TLS plaintext observation stays inside the agent")


# ---------------------------------------------------------------- 8. access
def access():
    o = []
    o.append(text(0, 12, "WHO CAN DO WHAT", 9.5, 700, DEEP, spacing=1.2))
    lad = [
        ("admin", "fleet mode and scope, apply and roll back policy, toggle features", 0),
        ("operator", "change rules, baselines and capture; download packet captures", 1),
        ("viewer", "read everything, run read-only plans and previews", 2),
    ]
    for t, b, i in lad:
        x, y = 0 + (2 - i) * 22, 24 + (2 - i) * 0
    y0 = 24
    for k, (t, b, i) in enumerate(lad):
        x = i * 22
        y = y0 + k * 64
        o.append(rect(x, y, 330 - x, 56, PALE if t == "admin" else "#fff", SIG if t == "admin" else LINE, 1.6, 9))
        o.append(text(x + 12, y + 21, t, 12, 700, DEEP if t == "admin" else INK))
        ln, _ = lines(x + 12, y + 37, b, 50, 9, 11, 400, SOFT)
        o.append(ln)
    o.append(text(0, 232, "SIGN-IN", 9.5, 700, DEEP, spacing=1.2))
    for i, s in enumerate(["OIDC login through your identity provider", "NETRA_API_KEY: always admin (break-glass)", "optional token on /metrics"]):
        o.append(circle(6, 250 + i * 17 - 3, 3, SIG))
        o.append(text(16, 250 + i * 17, s, 9.5, 400, INK))
    o.append(text(380, 12, "AGENT TO CONTROLLER", 9.5, 700, DEEP, spacing=1.2))
    o.append(card(380, 30, 120, 60, "netra-agent", "", 10, "#fff", INK, tsize=11.5))
    o.append(card(600, 30, 120, 60, "netrad", "", 10, "#fff", INK, tsize=11.5))
    o.append(line(500, 52, 600, 52, SIG, 2, None, True, "o"))
    o.append(line(600, 70, 500, 70, SIG, 2, None, True, "o"))
    o.append(text(550, 44, "TLS", 9.5, 700, DEEP, "middle"))
    o.append(text(550, 86, "+ client certificate", 8.5, 400, SOFT, "middle"))
    o.append(text(380, 126, "Stage it: off, optional, required", 10.5, 700))
    xs = [380, 480, 580]
    for x, (t, b) in zip(xs, [("off", "as today"), ("optional", "verified if offered, recorded per agent"), ("required", "agent key AND certificate")]):
        o.append(rect(x, 138, 96, 76, PALE if t == "required" else "#fff", SIG if t == "required" else LINE, 1.5, 9))
        o.append(text(x + 10, 158, t, 11, 700))
        ln, _ = lines(x + 10, 173, b, 15, 8.5, 10.5, 400, SOFT)
        o.append(ln)
    o.append(line(476, 176, 480, 176, SOFT, 1.4, None, True))
    o.append(line(576, 176, 580, 176, SOFT, 1.4, None, True))
    o.append(rect(380, 230, 340, 60, "#fff", LINE, 1.2, 9, "4 3"))
    ln, _ = lines(392, 250, "One certificate is shared by every agent: it proves it is an agent, not which node. It is a second factor a leaked agent key cannot satisfy. People are never asked for a certificate.", 62, 9, 11, 400, SOFT)
    o.append(ln)
    return svg(720, 300, "".join(o), "Roles and login, and staged mutual TLS between agent and controller")


# ---------------------------------------------------------------- 9. deploy / HA
def deploy_ha():
    o = []
    o.append(text(0, 12, "UPGRADE AND ROLLBACK", 9.5, 700, DEEP, spacing=1.2))
    o.append(card(0, 24, 130, 70, "Previous release", "", 10, GREY, LINE, tsize=11))
    o.append(card(158, 24, 172, 70, "helm upgrade", "--reset-then-reuse-values", cw(172, 9), PALE, SIG, size=9, tsize=11))
    o.append(line(130, 59, 158, 59, SOFT, 1.6, None, True))
    o.append(card(0, 130, 200, 70, "This release + agent DaemonSet", "controller rolls, the agent starts and reports", cw(200, 9), "#fff", INK, size=9, tsize=10.5))
    o.append(path("M 244 94 L 244 112 L 100 112 L 100 130", SOFT, 1.6, None, True))
    o.append(path("M 200 178 L 330 178 L 330 60", SIG, 1.4, "5 4", True, marker="o"))
    o.append(text(212, 194, "helm rollback", 9.5, 700, DEEP))
    for i, s in enumerate(["rules, baseline and API key survive", "a pod restart keeps the state", "mode returns to observe after a restart"]):
        o.append(circle(6, 226 + i * 17 - 3, 3, SIG))
        o.append(text(16, 226 + i * 17, s, 9.5, 400, INK))
    o.append(text(380, 12, "HIGH AVAILABILITY", 9.5, 700, DEEP, spacing=1.2))
    o.append(rect(380, 24, 140, 70, "#eaf6ef", GREEN, 1.8, 10))
    o.append(text(392, 44, "Leader", 11.5, 700, GREEN))
    o.append(text(392, 60, "Ready, serves the API", 9, 400, SOFT))
    o.append(text(392, 74, "holds the Lease", 9, 400, SOFT))
    o.append(rect(580, 24, 140, 70, GREY, LINE, 1.6, 10))
    o.append(text(592, 44, "Standby", 11.5, 700))
    o.append(text(592, 60, "alive, refuses the API", 9, 400, SOFT))
    o.append(text(592, 74, "takes over on failure", 9, 400, SOFT))
    o.append(rect(380, 134, 340, 50, "#fff", SIG, 1.6, 10))
    o.append(text(550, 156, "Shared volume + exclusive state lock", 11, 700, INK, "middle"))
    o.append(text(550, 172, "rules, audit, baselines and PCAP artifacts survive a failover", 9, 400, SOFT, "middle"))
    o.append(line(450, 94, 450, 134, SOFT, 1.4, None, True))
    o.append(line(650, 94, 650, 134, SOFT, 1.4, "4 3", True))
    o.append(text(380, 216, "On a crash or a graceful delete the standby is promoted. Enforcement", 9.5, 400, SOFT))
    o.append(text(380, 230, "restarts in observe: an old lease is never carried across.", 9.5, 400, SOFT))
    return svg(720, 262, "".join(o), "Upgrade and rollback flow, and active/passive high availability")


# ---------------------------------------------------------------- 10. how it is tested
def testing():
    o = []
    tiles = [
        ("EVERY PUSH", "unit tests and the race detector, gofmt, shellcheck, lint, a vulnerability scan, Helm rendering", GREY, LINE),
        ("REAL CONTROLLER", "MCP, persistence, alert and export sinks, OIDC, mutual TLS, every netractl command", "#fff", LINE),
        ("REAL KERNEL", "enforcement, packet capture and the sensors on a veth pair: x86_64 and arm64, Linux 6.8 and 6.17", PALE, SIG),
        ("REAL CLUSTER", "install, upgrade from the previous release, rollback, the plain manifests, HA failover", PALE, SIG),
        ("REAL BROWSER", "sign-in, all dashboard pages against a live controller, firewall actions", "#fff", LINE),
        ("EVERY NIGHT", "the whole suite under the race detector, fuzzing, a kernel matrix, multi-arch images", GREY, LINE),
    ]
    for i, (t, b, f, s) in enumerate(tiles):
        x, y = (i % 3) * 244, (i // 3) * 118
        o.append(rect(x, y, 232, 106, f, s, 1.6, 10))
        o.append(text(x + 14, y + 24, t, 10.5, 700, DEEP, spacing=1))
        ln, _ = lines(x + 14, y + 44, b, 38, 10, 12.5, 400, INK)
        o.append(ln)
    o.append(rect(0, 246, 720, 44, INK, INK, 0, 10))
    o.append(text(360, 273, "Each check is proven by breaking what it tests: the job must then fail.", 12, 700, "#fff", "middle"))
    return svg(720, 296, "".join(o), "What is tested for real, and how often")


ALL = {
    "ebpf_pipeline": ebpf_pipeline,
    "stack": stack,
    "timeline": timeline,
    "detect": detect,
    "capture": capture,
    "lease": lease,
    "sampling": sampling,
    "access": access,
    "deploy_ha": deploy_ha,
    "testing": testing,
}
