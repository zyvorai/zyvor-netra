// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
// Best-effort L7/DNS byte-level parsers shared by the Netra eBPF datapath
// and its host-side parser tests. They never reassemble TCP streams and
// only report what's visible in a single skb.

#ifndef NETRA_L7_H
#define NETRA_L7_H

static __inline__ __attribute__((always_inline)) unsigned char
netra_l7_lower_ascii(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return c + ('a' - 'A');
    return c;
}

static __inline__ __attribute__((always_inline)) int
netra_l7_hostname_char(unsigned char c)
{
    c = netra_l7_lower_ascii(c);
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
}

// netra_l7_http_method reads the request method at the start of the first
// n payload bytes in p.
static __inline__ __attribute__((always_inline)) int
netra_l7_http_method(const unsigned char *p, int n, char out[8])
{
    if (n < 8) return 0;
    if (p[0]=='G'&&p[1]=='E'&&p[2]=='T'&&p[3]==' ') { __builtin_memcpy(out,"GET",4); return 3; }
    if (p[0]=='P'&&p[1]=='O'&&p[2]=='S'&&p[3]=='T'&&p[4]==' ') { __builtin_memcpy(out,"POST",5); return 4; }
    if (p[0]=='P'&&p[1]=='U'&&p[2]=='T'&&p[3]==' ') { __builtin_memcpy(out,"PUT",4); return 3; }
    if (p[0]=='H'&&p[1]=='E'&&p[2]=='A'&&p[3]=='D'&&p[4]==' ') { __builtin_memcpy(out,"HEAD",5); return 4; }
    if (p[0]=='P'&&p[1]=='A'&&p[2]=='T'&&p[3]=='C'&&p[4]=='H'&&p[5]==' ') { __builtin_memcpy(out,"PATCH",6); return 5; }
    if (p[0]=='D'&&p[1]=='E'&&p[2]=='L'&&p[3]=='E'&&p[4]=='T'&&p[5]=='E'&&p[6]==' ') { __builtin_memcpy(out,"DELETE",7); return 6; }
    if (p[0]=='O'&&p[1]=='P'&&p[2]=='T'&&p[3]=='I'&&p[4]=='O'&&p[5]=='N'&&p[6]=='S'&&p[7]==' ') { __builtin_memcpy(out,"OPTIONS",8); return 7; }
    return 0;
}

// netra_l7_http_status reads an HTTP/1 status line that begins the skb.
// "HTTP/1.1 200" and "HTTP/1.0 204" sit at a fixed offset. This is not a
// scan, not TCP reassembly, and not HTTP/2 or HTTP/3. Returns 0 when the
// prefix is absent or the code is not 100-599.
static __inline__ __attribute__((always_inline)) int
netra_l7_http_status(void *payload, void *data_end)
{
    unsigned char *p = payload;
    if ((void *)(p + 12) > data_end) return 0;
    if (p[0] != 'H' || p[1] != 'T' || p[2] != 'T' || p[3] != 'P' || p[4] != '/' || p[5] != '1' || p[6] != '.' || p[8] != ' ') return 0;
    if (p[7] < '0' || p[7] > '9') return 0;
    if (p[9] < '0' || p[9] > '9' || p[10] < '0' || p[10] > '9' || p[11] < '0' || p[11] > '9') return 0;
    if ((void *)(p + 13) <= data_end && p[12] != ' ' && p[12] != '\r') return 0;
    int code = (p[9] - '0') * 100 + (p[10] - '0') * 10 + (p[11] - '0');
    if (code < 100 || code > 599) return 0;
    return code;
}

// The DNS, SNI and Host parsers read a copy of the payload held in a
// struct netra_l7_work and walk it with callbacks driven by bpf_loop. The
// verifier checks each callback once with an unknown index instead of every
// step with a known one; open-coded loops of this shape hit the fixed 8192
// pending-branch limit ("sequence of 8193 jumps is too complex") or the
// 1M-instruction budget on 6.8+ kernels. In the datapath the work area lives
// in a per-CPU map, so parser state read back from it is unknown to the
// verifier too and never multiplies the states it explores.
//
// A step reads at most NETRA_L7_LOOKAHEAD bytes past a position below
// NETRA_L7_SCAN, so masked indexes keep every read inside buf; bytes past
// the n actually copied are rejected logically, never relied on.
#define NETRA_L7_SCAN 512
#define NETRA_L7_LOOKAHEAD 128
#define NETRA_L7_BUF_LEN (NETRA_L7_SCAN + NETRA_L7_LOOKAHEAD)
#define NETRA_L7_SNI_MIN_POS 43
#define NETRA_L7_DNS_HDR 12
#define NETRA_L7_DNS_MAX_WIRE 96

struct netra_l7_work {
    unsigned char buf[NETRA_L7_BUF_LEN];
    char out[96];
    int n;         /* payload bytes copied into buf */
    int result;
    int pos;       /* first byte of the value being copied */
    int len;       /* SNI name length */
    int oi;        /* bytes written to out */
    int remaining; /* DNS label bytes left */
    int bad;
};

/* bpf_loop takes its context on the stack; the work area is map memory. */
struct netra_l7_ctx {
    struct netra_l7_work *wk;
};

#ifdef NETRA_BPF
static long (*netra_l7_bpf_loop)(unsigned int nr_loops, void *callback_fn, void *callback_ctx,
                                 unsigned long long flags) = (void *)BPF_FUNC_loop;
#define NETRA_L7_LOOP(nr, cb, w) do { \
        struct netra_l7_ctx netra_l7_c = { .wk = (w) }; \
        netra_l7_bpf_loop((nr), (void *)(cb), &netra_l7_c, 0); \
    } while (0)
#else
static __inline__ void
netra_l7_host_loop(unsigned int nr, long (*cb)(unsigned long long, void *), void *ctx)
{
    for (unsigned int i = 0; i < nr; i++)
        if (cb(i, ctx)) return;
}
#define NETRA_L7_LOOP(nr, cb, w) do { \
        struct netra_l7_ctx netra_l7_c = { .wk = (w) }; \
        netra_l7_host_loop((nr), (cb), &netra_l7_c); \
    } while (0)
#endif

#define NETRA_L7_WORK(ctx) (((struct netra_l7_ctx *)(ctx))->wk)

static long
netra_l7_dns_qname_step(unsigned long long idx, void *ctx)
{
    struct netra_l7_work *w = NETRA_L7_WORK(ctx);
    unsigned long long pos = NETRA_L7_DNS_HDR + (idx & 127);
    unsigned long long oi = (unsigned int)w->oi;
    if (pos + 1 > (unsigned int)w->n || oi >= 95) return 1;
    unsigned char c = w->buf[pos];
    if (w->remaining == 0) {
        if (c == 0 || c > 63) return 1;
        if (oi > 0) w->out[oi++] = '.';
        w->remaining = c;
    } else {
        w->out[oi++] = (char)netra_l7_lower_ascii(c);
        w->remaining--;
    }
    w->oi = (int)oi;
    return 0;
}

// dns_qname decodes the plain-DNS question name after the 12-byte header
// of w->buf, lowercased, into out. Compression pointers end the name.
// Returns the decoded length, or 0 if no valid name could be read; a
// truncated name returns what was decoded.
static __inline__ __attribute__((always_inline)) int
netra_l7_dns_qname(struct netra_l7_work *w, char out[96])
{
    if (w->n < NETRA_L7_DNS_HDR) return 0;
    __builtin_memset(w->out, 0, sizeof(w->out));
    w->oi = 0;
    w->remaining = 0;
    NETRA_L7_LOOP(NETRA_L7_DNS_MAX_WIRE, netra_l7_dns_qname_step, w);
    unsigned int oi = (unsigned int)w->oi;
    if (oi > 95) return 0;
    __builtin_memcpy(out, w->out, sizeof(w->out));
    return (int)oi;
}

static long
netra_l7_dns_qtype_step(unsigned long long idx, void *ctx)
{
    struct netra_l7_work *w = NETRA_L7_WORK(ctx);
    const unsigned char *p = w->buf;
    unsigned long long pos = NETRA_L7_DNS_HDR + (idx & 127);
    unsigned long long n = (unsigned int)w->n;
    if (pos + 1 > n) return 1;
    unsigned char c = p[pos];
    if (w->remaining) { w->remaining--; return 0; }
    if (c == 0) {
        if (pos + 5 <= n && p[pos + 3] == 0 && p[pos + 4] == 1)
            w->result = ((int)p[pos + 1] << 8) | p[pos + 2];
        return 1;
    }
    if (c > 63) return 1;
    w->remaining = c;
    return 0;
}

// Read QTYPE only from a complete, uncompressed first question. Unknown,
// oversized, compressed or truncated questions return zero; never guess.
static __inline__ __attribute__((always_inline)) unsigned short
netra_l7_dns_qtype(struct netra_l7_work *w)
{
    if (w->n < NETRA_L7_DNS_HDR || w->buf[4] != 0 || w->buf[5] != 1) return 0;
    w->result = 0;
    w->remaining = 0;
    NETRA_L7_LOOP(NETRA_L7_DNS_MAX_WIRE, netra_l7_dns_qtype_step, w);
    return (unsigned short)w->result;
}

static long
netra_l7_tls_sni_copy_step(unsigned long long idx, void *ctx)
{
    struct netra_l7_work *w = NETRA_L7_WORK(ctx);
    unsigned long long j = idx;
    unsigned long long base = (unsigned int)w->pos;
    if (j >= 95 || j >= (unsigned int)w->len || base > NETRA_L7_SCAN + 9) return 1;
    unsigned char ch = w->buf[base + j];
    if (!netra_l7_hostname_char(ch)) { w->bad = 1; return 1; }
    w->out[j] = (char)netra_l7_lower_ascii(ch);
    return 0;
}

// netra_l7_tls_sni_at tests for a server_name extension header at buf[i].
// Returns the name length on a match, 0 to keep searching, -1 to stop.
static __inline__ __attribute__((always_inline)) int
netra_l7_tls_sni_at(struct netra_l7_work *w, unsigned long long i)
{
    const unsigned char *p = w->buf;
    /* Need header bytes i..i+8 and up to 95 name bytes starting at i+9. */
    if (i + 9 + 95 > (unsigned int)w->n) return -1;
    if (p[i] != 0 || p[i + 1] != 0 || p[i + 6] != 0) return 0;
    unsigned short ext_len = ((unsigned short)p[i + 2] << 8) | p[i + 3];
    unsigned short list_len = ((unsigned short)p[i + 4] << 8) | p[i + 5];
    unsigned short name_len = ((unsigned short)p[i + 7] << 8) | p[i + 8];
    if (!name_len || name_len > 95 || ext_len < (unsigned short)(5 + name_len) || list_len < (unsigned short)(3 + name_len)) return 0;
    w->pos = (int)(i + 9);
    w->len = name_len;
    w->bad = 0;
    NETRA_L7_LOOP(95, netra_l7_tls_sni_copy_step, w);
    if (w->bad) { __builtin_memset(w->out, 0, sizeof(w->out)); return 0; }
    unsigned int len = (unsigned int)w->len;
    if (len > 95) return 0;
    w->out[len] = 0;
    return (int)len;
}

static long
netra_l7_tls_sni_step(unsigned long long idx, void *ctx)
{
    struct netra_l7_work *w = NETRA_L7_WORK(ctx);
    unsigned long long i = idx & (NETRA_L7_SCAN - 1);
    if (i < NETRA_L7_SNI_MIN_POS) return 0;
    int r = netra_l7_tls_sni_at(w, i);
    if (r == 0) return 0;
    w->result = r > 0 ? r : 0;
    return 1;
}

// tls_sni is a best-effort TLS ClientHello SNI parser over w->buf. It does
// not reassemble TCP streams and therefore only reports an SNI present in
// this skb.
static __inline__ __attribute__((always_inline)) int
netra_l7_tls_sni(struct netra_l7_work *w, char out[96])
{
    if (w->n < 9 || w->buf[0] != 0x16 || w->buf[5] != 0x01) return 0;
    __builtin_memset(w->out, 0, sizeof(w->out));
    w->result = 0;
    NETRA_L7_LOOP(NETRA_L7_SCAN, netra_l7_tls_sni_step, w);
    int r = w->result;
    if (r <= 0) return 0;
    __builtin_memcpy(out, w->out, sizeof(w->out));
    return r;
}

static long
netra_l7_http_host_copy_step(unsigned long long idx, void *ctx)
{
    struct netra_l7_work *w = NETRA_L7_WORK(ctx);
    unsigned long long j = idx;
    unsigned long long base = (unsigned int)w->pos;
    if (j >= 95 || base > NETRA_L7_SCAN + 13) return 1;
    unsigned long long pos = base + j;
    if (pos + 1 > (unsigned int)w->n) return 1;
    unsigned char ch = w->buf[pos];
    if (ch == '\r' || ch == '\n') return 1;
    if (ch < 0x21 || ch > 0x7e) { w->bad = 1; return 1; }
    w->out[j] = (char)netra_l7_lower_ascii(ch);
    w->oi = (int)j + 1;
    return 0;
}

// netra_l7_http_host_at tests for a "Host:" header starting a line at
// buf[i] and copies its value. Returns the value length on a match, 0 to
// keep searching, -1 to stop (the payload ran out or the value is malformed).
static __inline__ __attribute__((always_inline)) int
netra_l7_http_host_at(struct netra_l7_work *w, unsigned long long i)
{
    const unsigned char *p = w->buf;
    unsigned long long n = (unsigned int)w->n;
    if (i + 6 > n) return -1;
    if (i > 0 && p[i - 1] != '\n') return 0;
    if (netra_l7_lower_ascii(p[i]) != 'h' || netra_l7_lower_ascii(p[i + 1]) != 'o' ||
        netra_l7_lower_ascii(p[i + 2]) != 's' || netra_l7_lower_ascii(p[i + 3]) != 't' || p[i + 4] != ':')
        return 0;
    unsigned long long pos = i + 5;
    for (int s = 0; s < 8; s++) {
        if (pos + 1 > n) return -1;
        if (p[pos] != ' ' && p[pos] != '\t') break;
        pos++;
    }
    w->pos = (int)pos;
    w->oi = 0;
    w->bad = 0;
    NETRA_L7_LOOP(95, netra_l7_http_host_copy_step, w);
    if (w->bad) return -1;
    unsigned int oi = (unsigned int)w->oi;
    if (oi == 0 || oi > 95) return 0;
    w->out[oi] = 0;
    return (int)oi;
}

static long
netra_l7_http_host_step(unsigned long long idx, void *ctx)
{
    struct netra_l7_work *w = NETRA_L7_WORK(ctx);
    unsigned long long i = idx & (NETRA_L7_SCAN - 1);
    int r = netra_l7_http_host_at(w, i);
    if (r == 0) return 0;
    w->result = r > 0 ? r : 0;
    return 1;
}

// http_host is a best-effort HTTP/1.x Host-header scanner over w->buf.
static __inline__ __attribute__((always_inline)) int
netra_l7_http_host(struct netra_l7_work *w, char out[96])
{
    __builtin_memset(w->out, 0, sizeof(w->out));
    w->result = 0;
    NETRA_L7_LOOP(NETRA_L7_SCAN, netra_l7_http_host_step, w);
    int r = w->result;
    if (r <= 0) return 0;
    __builtin_memcpy(out, w->out, sizeof(w->out));
    return r;
}

#endif // NETRA_L7_H
