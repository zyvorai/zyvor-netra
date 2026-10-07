// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
// Best-effort L7/DNS byte-level parsers shared by the Netra eBPF datapath
// and its host-side parser tests. These functions only ever look at bytes
// already proven in-bounds against data_end; they never reassemble TCP
// streams and only report what's visible in a single skb.

#ifndef NETRA_L7_H
#define NETRA_L7_H

#ifdef NETRA_BPF
#define NETRA_L7_UNROLL _Pragma("unroll")
#else
#define NETRA_L7_UNROLL
#endif

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

// dns_qname decodes a plain-DNS question name starting at the UDP payload
// (12-byte header, then the QNAME label sequence), lowercased, into out.
// Returns the decoded length, or 0 if no valid name could be read.
static __inline__ __attribute__((always_inline)) int
netra_l7_dns_qname(void *payload, void *data_end, char out[96])
{
    unsigned char *p = payload;
    if ((void *)(p + 12) > data_end) return 0;
    p += 12;
    int oi = 0, remaining = 0;
    NETRA_L7_UNROLL
    for (int i = 0; i < 96; i++) {
        if ((void *)(p + 1) > data_end || oi >= 95) break;
        unsigned char c = *p++;
        if (remaining == 0) {
            if (c == 0) break;
            if ((c & 0xc0) != 0 || c > 63) break;
            if (oi > 0) out[oi++] = '.';
            remaining = c;
        } else {
            if (c >= 'A' && c <= 'Z') c += ('a' - 'A');
            out[oi++] = (char)c;
            remaining--;
        }
    }
    if (oi < 96) out[oi] = 0;
    return oi;
}

// Read QTYPE only from a complete, uncompressed first question. Unknown,
// oversized, compressed or truncated questions return zero; never guess.
static __inline__ __attribute__((always_inline)) unsigned short
netra_l7_dns_qtype(void *payload, void *data_end)
{
    unsigned char *p = payload;
    if ((void *)(p + 12) > data_end || p[4] != 0 || p[5] != 1) return 0;
    p += 12;
    int remaining = 0;
    NETRA_L7_UNROLL
    for (int i = 0; i < 96; i++) {
        if ((void *)(p + 1) > data_end) return 0;
        unsigned char c = *p++;
        if (remaining) { remaining--; continue; }
        if (c == 0) {
            if ((void *)(p + 4) > data_end || p[2] != 0 || p[3] != 1) return 0;
            return ((unsigned short)p[0] << 8) | p[1];
        }
        if (c > 63) return 0;
        remaining = c;
    }
    return 0;
}

// netra_l7_tls_sni_value copies and validates the name_len bytes at p[i+9:]
// once the SNI extension header at position i has already been validated by
// the caller.
static __attribute__((noinline)) int
netra_l7_tls_sni_value(unsigned char *p, int i, unsigned short name_len, char out[96])
{
    int ok = 1;
    for (int j = 0; j < 95; j++) {
        if (j >= name_len) break;
        unsigned char c = p[i + 9 + j];
        if (!netra_l7_hostname_char(c)) { ok = 0; break; }
        out[j] = (char)netra_l7_lower_ascii(c);
    }
    if (!ok) { __builtin_memset(out, 0, 96); return 0; }
    out[name_len] = 0;
    return name_len;
}

// tls_sni is a best-effort TLS ClientHello SNI parser. It intentionally
// does not reassemble TCP streams and therefore only reports an SNI
// present in this skb. Deliberately NOT always_inline (unlike almost every
// other helper in this file): a kernel verifier tracking the packet
// pointer's precise byte offset through this position-search loop's
// backedge, combined with the conntrack/policy/DNS logic already inlined
// ahead of it in the same program, hit a hard, fixed jump-history
// complexity ceiling on some kernels — independent of this loop's own trip
// count, since reducing it did not help. A real (non-inlined) BPF-to-BPF
// call gives the verifier a fresh, isolated budget for this whole
// function, checked once regardless of how it's called. See
// docs/l7-metadata.md.
static __attribute__((noinline)) int
netra_l7_tls_sni(void *payload, void *data_end, char out[96])
{
    unsigned char *p = payload;
    if ((void *)(p + 9) > data_end || p[0] != 0x16 || p[5] != 0x01) return 0;
    for (int i = 43; i < 512; i++) {
        /* Need header bytes i..i+8 and up to 95 name bytes starting at i+9. */
        if ((void *)(p + i + 9 + 95) > data_end) break;
        if (p[i] != 0 || p[i + 1] != 0 || p[i + 6] != 0) continue;
        unsigned short ext_len = ((unsigned short)p[i + 2] << 8) | p[i + 3];
        unsigned short list_len = ((unsigned short)p[i + 4] << 8) | p[i + 5];
        unsigned short name_len = ((unsigned short)p[i + 7] << 8) | p[i + 8];
        if (!name_len || name_len > 95 || ext_len < (unsigned short)(5 + name_len) || list_len < (unsigned short)(3 + name_len)) continue;
        int n = netra_l7_tls_sni_value(p, i, name_len, out);
        if (n > 0) return n;
    }
    return 0;
}

static __inline__ __attribute__((always_inline)) int
netra_l7_http_method(void *payload, void *data_end, char out[8])
{
    unsigned char *p = payload;
    if ((void *)(p + 8) > data_end) return 0;
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

// netra_l7_http_host_value parses the header value starting at byte offset
// pos in p (right after "host:"), once the caller has already found that
// literal at the current scan position. Return value: >0 is success (the
// copied length), 0 means this occurrence yielded nothing so the caller
// should keep scanning for a later "Host:" line, and -1 means the packet
// ran out mid-value (or a non-printable byte was hit) so the caller should
// stop scanning entirely.
static __attribute__((noinline)) int
netra_l7_http_host_value(unsigned char *p, void *data_end, int pos, char out[96])
{
    for (int s = 0; s < 8; s++) {
        if ((void *)(p + pos + 1) > data_end) return -1;
        if (p[pos] != ' ' && p[pos] != '\t') break;
        pos++;
    }
    int oi = 0, bad = 0;
    for (int j = 0; j < 95; j++) {
        if ((void *)(p + pos + 1) > data_end) break;
        unsigned char c = p[pos++];
        if (c == '\r' || c == '\n') break;
        if (c < 0x21 || c > 0x7e) { bad = 1; break; }
        out[oi++] = (char)netra_l7_lower_ascii(c);
    }
    if (bad) return -1;
    if (oi > 0) { out[oi] = 0; return oi; }
    return 0;
}

// http_host is a best-effort HTTP/1.x Host-header scanner. Deliberately
// NOT always_inline, for the same reason as netra_l7_tls_sni above: this
// isolates the whole position-search-plus-value-parse from the verifier
// complexity already accumulated by the conntrack/policy/DNS/SNI logic
// inlined ahead of it in the same program. See docs/l7-metadata.md.
static __attribute__((noinline)) int
netra_l7_http_host(void *payload, void *data_end, char out[96])
{
    unsigned char *p = payload;
    for (int i = 0; i < 512; i++) {
        if ((void *)(p + i + 6) > data_end) break;
        if (i > 0 && p[i - 1] != '\n') continue;
        if (netra_l7_lower_ascii(p[i])!='h'||netra_l7_lower_ascii(p[i+1])!='o'||netra_l7_lower_ascii(p[i+2])!='s'||netra_l7_lower_ascii(p[i+3])!='t'||p[i+4]!=':') continue;
        int r = netra_l7_http_host_value(p, data_end, i + 5, out);
        if (r > 0) return r;
        if (r < 0) return 0;
    }
    return 0;
}

#endif // NETRA_L7_H
