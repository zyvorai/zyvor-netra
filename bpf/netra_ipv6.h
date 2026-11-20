// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
// Bounded IPv6 extension-header walker shared by the Netra eBPF datapath and
// its host-side parser tests.

#ifndef NETRA_IPV6_H
#define NETRA_IPV6_H

#define NETRA_NH_HOP       0
#define NETRA_NH_ROUTING   43
#define NETRA_NH_FRAGMENT  44
#define NETRA_NH_ESP       50
#define NETRA_NH_AH        51
#define NETRA_NH_NONE      59
#define NETRA_NH_DEST      60

#define NETRA_IPV6_MAX_EXT 6

#ifdef NETRA_BPF
#define NETRA_UNROLL _Pragma("unroll")
#else
#define NETRA_UNROLL
#endif

struct netra_ipv6_l4 {
    void *l4;
    unsigned char proto;
    unsigned char ext_headers;
    unsigned char fragmented;
    unsigned char nonfirst_fragment;
    unsigned char more_fragments;
    unsigned char l4_parseable;
    unsigned char chain_truncated;
};

static __inline__ __attribute__((always_inline)) int
netra_ipv6_walk(unsigned char *cursor, void *data_end, unsigned char next_header,
                struct netra_ipv6_l4 *out)
{
    __builtin_memset(out, 0, sizeof(*out));
    out->l4 = cursor;
    out->proto = next_header;

    NETRA_UNROLL
    for (int i = 0; i < NETRA_IPV6_MAX_EXT; i++) {
        out->l4 = cursor;
        out->proto = next_header;

        if (next_header == NETRA_NH_HOP ||
            next_header == NETRA_NH_ROUTING ||
            next_header == NETRA_NH_DEST) {
            if ((void *)(cursor + 2) > data_end) {
                out->chain_truncated = 1;
                return 1;
            }
            unsigned char next = cursor[0];
            unsigned int bytes = ((unsigned int)cursor[1] + 1U) * 8U;
            if (bytes < 8U || (void *)(cursor + bytes) > data_end) {
                out->chain_truncated = 1;
                return 1;
            }
            cursor += bytes;
            next_header = next;
            out->ext_headers++;
            continue;
        }

        if (next_header == NETRA_NH_FRAGMENT) {
            if ((void *)(cursor + 8) > data_end) {
                out->chain_truncated = 1;
                return 1;
            }
            unsigned char next = cursor[0];
            unsigned short frag = ((unsigned short)cursor[2] << 8) | cursor[3];
            out->fragmented = 1;
            out->nonfirst_fragment = (frag & 0xfff8U) != 0;
            out->more_fragments = (frag & 0x0001U) != 0;
            out->ext_headers++;
            cursor += 8;
            next_header = next;
            out->l4 = cursor;
            out->proto = next_header;

            // Only fragment offset zero carries a trustworthy upper-layer
            // header. Later fragments retain the Fragment header Next Header value
            // for conservative flow accounting and address/CIDR policy.
            if (out->nonfirst_fragment)
                return 1;
            continue;
        }

        if (next_header == NETRA_NH_AH) {
            if ((void *)(cursor + 2) > data_end) {
                out->chain_truncated = 1;
                return 1;
            }
            unsigned char next = cursor[0];
            unsigned int bytes = ((unsigned int)cursor[1] + 2U) * 4U;
            // RFC 4302 AH has a 12-byte fixed portion.
            if (bytes < 12U || (void *)(cursor + bytes) > data_end) {
                out->chain_truncated = 1;
                return 1;
            }
            cursor += bytes;
            next_header = next;
            out->ext_headers++;
            continue;
        }

        // ESP is encrypted/opaque to this metadata-only datapath and No Next
        // Header has no transport header. Keep address/CIDR visibility, but do
        // not let callers parse ports or L7 metadata.
        if (next_header == NETRA_NH_ESP || next_header == NETRA_NH_NONE)
            return 1;

        out->l4 = cursor;
        out->proto = next_header;
        out->l4_parseable = 1;
        return 1;
    }

    // A deliberately bounded walk protects verifier complexity. A chain that
    // exceeds the bound remains address/CIDR-observable/enforceable, but L4/L7
    // parsing is suppressed because the terminal header is not trustworthy.
    out->l4 = cursor;
    out->proto = next_header;
    out->chain_truncated = 1;
    return 1;
}

#endif // NETRA_IPV6_H
