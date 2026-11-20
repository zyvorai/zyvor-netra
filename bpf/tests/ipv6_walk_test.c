// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "../netra_ipv6.h"

#define TCP 6
#define UDP 17

static void direct_tcp(void)
{
    unsigned char p[32] = {0};
    struct netra_ipv6_l4 x;
    assert(netra_ipv6_walk(p, p + sizeof(p), TCP, &x) == 1);
    assert(x.proto == TCP && x.l4 == p && x.l4_parseable == 1);
    assert(x.ext_headers == 0 && x.fragmented == 0 && x.chain_truncated == 0);
}

static void hop_dest_udp(void)
{
    unsigned char p[40] = {0};
    // Hop-by-Hop -> Destination Options -> UDP. Both extension headers are 8B.
    p[0] = NETRA_NH_DEST; p[1] = 0;
    p[8] = UDP; p[9] = 0;
    struct netra_ipv6_l4 x;
    assert(netra_ipv6_walk(p, p + sizeof(p), NETRA_NH_HOP, &x) == 1);
    assert(x.proto == UDP && x.l4 == p + 16 && x.l4_parseable == 1);
    assert(x.ext_headers == 2 && x.chain_truncated == 0);
}

static void routing_ah_tcp(void)
{
    unsigned char p[64] = {0};
    // Routing (8B) -> AH (12B; payload-len=1) -> TCP.
    p[0] = NETRA_NH_AH; p[1] = 0;
    p[8] = TCP; p[9] = 1;
    struct netra_ipv6_l4 x;
    assert(netra_ipv6_walk(p, p + sizeof(p), NETRA_NH_ROUTING, &x) == 1);
    assert(x.proto == TCP && x.l4 == p + 20 && x.l4_parseable == 1);
    assert(x.ext_headers == 2 && x.chain_truncated == 0);
}

static void atomic_fragment_udp(void)
{
    unsigned char p[32] = {0};
    p[0] = UDP;
    p[2] = 0; p[3] = 0; // offset=0, M=0
    struct netra_ipv6_l4 x;
    assert(netra_ipv6_walk(p, p + sizeof(p), NETRA_NH_FRAGMENT, &x) == 1);
    assert(x.proto == UDP && x.l4 == p + 8 && x.l4_parseable == 1);
    assert(x.fragmented == 1 && x.nonfirst_fragment == 0 && x.more_fragments == 0);
}

static void first_fragment_tcp(void)
{
    unsigned char p[32] = {0};
    p[0] = TCP;
    p[2] = 0; p[3] = 1; // offset=0, M=1
    struct netra_ipv6_l4 x;
    assert(netra_ipv6_walk(p, p + sizeof(p), NETRA_NH_FRAGMENT, &x) == 1);
    assert(x.proto == TCP && x.l4 == p + 8 && x.l4_parseable == 1);
    assert(x.fragmented == 1 && x.nonfirst_fragment == 0 && x.more_fragments == 1);
}

static void nonfirst_fragment_preserves_proto(void)
{
    unsigned char p[32] = {0};
    p[0] = UDP;
    p[2] = 0; p[3] = 8; // fragment offset = 1 * 8 bytes
    struct netra_ipv6_l4 x;
    assert(netra_ipv6_walk(p, p + sizeof(p), NETRA_NH_FRAGMENT, &x) == 1);
    assert(x.proto == UDP && x.l4 == p + 8 && x.l4_parseable == 0);
    assert(x.fragmented == 1 && x.nonfirst_fragment == 1);
}

static void opaque_headers(void)
{
    unsigned char p[16] = {0};
    struct netra_ipv6_l4 x;
    assert(netra_ipv6_walk(p, p + sizeof(p), NETRA_NH_ESP, &x) == 1);
    assert(x.proto == NETRA_NH_ESP && x.l4_parseable == 0 && x.chain_truncated == 0);
    assert(netra_ipv6_walk(p, p + sizeof(p), NETRA_NH_NONE, &x) == 1);
    assert(x.proto == NETRA_NH_NONE && x.l4_parseable == 0 && x.chain_truncated == 0);
}

static void malformed_extension_is_safe(void)
{
    unsigned char p[8] = {0};
    p[0] = UDP; p[1] = 7; // claims 64 bytes, only 8 available
    struct netra_ipv6_l4 x;
    assert(netra_ipv6_walk(p, p + sizeof(p), NETRA_NH_DEST, &x) == 1);
    assert(x.proto == NETRA_NH_DEST && x.l4_parseable == 0 && x.chain_truncated == 1);
}

static void bounded_chain(void)
{
    unsigned char p[64] = {0};
    for (int i = 0; i < 7; i++) {
        p[i * 8] = (i == 6) ? TCP : NETRA_NH_DEST;
        p[i * 8 + 1] = 0;
    }
    struct netra_ipv6_l4 x;
    assert(netra_ipv6_walk(p, p + sizeof(p), NETRA_NH_DEST, &x) == 1);
    assert(x.ext_headers == NETRA_IPV6_MAX_EXT);
    assert(x.l4_parseable == 0 && x.chain_truncated == 1);
}

int main(void)
{
    direct_tcp();
    hop_dest_udp();
    routing_ah_tcp();
    atomic_fragment_udp();
    first_fragment_tcp();
    nonfirst_fragment_preserves_proto();
    opaque_headers();
    malformed_extension_is_safe();
    bounded_chain();
    puts("netra ipv6 walker: ok");
    return 0;
}
