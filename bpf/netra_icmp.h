// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
#ifndef NETRA_ICMP_H
#define NETRA_ICMP_H

// Only fixed ICMP error headers are read. Quoted packets are never retained.
struct netra_icmp_error {
    unsigned int mtu;
    unsigned char type, code, valid;
};

static __inline__ __attribute__((always_inline)) void
netra_icmp_parse(const unsigned char *p, const void *end, unsigned char family,
                 struct netra_icmp_error *out)
{
    __builtin_memset(out, 0, sizeof(*out));
    if ((const void *)(p + 8) > end) return;
    unsigned char type = p[0], code = p[1];
    if (family == 4) {
        if (type != 3 && type != 11 && type != 12) return;
        if (type == 3 && code == 4)
            out->mtu = ((unsigned int)p[6] << 8) | p[7];
    } else if (family == 6) {
        if (type < 1 || type > 4) return;
        if (type == 2 && code == 0)
            out->mtu = ((unsigned int)p[4] << 24) | ((unsigned int)p[5] << 16) |
                       ((unsigned int)p[6] << 8) | p[7];
    } else return;
    out->type = type;
    out->code = code;
    out->valid = 1;
}
#endif
