// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
#include <assert.h>
#include <stdio.h>
#include "netra_icmp.h"

int main(void)
{
    struct netra_icmp_error e;
    unsigned char p[16] = {3,4,0,0,0,0,5,220};
    for (int n = 0; n < 8; n++) {
        netra_icmp_parse(p,p+n,4,&e);
        assert(!e.valid && !e.mtu);
    }
    netra_icmp_parse(p,p+8,4,&e);
    assert(e.valid && e.type == 3 && e.code == 4 && e.mtu == 1500);
    p[6] = p[7] = 0;
    netra_icmp_parse(p,p+8,4,&e);
    assert(e.valid && e.mtu == 0); // legacy router does not advertise MTU
    for (int family = 4; family <= 6; family += 2) {
        for (int type = 0; type < 256; type++) {
            for (int code = 0; code < 256; code++) {
                p[0] = type; p[1] = code;
                p[4] = 0x12; p[5] = 0x34; p[6] = 0x56; p[7] = 0x78;
                netra_icmp_parse(p,p+8,family,&e);
                int valid = family == 4 ? type == 3 || type == 11 || type == 12 : type >= 1 && type <= 4;
                assert(e.valid == valid);
                if (valid) assert(e.type == type && e.code == code);
                unsigned int mtu = family == 4 && type == 3 && code == 4 ? 0x5678U :
                    family == 6 && type == 2 && code == 0 ? 0x12345678U : 0;
                assert(e.mtu == mtu);
            }
        }
    }
    netra_icmp_parse(p,p+8,0,&e);
    assert(!e.valid);
    puts("ICMP parser: truncation, all type/code pairs, IPv4/IPv6 MTU and echo exclusion passed");
}
