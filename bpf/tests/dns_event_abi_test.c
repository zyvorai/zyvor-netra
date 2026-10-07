// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
#include <stddef.h>
#include <stdio.h>
#include "../netra_event.h"
_Static_assert(sizeof(struct obs_event)==196, "event ABI must remain 196 bytes");
_Static_assert(offsetof(struct obs_event, dns)==92, "DNS name decoder offset");
_Static_assert(offsetof(struct obs_event, latency_us)==188, "latency decoder offset");
_Static_assert(offsetof(struct obs_event, dns_rcode)==192, "rcode decoder offset");
_Static_assert(offsetof(struct obs_event, dns_qtype)==194, "QTYPE decoder offset");
int main(void) { puts("netra DNS event ABI: ok"); return 0; }
