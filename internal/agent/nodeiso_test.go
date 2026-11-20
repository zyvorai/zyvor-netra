// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"reflect"
	"testing"
)

func TestDefaultRouteInterfaces(t *testing.T) {
	route4 := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eno8303\t00000000\t0105A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"eno8303\t0005A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n" +
		"cilium_host\t00002A0A\t00002A0A\t0003\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
	route6 := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eno8304\n" +
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n" +
		"fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eno8303\n"
	if got := defaultRouteInterfaces(route4, route6); !reflect.DeepEqual(got, []string{"eno8303", "eno8304"}) {
		t.Fatalf("default route interfaces = %v", got)
	}
	if got := defaultRouteInterfaces("", ""); len(got) != 0 {
		t.Fatalf("empty tables gave %v", got)
	}
}

func TestNodeIsolationInterfacesPrecedence(t *testing.T) {
	if got := nodeIsolationInterfaces("eth1, eth2", []string{"eth0"}); !reflect.DeepEqual(got, []string{"eth1", "eth2"}) {
		t.Fatalf("explicit list ignored: %v", got)
	}
	if got := nodeIsolationInterfaces("", []string{"eth0"}); !reflect.DeepEqual(got, []string{"eth0"}) {
		t.Fatalf("agent interfaces ignored: %v", got)
	}
}
