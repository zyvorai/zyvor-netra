// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package flowlog

import "strings"

// Class returns a well-known-port hint. It does not parse payloads, so
// gRPC-over-443 stays "https" and an unusual port stays empty.
func Class(port uint16, protocol string) string {
	proto := strings.ToLower(protocol)
	switch port {
	case 53:
		return "dns"
	case 80, 8080, 8000, 8888:
		return "http"
	case 443, 8443:
		return "https"
	case 3306:
		return "mysql"
	case 5432:
		return "postgres"
	case 6379:
		return "redis"
	case 9092, 9093:
		return "kafka"
	case 5672, 5671:
		return "amqp"
	case 27017:
		return "mongodb"
	case 50051, 4317:
		return "grpc"
	case 11211:
		return "memcached"
	case 9200, 9300:
		return "elasticsearch"
	case 2379, 2380:
		return "etcd"
	case 1883, 8883:
		return "mqtt"
	case 6443:
		return "kubernetes"
	case 22:
		return "ssh"
	case 25, 587:
		return "smtp"
	case 123:
		if proto == "udp" || proto == "" {
			return "ntp"
		}
	}
	return ""
}
