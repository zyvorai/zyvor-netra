// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package insights

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func Dependencies(agents []models.AgentStatus, pods []models.PodInfo, services []models.ServiceInfo, limit int) models.DependencyGraph {
	if limit <= 0 {
		limit = 500
	}
	podByIP := map[string]models.PodInfo{}
	for _, p := range pods {
		if p.PodIP != "" {
			podByIP[p.PodIP] = p
		}
	}
	svcByIP := map[string]models.ServiceInfo{}
	for _, s := range services {
		if s.ClusterIP != "" {
			svcByIP[s.ClusterIP] = s
		}
	}

	nodes := map[string]models.DependencyNode{}
	type edgeKey struct {
		src, dst, proto string
		port            uint16
	}
	edges := map[edgeKey]models.DependencyEdge{}

	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, st := range a.Stats {
			if st.Direction == "ingress" || (st.Namespace == "" && st.Pod == "" && st.WorkloadName == "") {
				continue
			}
			srcID, srcNode := sourceNode(st)
			nodes[srcID] = srcNode
			dstID, dstNode, external := destinationNode(st.DestinationIP, podByIP, svcByIP)
			nodes[dstID] = dstNode
			k := edgeKey{srcID, dstID, strings.ToUpper(st.Protocol), st.Port}
			e := edges[k]
			e.Source, e.Target, e.Protocol, e.Port, e.External = srcID, dstID, k.proto, k.port, external
			e.Packets += st.Packets
			e.Bytes += st.Bytes
			e.Blocked += st.Blocked
			edges[k] = e
		}
	}
	outEdges := make([]models.DependencyEdge, 0, len(edges))
	for _, e := range edges {
		outEdges = append(outEdges, e)
	}
	sort.Slice(outEdges, func(i, j int) bool {
		if outEdges[i].Packets != outEdges[j].Packets {
			return outEdges[i].Packets > outEdges[j].Packets
		}
		if outEdges[i].Source != outEdges[j].Source {
			return outEdges[i].Source < outEdges[j].Source
		}
		return outEdges[i].Target < outEdges[j].Target
	})
	if len(outEdges) > limit {
		outEdges = outEdges[:limit]
	}
	used := map[string]bool{}
	for _, e := range outEdges {
		used[e.Source] = true
		used[e.Target] = true
	}
	outNodes := make([]models.DependencyNode, 0, len(used))
	for id := range used {
		outNodes = append(outNodes, nodes[id])
	}
	sort.Slice(outNodes, func(i, j int) bool { return outNodes[i].ID < outNodes[j].ID })
	return models.DependencyGraph{GeneratedAt: time.Now().UTC(), Nodes: outNodes, Edges: outEdges}
}

func sourceNode(st models.DestinationStat) (string, models.DependencyNode) {
	if st.Namespace != "" && st.WorkloadName != "" {
		kind := st.WorkloadKind
		if kind == "" {
			kind = "Workload"
		}
		id := models.CanonicalSource(st.Namespace, st.Pod, kind, st.WorkloadName, st.CgroupID)
		return id, models.DependencyNode{ID: id, Kind: "workload", Namespace: st.Namespace, Name: st.WorkloadName, WorkloadKind: kind}
	}
	id := models.CanonicalSource(st.Namespace, st.Pod, "", "", st.CgroupID)
	return id, models.DependencyNode{ID: id, Kind: "pod", Namespace: st.Namespace, Name: st.Pod}
}

func destinationNode(ip string, pods map[string]models.PodInfo, services map[string]models.ServiceInfo) (string, models.DependencyNode, bool) {
	if s, ok := services[ip]; ok {
		id := "service:" + s.Namespace + ":" + s.Name
		return id, models.DependencyNode{ID: id, Kind: "service", Namespace: s.Namespace, Name: s.Name, IP: ip}, false
	}
	if p, ok := pods[ip]; ok {
		if p.OwnerName != "" {
			kind := p.OwnerKind
			if kind == "" {
				kind = "Workload"
			}
			id := "workload:" + p.Namespace + ":" + strings.ToLower(kind) + ":" + p.OwnerName
			return id, models.DependencyNode{ID: id, Kind: "workload", Namespace: p.Namespace, Name: p.OwnerName, IP: ip, WorkloadKind: kind}, false
		}
		id := "pod:" + p.Namespace + ":" + p.Name
		return id, models.DependencyNode{ID: id, Kind: "pod", Namespace: p.Namespace, Name: p.Name, IP: ip}, false
	}
	id := "external:" + ip
	return id, models.DependencyNode{ID: id, Kind: "external", Name: ip, IP: ip}, true
}

func edgeDestination(e models.DependencyEdge, nodes map[string]models.DependencyNode) string {
	n := nodes[e.Target]
	if n.Kind == "service" {
		return n.Namespace + "/" + n.Name
	}
	if n.IP != "" {
		return n.IP + ":" + strconv.Itoa(int(e.Port))
	}
	return n.Name
}
