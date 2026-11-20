// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package kube

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// containerStatusJSON is the subset of Kubernetes' containerStatuses entry
// this package parses. Shared between ListPods and GetPod so both decode
// and interpret it identically.
type containerStatusJSON struct {
	Name         string `json:"name"`
	Ready        bool   `json:"ready"`
	RestartCount int    `json:"restartCount"`
	ImageID      string `json:"imageID"`
	State        struct {
		Running *struct {
			StartedAt time.Time `json:"startedAt"`
		} `json:"running"`
	} `json:"state"`
}

// podStartAndRestarts derives PodInfo.Started (the most recent Running
// startedAt across containers, nil if none are running) and RestartCount
// (summed across containers) from a pod's containerStatuses.
func podStartAndRestarts(statuses []containerStatusJSON) (*time.Time, int) {
	var started *time.Time
	restarts := 0
	for _, cs := range statuses {
		restarts += cs.RestartCount
		if cs.State.Running == nil || cs.State.Running.StartedAt.IsZero() {
			continue
		}
		t := cs.State.Running.StartedAt
		if started == nil || t.After(*started) {
			started = &t
		}
	}
	return started, restarts
}

// activePodsSelector skips pods that can no longer own traffic or a cgroup
// (Evicted, Completed, failed Jobs). Clusters accumulate these by the
// thousand, and their stale pod IPs may already belong to a new pod.
const activePodsSelector = "status.phase!=Failed,status.phase!=Succeeded"

// ListPods lists pods that are pending or running. ns empty means all
// namespaces.
func (c *Client) ListPods(ctx context.Context, ns string) ([]models.PodInfo, error) {
	return c.listPods(ctx, ns, true)
}

// ListAllPods also includes terminated pods.
func (c *Client) ListAllPods(ctx context.Context, ns string) ([]models.PodInfo, error) {
	return c.listPods(ctx, ns, false)
}

func (c *Client) listPods(ctx context.Context, ns string, activeOnly bool) ([]models.PodInfo, error) {
	p := "/api/v1/pods"
	if strings.TrimSpace(ns) != "" {
		p = "/api/v1/namespaces/" + esc(ns) + "/pods"
	}
	if activeOnly {
		p += "?fieldSelector=" + url.QueryEscape(activePodsSelector)
	}
	type podItem struct {
		Metadata struct {
			Name, Namespace string
			Labels          map[string]string             `json:"labels"`
			OwnerReferences []struct{ Kind, Name string } `json:"ownerReferences"`
		} `json:"metadata"`
		Spec struct {
			NodeName           string `json:"nodeName"`
			ServiceAccountName string `json:"serviceAccountName"`
		} `json:"spec"`
		Status struct {
			Phase, PodIP      string
			ContainerStatuses []containerStatusJSON `json:"containerStatuses"`
		} `json:"status"`
	}
	items, err := listItems[podItem](ctx, c, p)
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	out := make([]models.PodInfo, 0, len(items))
	for _, it := range items {
		ready := false
		for _, cs := range it.Status.ContainerStatuses {
			if cs.Ready {
				ready = true
				break
			}
		}
		p := models.PodInfo{
			Name: it.Metadata.Name, Namespace: it.Metadata.Namespace, Phase: it.Status.Phase,
			Node: it.Spec.NodeName, PodIP: it.Status.PodIP, Ready: ready, Labels: it.Metadata.Labels,
			ServiceAccountName: it.Spec.ServiceAccountName,
		}
		if len(it.Metadata.OwnerReferences) > 0 {
			p.OwnerKind = it.Metadata.OwnerReferences[0].Kind
			p.OwnerName = it.Metadata.OwnerReferences[0].Name
		}
		p.Started, p.RestartCount = podStartAndRestarts(it.Status.ContainerStatuses)
		out = append(out, p)
	}
	return out, nil
}

func (c *Client) GetPod(ctx context.Context, ns, name string) (*models.PodInfo, error) {
	b, err := c.do(ctx, "GET", "/api/v1/namespaces/"+esc(ns)+"/pods/"+esc(name), nil, "")
	if err != nil {
		return nil, err
	}
	var it struct {
		Metadata struct {
			Name, Namespace string
			Labels          map[string]string             `json:"labels"`
			OwnerReferences []struct{ Kind, Name string } `json:"ownerReferences"`
		} `json:"metadata"`
		Spec struct {
			NodeName            string                  `json:"nodeName"`
			ServiceAccountName  string                  `json:"serviceAccountName"`
			Containers          []struct{ Name string } `json:"containers"`
			InitContainers      []struct{ Name string } `json:"initContainers"`
			EphemeralContainers []struct{ Name string } `json:"ephemeralContainers"`
		} `json:"spec"`
		Status struct {
			Phase, PodIP      string
			ContainerStatuses []containerStatusJSON `json:"containerStatuses"`
		} `json:"status"`
	}
	if err := json.Unmarshal(b, &it); err != nil {
		return nil, fmt.Errorf("decode pod: %w", err)
	}
	statusByName := map[string]containerStatusJSON{}
	ready := false
	for _, cs := range it.Status.ContainerStatuses {
		statusByName[cs.Name] = cs
		if cs.Ready {
			ready = true
		}
	}
	containers := make([]models.ContainerInfo, 0, len(it.Spec.Containers))
	for _, ctn := range it.Spec.Containers {
		cs := statusByName[ctn.Name]
		ci := models.ContainerInfo{Name: ctn.Name, Ready: cs.Ready, RestartCount: cs.RestartCount, ImageID: cs.ImageID}
		if cs.State.Running != nil && !cs.State.Running.StartedAt.IsZero() {
			t := cs.State.Running.StartedAt
			ci.StartedAt = &t
		}
		containers = append(containers, ci)
	}
	p := &models.PodInfo{
		Name: it.Metadata.Name, Namespace: it.Metadata.Namespace, Phase: it.Status.Phase,
		Node: it.Spec.NodeName, PodIP: it.Status.PodIP, Ready: ready, Labels: it.Metadata.Labels,
		ServiceAccountName: it.Spec.ServiceAccountName, Containers: containers,
	}
	if len(it.Metadata.OwnerReferences) > 0 {
		p.OwnerKind = it.Metadata.OwnerReferences[0].Kind
		p.OwnerName = it.Metadata.OwnerReferences[0].Name
	}
	p.Started, p.RestartCount = podStartAndRestarts(it.Status.ContainerStatuses)
	return p, nil
}

func (c *Client) ListVMs(ctx context.Context, ns string) ([]models.VMInfo, bool, error) {
	p := "/apis/kubevirt.io/v1/virtualmachineinstances"
	if strings.TrimSpace(ns) != "" {
		p = "/apis/kubevirt.io/v1/namespaces/" + esc(ns) + "/virtualmachineinstances"
	}
	b, status, err := c.doRaw(ctx, "GET", p, nil, "")
	if err != nil {
		return nil, false, err
	}
	if status == http.StatusNotFound || kubeAPIMissing(b) {
		return []models.VMInfo{}, false, nil
	}
	if status >= 300 {
		return nil, false, fmt.Errorf("kubernetes API %d: %s", status, string(b))
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name, Namespace string
				Labels          map[string]string `json:"labels"`
			} `json:"metadata"`
			Status struct {
				Phase, NodeName string
				Interfaces      []struct {
					IP string `json:"ipAddress"`
				} `json:"interfaces"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, true, fmt.Errorf("decode vmis: %w", err)
	}
	out := make([]models.VMInfo, 0, len(list.Items))
	for _, it := range list.Items {
		vm := models.VMInfo{Name: it.Metadata.Name, Namespace: it.Metadata.Namespace, Phase: it.Status.Phase, Node: it.Status.NodeName, Running: strings.EqualFold(it.Status.Phase, "Running"), Labels: it.Metadata.Labels}
		if len(it.Status.Interfaces) > 0 {
			vm.PodIP = it.Status.Interfaces[0].IP
		}
		attachVirtLauncher(ctx, c, &vm)
		out = append(out, vm)
	}
	return out, true, nil
}

func (c *Client) GetVMI(ctx context.Context, ns, name string) (*models.VMInfo, bool, error) {
	b, status, err := c.doRaw(ctx, "GET", "/apis/kubevirt.io/v1/namespaces/"+esc(ns)+"/virtualmachineinstances/"+esc(name), nil, "")
	if err != nil {
		return nil, false, err
	}
	if status == http.StatusNotFound {
		if kubeAPIMissing(b) {
			return nil, false, nil
		}
		return nil, true, fmt.Errorf("vmi not found")
	}
	if status >= 300 {
		return nil, false, fmt.Errorf("kubernetes API %d: %s", status, string(b))
	}
	var it struct {
		Metadata struct {
			Name, Namespace string
			Labels          map[string]string `json:"labels"`
		} `json:"metadata"`
		Status struct {
			Phase, NodeName string
			Interfaces      []struct {
				IP string `json:"ipAddress"`
			} `json:"interfaces"`
		} `json:"status"`
	}
	if err := json.Unmarshal(b, &it); err != nil {
		return nil, true, fmt.Errorf("decode vmi: %w", err)
	}
	vm := &models.VMInfo{Name: it.Metadata.Name, Namespace: it.Metadata.Namespace, Phase: it.Status.Phase, Node: it.Status.NodeName, Running: strings.EqualFold(it.Status.Phase, "Running"), Labels: it.Metadata.Labels}
	if len(it.Status.Interfaces) > 0 {
		vm.PodIP = it.Status.Interfaces[0].IP
	}
	attachVirtLauncher(ctx, c, vm)
	return vm, true, nil
}

func attachVirtLauncher(ctx context.Context, c *Client, vm *models.VMInfo) {
	pods, err := c.ListPods(ctx, vm.Namespace)
	if err != nil {
		return
	}
	prefix := "virt-launcher-" + vm.Name + "-"
	for _, p := range pods {
		if strings.HasPrefix(p.Name, prefix) || (p.Labels != nil && p.Labels["kubevirt.io/domain"] == vm.Name) {
			vm.PodName = p.Name
			if vm.PodIP == "" {
				vm.PodIP = p.PodIP
			}
			if vm.Node == "" {
				vm.Node = p.Node
			}
			if vm.Labels == nil {
				vm.Labels = map[string]string{}
			}
			for k, v := range p.Labels {
				if _, ok := vm.Labels[k]; !ok {
					vm.Labels[k] = v
				}
			}
			return
		}
	}
}
func kubeAPIMissing(b []byte) bool {
	m := string(b)
	return strings.Contains(m, "the server could not find the requested resource") || strings.Contains(m, "no matches for kind") || strings.Contains(m, "could not find the requested resource")
}
func (c *Client) doRaw(ctx context.Context, method, p string, body []byte, contentType string) ([]byte, int, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+p, rdr)
	if err != nil {
		return nil, 0, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return b, resp.StatusCode, nil
}
