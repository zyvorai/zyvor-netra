// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/zyvorai/netra/internal/kube"
)

var consoleUpgrader = websocket.Upgrader{
	CheckOrigin:       func(*http.Request) bool { return true },
	HandshakeTimeout:  10 * time.Second,
	EnableCompression: false,
}

func (s *Server) requireConsole(w http.ResponseWriter) bool {
	if !s.consoleEnabled {
		errorJSON(w, http.StatusNotFound, "workload console is disabled; set NETRA_WORKLOAD_CONSOLE=true")
		return false
	}
	return true
}

func (s *Server) streamPodLogs(w http.ResponseWriter, r *http.Request) {
	if !s.requireConsole(w) {
		return
	}
	f, ok := w.(http.Flusher)
	if !ok {
		errorJSON(w, 500, "streaming unsupported")
		return
	}
	ns, name := r.PathValue("namespace"), r.PathValue("name")
	if ns == "" || name == "" {
		errorJSON(w, 400, "namespace and name are required")
		return
	}
	container := strings.TrimSpace(r.URL.Query().Get("container"))
	tail := 500
	if n, err := strconv.Atoi(r.URL.Query().Get("tailLines")); err == nil && n > 0 && n <= 10000 {
		tail = n
	}
	follow := !strings.EqualFold(r.URL.Query().Get("follow"), "false")

	body, err := s.kube.StreamPodLogs(r.Context(), ns, name, container, tail, follow)
	if err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	defer body.Close()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	fmt.Fprintf(w, "event: ready\ndata: {\"ok\":true}\n\n")
	f.Flush()

	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		payload, _ := json.Marshal(line)
		fmt.Fprintf(w, "event: log\ndata: %s\n\n", payload)
		f.Flush()
		if r.Context().Err() != nil {
			return
		}
	}
	if err := sc.Err(); err != nil && r.Context().Err() == nil {
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", strconv.Quote(err.Error()))
		f.Flush()
	}
	fmt.Fprintf(w, "event: done\ndata: {}\n\n")
	f.Flush()
}

func (s *Server) proxyPodExec(w http.ResponseWriter, r *http.Request) {
	if !s.requireConsole(w) {
		return
	}
	ns, name := r.PathValue("namespace"), r.PathValue("name")
	if ns == "" || name == "" {
		errorJSON(w, 400, "namespace and name are required")
		return
	}
	container := strings.TrimSpace(r.URL.Query().Get("container"))
	cmdRaw := strings.TrimSpace(r.URL.Query().Get("command"))
	var command []string
	if cmdRaw == "" {
		command = []string{"/bin/sh"}
	} else {
		command = strings.Fields(cmdRaw)
	}

	browser, err := consoleUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer browser.Close()

	kubeConn, err := s.kube.DialPodExec(r.Context(), ns, name, container, command, true)
	if err != nil {
		_ = browser.WriteMessage(websocket.TextMessage, []byte("exec error: "+err.Error()+"\r\n"))
		return
	}
	defer kubeConn.Close()

	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = browser.Close()
			_ = kubeConn.Close()
		})
	}

	go func() {
		defer closeBoth()
		for {
			mt, data, err := browser.ReadMessage()
			if err != nil {
				return
			}
			if mt == websocket.TextMessage || mt == websocket.BinaryMessage {
				if len(data) > 0 && data[0] == '{' {
					var msg struct {
						Type string `json:"type"`
						Cols uint16 `json:"cols"`
						Rows uint16 `json:"rows"`
					}
					if json.Unmarshal(data, &msg) == nil && msg.Type == "resize" && msg.Cols > 0 && msg.Rows > 0 {
						_ = kubeConn.WriteMessage(websocket.BinaryMessage, kube.EncodeExecResize(msg.Cols, msg.Rows))
						continue
					}
				}
				frame := make([]byte, 1+len(data))
				frame[0] = 0 // stdin
				copy(frame[1:], data)
				if err := kubeConn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
					return
				}
			}
		}
	}()

	for {
		_, data, err := kubeConn.ReadMessage()
		if err != nil {
			closeBoth()
			return
		}
		if len(data) == 0 {
			continue
		}
		switch data[0] {
		case 1, 2: // stdout, stderr
			if err := browser.WriteMessage(websocket.BinaryMessage, data[1:]); err != nil {
				closeBoth()
				return
			}
		case 3: // error stream (often JSON Status)
			_ = browser.WriteMessage(websocket.TextMessage, append([]byte("\r\n[exec] "), data[1:]...))
			closeBoth()
			return
		}
	}
}

func (s *Server) proxyVMVnc(w http.ResponseWriter, r *http.Request) {
	if !s.requireConsole(w) {
		return
	}
	ns, name := r.PathValue("namespace"), r.PathValue("name")
	if ns == "" || name == "" {
		errorJSON(w, 400, "namespace and name are required")
		return
	}

	browser, err := consoleUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer browser.Close()

	kubeConn, err := s.kube.DialVMIVnc(r.Context(), ns, name)
	if err != nil {
		_ = browser.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseInternalServerErr, err.Error()))
		return
	}
	defer kubeConn.Close()

	errc := make(chan struct{}, 2)
	pump := func(dst, src *websocket.Conn) {
		defer func() { errc <- struct{}{} }()
		for {
			mt, data, err := src.ReadMessage()
			if err != nil {
				return
			}
			if err := dst.WriteMessage(mt, data); err != nil {
				return
			}
		}
	}
	go pump(kubeConn, browser)
	go pump(browser, kubeConn)
	<-errc
}
