package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
)

type Tunnel struct {
	cfg        *Config
	proxies    map[string]*httputil.ReverseProxy
	backends   map[string]*BackendTunnel
	wsMu       sync.Mutex
	websockets map[string]map[string]net.Conn // session -> socketID -> conn
}

func NewTunnel(cfg *Config) *Tunnel {
	t := &Tunnel{
		cfg:        cfg,
		proxies:    make(map[string]*httputil.ReverseProxy),
		backends:   cfg.BackendTunnel,
		websockets: make(map[string]map[string]net.Conn),
	}

	for name, bt := range cfg.BackendTunnel {
		target := &url.URL{
			Scheme: "http",
			Host:   fmt.Sprintf("%s:%d", bt.Forward, bt.Port),
		}
		proxy := httputil.NewSingleHostReverseProxy(target)

		// 覆寫 Host header
		originalDirector := proxy.Director
		hostHeader := bt.Host
		proxy.Director = func(req *http.Request) {
			originalDirector(req)
			req.Host = hostHeader
		}

		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			fmt.Printf("=== proxy error === %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("The website is down or error occurred"))
		}

		t.proxies[name] = proxy
		fmt.Printf("init backend tunnel: %s on host %s port %d\n", name, bt.Host, bt.Port)
	}

	return t
}

// PassProxy 處理 HTTP 反向代理請求
func (t *Tunnel) PassProxy(domain, reply string, w http.ResponseWriter, r *http.Request) bool {
	backendName := t.resolveBackend(domain, reply)
	if backendName == "" {
		return false
	}
	proxy, ok := t.proxies[backendName]
	if !ok {
		fmt.Printf("unknown tunnel: %s\n", backendName)
		return false
	}
	proxy.ServeHTTP(w, r)
	return true
}

// PassWebSocket 處理 WebSocket upgrade 代理
func (t *Tunnel) PassWebSocket(domain, reply string, w http.ResponseWriter, r *http.Request) bool {
	backendName := t.resolveBackend(domain, reply)
	if backendName == "" {
		return false
	}
	bt, ok := t.backends[backendName]
	if !ok {
		fmt.Printf("unknown tunnel: %s\n", backendName)
		return false
	}

	// hijack client 連線
	hj, ok := w.(http.Hijacker)
	if !ok {
		fmt.Println("server doesn't support hijacking")
		return false
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		fmt.Printf("hijack failed: %v\n", err)
		return false
	}

	// 連到後端
	backendAddr := fmt.Sprintf("%s:%d", bt.Forward, bt.Port)
	backendConn, err := net.Dial("tcp", backendAddr)
	if err != nil {
		fmt.Printf("dial backend %s failed: %v\n", backendAddr, err)
		clientConn.Close()
		return false
	}

	// 將原始 request 轉送到後端（改寫 Host）
	r.Host = bt.Host
	if err := r.Write(backendConn); err != nil {
		fmt.Printf("write request to backend failed: %v\n", err)
		clientConn.Close()
		backendConn.Close()
		return false
	}

	// 如果 clientBuf 中有剩餘資料，先送到後端
	if clientBuf.Reader.Buffered() > 0 {
		buffered := make([]byte, clientBuf.Reader.Buffered())
		n, err := clientBuf.Read(buffered)
		if err != nil {
			fmt.Printf("read buffered data failed: %v\n", err)
			clientConn.Close()
			backendConn.Close()
			return false
		}
		if _, err := backendConn.Write(buffered[:n]); err != nil {
			fmt.Printf("write buffered data to backend failed: %v\n", err)
			clientConn.Close()
			backendConn.Close()
			return false
		}
	}

	// 追蹤 WebSocket 連線，以便 logout 時清除
	sessionKey := r.Header.Get("X-Proxy-Session-Key")
	socketID := fmt.Sprintf("%s-%p", domain, clientConn)
	if sessionKey != "" {
		t.SetWebSocket(sessionKey, clientConn, socketID)
	}

	// 雙向 pipe
	go func() {
		io.Copy(backendConn, clientConn)
		backendConn.Close()
	}()
	go func() {
		io.Copy(clientConn, backendConn)
		clientConn.Close()
		if sessionKey != "" {
			t.wsMu.Lock()
			if sockets, ok := t.websockets[sessionKey]; ok {
				delete(sockets, socketID)
				if len(sockets) == 0 {
					delete(t.websockets, sessionKey)
				}
			}
			t.wsMu.Unlock()
		}
	}()

	return true
}

func (t *Tunnel) resolveBackend(domain, reply string) string {
	ft, ok := t.cfg.FrontendTunnel[domain]
	if !ok {
		fmt.Printf("domain %s not found\n", domain)
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(reply)
	if err != nil {
		fmt.Printf("base64 decode failed: %v\n", err)
		return ""
	}
	username := string(decoded)
	acct, ok := ft.Account[username]
	if !ok {
		fmt.Printf("domain %s account %s can't find backend\n", domain, username)
		return ""
	}
	return acct.Backend
}

func (t *Tunnel) SetWebSocket(session string, conn net.Conn, socketID string) {
	t.wsMu.Lock()
	defer t.wsMu.Unlock()
	if t.websockets[session] == nil {
		t.websockets[session] = make(map[string]net.Conn)
	}
	t.websockets[session][socketID] = conn
	fmt.Printf("socket id: %s set ok\n", socketID)
}

func (t *Tunnel) RemoveWebSocket(session string) {
	t.wsMu.Lock()
	defer t.wsMu.Unlock()
	if sockets, ok := t.websockets[session]; ok {
		for _, conn := range sockets {
			conn.Close()
		}
		delete(t.websockets, session)
	}
}
