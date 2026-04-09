package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	cfg, err := LoadConfig("config.json")
	if err != nil {
		fmt.Printf("載入設定失敗: %v\n", err)
		os.Exit(1)
	}

	rc := NewRedisClient(cfg.RedisAddr, cfg.RedisPassword)
	if err := rc.Ping(); err != nil {
		fmt.Printf("Redis 連線失敗: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Redis 連線成功")

	view, err := NewView(cfg.Template)
	if err != nil {
		fmt.Printf("載入模板失敗: %v\n", err)
		os.Exit(1)
	}

	tunnel := NewTunnel(cfg)

	handler := &ProxyHandler{
		cfg:    cfg,
		rc:     rc,
		view:   view,
		tunnel: tunnel,
	}

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Port)
	fmt.Printf("啟動伺服器於 %s\n", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		fmt.Printf("伺服器啟動失敗: %v\n", err)
		os.Exit(1)
	}
}

type ProxyHandler struct {
	cfg    *Config
	rc     *RedisClient
	view   *View
	tunnel *Tunnel
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := r.Header.Get("X-Real-IP")
	if ip == "" {
		ip = r.RemoteAddr
	}
	host := r.Host
	pathname := r.URL.Path
	cookies := parseCookies(r)

	// favicon.ico 導向
	if pathname == "/favicon.ico" {
		http.Redirect(w, r, "https://testused.com/favicon.ico", http.StatusFound)
		return
	}

	// WebSocket upgrade
	if isWebSocketUpgrade(r) {
		h.handleWebSocket(w, r, ip, host, cookies)
		return
	}

	// 檢查 IP 是否被封鎖
	banReply, banExists, err := h.rc.Get(md5Hash(ip))
	if err != nil {
		w.Write([]byte("auth unavailable"))
		fmt.Printf("auth unavailable: %v\n", err)
		return
	}
	if banExists {
		banCount, _ := strconv.Atoi(banReply)
		if banCount >= h.cfg.MaxRetry {
			w.Write([]byte("banned ip " + ip))
			fmt.Printf("banned ip %s\n", ip)
			return
		}
	}

	session := cookies["proxysession"]

	if session != "" {
		// 有 session cookie
		h.handleWithSession(w, r, ip, host, pathname, session, cookies)
	} else {
		// 無 session cookie
		h.handleWithoutSession(w, r, ip, host, pathname, banReply)
	}
}

func (h *ProxyHandler) handleWithSession(w http.ResponseWriter, r *http.Request, ip, host, pathname, session string, cookies map[string]string) {
	// logout
	if pathname == getPrefixURL(h.cfg, host, "logout") {
		h.handleLogout(w, r, host, session, cookies)
		return
	}

	// 驗證 session
	sessionKey := sha512Hash(session + host + h.cfg.Secret)
	reply, exists, err := h.rc.Get(sessionKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("auth unavailable"))
		return
	}

	if !exists {
		// session 不存在
		h.rc.Incr(md5Hash(ip))
		banReply, _, _ := h.rc.Get(md5Hash(ip))

		expiredCookie := expireCookieHeader()

		if pathname == getPrefixURL(h.cfg, host, "check") {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Set-Cookie", expiredCookie)
			json.NewEncoder(w).Encode(map[string]string{"status": "false", "data": "session expire"})
			return
		}

		count := 0
		if banReply != "" {
			count, _ = strconv.Atoi(banReply)
		}

		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Set-Cookie", expiredCookie)
		w.Write([]byte(h.view.Render(host, ip, pathname, count, getPrefixURL(h.cfg, host, "exlogin"))))

		sendNotify(h.cfg, ip+" 連接 "+host+" session過期")
		return
	}

	// session 有效

	// check 路由
	if pathname == getPrefixURL(h.cfg, host, "check") {
		ttl, err := h.rc.TTL(sessionKey)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"status": "true", "data": "error"})
		} else {
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "true", "data": ttl})
		}
		return
	}

	// extend 路由
	if pathname == getPrefixURL(h.cfg, host, "extend") {
		decoded, _ := base64.StdEncoding.DecodeString(reply)
		username := string(decoded)
		sendNotify(h.cfg, username+" 於 "+ip+" 延長登入 "+host+"\r\nsession "+sessionKey[:5])

		if loginSuccess(h.cfg, h.rc, session, username, true, host, w) {
			fmt.Println("process relogin success")
		} else {
			fmt.Println("process relogin failed")
		}
		return
	}

	// 正常代理
	if !h.tunnel.PassProxy(host, reply, w, r) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error occur"))
	}
}

func (h *ProxyHandler) handleLogout(w http.ResponseWriter, r *http.Request, host, session string, cookies map[string]string) {
	expiredCookie := expireCookieHeader()

	reason := r.URL.Query().Get("reason")
	sessionScript := ""
	if reason != "" {
		reasonJSON, _ := json.Marshal(reason)
		sessionScript = fmt.Sprintf("sessionStorage.setItem('reason', %s);", string(reasonJSON))
	}

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Set-Cookie", expiredCookie)
	w.Write([]byte(
		"<script>" +
			sessionScript +
			`window.location.href="` + getPrefixURL(h.cfg, host, "exroot") + `";` +
			"</script>",
	))

	if session != "" {
		key := sha512Hash(session + host + h.cfg.Secret)
		h.tunnel.RemoveWebSocket(key)
		h.rc.Del(key)
	}
}

func (h *ProxyHandler) handleWithoutSession(w http.ResponseWriter, r *http.Request, ip, host, pathname, banReply string) {
	// POST login
	if r.Method == "POST" && pathname == getPrefixURL(h.cfg, host, "login") {
		h.handleLogin(w, r, ip, host)
		return
	}

	// check 路由（無 session）
	if pathname == getPrefixURL(h.cfg, host, "check") {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "false", "data": "no session"})
		return
	}

	// 顯示登入頁面
	count := 0
	if banReply != "" {
		count, _ = strconv.Atoi(banReply)
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(h.view.Render(host, ip, pathname, count, getPrefixURL(h.cfg, host, "exlogin"))))
}

func (h *ProxyHandler) handleLogin(w http.ResponseWriter, r *http.Request, ip, host string) {
	// 限制 body 大小
	r.Body = http.MaxBytesReader(w, r.Body, 1000)
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	rememberMe := r.FormValue("rememberme") == "true"

	if username == "" || password == "" {
		w.Header().Set("Content-Type", "text/html")
		json.NewEncoder(w).Encode(map[string]string{"code": "3"})
		return
	}

	if checkUser(h.cfg, host, username, password) {
		// 登入成功
		id := sha512Hash(randomString(32) + fmt.Sprintf("%d", time.Now().UnixNano()))
		if id == "" {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("generate ID fail"))
			return
		}

		redisKey := sha512Hash(id + host + h.cfg.Secret)
		sendNotify(h.cfg, username+" 於 "+ip+" 登入 "+host+"\r\nsession "+redisKey[:5])

		// 清除 ban 記錄
		h.rc.Del(md5Hash(ip))

		if loginSuccess(h.cfg, h.rc, id, username, rememberMe, host, w) {
			fmt.Println("process login success")
		} else {
			fmt.Println("process login failed")
		}
	} else {
		// 登入失敗
		h.rc.Incr(md5Hash(ip))
		banReply, _, _ := h.rc.Get(md5Hash(ip))

		w.Header().Set("Content-Type", "text/html")
		json.NewEncoder(w).Encode(map[string]string{"code": "2", "data": banReply})

		sendNotify(h.cfg, username+" 於 "+ip+" 登入 "+host+" 失敗")
	}
}

func (h *ProxyHandler) handleWebSocket(w http.ResponseWriter, r *http.Request, ip, host string, cookies map[string]string) {
	// 檢查 IP ban
	banReply, banExists, _ := h.rc.Get(md5Hash(ip))
	if banExists {
		banCount, _ := strconv.Atoi(banReply)
		if banCount >= h.cfg.MaxRetry {
			http.Error(w, "You are banned", http.StatusForbidden)
			fmt.Println("You are banned")
			return
		}
	}

	session := cookies["proxysession"]
	if session == "" {
		http.Error(w, "You are not allowed", http.StatusForbidden)
		fmt.Println("You are not allowed")
		return
	}

	key := sha512Hash(session + host + h.cfg.Secret)
	reply, exists, _ := h.rc.Get(key)
	if !exists {
		http.Error(w, "You are banned", http.StatusForbidden)
		fmt.Println("You are banned")
		return
	}

	if h.tunnel.PassWebSocket(host, reply, w, r) {
		// WebSocket 連線已交由 tunnel 處理
	} else {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		fmt.Println("passProxy error")
	}
}

// --- 輔助函式 ---

func parseCookies(r *http.Request) map[string]string {
	result := make(map[string]string)
	for _, c := range r.Cookies() {
		result[c.Name] = c.Value
	}
	return result
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Connection"), "Upgrade") &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func expireCookieHeader() string {
	t := time.Now().Add(-5 * 24 * time.Hour).UTC().Format(http.TimeFormat)
	return "proxysession=;path=/;Expires=" + t + ";httpOnly;Secure"
}
