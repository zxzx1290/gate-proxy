package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func md5Hash(data string) string {
	h := md5.Sum([]byte(data))
	return fmt.Sprintf("%x", h)
}

func sha512Hash(data string) string {
	h := sha512.Sum512([]byte(data))
	return fmt.Sprintf("%x", h)
}

func randomString(count int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz1234567890"
	result := make([]byte, count)
	for i := 0; i < count; i++ {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		result[i] = chars[n.Int64()]
	}
	return string(result)
}

func getPrefixURL(cfg *Config, domain, urlType string) string {
	ft, ok := cfg.FrontendTunnel[domain]
	if !ok {
		fmt.Printf("%s: not found\n", domain)
		return "/"
	}
	switch urlType {
	case "exroot":
		return ft.ExRoot
	case "exlogin":
		return ft.ExLogin
	case "login":
		return ft.Login
	case "logout":
		return ft.Logout
	case "check":
		return ft.Check
	case "extend":
		return ft.Extend
	default:
		return "/"
	}
}

var digitRegex = regexp.MustCompile(`^[0-9]{6}$`)

func checkUser(cfg *Config, host, username, password string) bool {
	ft, ok := cfg.FrontendTunnel[host]
	if !ok {
		return false
	}
	acct, ok := ft.Account[username]
	if !ok {
		return false
	}
	if !digitRegex.MatchString(password) {
		return false
	}
	if acct.TOTPSecret == "" {
		fmt.Printf("WARNING: account %s has empty TOTP secret, login denied\n", username)
		return false
	}
	rv, _ :=  totp.ValidateCustom(
		password,
		acct.TOTPSecret,
		time.Now(),
		totp.ValidateOpts{
			Period:    30, // 每個 TOTP 30 秒
			Skew:      2,  // 後各允許 2 個 step（約 ±60 秒）
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		},
	)
	return rv
}

func sendNotify(cfg *Config, text string) {
	if cfg.LoginNotify == "" {
		return
	}
	go func() {
		u := cfg.LoginNotify + url.QueryEscape(text)
		resp, err := http.Get(u)
		if err != nil {
			fmt.Printf("通知發送失敗: %v\n", err)
			return
		}
		resp.Body.Close()
	}()
}

func loginSuccess(cfg *Config, rc *RedisClient, proxySession, username string, longLive bool, host string, w http.ResponseWriter) bool {
	aliveSec := cfg.DefaultLoginAliveSec
	cookieExpires := ""
	if longLive {
		aliveSec = cfg.LongLoginAliveSec
		cookieExpires = time.Now().Add(time.Duration(aliveSec) * time.Second).UTC().Format(http.TimeFormat)
	}

	redisKey := sha512Hash(proxySession + host + cfg.Secret)
	usernameB64 := base64.StdEncoding.EncodeToString([]byte(username))

	if err := rc.SetEX(redisKey, usernameB64, aliveSec); err != nil {
		fmt.Printf("Redis SET 失敗: %v\n", err)
		return false
	}

	w.Header().Set("Content-Type", "text/html")

	cookies := []string{
		fmt.Sprintf("proxysession=%s;path=/;Expires=%s;httpOnly;Secure;SameSite=Lax", proxySession, cookieExpires),
		fmt.Sprintf("proxyuser=%s;path=/;Expires=%s;httpOnly;Secure;SameSite=Lax", username, cookieExpires),
		fmt.Sprintf("proxyhash=%s;path=/;Expires=%s;httpOnly;Secure;SameSite=Lax", md5Hash(username+cfg.UserSalt), cookieExpires),
	}
	for _, c := range cookies {
		w.Header().Add("Set-Cookie", c)
	}

	resp := map[string]string{"code": "1", "data": getPrefixURL(cfg, host, "exroot")}
	data, _ := json.Marshal(resp)
	w.Write(data)
	return true
}
