package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Account struct {
	TOTPSecret string `json:"totpSecret"`
	Backend    string `json:"backend"`
}

type FrontendTunnel struct {
	ExRoot  string              `json:"exroot"`
	ExLogin string              `json:"exlogin"`
	Login   string              `json:"login"`
	Logout  string              `json:"logout"`
	Check   string              `json:"check"`
	Extend  string              `json:"extend"`
	Account map[string]*Account `json:"account"`
}

type BackendTunnel struct {
	Host    string `json:"host"`
	Forward string `json:"forward"`
	Port    int    `json:"port"`
}

type Config struct {
	Template            string                     `json:"template"`
	LoginNotify         string                     `json:"loginNotify"`
	Secret              string                     `json:"secret"`
	UserSalt            string                     `json:"userSalt"`
	MaxRetry            int                        `json:"maxRetry"`
	RedisAddr           string                     `json:"redisAddr"`
	RedisPassword       string                     `json:"redisPassword"`
	DefaultLoginAliveSec int                       `json:"defaultLoginAliveSec"`
	LongLoginAliveSec   int                        `json:"longLoginAliveSec"`
	Port                int                        `json:"port"`
	FrontendTunnel      map[string]*FrontendTunnel `json:"frontendTunnel"`
	BackendTunnel       map[string]*BackendTunnel  `json:"backendTunnel"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("讀取設定檔失敗: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析設定檔失敗: %w", err)
	}
	return &cfg, nil
}
