package main

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisClient struct {
	client *redis.Client
	ctx    context.Context
}

func NewRedisClient(addr, password string) *RedisClient {
	opts := &redis.Options{
		Addr: addr,
	}
	if password != "" {
		opts.Password = password
	}
	client := redis.NewClient(opts)
	rc := &RedisClient{
		client: client,
		ctx:    context.Background(),
	}
	return rc
}

func (rc *RedisClient) Ping() error {
	_, err := rc.client.Ping(rc.ctx).Result()
	if err != nil {
		return fmt.Errorf("Redis 連線失敗: %w", err)
	}
	return nil
}

// Get 取得 key 的值，不存在回傳 ("", false, nil)
func (rc *RedisClient) Get(key string) (string, bool, error) {
	val, err := rc.client.Get(rc.ctx, key).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return val, true, nil
}

// SetEX 設定 key 的值並設定過期秒數
func (rc *RedisClient) SetEX(key, value string, seconds int) error {
	return rc.client.Set(rc.ctx, key, value, time.Duration(seconds)*time.Second).Err()
}

// Del 刪除 key
func (rc *RedisClient) Del(key string) error {
	return rc.client.Del(rc.ctx, key).Err()
}

// Incr 遞增 key 並回傳新值
func (rc *RedisClient) Incr(key string) (int64, error) {
	return rc.client.Incr(rc.ctx, key).Result()
}

// TTL 取得 key 的剩餘秒數
func (rc *RedisClient) TTL(key string) (int64, error) {
	d, err := rc.client.TTL(rc.ctx, key).Result()
	if err != nil {
		return 0, err
	}
	return int64(d.Seconds()), nil
}
