package parser

import (
	"sync"
	"time"
)

type cacheEntry struct {
	data      []byte
	expiresAt time.Time
}

// SubscriptionCache 提供内存订阅数据 TTL 缓存
type SubscriptionCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	ttl     time.Duration
}

var defaultCache = &SubscriptionCache{
	entries: make(map[string]cacheEntry),
	ttl:     5 * time.Minute,
}

// Get 获取缓存数据，若未命中或已过期返回 false
func (c *SubscriptionCache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.data, true
}

// Set 写入缓存数据并设置过期时间
func (c *SubscriptionCache) Set(key string, data []byte) {
	c.mu.Lock()
	c.entries[key] = cacheEntry{
		data:      data,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()
}

// Delete 删除指定缓存
func (c *SubscriptionCache) Delete(key string) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

// PurgeSubscriptionCache 清除指定订阅 URL 的缓存
func PurgeSubscriptionCache(key string) {
	defaultCache.Delete(key)
}
