package intel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"noctua/internal/event"
)

type Provider interface {
	Name() string
	CheckIP(ip string) (map[string]any, error)
}

type HashProvider interface {
	CheckHash(sha256 string) (map[string]any, error)
}

type cacheEntry struct {
	Data    map[string]any `json:"data"`
	Expires time.Time      `json:"expires"`
}

type Enricher struct {
	providers     []Provider
	hashProviders []HashProvider
	cache         map[string]cacheEntry
	cacheMu       sync.RWMutex
	cacheTTL      time.Duration
	cacheDir      string
}

func NewEnricher(cacheTTLMinutes int) *Enricher {
	homeDir, _ := os.UserHomeDir()
	cacheDir := filepath.Join(homeDir, ".noctua", "cache")
	os.MkdirAll(cacheDir, 0755)

	e := &Enricher{
		cache:    make(map[string]cacheEntry),
		cacheTTL: time.Duration(cacheTTLMinutes) * time.Minute,
		cacheDir: cacheDir,
	}
	e.loadCache()
	return e
}

func (e *Enricher) AddProvider(p Provider) {
	e.providers = append(e.providers, p)
}

func (e *Enricher) AddHashProvider(p HashProvider) {
	e.hashProviders = append(e.hashProviders, p)
}

func (e *Enricher) Enrich(ev *event.Event) {
	if ev.ThreatIntel == nil {
		ev.ThreatIntel = make(map[string]any)
	}

	// Enrich IPs
	if ip, ok := ev.Details["remote_addr"].(string); ok && ip != "" {
		for _, p := range e.providers {
			data := e.lookupIP(p, ip)
			if data != nil {
				ev.ThreatIntel[p.Name()] = data

				// Apply scoring bonuses
				if score, ok := data["abuse_score"].(float64); ok && score > 50 {
					ev.Score += 20
				}
				if isHighRisk, ok := data["high_risk_country"].(bool); ok && isHighRisk {
					ev.Score += 15
				}
			}
		}
	}

	// Enrich file hashes
	if hash, ok := ev.Details["new_hash"].(string); ok && hash != "" {
		for _, p := range e.hashProviders {
			data, err := p.CheckHash(hash)
			if err == nil && data != nil {
				ev.ThreatIntel["malware_check"] = data
				if known, ok := data["known_malware"].(bool); ok && known {
					ev.Score += 80
				}
			}
		}
	}
}

func (e *Enricher) LookupIP(ip string) map[string]any {
	result := make(map[string]any)
	for _, p := range e.providers {
		data := e.lookupIP(p, ip)
		if data != nil {
			result[p.Name()] = data
		}
	}
	return result
}

func (e *Enricher) lookupIP(p Provider, ip string) map[string]any {
	cacheKey := p.Name() + ":" + ip

	e.cacheMu.RLock()
	if entry, ok := e.cache[cacheKey]; ok && time.Now().Before(entry.Expires) {
		e.cacheMu.RUnlock()
		return entry.Data
	}
	e.cacheMu.RUnlock()

	data, err := p.CheckIP(ip)
	if err != nil {
		return nil
	}

	e.cacheMu.Lock()
	e.cache[cacheKey] = cacheEntry{
		Data:    data,
		Expires: time.Now().Add(e.cacheTTL),
	}
	e.cacheMu.Unlock()

	e.saveCache()
	return data
}

func (e *Enricher) loadCache() {
	path := filepath.Join(e.cacheDir, "intel_cache.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var entries map[string]cacheEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return
	}

	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()

	now := time.Now()
	for k, v := range entries {
		if now.Before(v.Expires) {
			e.cache[k] = v
		}
	}
}

func (e *Enricher) saveCache() {
	e.cacheMu.RLock()
	data, err := json.Marshal(e.cache)
	e.cacheMu.RUnlock()

	if err != nil {
		return
	}

	path := filepath.Join(e.cacheDir, "intel_cache.json")
	os.WriteFile(path, data, 0644)
}
