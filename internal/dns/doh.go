// Package dns provides DNS-over-HTTPS resolution to bypass ISP DNS manipulation.
package dns

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Provider represents a DoH provider configuration.
type Provider struct {
	Name        string
	URL         string
	BootstrapIP string // Direct IP to avoid DNS chicken-and-egg problem
}

var (
	Cloudflare = Provider{
		Name:        "Cloudflare",
		URL:         "https://cloudflare-dns.com/dns-query",
		BootstrapIP: "1.1.1.1",
	}
	Google = Provider{
		Name:        "Google",
		URL:         "https://dns.google/dns-query",
		BootstrapIP: "8.8.8.8",
	}
	Quad9 = Provider{
		Name:        "Quad9",
		URL:         "https://dns.quad9.net/dns-query",
		BootstrapIP: "9.9.9.9",
	}
	AdGuard = Provider{
		Name:        "AdGuard",
		URL:         "https://dns.adguard-dns.com/dns-query",
		BootstrapIP: "94.140.14.14",
	}
	Yandex = Provider{
		Name:        "Yandex",
		URL:         "https://common.dot.dns.yandex.net/dns-query",
		BootstrapIP: "77.88.8.8",
	}
)

// cacheEntry stores a cached DNS response with stale-while-revalidate support.
type cacheEntry struct {
	ips       []net.IP
	expiresAt time.Time // When the entry becomes stale
	deadAt    time.Time // When the entry should not be used at all
	updating  bool      // Whether a background refresh is in progress
}

// Resolver performs DNS resolution via DNS-over-HTTPS with intelligent caching.
type Resolver struct {
	providers []Provider
	client    *http.Client
	cache     map[string]*cacheEntry
	negCache  map[string]time.Time // Negative cache: failed lookups
	mu        sync.RWMutex
}

// NewResolver creates a new DoH resolver with the given providers.
func NewResolver(providers ...Provider) *Resolver {
	if len(providers) == 0 {
		providers = []Provider{Cloudflare, Google}
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, _ := net.SplitHostPort(addr)
			for _, p := range providers {
				if host == extractHost(p.URL) {
					addr = net.JoinHostPort(p.BootstrapIP, port)
					break
				}
			}
			dialer := &net.Dialer{Timeout: 3 * time.Second}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSHandshakeTimeout:   3 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          20,
		MaxIdleConnsPerHost:   5,
		ResponseHeaderTimeout: 3 * time.Second,
	}

	return &Resolver{
		providers: providers,
		client: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
		},
		cache:    make(map[string]*cacheEntry),
		negCache: make(map[string]time.Time),
	}
}

// Resolve resolves a hostname to IP addresses using DoH.
// Uses stale-while-revalidate: returns cached result immediately even if stale,
// while refreshing in the background.
func (r *Resolver) Resolve(ctx context.Context, hostname string) ([]net.IP, error) {
	// Check negative cache
	r.mu.RLock()
	if negExp, ok := r.negCache[hostname]; ok && time.Now().Before(negExp) {
		r.mu.RUnlock()
		return nil, fmt.Errorf("negative cache hit for %s", hostname)
	}

	// Check positive cache
	if entry, ok := r.cache[hostname]; ok {
		now := time.Now()

		// Fresh: return directly
		if now.Before(entry.expiresAt) {
			r.mu.RUnlock()
			return entry.ips, nil
		}

		// Stale but not dead: return stale + refresh in background
		if now.Before(entry.deadAt) && !entry.updating {
			ips := entry.ips
			r.mu.RUnlock()

			// Mark as updating and refresh in background
			r.mu.Lock()
			if e, ok := r.cache[hostname]; ok {
				e.updating = true
			}
			r.mu.Unlock()

			go r.refreshInBackground(hostname)
			return ips, nil
		}
	}
	r.mu.RUnlock()

	// Cache miss or dead entry — blocking resolve
	return r.resolveAndCache(ctx, hostname)
}

// resolveAndCache performs a fresh DoH query and caches the result.
func (r *Resolver) resolveAndCache(ctx context.Context, hostname string) ([]net.IP, error) {
	var lastErr error
	for _, provider := range r.providers {
		ips, ttl, err := r.queryDoH(ctx, provider, hostname)
		if err != nil {
			lastErr = err
			continue
		}

		r.cacheResult(hostname, ips, ttl)
		return ips, nil
	}

	// Cache the failure for 30 seconds
	r.mu.Lock()
	r.negCache[hostname] = time.Now().Add(30 * time.Second)
	r.mu.Unlock()

	return nil, fmt.Errorf("all DoH providers failed for %s: %w", hostname, lastErr)
}

// cacheResult stores a successful DNS result with stale-while-revalidate timing.
func (r *Resolver) cacheResult(hostname string, ips []net.IP, ttl uint32) {
	if ttl < 60 {
		ttl = 60 // Minimum 1 minute
	}

	r.mu.Lock()
	r.cache[hostname] = &cacheEntry{
		ips:       ips,
		expiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
		deadAt:    time.Now().Add(time.Duration(ttl*3) * time.Second), // 3x TTL stale window
		updating:  false,
	}
	// Remove from negative cache if present
	delete(r.negCache, hostname)
	r.mu.Unlock()
}

// refreshInBackground refreshes a stale cache entry.
func (r *Resolver) refreshInBackground(hostname string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, provider := range r.providers {
		ips, ttl, err := r.queryDoH(ctx, provider, hostname)
		if err != nil {
			continue
		}
		r.cacheResult(hostname, ips, ttl)
		return
	}

	// Refresh failed — allow retrying later
	r.mu.Lock()
	if e, ok := r.cache[hostname]; ok {
		e.updating = false
	}
	r.mu.Unlock()
}

// Prefetch resolves a list of hostnames in advance, populating the cache.
func (r *Resolver) Prefetch(hostnames []string) {
	log.Printf("[Sansürsüz] 🔄 %d domain DNS ön-yüklemesi başlatılıyor...", len(hostnames))

	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // Max 10 concurrent queries

	resolved := 0
	var mu sync.Mutex

	for _, h := range hostnames {
		wg.Add(1)
		go func(hostname string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			_, err := r.resolveAndCache(ctx, hostname)
			if err == nil {
				mu.Lock()
				resolved++
				mu.Unlock()
			}
		}(h)
	}

	wg.Wait()
	log.Printf("[Sansürsüz] ✅ DNS ön-yükleme tamamlandı: %d/%d başarılı", resolved, len(hostnames))
}

// ClearCache clears all caches.
func (r *Resolver) ClearCache() {
	r.mu.Lock()
	r.cache = make(map[string]*cacheEntry)
	r.negCache = make(map[string]time.Time)
	r.mu.Unlock()
}

// CacheSize returns the number of cached entries.
func (r *Resolver) CacheSize() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.cache)
}

// queryDoH sends a DNS query to a DoH provider and returns the resolved IPs.
func (r *Resolver) queryDoH(ctx context.Context, provider Provider, hostname string) ([]net.IP, uint32, error) {
	name, err := dnsmessage.NewName(hostname + ".")
	if err != nil {
		return nil, 0, fmt.Errorf("invalid hostname: %w", err)
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	wireMsg, err := msg.Pack()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(wireMsg)
	url := fmt.Sprintf("%s?dns=%s", provider.URL, encoded)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("DoH request to %s failed: %w", provider.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("DoH %s returned status %d", provider.Name, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read DoH response: %w", err)
	}

	var response dnsmessage.Message
	if err := response.Unpack(body); err != nil {
		return nil, 0, fmt.Errorf("failed to parse DNS response: %w", err)
	}

	var ips []net.IP
	var minTTL uint32 = 300

	for _, answer := range response.Answers {
		switch rr := answer.Body.(type) {
		case *dnsmessage.AResource:
			ips = append(ips, net.IP(rr.A[:]))
			if answer.Header.TTL < minTTL {
				minTTL = answer.Header.TTL
			}
		case *dnsmessage.AAAAResource:
			ips = append(ips, net.IP(rr.AAAA[:]))
			if answer.Header.TTL < minTTL {
				minTTL = answer.Header.TTL
			}
		}
	}

	if len(ips) == 0 {
		return nil, 0, fmt.Errorf("no A/AAAA records found for %s via %s", hostname, provider.Name)
	}

	return ips, minTTL, nil
}

// extractHost extracts the hostname from a URL.
func extractHost(rawURL string) string {
	start := 0
	for i := 0; i < len(rawURL); i++ {
		if rawURL[i] == '/' && i > 0 && rawURL[i-1] == '/' {
			start = i + 1
			break
		}
	}
	end := len(rawURL)
	for i := start; i < len(rawURL); i++ {
		if rawURL[i] == '/' || rawURL[i] == ':' {
			end = i
			break
		}
	}
	return rawURL[start:end]
}
