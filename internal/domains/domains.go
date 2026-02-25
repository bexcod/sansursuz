// Package domains manages the list of blocked/proxied domains.
package domains

import (
	"bufio"
	"embed"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

//go:embed turkey.txt
var turkeyList embed.FS

// Matcher checks if a hostname should be proxied (i.e., is blocked).
type Matcher struct {
	// Static domains from embedded list + config
	domains map[string]struct{}
	// Dynamically learned domains (auto-detected as blocked)
	learned map[string]struct{}
	mu      sync.RWMutex
}

// NewMatcher creates a new domain matcher pre-loaded with the Turkey blocklist.
func NewMatcher() *Matcher {
	m := &Matcher{
		domains: make(map[string]struct{}),
		learned: make(map[string]struct{}),
	}
	m.loadEmbedded()
	m.LoadLearned()
	return m
}

// loadEmbedded loads the embedded Turkey domain list.
func (m *Matcher) loadEmbedded() {
	data, err := turkeyList.ReadFile("turkey.txt")
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m.domains[strings.ToLower(line)] = struct{}{}
	}
}

// AddDomain adds a domain to the blocklist.
func (m *Matcher) AddDomain(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d := strings.ToLower(strings.TrimSpace(domain))
	m.domains[d] = struct{}{}
	m.learned[d] = struct{}{}
}

// AddDomains adds multiple domains to the blocklist.
func (m *Matcher) AddDomains(domains []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" {
			m.domains[d] = struct{}{}
		}
	}
}

// IsBlocked checks if a hostname (or any of its parent domains) is in the blocklist.
// Example: "cdn.discord.com" matches if "discord.com" is in the list.
func (m *Matcher) IsBlocked(hostname string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	hostname = strings.ToLower(strings.TrimSpace(hostname))

	// Check exact match
	if _, ok := m.domains[hostname]; ok {
		return true
	}

	// Check parent domains
	for {
		idx := strings.IndexByte(hostname, '.')
		if idx < 0 {
			break
		}
		hostname = hostname[idx+1:]
		if _, ok := m.domains[hostname]; ok {
			return true
		}
	}

	return false
}

// Count returns the number of domains in the blocklist.
func (m *Matcher) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.domains)
}

// AllDomains returns a copy of all domain names in the blocklist.
func (m *Matcher) AllDomains() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]string, 0, len(m.domains))
	for d := range m.domains {
		result = append(result, d)
	}
	return result
}

// LearnedCount returns the number of auto-detected domains.
func (m *Matcher) LearnedCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.learned)
}

// SaveLearned writes auto-detected domains to ~/.alcatraz/learned.txt
func (m *Matcher) SaveLearned() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.learned) == 0 {
		return
	}

	path := learnedFilePath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("[Sansürsüz] learned.txt dizini oluşturulamadı: %v", err)
		return
	}

	var sb strings.Builder
	sb.WriteString("# Alcatraz — Otomatik tespit edilen engelli domainler\n")
	sb.WriteString("# Bu dosyayı silmek öğrenilen listeyi sıfırlar\n\n")
	for d := range m.learned {
		sb.WriteString(d)
		sb.WriteString("\n")
	}

	if err := os.WriteFile(path, []byte(sb.String()), 0644); err != nil {
		log.Printf("[Sansürsüz] learned.txt yazılamadı: %v", err)
		return
	}

	log.Printf("[Sansürsüz] 💾 %d öğrenilen domain kaydedildi: %s", len(m.learned), path)
}

// LoadLearned reads auto-detected domains from ~/.alcatraz/learned.txt
func (m *Matcher) LoadLearned() {
	path := learnedFilePath()
	data, err := os.ReadFile(path)
	if err != nil {
		return // File doesn't exist yet, that's fine
	}

	count := 0
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		d := strings.ToLower(line)
		m.domains[d] = struct{}{}
		m.learned[d] = struct{}{}
		count++
	}

	if count > 0 {
		log.Printf("[Sansürsüz] 📂 %d öğrenilen domain yüklendi: %s", count, path)
	}
}

func learnedFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".alcatraz", "learned.txt")
}

// String returns a summary of the matcher state.
func (m *Matcher) String() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return fmt.Sprintf("%d domain (%d öğrenilen)", len(m.domains), len(m.learned))
}
